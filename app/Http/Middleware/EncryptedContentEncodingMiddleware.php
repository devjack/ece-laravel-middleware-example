<?php

namespace App\Http\Middleware;

use Closure;
use DevJack\EncryptedContentEncoding\RFC8188;
use DevJack\EncryptedContentEncoding\EncryptionKeyProviderInterface;
use Illuminate\Http\Request;
use App\Http\Request as EncryptedRequest;
use Base64Url\Base64Url as b64;

class EncryptedContentEncodingMiddleware
{
    protected $shouldErrorOnFailure = true;

    protected $initialRequest = null;
    protected $initialResponse = null;

    protected $encryptionKeyProvider;

    public function __construct(EncryptionKeyProviderInterface $encryptionKeyProvider) {
        $this->encryptionKeyProvider = $encryptionKeyProvider;
    }

    public function shouldAttemptToRunEceMiddleware($request) {
        // if content encoding is aes128gcm, fail with 400 for decode and 500 for encode
        $encoding = $request->header('Content-Encoding');
        if(strpos('aes128gcm', $encoding) !== false) {
            $this->shouldErrorOnFailure = true;
            return true;
        }

        $content_type = $request->header('Content-Type');
        if($content_type === "application/octet-stream") {
            // TODO: Implement config/settings that make this functionality optional.
            // We are making an assumption here, so don't error out.
            $this->shouldErrorOnFailure = false;
            return true;
        }
    }

    public function attemptDecodeRequest($request) {
        try {
            $decoded = RFC8188::rfc8188_decode(
                b64::decode($request->getContent()),
                $this->encryptionKeyProvider
            );

            return new Request(
                $request->query->all(),
                $request->request->all(),
                $request->attributes->all(),
                $request->cookies->all(),
                $request->files->all(),
                $request->server->all(),
                $decoded // set the content on the new request
            );
        } catch(\Exception $e) {
            if($this->shouldErrorOnFailure) {
                // Throw an appropriate response
                throw $e;
            } else {
                // Passthru without decoding.
                throw $e;
                return $this->initialRequest;
            }
        }

        return $request;
    }

    public function attemptEncodeResponse($response, $request = null, $keyid, $rs=256) {
        try {
            /*
            * TODO: If there is already content encoding then append 
            *   aes128gcm encoding as per the order it was applied.
            *   See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding#Syntax
            */

            //TODO: Implement different $rs strategies to determine the $rs value.
            
            $encryptionKeyProvider = $this->encryptionKeyProvider;
            $encoded = RFC8188::rfc8188_encode(
                $response->getContent(), // plaintext
                $encryptionKeyProvider($keyid), // encryption key
                $keyid,   // key ID
                $rs    // record size.
            );

            $encoded_request = new Request(
                $request->query->all(),
                $request->request->all(),
                $request->attributes->all(),
                $request->cookies->all(),
                $request->files->all(),
                $request->server->all(),
                b64::encode($encoded) // set the content on the new request
            );

            $encoded_request->headers->add(['Content-Encoding' => 'aes128gcm']);
            return $encoded_request;

        } catch(\Exception $e) {
            if($this->shouldErrorOnFailure) {
                // Throw an appropriate response
                
            } else {
                // Passthru without decoding.
                return $this->initialResponse;
            }
        }

        return $response;
    }

    public function determineEncryptionKeyId($request) {
        if(instance_of(App\Http\Request::class, $request)) {
            return $request->getEncryptionKeyId();
        }

        // TODO: default/fallback to the Api-Key header.

        // TODO: default to a system configured encryption key.

        // TODO: unable to decrypt exception.
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $this->initialRequest = $request;

        // Only run this middleware if the content is encoded
        if($this->shouldAttemptToRunEceMiddleware($request)) {
            $request = $this->attemptDecodeRequest($request);
        }
        
        $response = $next($request);

        $this->initialResponse = $response;

        if($this->shouldAttemptToRunEceMiddleware($request)) {
            $keyid = $this->determineEncryptionKeyId($request);
            $response = $this->attemptEncodeResponse($response, $request, $keyid);
        }

        return $response;
    }
}
