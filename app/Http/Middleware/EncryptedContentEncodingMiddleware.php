<?php

namespace App\Http\Middleware;

use Closure;
use DevJack\EncryptedContentEncoding\RFC8188;
use DevJack\EncryptedContentEncoding\EncryptionKeyProviderInterface;

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
        $encoding = $this->initialRequest->header('Content-Encoding');
        if(strpos('aes128gcm', $encoding) !== false) {
            $this->shouldErrorOnFailure = true;
            return true;
        }

        $content_type = $this->initialRequest->header('Content-Type');
        if($content_type === "application/octetd-stream") {
            // TODO: Implement config/settings that make this functionality optional.
            // We are making an assumption here, so don't error out.
            $this->shouldErrorOnFailure = false;
            return true;
        }
    }

    public function attemptDecodeRequest($request) {
        try {
            $decoded = RFC8188::rfc8188_decode(
                $encoded, // data to decode
                $this->encryptionKeyProvider
            );
            
        } catch(\Exception $e) {
            if($this->shouldErrorOnFailure) {
                // Throw an appropriate response
                
            } else {
                // Passthru without decoding.
                return $this->initialRequest;
            }
        }

        return $request;
    }

    public function attemptEncodeResponse($response, $request = null) {
        try {
            /*
            * TODO: If there is already content encoding then append 
            *   aes128gcm encoding as per the order it was applied.
            *   See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding#Syntax
            */
            // $response->headers->set('Content-Encoding', "aes128gcm");
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
        // if($this->shouldAttemptToRunEceMiddleware($request)) {
        //     $request = $this->attemptDecodeRequest($request);
        // }
        
        $response = $next($request);

        $this->initialResponse = $response;

        if($this->shouldAttemptToRunEceMiddleware($request)) {
            $response = $this->attemptEncodeResponse($response, $request);
        }

        return $response;
    }
}
