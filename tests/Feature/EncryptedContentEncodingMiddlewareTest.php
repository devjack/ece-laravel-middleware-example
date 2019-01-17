<?php

namespace Tests\Feature;

use DevJack\EncryptedContentEncoding\RFC8188;
use App\Http\Middleware\EncryptedContentEncodingMiddleware;
use App\Services\EncryptionKeyLookup;
use Base64Url\Base64Url as b64;
use Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Foundation\Testing\WithFaker;
use Illuminate\Foundation\Testing\RefreshDatabase;

class EncryptedContentEncodingMiddlewareTest extends TestCase
{
    /** @test */
    public function doesDetectAndSetContentEncodingByDefault() {
        $request = Request::create('/', 'GET');
        $request->headers->set('Content-Encoding', 'aes128gcm');
        
        // $middleware = new EncryptedContentEncodingMiddleware;
        $middleware = $this->app->make(EncryptedContentEncodingMiddleware::class);
        $this->assertTrue($middleware->shouldAttemptToRunEceMiddleware($request));
    }

    /** @test */
    public function doesOnlySetContentEncodingWhenDetected() {
        $request = Request::create('/', 'GET');
        // ** intentionally do not se content-encoding header herer **
        
        $middleware = $this->app->make(EncryptedContentEncodingMiddleware::class);
        $self = $this;
        $response = $middleware->handle($request, function($r) { return $r; });

        $this->assertFalse($response->headers->has('Content-Encoding'));
    }

    /** @test */
    public function doesNotSetContentEncodingIfConfigured() {
        $this->markTestSkipped('To be implemented');
    }

    /** @test */
    public function doesNotSetDescribeContentTypeIfConfigured() {
        $this->markTestSkipped('To be implemented');
    }

    /** @test */
    public function canDecryptWithKeyIDInEncodingHeader() {
        $encryptedContent = "uNCkWiNYzKTnBN9ji3-qWAAAABkCYTHOG8chz_gnvgOqdGYovxyjuqRyJFjEDyoF1Fvkj6hQPdPHI51OEUKEpgz3SsLWIqS_uA";

        $request = Request::create('/', 'POST', [], [], [], [], $encryptedContent);
        $request->headers->set('Content-Encoding', 'aes128gcm');
        
        $this->app->bind("DevJack\EncryptedContentEncoding\EncryptionKeyProviderInterface", function() {
            $lookup = new EncryptionKeyLookup();
            $lookup->addKey(b64::decode("BO3ZVPxUlnLORbVGMpbT1Q"), 'a1');
            return $lookup;
        });
        $middleware = $this->app->make(EncryptedContentEncodingMiddleware::class);
        
        $self = $this;
        $response = $middleware->handle($request, function($r) use ($self) {
            // This $next middleware gets executed after the decoding and before the encoding
            $self->assertEquals("I am the walrus", $r->getContent());
            return $r;
        });
    }

    /** @test */
    public function canFallbackToKeyIDHeader() {
        $this->markTestSkipped('To be implemented');
    }

    /** @test */
    public function doesUseEncodingHeaderBeforeHttpApiKeyHeader() {
        $this->markTestSkipped('To be implemented');
    }

    /** @test */
    public function canEncryptWithKeyIDInRequest() {
        // TODO: not sure the $request is actually needed in this test.
        $request = Request::create('/', 'GET');
        $request->headers->set('Content-Encoding', 'aes128gcm');

        // This is a request as passed to the 'after' part of the middleware.
        $response = Response::create();
        $response->setContent("I am the walrus");
        
        // Used for looking up API keys to do the encryption with.
        $lookup = new EncryptionKeyLookup();
        $lookup->addKey(b64::decode("BO3ZVPxUlnLORbVGMpbT1Q"), 'a1');
        
        $this->app->bind("DevJack\EncryptedContentEncoding\EncryptionKeyProviderInterface", function() use ($lookup) {
            return $lookup;
        });

        $middleware = $this->app->make(EncryptedContentEncodingMiddleware::class);

        $post_middleware_response = $middleware->attemptEncodeResponse($response, $request, 'a1');

        $decoded_response_content = RFC8188::rfc8188_decode(
            b64::decode($post_middleware_response->getContent()),
            $lookup
        );

        $this->assertEquals("I am the walrus", $decoded_response_content);
    }

    /** @test */
    public function canEncryptWithUsingApiKeyHeaderAsKeyId() {
        // TODO: not sure the $request is actually needed in this test.
        $request = Request::create('/', 'GET');
        $request->headers->set('Content-Encoding', 'aes128gcm');
        $request->headers->set('Api-Key', 'a1');

        // This is a request as passed to the 'after' part of the middleware.
        $response = Response::create();
        $response->setContent("I am the walrus");
        
        // Used for looking up API keys to do the encryption with.
        $lookup = new EncryptionKeyLookup();
        $lookup->addKey(b64::decode("BO3ZVPxUlnLORbVGMpbT1Q"), 'a1');
        
        $this->app->bind("DevJack\EncryptedContentEncoding\EncryptionKeyProviderInterface", function() use ($lookup) {
            return $lookup;
        });

        $middleware = $this->app->make(EncryptedContentEncodingMiddleware::class);

        $keyid = $middleware->determineEncryptionKeyId($request);
        $post_middleware_response = $middleware->attemptEncodeResponse($response, $request, $keyid);

        $decoded_response_content = RFC8188::rfc8188_decode(
            b64::decode($post_middleware_response->getContent()),
            $lookup
        );

        $this->assertEquals("I am the walrus", $decoded_response_content);

    }
}
