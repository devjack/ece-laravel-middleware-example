<?php

namespace Tests\Feature;

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
}
