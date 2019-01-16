<?php

namespace Tests\Feature;

use App\Http\Middleware\EncryptedContentEncodingMiddleware;
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
        
        $response = $middleware->handle($request, function($r) {return $r;});

        $this->assertTrue($response->headers->has('Content-Encoding'));
        $this->assertEquals('aes128gcm',$response->headers->get('Content-Encoding'));

    }

    /** @test */
    public function doesOnlySetContentEncodingWhenDetected() {
        $request = Request::create('/', 'GET');
        // ** intentionally do not se content-encoding header herer **
        
        $middleware = $this->app->make(EncryptedContentEncodingMiddleware::class);
        $response = $middleware->handle($request, function($r) {return $r;});

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
        $this->markTestSkipped('To be implemented');
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
