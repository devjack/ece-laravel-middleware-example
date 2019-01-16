<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;

use DevJack\EncryptedContentEncoding\EncryptionKeyProviderInterface;
use App\Http\Middleware\EncryptedContentEncodingMiddleware;
use App\Services\EncryptionKeyLookup;
use Base64Url\Base64Url as b64;

class EncryptionKeyLookupProvider extends ServiceProvider
{
    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        //
    }

    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        $this->app->bind("DevJack\EncryptedContentEncoding\EncryptionKeyProviderInterface", function() {
            $lookup = new EncryptionKeyLookup();
            $lookup->addKey(b64::decode("BO3ZVPxUlnLORbVGMpbT1Q"), 'a1');
            return $lookup;
        });
    }
}
