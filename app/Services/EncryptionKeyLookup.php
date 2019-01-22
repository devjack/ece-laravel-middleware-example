<?php

namespace App\Services;

use Illuminate\Support\ServiceProvider;

use DevJack\EncryptedContentEncoding\EncryptionKeyProviderInterface;
use DevJack\EncryptedContentEncoding\Exception\EncryptionKeyNotFound;


class EncryptionKeyLookup implements EncryptionKeyProviderInterface
{
    protected $keys = [];

    protected $useRequestFallbacks = false;

    protected $currentRequest = null;

    public function addKey($key, $keyid='') {
        $this->keys[$keyid] = $key;
    }
    public function __invoke($keyid) {

        if(!$keyid && $this->useRequestFallbacks && !is_null($this->request)) {
            $keyid = $this->determineEncryptionKeyId();
        }

        if (in_array($keyid, array_keys($this->keys))) {
            return $this->keys[$keyid];
        }
        throw new EncryptionKeyNotFound("Encryption key not found.");
    }

    public function useRequestFallbacks($enabled) {
        $this->useRequestFallbacks = true;
    }

    // TODO: set a typehint here
    public function setCurrentRequest($request) {
        $this->currentRequest = $request;
    }

    public function determineEncryptionKeyId($request) {
        if($request instanceof App\Http\Request) {
            return $request->getEncryptionKeyId();
        }

        // TODO: make the header name configurable and/or an ordered list of headers for fallbacks
        if($request->header('Api-Key')) {
            return $request->header('Api-Key');
        }

        // TODO: default to a system configured encryption key.

        // TODO: unable to decrypt exception.
    }
}
