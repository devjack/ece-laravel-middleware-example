<?php

namespace App\Services;

use Illuminate\Support\ServiceProvider;

use DevJack\EncryptedContentEncoding\EncryptionKeyProviderInterface;
use DevJack\EncryptedContentEncoding\Exception\EncryptionKeyNotFound;


class EncryptionKeyLookup implements EncryptionKeyProviderInterface
{
    protected $keys = [];

    public function addKey($key, $keyid='') {
        $this->keys[$keyid] = $key;
    }
    public function __invoke($keyid) {
        if (in_array($keyid, array_keys($this->keys))) {
            return $this->keys[$keyid];
        }
        throw new EncryptionKeyNotFound("Encryption key not found.");
    }
}
