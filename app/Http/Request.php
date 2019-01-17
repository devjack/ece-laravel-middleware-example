<?php
namespace App\Http;

use Illuminate\Http\Request as IlluminateRequest;

class Request extends IlluminateRequest  {
    protected $encryptionKeyId = null;

    public function setEncryptionKeyId($keyid) {
        $this->encryptionKeyId = $keyId;
    }

    public function getEncryptionKeyId() {
        return $this->encryptionKeyId;
    }
}