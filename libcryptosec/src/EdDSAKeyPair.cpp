#include "libcryptosec/EdDSAKeyPair.h"

EdDSAKeyPair::EdDSAKeyPair(ByteArray& derEncoded) throw (AsymmetricKeyException) {
	this->key = NULL;
	this->engine = NULL;
	// TODO: implement
	throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR,
				"EdDSAKeyPair::EdDSAKeyPair");
}

EdDSAKeyPair::EdDSAKeyPair(std::string& encoded) throw (AsymmetricKeyException) {
	this->key = NULL;
	this->engine = NULL;
	// TODO: implement
	throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR,
				"EdDSAKeyPair::EdDSAKeyPair");
}

EdDSAKeyPair::EdDSAKeyPair(AsymmetricKey::Curve curve)
		throw (AsymmetricKeyException) {
//	int r;
//	int nid = NID_undef;
//	EVP_PKEY_CTX *kctx = NULL;
//	EVP_PKEY *pkey = NULL;
//	ENGINE *e = NULL;
//
//	this->key = NULL;
//	this->engine = NULL;
//
//	switch (curve) {
//	case AsymmetricKey::ED25519:
//		nid = OBJ_sn2nid("ED25519");
//		break;
//	case AsymmetricKey::ED448:
//		nid = OBJ_sn2nid("ED448");
//		break;
//	case AsymmetricKey::ED521:
//		nid = OBJ_sn2nid("ED521");
//		break;
//	default:
//		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR,
//			"EdDSAKeyPair::EdDSAKeyPair");
//	}
//
//	if (nid == NID_undef) {
//		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR,
//			"EdDSAKeyPair::EdDSAKeyPair");
//	}
//	EVP_PKEY_asn1_find(&e, nid);
//	this->engine = e;
//
//	kctx = EVP_PKEY_CTX_new_id(nid, e);
//	if (kctx == NULL) {
//		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR,
//			"EdDSAKeyPair::EdDSAKeyPair");
//	}
//	r = EVP_PKEY_keygen_init(kctx);
//	if (r != 1) {
//		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR,
//			"EdDSAKeyPair::EdDSAKeyPair");
//	}
//	r = EVP_PKEY_keygen(kctx, &pkey);
//	if (r != 1) {
//		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR,
//			"EdDSAKeyPair::EdDSAKeyPair");
//	}
//	this->key = pkey;
    int rc;
    this->engine = NULL;
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_CTX *ctx = generateCTX(curve);


    if (!ctx) {
        throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR,
	    "EdDSAKeyPair::EdDSAKeyPair");
    }

    if (!EVP_PKEY_keygen_init(ctx)) {
        throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR,
	     "EdDSAKeyPair::EdDSAKeyPair");
    }
    
    if (!EVP_PKEY_keygen(ctx, &pkey)) {
        throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR,
	     "EdDSAKeyPair::EdDSAKeyPair");
    }
    
    EVP_PKEY_CTX_free(ctx);
    this->key = pkey;
}

EdDSAKeyPair::~EdDSAKeyPair() {
	if (this->key) {
		EVP_PKEY_free(this->key);
		this->key = NULL;
	}
	if (this->engine) {
		ENGINE_free(this->engine);
		this->engine = NULL;
	}
}

PublicKey* EdDSAKeyPair::getPublicKey() throw (AsymmetricKeyException,
		EncodeException) {
	PublicKey *ret;
	std::string keyTemp;
	keyTemp = this->getPublicKeyPemEncoded();
	ret = new EdDSAPublicKey(keyTemp);
	return ret;
}

PrivateKey* EdDSAKeyPair::getPrivateKey() throw (AsymmetricKeyException) {
	PrivateKey *ret;
	EVP_PKEY *pkey;
	ret = NULL;
	if (engine && !this->key) {
		pkey = ENGINE_load_private_key(this->engine, this->keyId.c_str(), NULL,
				NULL);
		if (!pkey) {
			throw AsymmetricKeyException(
					AsymmetricKeyException::UNAVAILABLE_KEY,
					"KeyId: " + this->keyId, "EdDSAKeyPair::getPrivateKey");
		}
		try {
			ret = new PrivateKey(pkey);
		} catch (...) {
			EVP_PKEY_free(pkey);
			throw;
		}
	} else {
		ret = new EdDSAPrivateKey(this->key);
		if (ret == NULL) {
			throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE,
					"EdDSAKeyPair::getPrivateKey");
		}
		EVP_PKEY_up_ref(this->key);
	}
	return ret;
}

AsymmetricKey::Algorithm EdDSAKeyPair::getAlgorithm()
		throw (AsymmetricKeyException) {
	return AsymmetricKey::EdDSA;
}

EVP_PKEY_CTX* EdDSAKeyPair::generateCTX(AsymmetricKey::Curve curve) {
  EVP_PKEY_CTX *ctx = NULL;

  switch (curve) {
    case AsymmetricKey::ED25519:
      ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
      break;
    case AsymmetricKey::ED448:
      ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED448, NULL);
      break;
    default:
      throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE,
          "EdDSAKeyPair::generateCTX");
      break;
  }

  return ctx;
}
