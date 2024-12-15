#include <libcryptosec/EdDSAPublicKey.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes unitários da classe EdDSAPublicKey
 */
class EdDSAPublicKeyTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    /**
     * @brief Loads EVP_PKEY structure with a PEM Encoded public key
     * @param pemEncoded PEM Encoded public key
     * @return EVP_PKEY pointer containing public key data
     */
    EVP_PKEY* loadEVPfromPem(std::string pemEncoded) {
      BIO *buffer = BIO_new(BIO_s_mem());
      BIO_write(buffer, pemEncoded.c_str(), pemEncoded.size());
      EVP_PKEY *pkey = PEM_read_bio_PUBKEY(buffer, NULL, NULL, NULL);
      BIO_free(buffer);

      return pkey;
    }

    /**
     * @brief Tests PEM Encoded constructor with a Ed25519 public key
     */
    void testPemEd25519() {
      EdDSAPublicKey ed = EdDSAPublicKey(ed25519PublicKey);

      ASSERT_EQ(ed.getPemEncoded(), ed25519PublicKey);
    }    

    /**
     * @brief Tests PEM Encoded constructor with a Ed448 public key
     */
    void testPemEd448() {
      EdDSAPublicKey ed = EdDSAPublicKey(ed448PublicKey);

      ASSERT_EQ(ed.getPemEncoded(), ed448PublicKey);
    }    

    /**
     * @brief Tests EVP_PKEY constructor with a Ed25519 public key
     */
    void testEVPEd25519() {
      EdDSAPublicKey ed = EdDSAPublicKey(loadEVPfromPem(ed25519PublicKey));

      ASSERT_EQ(ed.getPemEncoded(), ed25519PublicKey);
    }

    /**
     * @brief Tests EVP_PKEY constructor with a Ed448 public key
     */
    void testEVPEd448() {
      EdDSAPublicKey ed = EdDSAPublicKey(loadEVPfromPem(ed448PublicKey));

      ASSERT_EQ(ed.getPemEncoded(), ed448PublicKey);
    }

    /**
     * @brief Tests DER Encoded constructor with a Ed25519 public key
     */
    void testDerEd25519() {
      EdDSAPublicKey ed = EdDSAPublicKey(ed25519PublicKey);
      ByteArray ba = ed.getDerEncoded();
      EdDSAPublicKey copy = EdDSAPublicKey(ba);

      ASSERT_EQ(copy.getPemEncoded(), ed25519PublicKey);
    }    

    /**
     * @brief Tests DER Encoded constructor with a Ed448 public key
     */
    void testDerEd448() {
      EdDSAPublicKey ed = EdDSAPublicKey(ed448PublicKey);
      ByteArray ba = ed.getDerEncoded();
      EdDSAPublicKey copy = EdDSAPublicKey(ba);

      ASSERT_EQ(copy.getPemEncoded(), ed448PublicKey);
    }    

    /**
     * @brief Tests GetAlgorithm with a Ed25519 public key
     */
    void testGetAlgorithmEd25519() {
      EdDSAPublicKey ed = EdDSAPublicKey(ed25519PublicKey);

      ASSERT_EQ(ed.getAlgorithm(), AsymmetricKey::EdDSA);
    }

    /**
     * @brief Tests GetAlgorithm with a Ed448 public key
     */
    void testGetAlgorithmEd448() {
      EdDSAPublicKey ed = EdDSAPublicKey(ed448PublicKey);

      ASSERT_EQ(ed.getAlgorithm(), AsymmetricKey::EdDSA);
    }

    /**
     * @brief Tests GetKeyIdentifier (SHA1 digest of key value) of a Ed25519 public key
     */
    void testGetKeyIdentifierEd25519() {
      EdDSAPublicKey ed = EdDSAPublicKey(ed25519PublicKey);

      ASSERT_EQ(ed.getKeyIdentifier().toHex(), ed25519KeyIdentifierHex);
    }

    /**
     * @brief Tests GetKeyIdentifier (SHA1 digest of key value) of a Ed448 public key
     */
    void testGetKeyIdentifierEd448() {
      EdDSAPublicKey ed = EdDSAPublicKey(ed448PublicKey);

      ASSERT_EQ(ed.getKeyIdentifier().toHex(), ed448KeyIdentifierHex);
    }

    /**
     * @brief Tests key size in bytes of a Ed25519 public key
     */
    void testGetSizeEd25519() {
      EdDSAPublicKey ed = EdDSAPublicKey(ed25519PublicKey);

      ASSERT_EQ(ed.getSize(), 64);
    }

    /**
     * @brief Tests key size in bytes of a Ed448 public key
     */
    void testGetSizeEd448() {
      EdDSAPublicKey ed = EdDSAPublicKey(ed448PublicKey);

      ASSERT_EQ(ed.getSize(), 114);
    }

    /**
     * @brief Tests key size in bits of a Ed25519 public key
     */
    void testGetSizeBitsEd25519() {
      EdDSAPublicKey ed = EdDSAPublicKey(ed25519PublicKey);

      ASSERT_EQ(ed.getSizeBits(), 253);
    }

    /**
     * @brief Tests key size in bits of a Ed448 public key
     */
    void testGetSizeBitsEd448() {
      EdDSAPublicKey ed = EdDSAPublicKey(ed448PublicKey);

      ASSERT_EQ(ed.getSizeBits(), 456);
    }

    static std::string ed25519PrivateKey;
    static std::string ed25519PublicKey;
    static std::string ed25519KeyIdentifierHex;
    static std::string ed448PrivateKey;
    static std::string ed448PublicKey;
    static std::string ed448KeyIdentifierHex;
};

/*
 * Initialization of variables used in the tests
 */
std::string EdDSAPublicKeyTest::ed25519PrivateKey = "-----BEGIN PRIVATE KEY-----" "\n"
"MC4CAQAwBQYDK2VwBCIEINNB2daGywgXzJgwfqvOw4TCgicvKmbhqmA90rpkuHhy" "\n"
"-----END PRIVATE KEY-----" "\n";

std::string EdDSAPublicKeyTest::ed25519PublicKey = "-----BEGIN PUBLIC KEY-----" "\n"
"MCowBQYDK2VwAyEAJ19z3zUBCoLZybQ5QsfFS6vfu0sWimbAzkh0vTW8ZSQ=" "\n"
"-----END PUBLIC KEY-----" "\n";

std::string EdDSAPublicKeyTest::ed25519KeyIdentifierHex = "A52B890650D7F60E7485DCCBC524A763F8EF512B";

std::string EdDSAPublicKeyTest::ed448PrivateKey = "-----BEGIN PRIVATE KEY-----" "\n"
"MEcCAQAwBQYDK2VxBDsEOQ2Y9g6EHi49qlxTAUs7dZByZ9tSEDJuSRrMKF84IN3d" "\n"
"mwAiTLoaL6M+6rerCqn2/L6YBkwDq5zGwQ==" "\n"
"-----END PRIVATE KEY-----" "\n";

std::string EdDSAPublicKeyTest::ed448PublicKey = "-----BEGIN PUBLIC KEY-----" "\n"
"MEMwBQYDK2VxAzoA3xHhr0QaCUbLJTQfYf6tSDGN+Js79l/fgj/ycGabhQPK775o" "\n"
"lsrnd0ysz4eFM/cMU60DYI/QtgKA" "\n"
"-----END PUBLIC KEY-----" "\n";

std::string EdDSAPublicKeyTest::ed448KeyIdentifierHex = "274461DC47E92BB9632015A99F66A0199A14BE98";

TEST_F(EdDSAPublicKeyTest, Ed25519Pem) {
  testPemEd25519();
}

TEST_F(EdDSAPublicKeyTest, Ed448Pem) {
  testPemEd448();
}

TEST_F(EdDSAPublicKeyTest, Ed25519EVP) {
  testEVPEd25519();
}

TEST_F(EdDSAPublicKeyTest, Ed448EVP) {
  testEVPEd448();
}

TEST_F(EdDSAPublicKeyTest, Ed25519Der) {
  testDerEd25519();
}

TEST_F(EdDSAPublicKeyTest, Ed448Der) {
  testDerEd448();
}

TEST_F(EdDSAPublicKeyTest, Ed25519GetAlgorithm) {
  testGetAlgorithmEd25519();
}

TEST_F(EdDSAPublicKeyTest, Ed448GetAlgorithm) {
  testGetAlgorithmEd448();
}

TEST_F(EdDSAPublicKeyTest, Ed25519GetKeyIdentifier) {
  testGetKeyIdentifierEd25519();
}

TEST_F(EdDSAPublicKeyTest, Ed448GetKeyIdentifier) {
  testGetKeyIdentifierEd448();
}

TEST_F(EdDSAPublicKeyTest, Ed25519GetSize) {
  testGetSizeEd25519();
}

TEST_F(EdDSAPublicKeyTest, Ed448GetSize) {
  testGetSizeEd448();
}

TEST_F(EdDSAPublicKeyTest, Ed25519GetSizeBits) {
  testGetSizeBitsEd25519();
}

TEST_F(EdDSAPublicKeyTest, Ed448GetSizeBits) {
  testGetSizeBitsEd448();
}
