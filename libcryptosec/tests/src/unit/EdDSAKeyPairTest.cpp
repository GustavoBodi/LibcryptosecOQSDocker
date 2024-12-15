#include <libcryptosec/EdDSAKeyPair.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes unitários da classe GeneralName
 */
class EdDSAKeyPairTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    /**
     * @brief Tests constructor for Ed25519 algorithm
     */
    void testGenerateEd25519() {
      ASSERT_NO_THROW(EdDSAKeyPair(AsymmetricKey::ED25519));
    }

    /**
     * @brief Tests constructor for Ed448 algorithm
     */
    void testGenerateEd448() {
      ASSERT_NO_THROW(EdDSAKeyPair(AsymmetricKey::ED448));
    }

    /**
     * If the EVP_PKEY was not correctly loaded with the key, it should return a null pointer.
     * That's the reason why we test if the pointer is true (i.e. not nullptr)
     * 
     * @brief Tests getPrivateKey for Ed25519 algorithm
     */
    void testGetPrivateKeyEd25519() {
      EdDSAKeyPair kp = EdDSAKeyPair(AsymmetricKey::ED25519);
      PrivateKey* privateKey = kp.getPrivateKey();

      ASSERT_TRUE(privateKey->getEvpPkey());
    }

    /**
     * If the EVP_PKEY was not correctly loaded with the key, it should return a null pointer.
     * That's the reason why we test if the pointer is true (i.e. not nullptr)
     * 
     * @brief Tests getPrivateKey for Ed448 algorithm
     */
    void testGetPrivateKeyEd448() {
      EdDSAKeyPair kp = EdDSAKeyPair(AsymmetricKey::ED448);
      PrivateKey* privateKey = kp.getPrivateKey();

      ASSERT_TRUE(privateKey->getEvpPkey());
    }

    /**
     * If the EVP_PKEY was not correctly loaded with the key, it should return a null pointer.
     * That's the reason why we test if the pointer is true (i.e. not nullptr)
     * 
     * @brief Tests getPublicKey for Ed25519 algorithm
     */
    void testGetPublicKeyEd25519() {
      EdDSAKeyPair kp = EdDSAKeyPair(AsymmetricKey::ED25519);
      PublicKey* publicKey = kp.getPublicKey();

      ASSERT_TRUE(publicKey->getEvpPkey());
    }

    /**
     * If the EVP_PKEY was not correctly loaded with the key, it should return a null pointer.
     * That's the reason why we test if the pointer is true (i.e. not nullptr)
     *
     * @brief Tests getPublicKey for Ed448 algorithm
     */
    void testGetPublicKeyEd448() {
      EdDSAKeyPair kp = EdDSAKeyPair(AsymmetricKey::ED448);
      PublicKey* publicKey = kp.getPublicKey();

      ASSERT_TRUE(publicKey->getEvpPkey());
    }

    static std::string otherNameOid;
};

/*
 * Initialization of variables used in the tests
 */
std::string EdDSAKeyPairTest::otherNameOid = "2.16.76.1.3.3";

TEST_F(EdDSAKeyPairTest, GenerateEd25519) {
  testGenerateEd25519();
}

TEST_F(EdDSAKeyPairTest, GenerateEd448) {
  testGenerateEd448();
}

TEST_F(EdDSAKeyPairTest, GetPrivateKeyEd25519) {
  testGetPrivateKeyEd25519();
}

TEST_F(EdDSAKeyPairTest, GetPrivateKeyEd448) {
  testGetPrivateKeyEd448();
}

TEST_F(EdDSAKeyPairTest, GetPublicKeyEd25519) {
  testGetPublicKeyEd25519();
}

TEST_F(EdDSAKeyPairTest, GetPublicKeyEd448) {
  testGetPublicKeyEd448();
}
