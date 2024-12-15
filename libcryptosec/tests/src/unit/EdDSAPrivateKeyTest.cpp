#include <libcryptosec/EdDSAPrivateKey.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes unitários da classe EdDSAPrivateKey
 */
class EdDSAPrivateKeyTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    /**
     * @brief Loads a Private Key into a EVP_PKEY structure
     * @param pemEncoded PEM Encoded value of the private key to be loaded
     * @return EVP_PKEY pointer containing the private key data
     */
    EVP_PKEY* loadEVPfromPem(std::string pemEncoded) {
      BIO *buffer = BIO_new(BIO_s_mem());
      BIO_write(buffer, pemEncoded.c_str(), pemEncoded.size());
      EVP_PKEY *pkey = PEM_read_bio_PrivateKey(buffer, NULL, NULL, NULL);
      BIO_free(buffer);

      return pkey;
    }

    /**
     * @brief Tests PEM Encoded Constructor for Ed25519 private key
     */
    void testPemEd25519() {
      EdDSAPrivateKey ed = EdDSAPrivateKey(ed25519PrivateKey);

      ASSERT_EQ(ed.getPemEncoded(), ed25519PrivateKey);
    }    

    /**
     * @brief Tests PEM Encoded Constructor for Ed448 private key
     */
    void testPemEd448() {
      EdDSAPrivateKey ed = EdDSAPrivateKey(ed448PrivateKey);

      ASSERT_EQ(ed.getPemEncoded(), ed448PrivateKey);
    }    

    /**
     * @brief Tests PEM Encoded with password Constructor for Ed25519 private key
     */
    void testPemPasswordEd25519() {
      EdDSAPrivateKey ed = EdDSAPrivateKey(ed25519PrivateKeyPass, password);

      ASSERT_EQ(ed.getPemEncoded(), ed25519PrivateKeyPass);
    }    

    /**
     * @brief Tests PEM Encoded with password Constructor for Ed448 private key
     */
    void testPemPasswordEd448() {
      EdDSAPrivateKey ed = EdDSAPrivateKey(ed448PrivateKeyPass, password);

      ASSERT_EQ(ed.getPemEncoded(), ed448PrivateKeyPass);
    }   

    /**
     * @brief Tests EVP_PKEY Constructor for Ed25519 private key
     */
    void testEVPEd25519() {
      EdDSAPrivateKey ed = EdDSAPrivateKey(loadEVPfromPem(ed25519PrivateKey));

      ASSERT_EQ(ed.getPemEncoded(), ed25519PrivateKey);
    }

    /**
     * @brief Tests EVP_PKEY Constructor for Ed448 private key
     */
    void testEVPEd448() {
      EdDSAPrivateKey ed = EdDSAPrivateKey(loadEVPfromPem(ed448PrivateKey));

      ASSERT_EQ(ed.getPemEncoded(), ed448PrivateKey);
    }

    /**
     * @brief Tests DER Encoded Constructor for Ed25519 private key
     */
    void testDerEd25519() {
      EdDSAPrivateKey ed = EdDSAPrivateKey(ed25519PrivateKey);
      ByteArray ba = ed.getDerEncoded();
      EdDSAPrivateKey copy = EdDSAPrivateKey(ba);

      ASSERT_EQ(copy.getPemEncoded(), ed25519PrivateKey);
    }    

    /**
     * @brief Tests DER Encoded Constructor for Ed448 private key
     */
    void testDerEd448() {
      EdDSAPrivateKey ed = EdDSAPrivateKey(ed448PrivateKey);
      ByteArray ba = ed.getDerEncoded();
      EdDSAPrivateKey copy = EdDSAPrivateKey(ba);

      ASSERT_EQ(copy.getPemEncoded(), ed448PrivateKey);
    }    

    /**
     * @brief Tests GetAlgorithm for Ed25519 private key
     */
    void testGetAlgorithmEd25519() {
      EdDSAPrivateKey ed = EdDSAPrivateKey(ed25519PrivateKey);

      ASSERT_EQ(ed.getAlgorithm(), AsymmetricKey::EdDSA);
    }

    /**
     * @brief Tests GetAlgorithm for Ed448 private key
     */
    void testGetAlgorithmEd448() {
      EdDSAPrivateKey ed = EdDSAPrivateKey(ed448PrivateKey);

      ASSERT_EQ(ed.getAlgorithm(), AsymmetricKey::EdDSA);
    }

    /**
     * @brief Tests key size in bytes for Ed25519 private key
     */
    void testGetSizeEd25519() {
      EdDSAPrivateKey ed = EdDSAPrivateKey(ed25519PrivateKey);

      ASSERT_EQ(ed.getSize(), 64);
    }

    /**
     * @brief Tests key size in bytes for Ed448 private key
     */
    void testGetSizeEd448() {
      EdDSAPrivateKey ed = EdDSAPrivateKey(ed448PrivateKey);

      ASSERT_EQ(ed.getSize(), 114);
    }

    /**
     * @brief Tests key size in bits for Ed25519 private key
     */
    void testGetSizeBitsEd25519() {
      EdDSAPrivateKey ed = EdDSAPrivateKey(ed25519PrivateKey);

      ASSERT_EQ(ed.getSizeBits(), 253);
    }

    /**
     * @brief Tests key size in bits for Ed448 private key
     */
    void testGetSizeBitsEd448() {
      EdDSAPrivateKey ed = EdDSAPrivateKey(ed448PrivateKey);

      ASSERT_EQ(ed.getSizeBits(), 456);
    }

    /**
     * @brief Tests PEM Encoded with password Constructor if password is incorrect for Ed25519 private key
     */
    void testPemWrongPasswordEd25519() {
      ASSERT_THROW(EdDSAPrivateKey(ed25519PrivateKeyPass, wrongPassword), EncodeException);
    }    

    /**
     * @brief Tests PEM Encoded with password Constructor if password is incorrect for Ed448 private key
     */
    void testPemWrongPasswordEd448() {
      ASSERT_THROW(EdDSAPrivateKey(ed448PrivateKeyPass, wrongPassword), EncodeException);
    }   

    static std::string ed25519PrivateKey;
    static std::string ed25519PrivateKeyPass;
    static std::string ed448PrivateKey;
    static std::string ed448PrivateKeyPass;
    static ByteArray password;
    static ByteArray wrongPassword;
};

/*
 * Initialization of variables used in the tests
 */
std::string EdDSAPrivateKeyTest::ed25519PrivateKey = "-----BEGIN PRIVATE KEY-----" "\n"
"MC4CAQAwBQYDK2VwBCIEINNB2daGywgXzJgwfqvOw4TCgicvKmbhqmA90rpkuHhy" "\n"
"-----END PRIVATE KEY-----" "\n";

std::string EdDSAPrivateKeyTest::ed25519PrivateKeyPass = "-----BEGIN PRIVATE KEY-----" "\n"
"MC4CAQAwBQYDK2VwBCIEIBijgDGXYzbSDEY4v9qZUTPZw7Tmam2zyGm5xK9SWQsJ" "\n"
"-----END PRIVATE KEY-----" "\n";

std::string EdDSAPrivateKeyTest::ed448PrivateKey = "-----BEGIN PRIVATE KEY-----" "\n"
"MEcCAQAwBQYDK2VxBDsEOQ2Y9g6EHi49qlxTAUs7dZByZ9tSEDJuSRrMKF84IN3d" "\n"
"mwAiTLoaL6M+6rerCqn2/L6YBkwDq5zGwQ==" "\n"
"-----END PRIVATE KEY-----" "\n";

std::string EdDSAPrivateKeyTest::ed448PrivateKeyPass = "-----BEGIN PRIVATE KEY-----" "\n"
"MEcCAQAwBQYDK2VxBDsEOUf+ig2n0RrIIO6tG+HwiHGydE319ULCAgsNDRU7ykSr" "\n"
"0BlwLh1llLmBhyFgp0CrYTDYRSXjEVPk0Q==" "\n"
"-----END PRIVATE KEY-----" "\n";

ByteArray EdDSAPrivateKeyTest::password = ByteArray("pineapple");
ByteArray EdDSAPrivateKeyTest::wrongPassword = ByteArray("banana");

TEST_F(EdDSAPrivateKeyTest, Ed25519Pem) {
  testPemEd25519();
}

TEST_F(EdDSAPrivateKeyTest, Ed448Pem) {
  testPemEd448();
}

TEST_F(EdDSAPrivateKeyTest, Ed25519PemPassword) {
  testPemPasswordEd25519();
}

TEST_F(EdDSAPrivateKeyTest, Ed448PemPassword) {
  testPemPasswordEd448();
}

TEST_F(EdDSAPrivateKeyTest, Ed25519EVP) {
  testEVPEd25519();
}

TEST_F(EdDSAPrivateKeyTest, Ed448EVP) {
  testEVPEd448();
}

TEST_F(EdDSAPrivateKeyTest, Ed25519Der) {
  testDerEd25519();
}

TEST_F(EdDSAPrivateKeyTest, Ed448Der) {
  testDerEd448();
}

TEST_F(EdDSAPrivateKeyTest, Ed25519GetAlgorithm) {
  testGetAlgorithmEd25519();
}

TEST_F(EdDSAPrivateKeyTest, Ed448GetAlgorithm) {
  testGetAlgorithmEd448();
}

TEST_F(EdDSAPrivateKeyTest, Ed25519GetSize) {
  testGetSizeEd25519();
}

TEST_F(EdDSAPrivateKeyTest, Ed448GetSize) {
  testGetSizeEd448();
}

TEST_F(EdDSAPrivateKeyTest, Ed25519GetSizeBits) {
  testGetSizeBitsEd25519();
}

TEST_F(EdDSAPrivateKeyTest, Ed448GetSizeBits) {
  testGetSizeBitsEd448();
}


TEST_F(EdDSAPrivateKeyTest, Ed25519PemWrongPassword) {
  testPemPasswordEd25519();
}

TEST_F(EdDSAPrivateKeyTest, Ed448PemWrongPassword) {
  testPemPasswordEd448();
}
