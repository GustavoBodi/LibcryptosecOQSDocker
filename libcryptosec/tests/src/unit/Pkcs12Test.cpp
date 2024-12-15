#include <libcryptosec/Pkcs12.h>

#include <libcryptosec/Pkcs12Builder.h>
#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/DSAKeyPair.h>
#include <libcryptosec/ECDSAKeyPair.h>
#include <libcryptosec/certificate/Certificate.h>
#include <libcryptosec/certificate/CertificateBuilder.h>
#include <libcryptosec/certificate/BasicConstraintsExtension.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>
#include <time.h>

/**
 * @brief Testes unitários da classe Pkcs12
 */
class Pkcs12Test : public ::testing::Test {

protected:
    virtual void SetUp() {
      generateCA(rsaKeyPairCa);
      generateCertificate(rsaKeyPairCert, ca, *rsaKeyPairCa.getPrivateKey());
    }

    virtual void TearDown() {
      free(ca);
      free(cert);

      if(pkcs12) {
        free(pkcs12);
      }

      if(pkcs) {
        free(pkcs);
      }
    }

    void generateCA(KeyPair keypair) {
      CertificateBuilder builder;
      RDNSequence rdn;
      BigInteger bi;
      BasicConstraintsExtension bc;
      DateTime notBefore;
      DateTime notAfter;

      notBefore = DateTime(time(0));
      notAfter = DateTime(time(0) + 1000000000);

      bi.setRandValue();
      rdn.addEntry(RDNSequence::COMMON_NAME, "CA");
      bc.setCa(true);
      bc.setCritical(true);

      builder.setSerialNumber(bi);
      builder.setPublicKey(*keypair.getPublicKey());
      builder.setNotBefore(notBefore);
      builder.setNotAfter(notAfter);
      builder.setIssuer(rdn);
      builder.setSubject(rdn);
      builder.addExtension(bc);

      ca = builder.sign(*keypair.getPrivateKey(), MessageDigest::SHA512);
    }

    void generateCertificate(KeyPair keypair, Certificate *ca, PrivateKey caPrivKey) {
      CertificateBuilder builder;
      RDNSequence rdn;
      BigInteger bi;
      BasicConstraintsExtension bc;
      DateTime notBefore;
      DateTime notAfter;

      notBefore = DateTime(time(0));
      notAfter = DateTime(time(0) + 1000000000);

      bi.setRandValue();
      rdn.addEntry(RDNSequence::COMMON_NAME, "Certificate");
      bc.setCa(false);
      bc.setCritical(false);

      builder.setSerialNumber(bi);
      builder.setPublicKey(*keypair.getPublicKey());
      builder.setNotBefore(notBefore);
      builder.setNotAfter(notAfter);
      builder.setIssuer(ca->getX509());
      builder.setSubject(rdn);
      builder.addExtension(bc);

      cert = builder.sign(caPrivKey, MessageDigest::SHA512);
    }

    void createPkcs12(Certificate *cert, KeyPair kp, std::string password = "", Certificate *ca = NULL) {
      EVP_PKEY *key = kp.getPrivateKey()->getEvpPkey();
      X509 *crt = cert->getX509();
      STACK_OF(X509) *cas = sk_X509_new_null();
      
      if (ca) {
        sk_X509_push(cas, ca->getX509());
      }

      pkcs = PKCS12_create(password.c_str(), NULL, key, crt, cas,
	                                0, 0, 0, 0, 0);

      pkcs12 = new Pkcs12(pkcs);
    }

    void testPrivateKey(std::string password, KeyPair kp) {
      ASSERT_EQ(pkcs12->getPrivKey(password)->getPemEncoded(), kp.getPrivateKey()->getPemEncoded());
    }

    void testPrivateKeyWrongPassword() {
      ASSERT_THROW(pkcs12->getPrivKey(wrongPw), Pkcs12Exception);
    }

    void testCertificate(std::string password = "") {
      ASSERT_EQ(pkcs12->getCertificate(password)->getPemEncoded(), cert->getPemEncoded());
    }

    void testCertificateWrongPassword() {
      ASSERT_THROW(pkcs12->getCertificate(wrongPw), Pkcs12Exception);
    }

    void testEmptyAdditionalCertificates(std::string password = "") {
      vector<Certificate *> certs = pkcs12->getAdditionalCertificates(password);
      ASSERT_EQ(certs.size(), 0);
    }

    void testAdditionalCertificates(std::string password = "") {
      vector<Certificate *> certs = pkcs12->getAdditionalCertificates(password);
      ASSERT_EQ(certs.size(), 1);
      ASSERT_EQ(certs.at(0)->getPemEncoded(), ca->getPemEncoded());
    }

    void testAdditionalCertificatesWrongPassword() {
      ASSERT_THROW(pkcs12->getAdditionalCertificates(wrongPw), Pkcs12Exception);
    }

    Certificate *ca;
    Certificate *cert;
    Pkcs12 *pkcs12;
    PKCS12 *pkcs;
    static RSAKeyPair rsaKeyPairCa;
    static RSAKeyPair rsaKeyPairCert;
    static DSAKeyPair dsaKeyPairCa;
    static DSAKeyPair dsaKeyPairCert;
    static ECDSAKeyPair ecdsaKeyPairCa;
    static ECDSAKeyPair ecdsaKeyPairCert;
    static std::string pw;
    static std::string wrongPw;
};

/*
 * Initialization of variables used in the tests
 */
std::string Pkcs12Test::pw = "password";
std::string Pkcs12Test::wrongPw = "drowssap";
RSAKeyPair Pkcs12Test::rsaKeyPairCa = RSAKeyPair(2048);
RSAKeyPair Pkcs12Test::rsaKeyPairCert = RSAKeyPair(2048);
DSAKeyPair Pkcs12Test::dsaKeyPairCa = DSAKeyPair(2048);
DSAKeyPair Pkcs12Test::dsaKeyPairCert = DSAKeyPair(2048);
ECDSAKeyPair Pkcs12Test::ecdsaKeyPairCa = ECDSAKeyPair(AsymmetricKey::NISTSECG_SECP224R1);
ECDSAKeyPair Pkcs12Test::ecdsaKeyPairCert = ECDSAKeyPair(AsymmetricKey::NISTSECG_SECP224R1);

TEST_F(Pkcs12Test, RsaPrivateKey) {
  createPkcs12(Pkcs12Test::cert, Pkcs12Test::rsaKeyPairCert, Pkcs12Test::pw);
  testPrivateKey(Pkcs12Test::pw, Pkcs12Test::rsaKeyPairCert);
}

TEST_F(Pkcs12Test, RsaPrivateKeyNoPassword) {
  createPkcs12(Pkcs12Test::cert, Pkcs12Test::rsaKeyPairCert, "");
  testPrivateKey("", Pkcs12Test::rsaKeyPairCert);

}

TEST_F(Pkcs12Test, RsaPrivateKeyWrongPassword) {
  createPkcs12(Pkcs12Test::cert, Pkcs12Test::rsaKeyPairCert, Pkcs12Test::pw);
  testPrivateKeyWrongPassword();
}

TEST_F(Pkcs12Test, DsaPrivateKey) {
  generateCertificate(Pkcs12Test::dsaKeyPairCert, Pkcs12Test::ca, *Pkcs12Test::rsaKeyPairCa.getPrivateKey());
  createPkcs12(Pkcs12Test::cert, Pkcs12Test::dsaKeyPairCert, Pkcs12Test::pw);
  testPrivateKey(Pkcs12Test::pw, Pkcs12Test::dsaKeyPairCert);
}

TEST_F(Pkcs12Test, DsaPrivateKeyNoPassword) {
  generateCertificate(Pkcs12Test::dsaKeyPairCert, Pkcs12Test::ca, *Pkcs12Test::rsaKeyPairCa.getPrivateKey());
  createPkcs12(Pkcs12Test::cert, Pkcs12Test::dsaKeyPairCert, "");
  testPrivateKey("", Pkcs12Test::dsaKeyPairCert);

}

TEST_F(Pkcs12Test, DsaPrivateKeyWrongPassword) {
  generateCertificate(Pkcs12Test::dsaKeyPairCert, Pkcs12Test::ca, *Pkcs12Test::rsaKeyPairCa.getPrivateKey());
  createPkcs12(Pkcs12Test::cert, Pkcs12Test::dsaKeyPairCert, Pkcs12Test::pw);
  testPrivateKeyWrongPassword();
}

TEST_F(Pkcs12Test, ECDsaPrivateKey) {
  generateCertificate(Pkcs12Test::ecdsaKeyPairCert, Pkcs12Test::ca, *Pkcs12Test::rsaKeyPairCa.getPrivateKey());
  createPkcs12(Pkcs12Test::cert, Pkcs12Test::ecdsaKeyPairCert, Pkcs12Test::pw);
  testPrivateKey(Pkcs12Test::pw, Pkcs12Test::ecdsaKeyPairCert);
}

TEST_F(Pkcs12Test, ECDsaPrivateKeyNoPassword) {
  generateCertificate(Pkcs12Test::ecdsaKeyPairCert, Pkcs12Test::ca, *Pkcs12Test::rsaKeyPairCa.getPrivateKey());
  createPkcs12(Pkcs12Test::cert, Pkcs12Test::ecdsaKeyPairCert, "");
  testPrivateKey("", Pkcs12Test::ecdsaKeyPairCert);

}

TEST_F(Pkcs12Test, ECDsaPrivateKeyWrongPassword) {
  generateCertificate(Pkcs12Test::ecdsaKeyPairCert, Pkcs12Test::ca, *Pkcs12Test::rsaKeyPairCa.getPrivateKey());
  createPkcs12(Pkcs12Test::cert, Pkcs12Test::ecdsaKeyPairCert, Pkcs12Test::pw);
  testPrivateKeyWrongPassword();
}

TEST_F(Pkcs12Test, Certificate) {
  createPkcs12(Pkcs12Test::cert, Pkcs12Test::rsaKeyPairCert, Pkcs12Test::pw);
  testCertificate(Pkcs12Test::pw);

}

TEST_F(Pkcs12Test, CertificateNoPassword) {
  createPkcs12(Pkcs12Test::cert, Pkcs12Test::rsaKeyPairCert, "");
  testCertificate("");

}

TEST_F(Pkcs12Test, CertificateWrongPassword) {
  createPkcs12(Pkcs12Test::cert, Pkcs12Test::rsaKeyPairCert, Pkcs12Test::pw);
  testCertificateWrongPassword();
}

TEST_F(Pkcs12Test, AdditionalCertificatesEmpty) {
  createPkcs12(Pkcs12Test::cert, Pkcs12Test::rsaKeyPairCert, Pkcs12Test::pw);
  testEmptyAdditionalCertificates(Pkcs12Test::pw);
}

TEST_F(Pkcs12Test, AdditionalCertificatesEmptyNoPassword) {
  createPkcs12(Pkcs12Test::cert, Pkcs12Test::rsaKeyPairCert, "");
  testEmptyAdditionalCertificates("");

}

TEST_F(Pkcs12Test, AdditionalCertificatesEmptyWrongPassword) {
  createPkcs12(Pkcs12Test::cert, Pkcs12Test::rsaKeyPairCert, Pkcs12Test::pw);
  testAdditionalCertificatesWrongPassword();
}

TEST_F(Pkcs12Test, AdditionalCertificates) {
  createPkcs12(Pkcs12Test::cert, Pkcs12Test::rsaKeyPairCert, Pkcs12Test::pw, Pkcs12Test::ca);
  testAdditionalCertificates(Pkcs12Test::pw);
}

TEST_F(Pkcs12Test, AdditionalCertificatesNoPassword) {
  createPkcs12(Pkcs12Test::cert, Pkcs12Test::rsaKeyPairCert, "", Pkcs12Test::ca);
  testAdditionalCertificates("");
}

TEST_F(Pkcs12Test, AdditionalCertificatesWrongPassword) {
  createPkcs12(Pkcs12Test::cert, Pkcs12Test::rsaKeyPairCert, Pkcs12Test::pw, Pkcs12Test::ca);
  testAdditionalCertificatesWrongPassword();
}

