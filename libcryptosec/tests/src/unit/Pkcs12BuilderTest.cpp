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
class Pkcs12BuilderTest : public ::testing::Test {

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

    void generatePkcs12(Certificate *cert, KeyPair kp, std::string password = "", Certificate *ca = NULL, bool clear = false) {
      Pkcs12Builder builder;

      builder.setKeyAndCertificate(kp.getPrivateKey(), cert);
      
      if (ca) {
        builder.addAdditionalCert(ca);
      }

      if (clear) {
        builder.clearAdditionalCerts();
      }

      pkcs12 = builder.doFinal(password);
    }

    void generatePkcs12SetAdditionalCertificates(Certificate *cert, KeyPair kp, std::string password, Certificate *ca, bool clear = false) {
      Pkcs12Builder builder;
      std::vector<Certificate *> cas;

      cas.push_back(ca);
      
      builder.setKeyAndCertificate(kp.getPrivateKey(), cert);
      builder.setAdditionalCerts(cas);

      if (clear) {
        builder.clearAdditionalCerts();
      }

      pkcs12 = builder.doFinal(password);
    }

    void testPkcs12(std::string password, KeyPair kp) {
      ASSERT_EQ(pkcs12->getPrivKey(password)->getPemEncoded(), kp.getPrivateKey()->getPemEncoded());
      ASSERT_EQ(pkcs12->getCertificate(password)->getPemEncoded(), cert->getPemEncoded());
      
      vector<Certificate *> certs = pkcs12->getAdditionalCertificates(password);
      
      ASSERT_EQ(certs.size(), 1);
      ASSERT_EQ(certs.at(0)->getPemEncoded(), ca->getPemEncoded());
    }

    void testPkcs12NoAdditionalCertificates(std::string password, KeyPair kp) {
      ASSERT_EQ(pkcs12->getPrivKey(password)->getPemEncoded(), kp.getPrivateKey()->getPemEncoded());
      ASSERT_EQ(pkcs12->getCertificate(password)->getPemEncoded(), cert->getPemEncoded());
      
      vector<Certificate *> certs = pkcs12->getAdditionalCertificates(password);
      
      ASSERT_EQ(certs.size(), 0);
    }

    Certificate *ca;
    Certificate *cert;
    Pkcs12 *pkcs12;
    static RSAKeyPair rsaKeyPairCa;
    static RSAKeyPair rsaKeyPairCert;
    static DSAKeyPair dsaKeyPairCa;
    static DSAKeyPair dsaKeyPairCert;
    static ECDSAKeyPair ecdsaKeyPairCa;
    static ECDSAKeyPair ecdsaKeyPairCert;
    static std::string pw;
};

/*
 * Initialization of variables used in the tests
 */
std::string Pkcs12BuilderTest::pw = "password";
RSAKeyPair Pkcs12BuilderTest::rsaKeyPairCa = RSAKeyPair(2048);
RSAKeyPair Pkcs12BuilderTest::rsaKeyPairCert = RSAKeyPair(2048);
DSAKeyPair Pkcs12BuilderTest::dsaKeyPairCa = DSAKeyPair(2048);
DSAKeyPair Pkcs12BuilderTest::dsaKeyPairCert = DSAKeyPair(2048);
ECDSAKeyPair Pkcs12BuilderTest::ecdsaKeyPairCa = ECDSAKeyPair(AsymmetricKey::NISTSECG_SECP224R1);
ECDSAKeyPair Pkcs12BuilderTest::ecdsaKeyPairCert = ECDSAKeyPair(AsymmetricKey::NISTSECG_SECP224R1);

TEST_F(Pkcs12BuilderTest, RsaSetKeyAndCertificate) {
  generatePkcs12(Pkcs12BuilderTest::cert, Pkcs12BuilderTest::rsaKeyPairCert, Pkcs12BuilderTest::pw);
  testPkcs12NoAdditionalCertificates(Pkcs12BuilderTest::pw, Pkcs12BuilderTest::rsaKeyPairCert);
}

TEST_F(Pkcs12BuilderTest, RsaSetKeyAndCertificateNoPassword) {
  generatePkcs12(Pkcs12BuilderTest::cert, Pkcs12BuilderTest::rsaKeyPairCert, "");
  testPkcs12NoAdditionalCertificates("", Pkcs12BuilderTest::rsaKeyPairCert);

}

TEST_F(Pkcs12BuilderTest, DsaSetKeyAndCertificate) {
  generateCertificate(Pkcs12BuilderTest::dsaKeyPairCert, Pkcs12BuilderTest::ca, *Pkcs12BuilderTest::rsaKeyPairCa.getPrivateKey());
  generatePkcs12(Pkcs12BuilderTest::cert, Pkcs12BuilderTest::dsaKeyPairCert, Pkcs12BuilderTest::pw);
  testPkcs12NoAdditionalCertificates(Pkcs12BuilderTest::pw, Pkcs12BuilderTest::dsaKeyPairCert);
}

TEST_F(Pkcs12BuilderTest, DsaSetKeyAndCertificateNoPassword) {
  generateCertificate(Pkcs12BuilderTest::dsaKeyPairCert, Pkcs12BuilderTest::ca, *Pkcs12BuilderTest::rsaKeyPairCa.getPrivateKey());
  generatePkcs12(Pkcs12BuilderTest::cert, Pkcs12BuilderTest::dsaKeyPairCert, "");
  testPkcs12NoAdditionalCertificates("", Pkcs12BuilderTest::dsaKeyPairCert);

}

TEST_F(Pkcs12BuilderTest, ECDsaSetKeyAndCertificate) {
  generateCertificate(Pkcs12BuilderTest::ecdsaKeyPairCert, Pkcs12BuilderTest::ca, *Pkcs12BuilderTest::rsaKeyPairCa.getPrivateKey());
  generatePkcs12(Pkcs12BuilderTest::cert, Pkcs12BuilderTest::ecdsaKeyPairCert, Pkcs12BuilderTest::pw);
  testPkcs12NoAdditionalCertificates(Pkcs12BuilderTest::pw, Pkcs12BuilderTest::ecdsaKeyPairCert);
}

TEST_F(Pkcs12BuilderTest, ECDsaSetKeyAndCertificateNoPassword) {
  generateCertificate(Pkcs12BuilderTest::ecdsaKeyPairCert, Pkcs12BuilderTest::ca, *Pkcs12BuilderTest::rsaKeyPairCa.getPrivateKey());
  generatePkcs12(Pkcs12BuilderTest::cert, Pkcs12BuilderTest::ecdsaKeyPairCert, "");
  testPkcs12NoAdditionalCertificates("", Pkcs12BuilderTest::ecdsaKeyPairCert);
}

TEST_F(Pkcs12BuilderTest, SetAdditionalCertificates) {
  generatePkcs12SetAdditionalCertificates(Pkcs12BuilderTest::cert, Pkcs12BuilderTest::rsaKeyPairCert, Pkcs12BuilderTest::pw, Pkcs12BuilderTest::ca);
  testPkcs12(Pkcs12BuilderTest::pw, Pkcs12BuilderTest::rsaKeyPairCert);
}

TEST_F(Pkcs12BuilderTest, AddAdditionalCert) {
  generatePkcs12(Pkcs12BuilderTest::cert, Pkcs12BuilderTest::rsaKeyPairCert, Pkcs12BuilderTest::pw, Pkcs12BuilderTest::ca);
  testPkcs12(Pkcs12BuilderTest::pw, Pkcs12BuilderTest::rsaKeyPairCert);
}

TEST_F(Pkcs12BuilderTest, SetAdditionalCertificatesClear) {
  generatePkcs12SetAdditionalCertificates(Pkcs12BuilderTest::cert, Pkcs12BuilderTest::rsaKeyPairCert, Pkcs12BuilderTest::pw, Pkcs12BuilderTest::ca, true);
  testPkcs12NoAdditionalCertificates(Pkcs12BuilderTest::pw, Pkcs12BuilderTest::rsaKeyPairCert);
}


TEST_F(Pkcs12BuilderTest, AddAdditionalCertClear) {
  generatePkcs12(Pkcs12BuilderTest::cert, Pkcs12BuilderTest::rsaKeyPairCert, Pkcs12BuilderTest::pw, Pkcs12BuilderTest::ca, true);
  testPkcs12NoAdditionalCertificates(Pkcs12BuilderTest::pw, Pkcs12BuilderTest::rsaKeyPairCert);
}
