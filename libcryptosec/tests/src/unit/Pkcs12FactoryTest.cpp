#include <libcryptosec/Pkcs12Factory.h>

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
class Pkcs12FactoryTest : public ::testing::Test {

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

    void generatePkcs12(Certificate *cert, KeyPair kp, std::string password, Certificate *ca) {
      Pkcs12Builder builder;

      builder.setKeyAndCertificate(kp.getPrivateKey(), cert);
      builder.addAdditionalCert(ca);

      pkcs12 = builder.doFinal(password);
    }

    void testPkcs12(std::string password, KeyPair kp) {
      ASSERT_EQ(pkcs12->getPrivKey(password)->getPemEncoded(), kp.getPrivateKey()->getPemEncoded());
      ASSERT_EQ(pkcs12->getCertificate(password)->getPemEncoded(), cert->getPemEncoded());
      
      vector<Certificate *> certs = pkcs12->getAdditionalCertificates(password);
      
      ASSERT_EQ(certs.size(), 1);
      ASSERT_EQ(certs.at(0)->getPemEncoded(), ca->getPemEncoded());
    }

    void testFactory(std::string password, KeyPair kp) {
      ByteArray ba = pkcs12->getDerEncoded();

      pkcs12 = NULL;
      pkcs12 = Pkcs12Factory::fromDerEncoded(ba);

      testPkcs12(password, kp);
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
std::string Pkcs12FactoryTest::pw = "password";
RSAKeyPair Pkcs12FactoryTest::rsaKeyPairCa = RSAKeyPair(2048);
RSAKeyPair Pkcs12FactoryTest::rsaKeyPairCert = RSAKeyPair(2048);
DSAKeyPair Pkcs12FactoryTest::dsaKeyPairCa = DSAKeyPair(2048);
DSAKeyPair Pkcs12FactoryTest::dsaKeyPairCert = DSAKeyPair(2048);
ECDSAKeyPair Pkcs12FactoryTest::ecdsaKeyPairCa = ECDSAKeyPair(AsymmetricKey::NISTSECG_SECP224R1);
ECDSAKeyPair Pkcs12FactoryTest::ecdsaKeyPairCert = ECDSAKeyPair(AsymmetricKey::NISTSECG_SECP224R1);

TEST_F(Pkcs12FactoryTest, FromDerEncoded) {
  generatePkcs12(Pkcs12FactoryTest::cert, Pkcs12FactoryTest::rsaKeyPairCert, Pkcs12FactoryTest::pw, Pkcs12FactoryTest::ca);
  testFactory(Pkcs12FactoryTest::pw, Pkcs12FactoryTest::rsaKeyPairCert);
}

