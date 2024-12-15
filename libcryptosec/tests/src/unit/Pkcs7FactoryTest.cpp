#include <libcryptosec/Pkcs7Factory.h>

#include <libcryptosec/KeyPair.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes unitários da classe Pkcs7Factory
 */
class Pkcs7FactoryTest : public ::testing::Test {

protected:
    virtual void SetUp() {
    
    }

    virtual void TearDown() {
    
    }

    PKCS7* genPkcs7(std::string pem) {
      BIO *buffer = BIO_new(BIO_s_mem());
      BIO_write(buffer, pem.c_str(), pem.size());
      PKCS7 *pkcs7 = PEM_read_bio_PKCS7(buffer, NULL, NULL, NULL);
      
      return pkcs7; 
    }

    void testPemEncodedSignedData() {
      Pkcs7SignedData signP7 = Pkcs7SignedData(genPkcs7(signedDataPem));
      
      Pkcs7 *p7 = Pkcs7Factory::fromPemEncoded(signedDataPem);

      ASSERT_EQ(p7->getPemEncoded(), signedDataPem);
      ASSERT_EQ(p7->getDerEncoded(), signP7.getDerEncoded());
    }

    void testPemEncodedEnvelopedData() {
      Pkcs7EnvelopedData envelopedP7 = Pkcs7EnvelopedData(genPkcs7(envelopedDataPem));
      
      Pkcs7 *p7 = Pkcs7Factory::fromPemEncoded(envelopedDataPem);

      ASSERT_EQ(p7->getPemEncoded(), envelopedDataPem);
      ASSERT_EQ(p7->getDerEncoded(), envelopedP7.getDerEncoded());
    }

    void testDerEncodedSignedData() {
      Pkcs7SignedData signP7 = Pkcs7SignedData(genPkcs7(signedDataPem));
      ByteArray ba = signP7.getDerEncoded();
      
      Pkcs7 *p7 = Pkcs7Factory::fromDerEncoded(ba);
      
      ASSERT_EQ(p7->getPemEncoded(), signP7.getPemEncoded());
      ASSERT_EQ(p7->getDerEncoded(), signP7.getDerEncoded());
    }

    void testDerEncodedEnvelopedData() {
      Pkcs7EnvelopedData envelopedP7 = Pkcs7EnvelopedData(genPkcs7(envelopedDataPem));
      ByteArray ba = envelopedP7.getDerEncoded();

      Pkcs7 *p7 = Pkcs7Factory::fromDerEncoded(ba);
      
      ASSERT_EQ(p7->getPemEncoded(), envelopedP7.getPemEncoded());
      ASSERT_EQ(p7->getDerEncoded(), envelopedP7.getDerEncoded());
    }

    void testInvalidPem() {
      ASSERT_THROW(Pkcs7Factory::fromPemEncoded(invalidPem), EncodeException);
    }

    static std::string signedDataPem;
    static std::string envelopedDataPem;
    static std::string invalidPem;
};

/*
 * Initialization of variables used in the tests
 */

std::string Pkcs7FactoryTest::signedDataPem = "-----BEGIN PKCS7-----" "\n"
"MIIEgwYJKoZIhvcNAQcCoIIEdDCCBHACAQExDzANBglghkgBZQMEAgMFADALBgkq" "\n"
"hkiG9w0BBwGgggLnMIIC4zCCAcsCCQCTpp1rF8egkjANBgkqhkiG9w0BAQ0FADAo" "\n"
"MSYwJAYDVQQDDB1UcnVzdGVkIENlcnRpZmljYXRlIEF1dGhvcml0eTAgFw0wMDAx" "\n"
"MDEwMDAwMDBaGA8yMTAwMDEwMTAwMDAwMFowKDEmMCQGA1UEAwwdVHJ1c3RlZCBD" "\n"
"ZXJ0aWZpY2F0ZSBBdXRob3JpdHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK" "\n"
"AoIBAQDhZhQqHMK3+G7NWfDDJeAkZIyKLVTIDJ9T4eQe5ZXcxcT0NQRprHEuwzJ8" "\n"
"JgLaXkWgPjc0k/LCi1gV/EtQ12gGRjk9CejwpgRkuUD6fqLJsOsxPlREb9G/woEE" "\n"
"cfASbihkYD9dUuXh4HlWh5hqIi6FVhSLM7O70XHtmsw168l9Jmql8TBvI6O+Iorx" "\n"
"Vk93ZJR9CuBQxaPEzbnFUYF1bjX2vqZQoY+mQVKLqCaX2ZGEzyGnouIahkj6VWjq" "\n"
"yi/BhMxWFpV8uQYIc4Znz4f68KaILx8JjW0TI5Rck4ERVqReDhD4R3QfFQULr0N+" "\n"
"mhwosA+/zWZXHNMdmNfdKs+3K/7rAgMBAAGjEzARMA8GA1UdEwEB/wQFMAMBAf8w" "\n"
"DQYJKoZIhvcNAQENBQADggEBABmNbAdzpwbEA3fc4B02vjVbNkc8Y2Q/GdqKK3Cl" "\n"
"FqjMYvFj/a2/wpzYfL3axC2+lUO2FwHPSr5ZFyg/5cjbLPb+Q/zkMng2ydXz87/K" "\n"
"cS8z8B4SxKdr1QHuYB5WyFdTCQc4uTJUrhXWW/4vYK9SW3nycP74AwbJ/oqDHG1F" "\n"
"JgmhQRLsMF6scs7sswtCZ8b4pZOo0391+lQFR1gJuEAB25XYu2MZxl9IQGp/TnSf" "\n"
"/whwAPUdfyDXI+GGrxV9mQrBGcVMa/MKbUR3F6ZNoI38niaM8KLA1Xh33YNhoGBw" "\n"
"SLJU24nl0jp7xc4g/zRzPXJT0nQ9AgvIaoEIa2fnYKc7CnwxggFgMIIBXAIBATA1" "\n"
"MCgxJjAkBgNVBAMMHVRydXN0ZWQgQ2VydGlmaWNhdGUgQXV0aG9yaXR5AgkAk6ad" "\n"
"axfHoJIwDQYJYIZIAWUDBAIDBQAwDQYJKoZIhvcNAQEBBQAEggEALZyPYIJsjvbS" "\n"
"bFq6H5iEQz34wY5LYDXaUnmZXwdYL/SVh345NFIQmMbrE4ZmrspJOByEQrBuwsQH" "\n"
"WxoPooMa/l6ntmWsgM2B+i1YHnE169/40/Q3RvD7yWf0HARnz5V0+4tP5N4ELWyp" "\n"
"3DAio+GC+cC2I5B4snITBx/lJnqalZHSQWqGXDnRYc0CahHU3M0p8J5t1CvWegoF" "\n"
"Ak7jLxjMcYn5o66V+FM6GJs3Ox14ir8BnG6WXv7pU89ghfw19hjOeqJIgZL25X4n" "\n"
"crHa9Fccf6D+/vwQXczWlO5biDQuzkNS49pacvg7nkLy3Dr67tILAUh5pM7gzd5h" "\n"
"LraF5z7SAg==" "\n"
"-----END PKCS7-----" "\n";

std::string Pkcs7FactoryTest::envelopedDataPem = "-----BEGIN PKCS7-----" "\n"
"MIIC+QYJKoZIhvcNAQcDoIIC6jCCAuYCAQAxggKhMIIBTAIBADA0MCgxJjAkBgNV" "\n"
"BAMMHVRydXN0ZWQgQ2VydGlmaWNhdGUgQXV0aG9yaXR5Aggyc5P3LNjhtzANBgkq" "\n"
"hkiG9w0BAQEFAASCAQBKxfMM/Xt/ao7riDOejOsmXLwJUtIriM38Im3oSL7+yOES" "\n"
"B6hoaDid/cJPKp/QsIYwAKPeId8pNGJWuB/xpS54vT5q5/0vCAhAix/pLmmJoDeb" "\n"
"4oHF7jCXGMa8guFWP2gJi7vXLjuJUnfeoG9B6RulpxLPOtyLCG/RfUP4n0BlEre6" "\n"
"SB9/DOhjTIi2G40ETCyXXNdd3BlxmxODCKXnZ9q6otXZ+c1YibD5HUORNAhnNfZZ" "\n"
"NcGNu/6zXni0gJqHJZUKaSdBAX6aOYGDLFK5PQIV/164CJdmbvxJF1ZMo/D2OQSA" "\n"
"k/To/VWD6o3p1BmqKZOBFpahQro7HG/JA9JDrXn4MIIBTQIBADA1MCgxJjAkBgNV" "\n"
"BAMMHVRydXN0ZWQgQ2VydGlmaWNhdGUgQXV0aG9yaXR5AgkAk6adaxfHoJIwDQYJ" "\n"
"KoZIhvcNAQEBBQAEggEApOBENtKxkGBpijOb3/gFHmcAKU64qHIp54d8xqrfz10i" "\n"
"VDDM+Q0B7Xnqi5fZmrtYP63nh+kgn9EfbRPQhyRurENH0ZWXyYOH+7uRuTabjnws" "\n"
"u+PRD8+nQszX7qWU2VOgj+LFvX8/llPd7MHxx3WzCPMXIHymMtqBXJctoQiIWqJI" "\n"
"L1ZGUdvSlT6k3kR1XOI3LybZBKKOH9Zz+xn0APWnzza6PKuHf/1DOPaiIgx1N9Dy" "\n"
"Rl3H7s9r0PeoJaTmdHevoe4PHRGB2T2ljTJoLLatIWwYJAc6ntGSltU83JiWtIIN" "\n"
"Oej7AnaB9txk4egCFK3UwbHjRDzai2QgIHeobqYwdDA8BgkqhkiG9w0BBwEwHQYJ" "\n"
"YIZIAWUDBAEqBBCAM/waNkTBU3/nCaQbPx+KgBAvHD3umDx+0VnSP6YpSsYr" "\n"
"-----END PKCS7-----" "\n";


std::string Pkcs7FactoryTest::invalidPem = "-----BEGIN CERTIFICATE-----" "\n"
"MIIC4zCCAcsCCQCTpp1rF8egkjANBgkqhkiG9w0BAQ0FADAoMSYwJAYDVQQDDB1U" "\n"
"cnVzdGVkIENlcnRpZmljYXRlIEF1dGhvcml0eTAgFw0wMDAxMDEwMDAwMDBaGA8y" "\n"
"MTAwMDEwMTAwMDAwMFowKDEmMCQGA1UEAwwdVHJ1c3RlZCBDZXJ0aWZpY2F0ZSBB" "\n"
"dXRob3JpdHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDhZhQqHMK3" "\n"
"+G7NWfDDJeAkZIyKLVTIDJ9T4eQe5ZXcxcT0NQRprHEuwzJ8JgLaXkWgPjc0k/LC" "\n"
"i1gV/EtQ12gGRjk9CejwpgRkuUD6fqLJsOsxPlREb9G/woEEcfASbihkYD9dUuXh" "\n"
"4HlWh5hqIi6FVhSLM7O70XHtmsw168l9Jmql8TBvI6O+IorxVk93ZJR9CuBQxaPE" "\n"
"zbnFUYF1bjX2vqZQoY+mQVKLqCaX2ZGEzyGnouIahkj6VWjqyi/BhMxWFpV8uQYI" "\n"
"c4Znz4f68KaILx8JjW0TI5Rck4ERVqReDhD4R3QfFQULr0N+mhwosA+/zWZXHNMd" "\n"
"mNfdKs+3K/7rAgMBAAGjEzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEN" "\n"
"BQADggEBABmNbAdzpwbEA3fc4B02vjVbNkc8Y2Q/GdqKK3ClFqjMYvFj/a2/wpzY" "\n"
"fL3axC2+lUO2FwHPSr5ZFyg/5cjbLPb+Q/zkMng2ydXz87/KcS8z8B4SxKdr1QHu" "\n"
"YB5WyFdTCQc4uTJUrhXWW/4vYK9SW3nycP74AwbJ/oqDHG1FJgmhQRLsMF6scs7s" "\n"
"swtCZ8b4pZOo0391+lQFR1gJuEAB25XYu2MZxl9IQGp/TnSf/whwAPUdfyDXI+GG" "\n"
"rxV9mQrBGcVMa/MKbUR3F6ZNoI38niaM8KLA1Xh33YNhoGBwSLJU24nl0jp7xc4g" "\n"
"/zRzPXJT0nQ9AgvIaoEIa2fnYKc7Cnw=" "\n"
"-----END CERTIFICATE-----" "\n";


TEST_F(Pkcs7FactoryTest, FromPemSignedData) {
  testPemEncodedSignedData();
}

TEST_F(Pkcs7FactoryTest, FromDerSignedData) {
  testDerEncodedSignedData();
}

TEST_F(Pkcs7FactoryTest, FromPemEnvelopedData) {
  testPemEncodedEnvelopedData();
}

TEST_F(Pkcs7FactoryTest, FromDerEnvelopedData) {
  testDerEncodedEnvelopedData();
}

TEST_F(Pkcs7FactoryTest, InvalidPem) {
  testInvalidPem();
}
