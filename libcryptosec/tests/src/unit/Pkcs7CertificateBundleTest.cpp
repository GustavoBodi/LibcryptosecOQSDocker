#include <libcryptosec/Pkcs7CertificateBundle.h>

#include <libcryptosec/KeyPair.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes unitários da classe Pkcs7CertificateBundle
 */
class Pkcs7CertificateBundleTest : public ::testing::Test {

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

    void testExtract() {
      Pkcs7CertificateBundle *bundle = new Pkcs7CertificateBundle(genPkcs7(bundlePem));
      std::ostringstream *out = new std::ostringstream();
      bundle->extract(out);

      ASSERT_EQ(out->str(), plainText);
      free(bundle);
      free(out);
    }

    void testExtractEmpty() {
      Pkcs7CertificateBundle *bundle = new Pkcs7CertificateBundle(genPkcs7(emptyPem));
      std::ostringstream *out = new std::ostringstream();
      bundle->extract(out);

      ASSERT_EQ(out->str(), "");
      free(bundle);
      free(out);
    }

    void testGetCertificates() {
      Pkcs7CertificateBundle *bundle = new Pkcs7CertificateBundle(genPkcs7(bundlePem));
      std::vector<Certificate *> certs = bundle->getCertificates();

      ASSERT_EQ(certs.size(), 3);
      ASSERT_EQ(certs.at(0)->getPemEncoded(), caPem);
      ASSERT_EQ(certs.at(1)->getPemEncoded(), intermediateCaPem);
      ASSERT_EQ(certs.at(2)->getPemEncoded(), certPem);
      free(bundle);
    }

    void testGetType() {
      Pkcs7CertificateBundle *bundle = new Pkcs7CertificateBundle(genPkcs7(bundlePem));
      ASSERT_EQ(bundle->getType(), Pkcs7::CERTIFICATE_BUNDLE);
      free(bundle);
    }

    void testInvalidPkcs7() {
      ASSERT_THROW(Pkcs7CertificateBundle(genPkcs7(invalidPem)), Pkcs7Exception);
    }

    static std::string plainText;
    static std::string bundlePem;
    static std::string caPem;
    static std::string intermediateCaPem;
    static std::string certPem;
    static std::string invalidPem;
    static std::string emptyPem;
};

/*
 * Initialization of variables used in the tests
 */

std::string Pkcs7CertificateBundleTest::plainText = "plain text";

std::string Pkcs7CertificateBundleTest::invalidPem = "-----BEGIN PKCS7-----" "\n"
"MIIBqQYJKoZIhvcNAQcDoIIBmjCCAZYCAQAxggFRMIIBTQIBADA1MCgxJjAkBgNV" "\n"
"BAMMHVRydXN0ZWQgQ2VydGlmaWNhdGUgQXV0aG9yaXR5AgkAk6adaxfHoJIwDQYJ" "\n"
"KoZIhvcNAQEBBQAEggEAMajO+AeI5reYbn7/qRN0AK8z0TuSWgjXHUBMLDHD4LO1" "\n"
"wLh70lQNZtaCfvSdhKcx7DREU4p+ij7CQ68t0ZXb7K7bljOOgOwOjA1HG9uQi3Nr" "\n"
"U6W0TN2mUJwfIMrya9fOnrSdCoAWuwXpxoOPcSr0xKPKq23dyfubuOFSzoiQPFMw" "\n"
"3ZIhjGVSABHycfGpRDRxguUIM2B3uWrvUiNHPYDPdleRAfvId9Pcz8hCTEPKHPmH" "\n"
"Fc2NHTsUUMyVTB6tAP4s9UxuGcwaxjbB4uK4UiYtIfjExmO4eyuDnCuNfWWfI9DJ" "\n"
"AaG8MtyHxQZ3JxyopZUMPFMex21Sr07U40p3O0ctjjA8BgkqhkiG9w0BBwEwHQYJ" "\n"
"YIZIAWUDBAEqBBAXkBTKRBZqAH3lHgYZZ039gBBJSh8fZE+bx9XnijaYq7gS" "\n"
"-----END PKCS7-----" "\n";

std::string Pkcs7CertificateBundleTest::emptyPem = "-----BEGIN PKCS7-----" "\n"
"MCcGCSqGSIb3DQEHAqAaMBgCAQExADAPBgkqhkiG9w0BBwGgAgQAMQA=" "\n"
"-----END PKCS7-----" "\n";


std::string Pkcs7CertificateBundleTest::bundlePem = "-----BEGIN PKCS7-----" "\n"
"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" "\n"
"JccspSlFe1buL7CkqbJIj/KUmt8g9Cp7MQA=" "\n"
"-----END PKCS7-----" "\n";

std::string Pkcs7CertificateBundleTest::caPem = "-----BEGIN CERTIFICATE-----" "\n"
"MIIC4zCCAcsCCQDrfn+TvOi8KzANBgkqhkiG9w0BAQ0FADAoMSYwJAYDVQQDDB1U" "\n"
"cnVzdGVkIENlcnRpZmljYXRlIEF1dGhvcml0eTAgFw0wMDAxMDEwMDAwMDBaGA8y" "\n"
"MTAwMDEwMTAwMDAwMFowKDEmMCQGA1UEAwwdVHJ1c3RlZCBDZXJ0aWZpY2F0ZSBB" "\n"
"dXRob3JpdHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDTp8YbJmUZ" "\n"
"JgwkRGICuAJpn1e7lEaf/9lHzmJGYbe+5zjE9YJxlqWbxRRERw5AsRsze0ittE5X" "\n"
"0/hVQ74AMcWt+M5h2geKpdEUBXXXtJPG7R4825NHw6B65TdLJ9UB64Qd/za8uJnR" "\n"
"Ym/9ZIe0tGDSvOtR9tJ5CuBkrWEDT6+76O/E7Clz1is3XznI1OFTVy+98nn7/fft" "\n"
"84GY4RpIYskmJqIrk2SHAGB02X4UCxw3bmgBOHDJbmMQZE54U2jjwWFnvC3E8/tF" "\n"
"kiMEd4aTaU6axl/mzLJoLzVHgDFTnuo9NES4mxZ4sNikk0FMzS5JarMFRFUNdr3m" "\n"
"wCJ9c3j4iYDbAgMBAAGjEzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEN" "\n"
"BQADggEBAATfZ1GwI3lbzPQ7ykkGg2u9gIC/6yUCarz5snvntIPInH6IbOpWWXYZ" "\n"
"liPZKOItqR6APGiCxLswsWY6zwNlQelmXDZnnFXfHIhWjcOM9Cb0Be9w6elX+/8e" "\n"
"Wp/N2JruLdf30MS4uXxQmpgR6+pcOUG73oqItOl3HTtcNRmKcX+SIgJB2dy5ELO2" "\n"
"X1m6fVkiA021W1AI78YOGAzKhwQmUp4IRTMW0iK3FUDYGRO8FW3hZJMn+hM6MRe4" "\n"
"sFUaRkiuisix2O5zGsV/UvC0oWbIs7umXLoYoe0AM88MHf4kpIq15lq6X6k1JAii" "\n"
"DFOVgLYzxzmV2SMJ/NlZeB4S0VGm85E=" "\n"
"-----END CERTIFICATE-----" "\n";

std::string Pkcs7CertificateBundleTest::intermediateCaPem = "-----BEGIN CERTIFICATE-----" "\n"
"MIIC8DCCAdgCCQCZY9E6IL8aazANBgkqhkiG9w0BAQ0FADAoMSYwJAYDVQQDDB1U" "\n"
"cnVzdGVkIENlcnRpZmljYXRlIEF1dGhvcml0eTAgFw0wMDAxMDEwMDAwMDBaGA8y" "\n"
"MTAwMDEwMTAwMDAwMFowNTEzMDEGA1UEAwwqVHJ1c3RlZCBJbnRlcm1lZGlhdGUg" "\n"
"Q2VydGlmaWNhdGUgQXV0aG9yaXR5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB" "\n"
"CgKCAQEAvv4WARioU+x8meSQBqD8IlG5bLNXlBLocVSOwoHU6gGIdUbiU2vQiGIM" "\n"
"C1NGRztyjtmPGcH+93XdcjcWo/4Pya/A+DcZY/B6bHZCNkW0Ox95VrZWJrEP3EgZ" "\n"
"GcuTx+Z+8b6xCP2s8ZMc6XU6aCnedfht1BTIVelaGOrZk5EeltWu6KqtQXDcaJ8O" "\n"
"ncUW05zfke6A5KaDhyzuUpdQxJiJ7gxkoEAwwU0VeD7TIXZtDR/QhSZ/UYvPfvqO" "\n"
"RUBLpZJ2EzOvVxQBmGadnNcvYdPtzvp7bibJiOCGxc2OgCQ8OVZ3CmhwGZ7q4SMn" "\n"
"qQooAWqkUv6osVCgI8oCwDCp8+ZIQwIDAQABoxMwETAPBgNVHRMBAf8EBTADAQH/" "\n"
"MA0GCSqGSIb3DQEBDQUAA4IBAQBJiDMri0naQ6T96XiPVdbmmm4vbw0DP2mKhCc9" "\n"
"unvHOALLkcD2webJLrYb8GwYrg6KIriERBjxQKUV+0CuLbRblqHmfIggfFfKR0tw" "\n"
"QfKfqggeq3X/0kOBHLPKsJUbB0KgLpsCJ0rfv5y6gZUpEf1Gr2Ytyj03YArsF4Cs" "\n"
"fiEnPU3mDVN5Nql6Usvv6AR5DjWyPxos0zyvtGfAwN9dCTL3PQwd3p5pHRJs6Z65" "\n"
"c9c0zDD/ludNQzIkFU2ZXbv20vru6xTzLP6sHJ5i8nqQQ/x053U3B+xTnZwOD1XG" "\n"
"KHnX4A61PKSJo1hGD1+5wKD02zDO1SCXj3L5Hf4+XmHM4vxB" "\n"
"-----END CERTIFICATE-----" "\n";

std::string Pkcs7CertificateBundleTest::certPem = "-----BEGIN CERTIFICATE-----" "\n"
"MIICzjCCAbYCCQCELgBb5E+vFTANBgkqhkiG9w0BAQ0FADA1MTMwMQYDVQQDDCpU" "\n"
"cnVzdGVkIEludGVybWVkaWF0ZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwIBcNMDAw" "\n"
"MTAxMDAwMDAwWhgPMjEwMDAxMDEwMDAwMDBaMBsxGTAXBgNVBAMMEFRydXN0ZWQg" "\n"
"T3BlcmF0b3IwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4qpnqD1ts" "\n"
"+I9pYmlSvoxZgK2f+6+8sqQGjOECvdw/kpFnLERHcDRvLfuhIpD+Yqv52loBUb6Z" "\n"
"LdnL6ZAfSXO5l4FXYZiGaf/s04l8x6PLGTtEFaDHlJz7ZtGM2voyyKe7ZgAtjL6L" "\n"
"F60VFi5Z8CjZ+KS1Bd0K3zqGtXtsudVQneyAL7LwtHCCDI6kyyK/22SwGbu16ea4" "\n"
"XOLnYz+lJ3KfKr6X2nZiWnmd00iengSo5vkCdQkNbTOLNqupuWGciDOjd7vV2geg" "\n"
"HCT+O+Vfg4bTXOSj3Zrr6jk3KcTmyCT5qI7jvFmS0IlXgSOxUnN261u/PC4QZ3yJ" "\n"
"YP3rxtgiin5TAgMBAAEwDQYJKoZIhvcNAQENBQADggEBAKeNKVk6aW2SCO1fnulV" "\n"
"u3yHB8o0zg2UsRGyASmxC0p2vM9A2ztg8FyYYagUBxjQuyJfUvHZa6G52T1lz/As" "\n"
"iMtX4lcurlzPKdpm8SlaCHwkkzp/+PUWZDvYiYyQeNU+nRE2WB3YS2K9JniSv6gM" "\n"
"QYW4iTdS50k4EodmsZNBe8tJRMAHNB0R4G0qVRWiBvQ6vVT6AX5Dos3qR/dYunmX" "\n"
"21KmcML2yUWqkMOMFUQUZ0/guoOXdNwhiUGjwEqT/11YRJwtJkMapP85sbuSJX9c" "\n"
"7705E7OxdBsTLPCjOS3SyceKBZ8h0gSpMYwlxyylKUV7Vu4vsKSpskiP8pSa3yD0" "\n"
"Kns=" "\n"
"-----END CERTIFICATE-----" "\n";

TEST_F(Pkcs7CertificateBundleTest, Extract) {
  testExtract();
}

TEST_F(Pkcs7CertificateBundleTest, ExtractEmpty) {
  testExtractEmpty();
}

TEST_F(Pkcs7CertificateBundleTest, GetCertificates) {
  testGetCertificates();
}

TEST_F(Pkcs7CertificateBundleTest, GetType) {
  testGetType();
}

TEST_F(Pkcs7CertificateBundleTest, InvalidPkcs7) {
  testInvalidPkcs7();
}
