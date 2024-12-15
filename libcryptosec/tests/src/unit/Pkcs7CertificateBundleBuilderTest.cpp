#include <libcryptosec/Pkcs7CertificateBundleBuilder.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes unitários da classe Pkcs7CertificateBundleBuilder
 */
class Pkcs7CertificateBundleBuilderTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    void testAddCertificate() {
      Certificate ca = Certificate(caPem);
      Certificate intermediateCa = Certificate(intermediateCaPem);
      Certificate cert = Certificate(certPem);

      Pkcs7CertificateBundleBuilder builder;

      builder.addCertificate(ca);
      builder.addCertificate(intermediateCa);
      builder.addCertificate(cert);

      Pkcs7CertificateBundle *bundle = builder.doFinal();

      std::vector<Certificate *> certs = bundle->getCertificates();

      ASSERT_EQ(certs.size(), 3);
      ASSERT_EQ(certs.at(0)->getPemEncoded(), caPem);
      ASSERT_EQ(certs.at(1)->getPemEncoded(), intermediateCaPem);
      ASSERT_EQ(certs.at(2)->getPemEncoded(), certPem);
    }

    void testInitAfterAddingCertificate() {
      Certificate ca = Certificate(caPem);
      Certificate cert = Certificate(certPem);

      Pkcs7CertificateBundleBuilder builder;

      builder.addCertificate(cert);
      builder.init();
      builder.addCertificate(ca);

      Pkcs7CertificateBundle *bundle = builder.doFinal();

      std::vector<Certificate *> certs = bundle->getCertificates();

      ASSERT_EQ(certs.size(), 1);
      ASSERT_EQ(certs.at(0)->getPemEncoded(), caPem);
    }

    static std::string plainText;
    static std::string caPem;
    static std::string intermediateCaPem;
    static std::string certPem;
};

/*
 * Initialization of variables used in the tests
 */
std::string Pkcs7CertificateBundleBuilderTest::plainText = "plain text";

std::string Pkcs7CertificateBundleBuilderTest::caPem = "-----BEGIN CERTIFICATE-----" "\n"
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

std::string Pkcs7CertificateBundleBuilderTest::intermediateCaPem = "-----BEGIN CERTIFICATE-----" "\n"
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

std::string Pkcs7CertificateBundleBuilderTest::certPem = "-----BEGIN CERTIFICATE-----" "\n"
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

TEST_F(Pkcs7CertificateBundleBuilderTest, AddCertificate) {
  testAddCertificate();
}

TEST_F(Pkcs7CertificateBundleBuilderTest, InitAfterAddingCertificate) {
  testInitAfterAddingCertificate();
}
