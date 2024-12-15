#include <libcryptosec/certificate/CertPathValidator.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes unitários da classe CertPathValidator
 */
class CertPathValidatorTest : public ::testing::Test {

protected:
    virtual void SetUp() {
      trustedCa = new Certificate(trustedCaPem);
      trustedIntermediateCa = new Certificate(trustedIntermediateCaPem);
      validCert = new Certificate(validCertPem);
      untrustedIntermediateCa = new Certificate(untrustedIntermediateCaPem);
      invalidCert = new Certificate(invalidCertPem);
      caCrl = new CertificateRevocationList(caCrlPem);
      intermediateCaCrl = new CertificateRevocationList(intermediateCaCrlPem);
    }

    virtual void TearDown() {
      free(trustedCa);
      free(trustedIntermediateCa);
      free(validCert);
      free(untrustedIntermediateCa);
      free(invalidCert);
      free(caCrl);
      free(intermediateCaCrl);
    }

    /**
    * @brief Given a valid path that can validate validCert, checks if validCert is valid
    */
    void testValidPath() {
      vector<Certificate> trustedChain, untrustedChain;
      
      trustedChain.push_back(*trustedCa);
      untrustedChain.push_back(*trustedIntermediateCa);

      CertPathValidator validator(*validCert, untrustedChain, trustedChain);

      ASSERT_EQ(validator.verify(), true);
    }

    /**
    * @brief Given a valid path that can validate validCert, checks if validCert is invalid after expiring
    */
    void testValidPathCertificateExpired() {
      DateTime when("21000101010000Z");
      vector<Certificate> trustedChain, untrustedChain;
      
      trustedChain.push_back(*trustedCa);
      untrustedChain.push_back(*trustedIntermediateCa);

      CertPathValidator validator(*validCert, untrustedChain, trustedChain, when);

      ASSERT_EQ(validator.verify(), false);

    }

    /**
    * @brief Given a valid certificate path that can't validate invalidCert, checks if invalidCert is invalid
    */
    void testValidPathInvalidCertificate() {
      vector<Certificate> trustedChain, untrustedChain;
      
      trustedChain.push_back(*trustedCa);
      untrustedChain.push_back(*trustedIntermediateCa);

      CertPathValidator validator(*invalidCert, untrustedChain, trustedChain);

      ASSERT_EQ(validator.verify(), false);
    }

    /**
    * @brief Given an invalid path that can't validate validCert, checks if validCert is invalid
    */
    void testInvalidPathInvalidIntermediateCertificate() {
      vector<Certificate> trustedChain, untrustedChain;
      
      trustedChain.push_back(*trustedCa);
      untrustedChain.push_back(*untrustedIntermediateCa);

      CertPathValidator validator(*validCert, untrustedChain, trustedChain);

      ASSERT_EQ(validator.verify(), false);
    }

    /**
    * @brief Given a path that can validate validCert and a CRL that revokes validCert, checks if validCert is invalid
    */
    void testValidPathRevokedCertificate() {
      vector<Certificate> trustedChain, untrustedChain;
      vector<CertificateRevocationList> crls;

      trustedChain.push_back(*trustedCa);
      untrustedChain.push_back(*trustedIntermediateCa);
      crls.push_back(*intermediateCaCrl);

      CertPathValidator validator(*validCert, untrustedChain, trustedChain, DateTime(time(NULL)), crls);
      // This line is needed to verify CRLs but it only applies to the certificate being checked, it doesn't check the entire chain
      validator.setVerificationFlags(ValidationFlags::CRL_CHECK);

      ASSERT_EQ(validator.verify(), false);
    }

    /**
    * @brief Given a path that can validate validCert and a CRL that revokes the Intermediate CA, checks if validCert is invalid
    */
    void testValidPathRevokedIntermediateCa() {
      vector<Certificate> trustedChain, untrustedChain;
      vector<CertificateRevocationList> crls;

      trustedChain.push_back(*trustedCa);
      untrustedChain.push_back(*trustedIntermediateCa);
      crls.push_back(*caCrl);

      CertPathValidator validator(*validCert, untrustedChain, trustedChain, DateTime(time(NULL)), crls);
      // This line is needed to verify CRL for ALL certificates, including the ones in the chain
      validator.setVerificationFlags(ValidationFlags::CRL_CHECK_ALL);

      ASSERT_EQ(validator.verify(), false);
    }

    Certificate *trustedCa;
    Certificate *trustedIntermediateCa;
    Certificate *validCert;
    Certificate *untrustedIntermediateCa;
    Certificate *invalidCert;
    CertificateRevocationList *caCrl;
    CertificateRevocationList *intermediateCaCrl;
    static std::string trustedCaPem;
    static std::string trustedIntermediateCaPem;
    static std::string untrustedIntermediateCaPem;
    static std::string validCertPem;
    static std::string invalidCertPem;
    static std::string caCrlPem;
    static std::string intermediateCaCrlPem;
};

/*
 * Initialization of variables used in the tests
 */
std::string CertPathValidatorTest::trustedCaPem = "-----BEGIN CERTIFICATE-----" "\n"
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
"-----END CERTIFICATE-----";

std::string CertPathValidatorTest::trustedIntermediateCaPem = "-----BEGIN CERTIFICATE-----" "\n"
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
"-----END CERTIFICATE-----";

std::string CertPathValidatorTest::untrustedIntermediateCaPem = "-----BEGIN CERTIFICATE-----" "\n"
"MIIC9DCCAdwCCQCUgY+3f8OPnzANBgkqhkiG9w0BAQ0FADAAMCAXDTAwMDEwMTAw" "\n"
"MDAwMFoYDzIxMDAwMTAxMDAwMDAwWjBhMTUwMwYDVQQDDCxVbnRydXN0ZWQgSW50" "\n"
"ZXJtZWRpYXRlIENlcnRpZmljYXRlIEF1dGhvcml0eTEoMCYGA1UEAwwfVW50cnVz" "\n"
"dGVkIENlcnRpZmljYXRlIEF1dGhvcml0eTCCASIwDQYJKoZIhvcNAQEBBQADggEP" "\n"
"ADCCAQoCggEBAMFMiVz2GW5dCbapz1XhcsqMNywgUMLucuysIRkmZeMAFRpPZk1C" "\n"
"0eWjMh9Zkhy2s4ONzRk1H06qjsCoI+tbHht4cc/GuEm1icjuWAdEgL3xbqoHvdLL" "\n"
"NKF9hAQvtWblKMiIbVxSYwwvrStf93gLLpI+Rk6mu6T3keGOx8/fE3lX4TwoZSNh" "\n"
"H2ga7RNcW+I+fwGq8OExoRhmsm+s9yoZvKGmGRQmn4vWvcicx3rDXWy0L5mRJ9bE" "\n"
"A0qAyGkRnsaUnfTW99mLs9WhN4vKxtxhez8KipEgFkoIVOQDVnLj5sO9b45c0LZo" "\n"
"if4cZMNlXW38A33qvlMSWGyxYE3ctQ7/M80CAwEAAaMTMBEwDwYDVR0TAQH/BAUw" "\n"
"AwEB/zANBgkqhkiG9w0BAQ0FAAOCAQEAII3Ga9nN+H6Nl4ZoqeZ6sh+yEzjKlOrb" "\n"
"Dkoi2xvLei4BlKW/wc4Ugv5Ap6GwxDoUrdhY3WohlZ3de5KeWyRrJ51miwQsVJsk" "\n"
"+kIwARJnJulaBVrMYPa3xvKkNT4jki2FTttJCDQPJjxDEAwXZRmHWkzNCmW5UYWq" "\n"
"wYRzsjZozj47K2ewseUkjP8l2KDHKlCOEJtryV0cMndhh05OaKBryeQGEdWjCdy1" "\n"
"TXgDg2ElyDYsndTy7dYu9GC/a4FDGObhKZ5w8zIPcSQG+SJquk714gm4QDuyoAh5" "\n"
"pw2XcG8jWGO3liVBOIrwM4vQupb8fyUcsMTjVM1BWnxsIwOeR1oyBA==" "\n"
"-----END CERTIFICATE-----";

std::string CertPathValidatorTest::validCertPem = "-----BEGIN CERTIFICATE-----" "\n"
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
"-----END CERTIFICATE-----";

std::string CertPathValidatorTest::invalidCertPem = "-----BEGIN CERTIFICATE-----" "\n"
"MIIC/DCCAeQCCQDTeCT+CV0nNTANBgkqhkiG9w0BAQ0FADBhMTUwMwYDVQQDDCxV" "\n"
"bnRydXN0ZWQgSW50ZXJtZWRpYXRlIENlcnRpZmljYXRlIEF1dGhvcml0eTEoMCYG" "\n"
"A1UEAwwfVW50cnVzdGVkIENlcnRpZmljYXRlIEF1dGhvcml0eTAgFw0wMDAxMDEw" "\n"
"MDAwMDBaGA8yMTAwMDEwMTAwMDAwMFowHTEbMBkGA1UEAwwSVW50cnVzdGVkIE9w" "\n"
"ZXJhdG9yMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzDGYjHpDl0os" "\n"
"/Roem662vMbNrVqNj7oTSHDNnh1DXvwe1vHsDpOoCcZoEh72unmadTVETIo2LQdF" "\n"
"nVw3GYkxlUdNHc93zBSuFSdfDQHu40OGP7P6IwxQ11eq7quGAPNtHfN1x0RECxoL" "\n"
"T1HHyne9ZSXeIdGfLpRZAHzdhc5d0uBx1+d/U4f5LVqKXYvXJxkGcuDE3HQepAB2" "\n"
"0Lhu/AHDLqK+rbYdYcmH5NAppO4jV68Hq/Mb+8hkb9K5PqTZ/jiO7wKWPNbU1Ozj" "\n"
"qJzGFbdvMtI/aOKq8sD0Bko5/td3LuX7J4yQBZHhGOK4WoP0Z/NFVAwLT/EJhzk3" "\n"
"H0VB0Vd0HQIDAQABMA0GCSqGSIb3DQEBDQUAA4IBAQChRXdLi023EXm4tdpeVbMu" "\n"
"IC1C4kn7SX2AywB10cXD2tdpYlMHBMxlmRO0sfteLDBHMlrxYjvw0Z3jGYM0xl+Y" "\n"
"YoAkv1Bm1/NmEmKoy1gqXSrpJrz5zMviz8HczvRo/O++Z87Ixj4lQYJtO+i0HpWT" "\n"
"K4nT1xJFBVPZlWbeSK4ndwvZmDynTNVy7Wa9+VCUrxaBGsvU+rXqWYaW20x7zZUQ" "\n"
"1Mxss+kzVKFQtVdSL1mK/Dc3knjqyzj5d1TYL2JQdIKM0J7jBPNqZX7x4x+xi11G" "\n"
"zd+5tkNpUsRgPheXFOBz+4LGby3O6ChgApit0JcqOUjPprWZTv3HoY2bZX2UfYtl" "\n"
"-----END CERTIFICATE-----";

std::string CertPathValidatorTest::caCrlPem = "-----BEGIN X509 CRL-----" "\n"
"MIIBozCBjAIBATANBgkqhkiG9w0BAQ0FADAoMSYwJAYDVQQDDB1UcnVzdGVkIENl" "\n"
"cnRpZmljYXRlIEF1dGhvcml0eRcNMzAwMTAxMDAwMDAwWhgPMjEzMDAxMDEwMDAw" "\n"
"MDBaMB4wHAIJAJlj0TogvxprGA8yMDUwMDEwMTAwMDAwMFqgDjAMMAoGA1UdFAQD" "\n"
"AgEBMA0GCSqGSIb3DQEBDQUAA4IBAQBZ8wptno3hjqAUYhIBMUmrsaQQZ08nLUjf" "\n"
"ngFNRiy2ALERtvg+t2HDFVGDTwf3xcYuO5Xxo73RFOc13vsljQoiBc25xX/aTy6D" "\n"
"NvgfBS/gYegpE3y9KGJkFJTYpEmqCUHCFuOWPolFuUEIrIU1AYEKDBHrXkBfpO+G" "\n"
"HcuAPt2HOMoQezHMbyjq8dIa3GjRRypQ5R0W4NgLxQ6Ei0jrgf5rRJZjk9iS4t5i" "\n"
"Z0PkEOhfR9XAuzLQS3E4jMp+/uUNpMJvkFJfwFJ11dLtibA4GkFu19EmaJZxMOD/" "\n"
"XUnH0Ryxl/ZB28JlT+Ptm3eyYQXke//qSE8MenPQGLC74xCwAZEi" "\n"
"-----END X509 CRL-----";

std::string CertPathValidatorTest::intermediateCaCrlPem = "-----BEGIN X509 CRL-----" "\n"
"MIIBsDCBmQIBATANBgkqhkiG9w0BAQ0FADA1MTMwMQYDVQQDDCpUcnVzdGVkIElu" "\n"
"dGVybWVkaWF0ZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkXDTMwMDEwMTAwMDAwMFoY" "\n"
"DzIxMzAwMTAxMDAwMDAwWjAeMBwCCQCELgBb5E+vFRgPMjA1MDAxMDEwMDAwMDBa" "\n"
"oA4wDDAKBgNVHRQEAwIBATANBgkqhkiG9w0BAQ0FAAOCAQEAV97416d3r+g4f3TQ" "\n"
"I/D54qiBx52CIl7JYmyAK+ER91II5ReLTwb8iEK8fzXKuUqov1Iwo/kmtki6IrXN" "\n"
"UczjdbeqPT8FcpDXNDiw0ejNPJeiSY/0PKMSCnbkrg7NGa4WeysIF0tBI048O6GZ" "\n"
"jZwmoY0+k0tn4Yd8FL0UOZdIEOJEijMnBK+DUaAQr9J4tDaMLEbL30iAhCyyuVBD" "\n"
"B6rB2HHB7AqvHNp83jKPFc12s3VOdppSrBjHi0DP6XuL0hs7Wa2TzY90QngYw3E8" "\n"
"ClulM1s2qNucWDU/ilM1sSP01NSF8enW2Imk5WHEqSWdIj1FNVbT3Y9I7Cc8ue8Z" "\n"
"Ug1AFw==" "\n"
"-----END X509 CRL-----";

TEST_F(CertPathValidatorTest, ValidPath) {
  testValidPath();
}

TEST_F(CertPathValidatorTest, ValidPathCertificateExpired) {
  testValidPathCertificateExpired();
}

TEST_F(CertPathValidatorTest, ValidPathInvalidCertificate) {
  testValidPathInvalidCertificate();
}

TEST_F(CertPathValidatorTest, InvalidPathInvalidIntermediateCertificate) {
  testInvalidPathInvalidIntermediateCertificate();
}

TEST_F(CertPathValidatorTest, ValidPathRevokedCertificate) {
  testValidPathRevokedCertificate();
}

TEST_F(CertPathValidatorTest, ValidPathRevokedIntermediateCa) {
  testValidPathRevokedIntermediateCa();
}
