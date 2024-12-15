#include <libcryptosec/Pkcs7SignedDataBuilder.h>

#include <libcryptosec/KeyPair.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes unitários da classe Pkcs7SignedDataBuilder
 */
class Pkcs7SignedDataBuilderTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    void testAddCertificate() {
      Pkcs7SignedDataBuilder builder = Pkcs7SignedDataBuilder(MessageDigest::SHA512, ca, *caKeyPair.getPrivateKey(), false);

      builder.addCertificate(cert);

      Pkcs7SignedData *data = builder.doFinal();

      std::vector<Certificate *> certs = data->getCertificates();
  
      ASSERT_EQ(certs.size(), 2);
      ASSERT_EQ(certs.at(0)->getPemEncoded(), ca.getPemEncoded());
      ASSERT_EQ(certs.at(1)->getPemEncoded(), cert.getPemEncoded());
    }

    void testAddSigner() {
      Pkcs7SignedDataBuilder builder = Pkcs7SignedDataBuilder(MessageDigest::SHA512, ca, *caKeyPair.getPrivateKey(), false);

      builder.addSigner(MessageDigest::SHA512, coSigner, *coSignerKeyPair.getPrivateKey());

      Pkcs7SignedData *data = builder.doFinal();

      std::vector<Certificate> trusted;
      trusted.push_back(cert);

      std::vector<Certificate> trustedCoSigner;
      trustedCoSigner.push_back(coSigner);

      ASSERT_TRUE(data->verify(true, trusted));
      ASSERT_TRUE(data->verify(true, trustedCoSigner));
    }

    void testAddCrl() {
      Pkcs7SignedDataBuilder builder = Pkcs7SignedDataBuilder(MessageDigest::SHA512, ca, *caKeyPair.getPrivateKey(), false);

      builder.addCrl(crl);

      Pkcs7SignedData *data = builder.doFinal();

      std::vector<CertificateRevocationList *> crls = data->getCrls();

      ASSERT_EQ(crls.at(0)->getPemEncoded(), crl.getPemEncoded());
    }

    void testDoFinalString() {
      Pkcs7SignedDataBuilder builder = Pkcs7SignedDataBuilder(MessageDigest::SHA512, ca, *caKeyPair.getPrivateKey(), false);

      Pkcs7SignedData *data = builder.doFinal(plainText);

      ASSERT_EQ(data->getPemEncoded(), signedDataPem);
    }

    void testDoFinalByteArray() {
      Pkcs7SignedDataBuilder builder = Pkcs7SignedDataBuilder(MessageDigest::SHA512, ca, *caKeyPair.getPrivateKey(), false);

      Pkcs7SignedData *data = builder.doFinal(baPlainText);

      ASSERT_EQ(data->getPemEncoded(), signedDataPem);
    }

    static Certificate ca;
    static Certificate coSigner;
    static Certificate intermediateCa;
    static Certificate cert;

    static CertificateRevocationList crl;

    static KeyPair caKeyPair;
    static KeyPair coSignerKeyPair;

    static ByteArray baPlainText;

    static std::string plainText;
    static std::string caPem;
    static std::string caPrivKeyPem;
    static std::string coSignerPem;
    static std::string coSignerPrivKeyPem;
    static std::string intermediateCaPem;
    static std::string certPem;
    static std::string crlPem;
    static std::string signedDataPem;
};

/*
 * Initialization of variables used in the tests
 */
std::string Pkcs7SignedDataBuilderTest::plainText = "plainText";

std::string Pkcs7SignedDataBuilderTest::caPem = "-----BEGIN CERTIFICATE-----" "\n"
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

std::string Pkcs7SignedDataBuilderTest::caPrivKeyPem = "-----BEGIN PRIVATE KEY-----" "\n"
"MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDhZhQqHMK3+G7N" "\n"
"WfDDJeAkZIyKLVTIDJ9T4eQe5ZXcxcT0NQRprHEuwzJ8JgLaXkWgPjc0k/LCi1gV" "\n"
"/EtQ12gGRjk9CejwpgRkuUD6fqLJsOsxPlREb9G/woEEcfASbihkYD9dUuXh4HlW" "\n"
"h5hqIi6FVhSLM7O70XHtmsw168l9Jmql8TBvI6O+IorxVk93ZJR9CuBQxaPEzbnF" "\n"
"UYF1bjX2vqZQoY+mQVKLqCaX2ZGEzyGnouIahkj6VWjqyi/BhMxWFpV8uQYIc4Zn" "\n"
"z4f68KaILx8JjW0TI5Rck4ERVqReDhD4R3QfFQULr0N+mhwosA+/zWZXHNMdmNfd" "\n"
"Ks+3K/7rAgMBAAECggEBAJjPStZuHzj4ba48zrSO5hHmNT2sk/D4VcBZwf2Mavh9" "\n"
"ABUMKIy4AxfP8FcosgB3rz5/T5AOyaNJMxPcsvcAwp6WV1HheRJFi276BWqOFjEl" "\n"
"B56gAiNPp+UYqb1ovXjRRAMhGXRcsktbkwet8A/sUpvFCzKAf9bSnSmYK+BWlYiJ" "\n"
"D/12+5XuNo8/9+K+HkIBr9SL+o1veAClyIRDkbfm+9JGIYtyDN4A++oQBYZWD1I7" "\n"
"Kmb5zl0rTeo6TP7b8Lt015Cv6Pe9VENqiozAecISCxmDzgD4Tqvjx5/KHQonpvym" "\n"
"ZOEZ8TClj7k/4HFZcVJA4oy71/CxFsd2jVZARFJy4XkCgYEA+qOFn92gLYnLIOXH" "\n"
"ej4rWU3Msk/QEF5B9M2pgbq+TzLxROS+rXr4cCSgXkzujnvF3MDfPk7KZnqDn9Hc" "\n"
"O2XL0oFHh7DFo+ZZ1xk0MS0yvr53l2ac0x7LklNFImSB+GHmzkFpZrNOav8IiB4h" "\n"
"Vx8OmQzH9sHK5i8qAD1Ph+87ZI0CgYEA5jhYMAxWdyiCcqqX8q6/A5gJ38BKEzIC" "\n"
"+pprUncUnkfYKuaG/NWIljEOBNunx7GErpmLTK8m3kpHtbg/cfk45eMIJKrEYoDg" "\n"
"WZIVGVt4ZomOAIB6IWf5Pdn7DlZsdVa/siwhpEnxu2ZEF7mJlZdnKWbmjI5WLMqW" "\n"
"VxY73fB+31cCgYEAkADfx2g4nbFryez7XVrW4Sp4D4MX0i+1yYdYerbmnO5x/NlI" "\n"
"TLg4gYYptcSR0799gUY3fb8bPyHo+ixDUsU8BChPBsEj7PVubM2IVTDY1Qrt/0jv" "\n"
"lcU9xUaelBIXMrRdPegLPPyMc6EwL7TQBxRK+NiFE1tozjQO97BCP6HOCAkCgYEA" "\n"
"k4K2vtKo9GC4dNBp282sBpl8eimzTOlWj0wyR/yU8XYHRDXBeG85vUJhQSudLY7I" "\n"
"/TbU0qXHudbOa9lKjbSqiGIX7aadfqAlID9B1aWOV+T7X8byekUspjztaBpoFCcp" "\n"
"XPh59dKLWRAFwU3YokkIiLauMpFhFgIYomRUp7hZErECgYEA6UAyWXMfEvmywK/c" "\n"
"0LIGKZz8M6/99FRScFIIOBIrjtqJm7bkUx7RDOu7eLy1xEQCphIacNbDkXLJ9TO/" "\n"
"ab3OhEUC6ZtM8dXLe9iJD8/7ML4p1ScSJk0K/uLP2WGwoHL+IQcLyC1WvPSXWbxr" "\n"
"YI7O7p1OjaiuyFvrRMXOPKsVkIs=" "\n"
"-----END PRIVATE KEY-----" "\n";

std::string Pkcs7SignedDataBuilderTest::coSignerPem = "-----BEGIN CERTIFICATE-----" "\n"
"MIIC4jCCAcoCCDJzk/cs2OG3MA0GCSqGSIb3DQEBDQUAMCgxJjAkBgNVBAMMHVRy" "\n"
"dXN0ZWQgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MCAXDTAwMDEwMTAwMDAwMFoYDzIx" "\n"
"MDAwMTAxMDAwMDAwWjAoMSYwJAYDVQQDDB1UcnVzdGVkIENlcnRpZmljYXRlIEF1" "\n"
"dGhvcml0eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK7vT1AyPqK3" "\n"
"7kcorICBUsLzLOT5eP+eDiuP6tiB0/pJ8IQvBbF8zyJS8dp9gEuUwF+VEVOW1OYd" "\n"
"zLmJSKy50ifG0DfkjnGzDbhkODe+Fs6v7vANTXGj0UJrCZo5rz1bPXPNS9ME6YLa" "\n"
"dguo/mVVzk+xzYJvlV29fJwmWyOSN4MKlotGF2axNQcCOwMO37CrGnBoDE3Hc2kD" "\n"
"tBeY1UL63AFih+ZIs7I/XVV/Zdte9WbRMhhrR+5Rg2AydMie/E3OkhZehk2gvhvg" "\n"
"ncn6feMKJq+qQyBYVJDelDLm75NGCXlIV6DDWKr3/HMscuRCC/aP8EvQmcM8+rad" "\n"
"QA+4/9f4cb0CAwEAAaMTMBEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQ0F" "\n"
"AAOCAQEAfUuYsBmWB+6aAP0jGJdzStZ+fLjX4OfqyqsBYz0OWKVeM9w7oPH9zmBS" "\n"
"nIOmMYp1209u+YKJ1gVPIGmXrffeC1R3C9ADUJfpXBvXVW28yRIPFVjdN5mGxoY7" "\n"
"Pzkeia9e4k57+zJj9awDLolonLGHsWlylGa63q5VtFuajHEvFK9n46hH+nJfQYGF" "\n"
"F9u37fMRfTs8XnLEKZ+vk8jv1irwW1/nvFB05SvRq3vxIChTbwmqkwQ2O3XVU82E" "\n"
"06aqZK1UnDF3ObWlnUmFjprmG8E3jBbXD/X4GSZM0C9LWIwK0OfMPmfZwq4pqFFU" "\n"
"JX7W2KpInGvJltb3hq2CWGXyMpUqPQ==" "\n"
"-----END CERTIFICATE-----" "\n";

std::string Pkcs7SignedDataBuilderTest::coSignerPrivKeyPem = "-----BEGIN PRIVATE KEY-----" "\n"
"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCu709QMj6it+5H" "\n"
"KKyAgVLC8yzk+Xj/ng4rj+rYgdP6SfCELwWxfM8iUvHafYBLlMBflRFTltTmHcy5" "\n"
"iUisudInxtA35I5xsw24ZDg3vhbOr+7wDU1xo9FCawmaOa89Wz1zzUvTBOmC2nYL" "\n"
"qP5lVc5Psc2Cb5VdvXycJlsjkjeDCpaLRhdmsTUHAjsDDt+wqxpwaAxNx3NpA7QX" "\n"
"mNVC+twBYofmSLOyP11Vf2XbXvVm0TIYa0fuUYNgMnTInvxNzpIWXoZNoL4b4J3J" "\n"
"+n3jCiavqkMgWFSQ3pQy5u+TRgl5SFegw1iq9/xzLHLkQgv2j/BL0JnDPPq2nUAP" "\n"
"uP/X+HG9AgMBAAECggEARlL6BXlNaMicR4r4XeifRrPPdnU7yTbW53hBpqv6dYHH" "\n"
"6LumhEVyV5AUngsZykiQVVxtzLaz+5Y7ONMRni5NZ6QrDG0bPmYGu/u+Bdqq/IgJ" "\n"
"fAM9ANQkSZkSESfjZL0LJUSAmOI+pVYBYoqbSk2GVM9bmHYXC8ojD/rzZIdhPZIX" "\n"
"7XQNxNQHdDpWA56euQlOZoJwUUvgJFP/xWqq00Aw9aPdzIkuEilYLzXw4l28DRYd" "\n"
"KgOvSqM8Iai74RhuWB+73qHI82Pbg3I4WVFHaUjb3+etk00y1FKMGCCxHfDGlmAd" "\n"
"4106D5r2gBKzNsjXWAdWBgvKe7NaYyAGknKI06bRgQKBgQDWiB2okgAtMlVUI1bN" "\n"
"NHhiJm4z4ERSwGjVUm+3ekVQWfbKRJThnypH68ll+Y5wsxyHEsDUd3Vf6AGgh7E1" "\n"
"0A97SS3TdCdmkwhWP5sr5tWXbQ2lVl5bmjUA+RANCvx0J9QTRbA7D5wmos8j7XEv" "\n"
"axoxoPWuDQKRL1sTkDiIOdfeUQKBgQDQv8gRnkd2y21P/bzoah/f6oJv0Zz/0E5+" "\n"
"rR3rkXMFnxhgK87ixkRD6ZBf/4XKsbPUeRMC0tClURTtRDXIWfff1ukR8lJjVmrA" "\n"
"z60vGKJZRBfUvOjUqoIBCgZeZYWH9L+l0h1X5lziM9py6+TCppA2hV6PNmAh1TP4" "\n"
"giJRbb2lrQKBgCehr7Dzf9rZoI/Rk3iHR/IB3Xvx401SREucVg0UJnfolsHZF5Py" "\n"
"vnHY6jTPfHPvcsa1PTBC/UkBaEOKrb8eN63z3+ZfX+QAJ5sfVwAuPakiuVGg+f98" "\n"
"JmyOlluCew7OSMxipGLUyGkOzKt7ctxqscUXUiucNawyjmW3z+nCndFxAoGBAMZ7" "\n"
"s9Xcs4KmxldqofYzAf+8US3VFvy9qgUUwgA8mitcLKc0wFAryLjyGc7NfP9Pm/eI" "\n"
"76SdormtsMIxOxo3QVLaW14vFFtTzclrLfY77BIIhshGnvOm9FncmFWlHiQ5eQhI" "\n"
"EpKDfQmv2COxXCAgk7rjcRem0h0ZRYMi6VKXj905AoGAK6fL+pjxdA6MmR7oUehT" "\n"
"nt4+9JXwif8QWUmhI29iJzpixTVH52v0s70QRHehaarLZXC4TTwnkNKPBNVHLeSO" "\n"
"fpR99E3lhUGd0vBYKO2fiGUhmxagTfvzBm6c8BcfcDHnm32pL596DsxjYbJaVpY4" "\n"
"ZORn4Od579vUyC6vMWwMn9w=" "\n"
"-----END PRIVATE KEY-----" "\n";

std::string Pkcs7SignedDataBuilderTest::intermediateCaPem = "-----BEGIN CERTIFICATE-----" "\n"
"MIIC8DCCAdgCCQDdBn79VCiY9TANBgkqhkiG9w0BAQ0FADAoMSYwJAYDVQQDDB1U" "\n"
"cnVzdGVkIENlcnRpZmljYXRlIEF1dGhvcml0eTAgFw0wMDAxMDEwMDAwMDBaGA8y" "\n"
"MTAwMDEwMTAwMDAwMFowNTEzMDEGA1UEAwwqVHJ1c3RlZCBJbnRlcm1lZGlhdGUg" "\n"
"Q2VydGlmaWNhdGUgQXV0aG9yaXR5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB" "\n"
"CgKCAQEAo/SUpk/6ZPc8F6NA/vR3kh8zJE5QWTRZKsV++91FQkrF72qPMQncnuV4" "\n"
"U5D4YxVWU5eKvueiC3ybXqUjlp+eNdenZ6qf/93m2rTgE+laSR8MLncfetL4tqXo" "\n"
"CcBYiLy2lRe14GHAZGZZnU0jTaJoqmpxXDp7KnwG9tjnh8Op8PZwwJRINtAgqCX5" "\n"
"CkJmxwIe96filixtItZ1nmpymM8mV/QRpFKzst+EIjzNq/wFBwYAAXIXxR2XtNg8" "\n"
"nCSZAe0HXiYRaMEe5xYBeJFdfglU5YznE0lPTIYQJdolWgyOxpROYT8iZIcqKvpa" "\n"
"pzS/6g+abSKH9m1S1SVITYZftRxUeQIDAQABoxMwETAPBgNVHRMBAf8EBTADAQH/" "\n"
"MA0GCSqGSIb3DQEBDQUAA4IBAQCzsS7wjfEBO4lFy+aXZi4R7DOOgBkUlx28pzQI" "\n"
"6nCeKjmDMbxOH0BuXaFVOsepQwuzRzTo5Mvh/hW2vJjG5cp2V8Qvf8G8RJ11raZN" "\n"
"TixkZzzHQfp5Z1C9eXhWMcLhxQKZqWf/MX97XQUJUc/FG4BjxZLZkojz8AQARI8S" "\n"
"XjICUzqmaI/JvisLiTY0J5cW5t2itTnQv1Nf+psYFsIH2oc9gW5uAdYSPxXaTuB2" "\n"
"nG1uaKbjc1sa/dzZIYMYnUGr7SH0Fx63yxogOWKjDKTSD3Mff1oRYshhZxmUIUYK" "\n"
"43ewWr/RYl0oDkbqsF7qssQ+Y70gb0u7+pMFMd/W975VSD60" "\n"
"-----END CERTIFICATE-----" "\n";

std::string Pkcs7SignedDataBuilderTest::certPem = "-----BEGIN CERTIFICATE-----" "\n"
"MIICzTCCAbUCCAtOUEcL1aHRMA0GCSqGSIb3DQEBDQUAMDUxMzAxBgNVBAMMKlRy" "\n"
"dXN0ZWQgSW50ZXJtZWRpYXRlIENlcnRpZmljYXRlIEF1dGhvcml0eTAgFw0wMDAx" "\n"
"MDEwMDAwMDBaGA8yMTAwMDEwMTAwMDAwMFowGzEZMBcGA1UEAwwQVHJ1c3RlZCBP" "\n"
"cGVyYXRvcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMV7NJ0oCxva" "\n"
"wAKKfSQ1vSIlo9sdRpjykpd32S+jHyaYHLkxNbCtQ8C0hANNkntMOqiN/hGmK/fL" "\n"
"WlpetG9EQevE2NHK9gskVpX775tAQCLEPuZCq1ieF5H+jB1b4SIirLZ6jEm+NXJF" "\n"
"LO3p4sZGJZnkvnEwxj52nII5uej5KMCyLWYPftl74yWdoQiagmASOL3xhawzj8ft" "\n"
"9LsvEyCd3GRZLdZd2HldX+HrZICz63QF/jshbSQErDwwj2m0S3QKysknQBdhfOg5" "\n"
"G613YzlNCFMYd1VhvQKkoypci8wdSxXLGBROBj43yJqVesEtYFWyWovuSxcVPc9n" "\n"
"dq7TFOW1iqMCAwEAATANBgkqhkiG9w0BAQ0FAAOCAQEAk9Icl8yhaUp4aDanCF4C" "\n"
"9ZxhIrEYCmmbf4+wFQBTQEI7y2iZYivkyjAYdUSl3xEwiLmNDm1HUP5pO0Z5z9zd" "\n"
"NgT3Ihpv1IpJXtg3Z1eGXoc4tYp4NOLiIP8Tc/CSu9R8zJptn1O567aak4szpRC9" "\n"
"JZBvKFPFB8qiyHS8JtMv+goW/51sbCSnKPKes9v451VeQvDp+eFoP4CiRpVmH+rw" "\n"
"Iv77mPc2IhZA5CCuqjUgQ/+H1RfaT4y3FruUhJf95RWUCxPp9QFVmGfJp9ifDVTH" "\n"
"onS5YaZ+DDVtfpnSD7Ou0qZa3lEQI7QesnqqYsmGukuekbo4+AGNZ0pBfeOATOFa" "\n"
"1A==" "\n"
"-----END CERTIFICATE-----" "\n";

std::string Pkcs7SignedDataBuilderTest::crlPem = "-----BEGIN X509 CRL-----" "\n"
"MIIBozCBjAIBATANBgkqhkiG9w0BAQ0FADAoMSYwJAYDVQQDDB1UcnVzdGVkIENl" "\n"
"cnRpZmljYXRlIEF1dGhvcml0eRcNMzAwMTAxMDAwMDAwWhgPMjEzMDAxMDEwMDAw" "\n"
"MDBaMB4wHAIJAN0Gfv1UKJj1GA8yMDUwMDEwMTAwMDAwMFqgDjAMMAoGA1UdFAQD" "\n"
"AgEBMA0GCSqGSIb3DQEBDQUAA4IBAQBQzxWcJv2S4LeZ6UlyPSrAoHYao93kcLsv" "\n"
"jwu9DgCH11s+M6kNnwcSnenQhS4W19Hl3MHiX0Ooi+hko2W6aEGBZ7PkWCQfxIln" "\n"
"TeBBbqCYU56bq5ItVUU0LMK5eTM/7TQewCyuj+6x/TE+EZc+oMMZO/YRZC45Cmak" "\n"
"d22Z3r0hSKtEtOCjJBUfIylhnAd3B2rDGEKfDFYok6BefjAjWDQ/wW4pgMOFWzdP" "\n"
"Alet2JoENDWPGsLUiFhASnlVCEiqKrCehHYOH3KNaRPVXJJFi0lUym+gHbIr4n7d" "\n"
"nsULI7v38AcSwqjhZpE+vBP9JOafVdXCGG1JMRRDJjY2vVghIRfL" "\n"
"-----END X509 CRL-----" "\n";

std::string Pkcs7SignedDataBuilderTest::signedDataPem = "-----BEGIN PKCS7-----" "\n"
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


Certificate Pkcs7SignedDataBuilderTest::ca = Certificate(Pkcs7SignedDataBuilderTest::caPem);
Certificate Pkcs7SignedDataBuilderTest::coSigner = Certificate(Pkcs7SignedDataBuilderTest::coSignerPem);
Certificate Pkcs7SignedDataBuilderTest::intermediateCa = Certificate(Pkcs7SignedDataBuilderTest::intermediateCaPem);
Certificate Pkcs7SignedDataBuilderTest::cert = Certificate(Pkcs7SignedDataBuilderTest::certPem);

CertificateRevocationList Pkcs7SignedDataBuilderTest::crl = CertificateRevocationList(Pkcs7SignedDataBuilderTest::crlPem);

KeyPair Pkcs7SignedDataBuilderTest::caKeyPair = KeyPair(Pkcs7SignedDataBuilderTest::caPrivKeyPem);
KeyPair Pkcs7SignedDataBuilderTest::coSignerKeyPair = KeyPair(Pkcs7SignedDataBuilderTest::coSignerPrivKeyPem);

ByteArray Pkcs7SignedDataBuilderTest::baPlainText = ByteArray(Pkcs7SignedDataBuilderTest::plainText);

TEST_F(Pkcs7SignedDataBuilderTest, AddCertificate) {
  testAddCertificate();
}

TEST_F(Pkcs7SignedDataBuilderTest, AddSigner) {
  testAddSigner();
}

TEST_F(Pkcs7SignedDataBuilderTest, AddCrl) {
  testAddCrl();
}

TEST_F(Pkcs7SignedDataBuilderTest, DoFinalString) {
  testDoFinalString();
}

TEST_F(Pkcs7SignedDataBuilderTest, DoFinalByteArray) {
  testDoFinalByteArray();
}
