#include <libcryptosec/Pkcs7EnvelopedDataBuilder.h>

#include <libcryptosec/KeyPair.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes unitários da classe Pkcs7EnvelopedDataBuilder
 */
class Pkcs7EnvelopedDataBuilderTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    void testDoFinal() {
      Pkcs7EnvelopedDataBuilder builder = Pkcs7EnvelopedDataBuilder(ca, SymmetricKey::AES_256, SymmetricCipher::CBC);

      builder.update(plainText);
      Pkcs7EnvelopedData *data = builder.doFinal();

      std::ostringstream *out = new std::ostringstream;
      data->decrypt(ca, *caKeyPair.getPrivateKey(), out);

      ASSERT_EQ(plainText, out->str());
    }

    void testDoFinalString() {
      Pkcs7EnvelopedDataBuilder builder = Pkcs7EnvelopedDataBuilder(ca, SymmetricKey::AES_256, SymmetricCipher::CBC);

      Pkcs7EnvelopedData *data = builder.doFinal(plainText);

      std::ostringstream *out = new std::ostringstream;
      data->decrypt(ca, *caKeyPair.getPrivateKey(), out);

      ASSERT_EQ(plainText, out->str());
    }

    void testDoFinalByteArray() {
      Pkcs7EnvelopedDataBuilder builder = Pkcs7EnvelopedDataBuilder(ca, SymmetricKey::AES_256, SymmetricCipher::CBC);
      ByteArray ba = ByteArray(plainText);
      
      Pkcs7EnvelopedData *data = builder.doFinal(ba);

      std::ostringstream *out = new std::ostringstream;
      data->decrypt(ca, *caKeyPair.getPrivateKey(), out);

      ASSERT_EQ(plainText, out->str());
    }

    void testInit() {
      Pkcs7EnvelopedDataBuilder builder = Pkcs7EnvelopedDataBuilder(ca, SymmetricKey::AES_256, SymmetricCipher::CBC);
      builder.update(plainText);

      builder.init(coCipher, SymmetricKey::AES_256, SymmetricCipher::CBC);
      builder.update(plainText);

      Pkcs7EnvelopedData *data = builder.doFinal();

      std::ostringstream *out = new std::ostringstream;
      data->decrypt(coCipher, *coCipherKeyPair.getPrivateKey(), out);

      ASSERT_EQ(plainText, out->str());
    }

    void testAddCipher() {
      Pkcs7EnvelopedDataBuilder builder = Pkcs7EnvelopedDataBuilder(ca, SymmetricKey::AES_256, SymmetricCipher::CBC);
      builder.addCipher(coCipher);
      
      Pkcs7EnvelopedData *data = builder.doFinal(plainText);

      std::ostringstream *out = new std::ostringstream;
      data->decrypt(coCipher, *coCipherKeyPair.getPrivateKey(), out);
      
      std::ostringstream *coCipherOut = new std::ostringstream;
      data->decrypt(coCipher, *coCipherKeyPair.getPrivateKey(), coCipherOut);

      ASSERT_EQ(plainText, out->str());
      ASSERT_EQ(plainText, coCipherOut->str());
    }

    static Certificate ca;
    static Certificate coCipher;
    
    static KeyPair caKeyPair;
    static KeyPair coCipherKeyPair;
    
    static std::string caPem;
    static std::string caPrivKeyPem;
    static std::string coCipherPem;
    static std::string coCipherPrivKeyPem;

    static std::string plainText;
};

/*
 * Initialization of variables used in the tests
 */
std::string Pkcs7EnvelopedDataBuilderTest::plainText = "plain text";

std::string Pkcs7EnvelopedDataBuilderTest::caPem = "-----BEGIN CERTIFICATE-----" "\n"
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

std::string Pkcs7EnvelopedDataBuilderTest::caPrivKeyPem = "-----BEGIN PRIVATE KEY-----" "\n"
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

std::string Pkcs7EnvelopedDataBuilderTest::coCipherPem = "-----BEGIN CERTIFICATE-----" "\n"
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

std::string Pkcs7EnvelopedDataBuilderTest::coCipherPrivKeyPem = "-----BEGIN PRIVATE KEY-----" "\n"
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

Certificate Pkcs7EnvelopedDataBuilderTest::ca = Certificate(Pkcs7EnvelopedDataBuilderTest::caPem);
Certificate Pkcs7EnvelopedDataBuilderTest::coCipher = Certificate(Pkcs7EnvelopedDataBuilderTest::coCipherPem);

KeyPair Pkcs7EnvelopedDataBuilderTest::caKeyPair = KeyPair(Pkcs7EnvelopedDataBuilderTest::caPrivKeyPem);
KeyPair Pkcs7EnvelopedDataBuilderTest::coCipherKeyPair = KeyPair(Pkcs7EnvelopedDataBuilderTest::coCipherPrivKeyPem);

TEST_F(Pkcs7EnvelopedDataBuilderTest, DoFinal) {
  testDoFinal();
}

TEST_F(Pkcs7EnvelopedDataBuilderTest, DoFinalString) {
  testDoFinalString();
}

TEST_F(Pkcs7EnvelopedDataBuilderTest, DoFinalByteArray) {
  testDoFinalByteArray();
}

TEST_F(Pkcs7EnvelopedDataBuilderTest, AddCipher) {
  testAddCipher();
}

TEST_F(Pkcs7EnvelopedDataBuilderTest, Init) {
  testInit();
}

