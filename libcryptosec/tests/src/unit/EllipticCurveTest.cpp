#include <libcryptosec/ec/EllipticCurve.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes unitários da classe EllipticCurve
 */
class EllipticCurveTest : public ::testing::Test {

protected:
    virtual void SetUp() {
      curve = new EllipticCurve();
    }

    virtual void TearDown() {
      free(curve);
    }

    // not implemented
    void testByteArrayConstructor() {
      ByteArray ba;
      EllipticCurve ec(ba);
    }

    // not implemented
    void testPemConstructor() {
      EllipticCurve ec(a);
    }

    void testName() {
      curve->setName(name);

      ASSERT_EQ(curve->getName(), name);
    }

    void testOid() {
      curve->setOid(oid);

      ASSERT_EQ(curve->getOid(), oid);
    }

    void testHexA() {
      curve->setA(a);

      ASSERT_EQ(curve->getA().toHex(), a);
    }

    void testBigIntA() {
      BigInteger bi;
      bi.setHexValue(a);

      curve->setA(bi);

      ASSERT_EQ(curve->getA().toHex(), a);
    }

    void testHexB() {
      curve->setB(b);

      ASSERT_EQ(curve->getB().toHex(), b);
    }

    void testBigIntB() {
      BigInteger bi;
      bi.setHexValue(b);

      curve->setB(bi);

      ASSERT_EQ(curve->getB().toHex(), b);
    }

    void testHexP() {
      curve->setP(p);

      ASSERT_EQ(curve->getP().toHex(), p);
    }

    void testBigIntP() {
      BigInteger bi;
      bi.setHexValue(p);

      curve->setP(bi);

      ASSERT_EQ(curve->getP().toHex(), p);
    }

    void testHexX() {
      curve->setX(x);

      ASSERT_EQ(curve->getX().toHex(), x);
    }

    void testBigIntX() {
      BigInteger bi;
      bi.setHexValue(x);

      curve->setX(bi);

      ASSERT_EQ(curve->getX().toHex(), x);
    }

    void testHexY() {
      curve->setY(y);

      ASSERT_EQ(curve->getY().toHex(), y);
    }

    void testBigIntY() {
      BigInteger bi;
      bi.setHexValue(y);

      curve->setY(bi);

      ASSERT_EQ(curve->getY().toHex(), y);
    }

    void testHexOrder() {
      curve->setOrder(order);

      ASSERT_EQ(curve->getOrder().toHex(), order);
    }

    void testBigIntOrder() {
      BigInteger bi;
      bi.setHexValue(order);

      curve->setOrder(bi);

      ASSERT_EQ(curve->getOrder().toHex(), order);
    }

    void testHexCofactor() {
      curve->setCofactor(cofactor);

      ASSERT_EQ(curve->getCofactor().toDec(), cofactor);
    }

    void testBigIntCofactor() {
      BigInteger bi;
      bi.setHexValue(cofactor);

      curve->setCofactor(bi);

      ASSERT_EQ(curve->getCofactor().toDec(), cofactor);
    }

    void testBigNumA() {
      BigInteger bi;
      const BIGNUM *bn;

      curve->setA(a);
      bn = curve->BN_a();
      bi = BigInteger(bn);

      ASSERT_EQ(bi.toHex(), a);
    }

    void testBigNumB() {
      BigInteger bi;
      const BIGNUM *bn;

      curve->setB(b);
      bn = curve->BN_b();
      bi = BigInteger(bn);

      ASSERT_EQ(bi.toHex(), b);
    }

    void testBigNumP() {
      BigInteger bi;
      const BIGNUM *bn;

      curve->setP(p);
      bn = curve->BN_p();
      bi = BigInteger(bn);

      ASSERT_EQ(bi.toHex(), p);
    }

    void testBigNumX() {
      BigInteger bi;
      const BIGNUM *bn;

      curve->setX(x);
      bn = curve->BN_x();
      bi = BigInteger(bn);

      ASSERT_EQ(bi.toHex(), x);
    }

    void testBigNumY() {
      BigInteger bi;
      const BIGNUM *bn;

      curve->setY(y);
      bn = curve->BN_y();
      bi = BigInteger(bn);

      ASSERT_EQ(bi.toHex(), y);
    }

    void testBigNumOrder() {
      BigInteger bi;
      const BIGNUM *bn;

      curve->setOrder(order);
      bn = curve->BN_order();
      bi = BigInteger(bn);

      ASSERT_EQ(bi.toHex(), order);
    }

    void testBigNumCofactor() {
      BigInteger bi;
      const BIGNUM *bn;

      curve->setCofactor(cofactor);
      bn = curve->BN_cofactor();
      bi = BigInteger(bn);

      ASSERT_EQ(bi.toDec(), cofactor);
    }

    EllipticCurve *curve;

    static std::string oid;
    static std::string name;
    static std::string a;
    static std::string b;
    static std::string p;
    static std::string x;
    static std::string y;
    static std::string order;
    static std::string cofactor;
};

/*
 * Initialization of variables used in the tests
 */
std::string EllipticCurveTest::oid = "1.3.36.3.3.2.8.1.1.1";
std::string EllipticCurveTest::name = "brainpoolP160r1";
std::string EllipticCurveTest::a = "340E7BE2A280EB74E2BE61BADA745D97E8F7C300";
std::string EllipticCurveTest::b = "1E589A8595423412134FAA2DBDEC95C8D8675E58";
std::string EllipticCurveTest::p = "E95E4A5F737059DC60DFC7AD95B3D8139515620F";
std::string EllipticCurveTest::x = "BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3";
std::string EllipticCurveTest::y = "1667CB477A1A8EC338F94741669C976316DA6321";
std::string EllipticCurveTest::order = "E95E4A5F737059DC60DF5991D45029409E60FC09";
std::string EllipticCurveTest::cofactor = "1";

TEST_F(EllipticCurveTest, ByteArrayConstructor) {
  testByteArrayConstructor();
}

TEST_F(EllipticCurveTest, PemConstructor) {
  testPemConstructor();
}

TEST_F(EllipticCurveTest, Name) {
  testName();
}

TEST_F(EllipticCurveTest, Oid) {
  testOid();
}

TEST_F(EllipticCurveTest, HexA) {
  testHexA();
}

TEST_F(EllipticCurveTest, BigIntA) {
  testBigIntA();
}

TEST_F(EllipticCurveTest, HexB) {
  testHexB();
}

TEST_F(EllipticCurveTest, BigIntB) {
  testBigIntB();
}

TEST_F(EllipticCurveTest, HexP) {
  testHexP();
}

TEST_F(EllipticCurveTest, BigIntP) {
  testBigIntP();
}

TEST_F(EllipticCurveTest, HexX) {
  testHexX();
}

TEST_F(EllipticCurveTest, BigIntX) {
  testBigIntX();
}

TEST_F(EllipticCurveTest, HexY) {
  testHexY();
}

TEST_F(EllipticCurveTest, BigIntY) {
  testBigIntY();
}

TEST_F(EllipticCurveTest, HexOrder) {
  testHexOrder();
}

TEST_F(EllipticCurveTest, BigIntOrder) {
  testBigIntOrder();
}

TEST_F(EllipticCurveTest, HexCofactor) {
  testHexCofactor();
}

TEST_F(EllipticCurveTest, BigIntCofactor) {
  testBigIntCofactor();
}

TEST_F(EllipticCurveTest, BigNumA) {
  testBigNumA();
}

TEST_F(EllipticCurveTest, BigNumB) {
  testBigNumB();
}

TEST_F(EllipticCurveTest, BigNumP) {
  testBigNumP();
}

TEST_F(EllipticCurveTest, BigNumX) {
  testBigNumX();
}

TEST_F(EllipticCurveTest, BigNumY) {
  testBigNumY();
}

TEST_F(EllipticCurveTest, BigNumOrder) {
  testBigNumOrder();
}

TEST_F(EllipticCurveTest, BigNumCofactor) {
  testBigNumCofactor();
}
