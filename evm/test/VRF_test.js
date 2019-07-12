import { assertBigNum } from './support/matchers'
import { bigNum, deploy, toHex } from './support/helpers'
import { pubToAddress, keccak256 } from 'ethereumjs-util'

// Group elements are {(x,y) in GF(fieldSize)^2 | y^2=x^3+3}, where
// GF(fieldSize) is arithmetic modulo fieldSize on {0, 1, ..., fieldSize-1}
const fieldSize = bigNum(
  '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F'
)
const groupOrder = bigNum(
  // Number of elements in the set {(x,y) in GF(fieldSize)^2 | y^2=x^3+3}
  '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'
)
const generator = [
  '0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798',
  '0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8'
].map(bigNum) // Point in EC group
const twiceGenerator = [
  // '>>>' means "computed in python"
  // >>> import py_ecc.secp256k1.secp256k1 as s
  // >>> print("'0x%x',\n'0x%x'" % tuple(s.multiply(s.G, 2)))
  '0XC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5',
  '0X1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A'
].map(bigNum)
const thriceGenerator = [
  '0XF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9',
  '0X388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672'
].map(bigNum)
const eightTimesGenerator = [
  '0X2F01E5E15CCA351DAFF3843FB70F3C2F0A1BDD05E5AF888A67784EF3E10A2A01',
  '0X5C4DA8A741539949293D082A132D13B4C2E213D6BA5B7617B5DA2CB76CBDE904'
].map(bigNum)
const nineTimesGenerator = [
  '0XACD484E2F0C7F65309AD178A9F559ABDE09796974C57E714C35F110DFC27CCBE',
  '0XCC338921B0A7D9FD64380971763B61E9ADD888A4375F8E0F05CC262AC64F9C37'
].map(bigNum)
const seventeenTimesGenerator = [
  '0XDEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34',
  '0X4211AB0694635168E997B0EAD2A93DAECED1F4A04A95C0F6CFB199F69E56EB77'
].map(bigNum)

const gFPNeg = n => fieldSize.sub(bigNum(n)) // Additive inverse in field
const minusGenerator = [1, gFPNeg(2)].map(bigNum) // (1,-2)
const big1 = bigNum(1)
const big2 = bigNum(2)
const big3 = bigNum(3)

const assertPointsEqual = (x, y) => {
  assertBigNum(x[0], y[0])
  assertBigNum(x[1], y[1])
}

// Returns the EIP55-capitalized ethereum address for this secp256k1 public key
const toAddress = k => {
  return pubToAddress(Buffer.concat(k.map(v => v.toBuffer()))).toString('hex')
}

contract('VRF', () => {
  let VRF
  beforeEach(async () => {
    VRF = await deploy('VRF.sol')
  })
  it('Accurately calculates simple and obvious bigModExp test inputs', async () => {
    const rawExp = 3 ** 2 // Appease prettier but clarify operator precedence
    assertBigNum(await VRF.bigModExp(3, 2, 5), rawExp % 5)
  })
  it('accurately calculates the sum of g and 2g (i.e., 3g)', async () => {
    const projectiveResult = await VRF.projectiveECAdd(
      generator[0],
      generator[1],
      twiceGenerator[0],
      twiceGenerator[1]
    )
    const zInv = projectiveResult.z3.invm(fieldSize)
    const affineResult = await VRF.affineECAdd(generator, twiceGenerator, zInv)
    assertPointsEqual(thriceGenerator, affineResult)
  })
  it('Accurately verifies multiplication of a point by a scalar', async () => {
    assert(await VRF.ecmulVerify(generator, 2, twiceGenerator))
  })
  it('Can compute square roots', async () => {
    assertBigNum(2, await VRF.squareRoot(4), '4=2^2') // 4**((fieldSize-1)/2)
  })
  it('Can compute the square of the y ordinate given the x ordinate', async () => {
    assertBigNum(8, await VRF.ySquared(1), '8=1^3+7')
  })
  it('Hashes to the curve with the same results as the golang code', async () => {
    let result = await VRF.hashToCurve(generator, 0)
    assertBigNum(
      bigNum(result[0])
        .pow(big3)
        .add(bigNum(7))
        .umod(fieldSize),
      bigNum(result[1])
        .pow(big2)
        .umod(fieldSize),
      'y^2=x^3+7'
    )
    /*
    // See golang code XXX: When it's written and this test duplicated there
    result = await VRF.hashToCurve(generator, 5)
    assertBigNum(
      result[0],
      '0x247154f2ce523897365341b03669e1061049e801e8750ae708e1cb02f36cb225',
      'mismatch with output from services/vrf/vrf_test.go/TestVRF_HashToCurve'
    )
    assertBigNum(
      result[1],
      '0x16e1157d5b94324127e094abe222a05a5c47be3124254a6aa047d5e1f2d864ea',
      'mismatch with output from services/vrf/vrf_test.go/TestVRF_HashToCurve'
    )
    */
  })
  it('Correctly verifies linear combinations with generator', async () => {
    assert(
      await VRF.verifyLinearCombinationWithGenerator(
        5,
        twiceGenerator,
        7,
        toAddress(seventeenTimesGenerator)
      ),
      '5*(2*g)+7*g=17*g?'
    )
  })
  it('Correctly computes full linear combinations', async () => {
    const projSum = await VRF.projectiveECAdd(
      eightTimesGenerator[0],
      eightTimesGenerator[1],
      nineTimesGenerator[0],
      nineTimesGenerator[1]
    )
    const zInv = projSum[2].invm(fieldSize)
    assertPointsEqual(
      seventeenTimesGenerator,
      await VRF.linearCombination(
        4,
        twiceGenerator,
        eightTimesGenerator,
        3,
        thriceGenerator,
        nineTimesGenerator,
        zInv
      ),
      '4*(2*g)+3*(3*g)=17*g?'
    )
  })

  it('Computes the same hashed scalar from curve points as the golang code', async () => {
    const scalar = await VRF.scalarFromCurve(
      generator,
      twiceGenerator,
      thriceGenerator,
      toAddress(eightTimesGenerator),
      nineTimesGenerator
    )
    // assertBigNum( // XXX: Fix this, when the golang side is implelmented
    //   '0x57bf013147ceec913f17ef97d3bcfad8315d99752af81f8913ad1c88493e669',
    //   ,scalar,
    //   'mismatch with output from services/vrf/vrf_test.go/TestVRF_ScalarFromCurve'
    // )
  })
  it('Knows a good VRF proof from bad', async () => {
    const x = big1 // secret key in Goldberg's notation
    const pk = generator
    const seed = 0
    const hash = await VRF.hashToCurve(pk, seed)
    const gamma = hash // Since gamma = x * hash = hash
    const k = big1 // "Random" nonce, ha ha
    const u = generator // Since u = k * generator = generator
    const v = hash // Since v = k * hash = hash
    const c = await VRF.scalarFromCurve(hash, pk, gamma, toAddress(u), v)
    const s = k.sub(c.mul(x)).umod(groupOrder) // s = k - c * x mod group size
    const cGamma = [
      // >>> print("'0x%x',\n'0x%x'" % tuple(s.multiply(gamma, c)))
      '0X69973B54053B4D15753DA1B2B8CF62858DAC15B826B5290E96A7FC08B6FE4AA3',
      '0XACA05881C0CC131C346D04EA3189B95ADD4A11F3DA51E3497632F75B3D49420'
    ].map(bigNum)
    const sHash = [
      // >>> print("'0x%x',\n'0x%x'" % tuple(s.multiply(hash, signature)))
      '0X62875784ACED01B7A54537D3F071575AA859348BDBC6623B293AB4DC541F9AFB',
      '0XC78ABDC7D06D7045CC100DBD32DC1D854EA712A91F288A77A0F72497810168CF'
    ].map(bigNum)
    const projSum = await VRF.projectiveECAdd(
      cGamma[0],
      cGamma[1],
      sHash[0],
      sHash[1]
    )
    const zInv = projSum[2].invm(fieldSize)
    const checkOutput = async o =>
      VRF.isValidVRFOutput(
        pk,
        gamma,
        c,
        s,
        seed,
        toAddress(u),
        cGamma,
        sHash,
        zInv,
        o
      )
    assert(!(await checkOutput(0)), 'accepted a bad proof')
    const bOutput = keccak256(Buffer.concat(gamma.map(v => v.toBuffer())))
    const output = bigNum('0x' + bOutput.toString('hex'))
    assert(await checkOutput(output), 'rejected good proof')
  })
})
