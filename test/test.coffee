dcrypt = require '../dcrypt'
sys = require 'sys'
crypto = require 'crypto'
assert = require 'assert'
fs = require 'fs'

console.log dcrypt

#
# Random Byte Generation Tests
#
testRandBytes = (test) ->
  size = 16
  test.expect 3
  r = dcrypt.random.randomBytes size 
  test.equal "object", typeof r
  test.notEqual r, [], 'Random bytes are empty'
  test.equal size, r.length, 'Size does not match expected size'
  test.done()

#
# Keypair Generation Tests
#
testKeyPairs = (test) ->
  test.expect(8)
  test.notDeepEqual(dcrypt.keypair.newRSA(), {}, 'Keypair is empty')
  test.notDeepEqual(dcrypt.keypair.newRSA(1024), {}, 'Keypair is empty')
  test.notDeepEqual(dcrypt.keypair.newRSA(2048, 3), {}, 'Keypair is empty')
  test.throws(dcrypt.keypair.newRSA(2048, 3), 'Creating a bad RSA keypair should throw an error')

  test.notDeepEqual(dcrypt.keypair.newECDSA(), {}, 'Keypair is empty')
  test.notDeepEqual(dcrypt.keypair.newECDSA('prime192v1'), {}, 'Keypair is empty')
  test.notDeepEqual(dcrypt.keypair.newECDSA('prime256v1'), {}, 'Keypair is empty')
  #for some reason nodeunit wont treat test.throws as working with newECDSA with a bad curve
  try
    dcrypt.keypair.newECDSA('1234')
    test.throws(1)
  catch error
    test.ok true
  test.done()

testHash = (test)  ->
  hash1 = dcrypt.hash.createHash('SHA256')
                     .update('test')
                     .digest('hex')

  hash2 = crypto.createHash('SHA256')
                .update('test')
                .digest('hex')

  test.deepEqual hash1, hash2, 'Digest Interop failure'
  test.notDeepEqual hash1, '', 'Digest should not be empty'

  hasher = dcrypt.hash.createHash('SHA256')
  for i in [1..10]
    h2 = hasher.update("test").digest('hex')
    test.deepEqual hash1, h2

  test.done()

testSign = (test) ->
  algo = 'SHA256'
  message = 'this is a test message'

  keys = dcrypt.keypair.newRSA()
  pub = keys.pem_pub
  priv = keys.pem_priv

  nsig = crypto.createSign(algo)
               .update(message)
               .sign(priv, 'hex')

  npass = crypto.createVerify(algo)
                .update(message)
                .verify(pub, nsig, 'hex')

  dpass = dcrypt.verify.createVerify(algo)
                       .update(message)
                       .verify(pub, nsig, 'hex')
  test.same true, dpass, 'RSA signature should have been verified'

  sig = dcrypt.sign.createSign(algo)
                   .update(message)
                   .sign(priv, 'hex')
  test.deepEqual nsig, sig, 'RSA Signature Interop failure'

  dpass = dcrypt.verify.createVerify(algo)
                       .update(message)
                       .verify(pub, 'bad sig', 'hex')
  test.same false, dpass, 'Signature verification should have failed'

  keys = dcrypt.keypair.newECDSA()

  ecsig = dcrypt.sign.createSign('SHA1')
                     .update(message)
                     .sign(keys.pem_priv, 'hex')

  ecpass = dcrypt.verify.createVerify('SHA1')
                        .update(message)
                        .verify(keys.pem_pub, ecsig, 'hex')
  test.same true, ecpass, 'ECDSA signature verification failure'

  ec_bad_pass = dcrypt.verify.createVerify('SHA1')
                             .update(message)
                             .verify(keys.pem_pub, 'fake', 'hex')
  test.same -1, ec_bad_pass, 'ECDSA signature verification should have failed '
  test.notDeepEqual sig, ecsig, 'Signatures should not be the same'
  test.done()


#
# Cipher Tests
#
testCipher = (test) ->
  key = 'Test key here'
  message = 'This is the test message!'
  algo = 'aes-256-cbc'

  cipher = dcrypt.cipher.createCipher(algo, key)
  ct = cipher.update(message, 'utf8', 'hex')
  ct += cipher.final('hex')

  test.notDeepEqual(message, ct)

  ndecipher = crypto.createDecipher(algo, key)
  mt = ndecipher.update(ct, 'hex', 'utf8')
  mt += ndecipher.final('utf8')

  test.deepEqual(mt, message, 'Cipher encrypt and decrypt Interop failure')

  #reuse
  cipher.init(algo, key)
  ct2 = cipher.update(message, 'utf8', 'hex')
  ct2 += cipher.final('hex')

  decipher = dcrypt.decipher.createDecipher(algo, key)
  clear = decipher.update(ct2, 'hex', 'utf8')
  clear += decipher.final('utf8')

  test.deepEqual(clear, message, 'Cipher encrypt and decrypt equal failure')

  test.deepEqual(ct, ct2, 'Reuse of cipher object failure')
  test.done()

#
# RSA Encrypt/Decrypt Tests
#
testRSAEncrypt = (test) ->
  key = dcrypt.keypair.newRSA()
  pub = key.pem_pub
  priv = key.pem_priv
  message = 'test message'

  enc = dcrypt.rsa.encrypt(pub, message, 'RSA_PKCS1_PADDING', 'hex')
  clear_msg = dcrypt.rsa.decrypt(priv, enc, 'RSA_PKCS1_PADDING', 'hex')
  test.deepEqual clear_msg, message, 'RSA with PKCS1 PADDING encryption and decryption failure'
  test.done()

#
# HMAC Tests
#
testHMAC = (test) ->
  key = 'test key'
  message = 'message for me and you'

  n_msg = crypto.createHmac('sha256', key)
                .update(message)
                .digest('hex')

  d_msg = dcrypt.hmac.createHmac('sha256', key)
                     .update(message)
                     .digest('hex')
  test.deepEqual d_msg, n_msg, 'HMAC Interop equal failure'
  test.done()

#
# Issue 7
# Linux failing on ECDSA signatures, versions less than 1.0.0
# Dcrypt would return an empty string as there was a failure on EVP_VerifyFinal
#
testIssue7_ecdsa_sha1 = (test) ->
  keys = dcrypt.keypair.newECDSA()

  signature = dcrypt.sign.createSign('SHA1')
                    .update('test message')
                    .sign(keys.pem_priv, 'hex')

  node_sig = crypto.createSign('SHA1')
                   .update('test message')
                   .sign(keys.pem_priv, 'hex')

  test.notDeepEqual(signature, '', 'ECDSA Signature from Dcrypt should not be empty')
  test.notDeepEqual(node_sig, '', 'ECDSA signature from node_crypto should not be empty')

  passed = dcrypt.verify.createVerify('SHA1')
                        .update('test message')
                        .verify(keys.pem_pub, signature, 'hex')
  test.same true, passed, 'ECDSA Signature should have passed'
  test.done()

#
# KAT Tests
#
#OpenSSL doesn't output a form in which OpenSSL likes to read
testKAT_sign = (test) ->
  #RSA KAT
  rsa_1_signature = fs.readFileSync('test/kat/rsa/message.bin.sha1')
  rsa_1_message = fs.readFileSync('test/kat/rsa/message')
  rsa_1_priv_pem = fs.readFileSync('test/kat/rsa/rsa_priv.pem')
  rsa_1_pub_pem = fs.readFileSync('test/kat/rsa/rsa_pub.pem')
  rsa_1_cert_pem = fs.readFileSync('test/kat/rsa/rsa_cert.pem')

  rsa_1_status = dcrypt.verify.createVerify('RSA-SHA1')
                       .update(rsa_1_message)
                       .verify(rsa_1_cert_pem, rsa_1_signature, 'binary')
  test.same true, rsa_1_status, "RSA KAT test should have passed"

  #EC KAT
  ec_param_1_signature = fs.readFileSync('test/kat/ec/ec_param_1_message.sha1').toString()
  ec_param_1_message = fs.readFileSync('test/kat/ec/ec_param_1_message').toString()
  ec_param_1_priv_pem = fs.readFileSync('test/kat/ec/ec_param_1_priv.pem').toString()
  ec_param_1_pub_pem = fs.readFileSync('test/kat/ec/ec_param_1_pub.pem').toString()

  ec_param_1_verifer = dcrypt.verify.createVerify('SHA1')
  ec_param_1_verifer.update ec_param_1_message
  ec_param_1_status = ec_param_1_verifer.verify(ec_param_1_pub_pem, ec_param_1_signature, 'hex')
  test.same true, ec_param_1_status, "ECDSA KAT test should have been verified"
  console.log ec_param_1_status

  test.done()

#
# Node.js Crypto Tests
#
testNodeCryptoFixtures = (test) ->
  fixtures = 'test/node/fixtures'
  caPem = fs.readFileSync(fixtures + '/test_ca.pem', 'ascii')
  certPem = fs.readFileSync(fixtures + '/test_cert.pem', 'ascii')
  keyPem = fs.readFileSync(fixtures + '/test_key.pem', 'ascii')

  #Signing/Verifying with Cert
   #base 64
  s1 = dcrypt.sign.createSign('RSA-SHA1')
             .update('Test123')
             .sign(keyPem, 'base64')
  verified = dcrypt.verify.createVerify('RSA-SHA1')
                          .update('Test')
                          .update('123')
                          .verify(certPem, s1, 'base64')
  test.same true, verified, 'Node Crypto Signing Test with Cert failed - base64'

   #binary
  s1 = dcrypt.sign.createSign('RSA-SHA1')
             .update('Test123')
             .sign(keyPem, 'binary')
  verified = dcrypt.verify.createVerify('RSA-SHA1')
                          .update('Test')
                          .update('123')
                          .verify(certPem, s1, 'binary')
  test.same true, verified, 'Node Crypto Signing Test with Cert failed - binary'

  a0 = dcrypt.hash.createHash('sha1').update('Test123').digest('hex')
  a1 = dcrypt.hash.createHash('md5').update('Test123').digest('binary')
  a2 = dcrypt.hash.createHash('sha256').update('Test123').digest('base64')
  a3 = dcrypt.hash.createHash('sha512').update('Test123').digest() #binary

  test.deepEqual(a0, '8308651804facb7b9af8ffc53a33a22d6a1c8ac2', 'Test SHA1')
  test.deepEqual(a1, 'h\u00ea\u00cb\u0097\u00d8o\fF!\u00fa+\u000e\u0017\u00ca' +
             '\u00bd\u008c', 'Test MD5 as binary')
  test.deepEqual(a2, '2bX1jws4GYKTlxhloUB09Z66PoJZW+y+hq5R8dnx9l4=',
             'Test SHA256 as base64')
  test.deepEqual(a3, '\u00c1(4\u00f1\u0003\u001fd\u0097!O\'\u00d4C/&Qz\u00d4' +
                 '\u0094\u0015l\u00b8\u008dQ+\u00db\u001d\u00c4\u00b5}\u00b2' +
                 '\u00d6\u0092\u00a3\u00df\u00a2i\u00a1\u009b\n\n*\u000f' +
                 '\u00d7\u00d6\u00a2\u00a8\u0085\u00e3<\u0083\u009c\u0093' +
                 '\u00c2\u0006\u00da0\u00a1\u00879(G\u00ed\'',
             'Test SHA512 as assumed binary')

  #CipherIvs
  plaintext = 'Once more into the breach'
  encryption_key = '0123456789abcd0123456789'
  iv = '12345678'

  cipher = crypto.createCipheriv('des-ede3-cbc', encryption_key, iv)
  ciph = cipher.update(plaintext, 'utf8', 'hex')
  ciph += cipher.final('hex')

  decipher = crypto.createDecipheriv('des-ede3-cbc', encryption_key, iv)
  txt = decipher.update(ciph, 'hex', 'utf8')
  txt += decipher.final('utf8')
  test.deepEqual(txt, plaintext, 'Encryption and decryption with IV should be equal')

  test.done()

#
# X509 tests
#
testx509 = (test) ->
  fixtures = 'test/node/fixtures'
  caPem = fs.readFileSync(fixtures + '/test_ca.pem', 'ascii')
  certPem = fs.readFileSync(fixtures + '/test_cert.pem', 'ascii')
  keyPem = fs.readFileSync(fixtures + '/test_key.pem', 'ascii')
  cert =  dcrypt.x509.parse(certPem)
  test.notDeepEqual cert, {}, 'x509 should not be empty'
  test.notDeepEqual cert.subject, '', 'x509 Subject should not be empty'
  test.notDeepEqual cert.serial, '', 'x509 serial should not be empty'
  test.notDeepEqual cert.issuer, '', 'x509 issuer should not be empty'
  test.notDeepEqual cert.public_key_algo, '', 'x509 public key algoirthm should not be empty'
  test.notDeepEqual cert.signature, '', 'x509 signature should not be empty'
  test.deepEqual cert.signature_algorithm, 'sha1WithRSAEncryption', 'This x509 certificate should have sha1WithRSAEncr'
  test.deepEqual cert.public_key_algo, 'rsaEncryption', 'This x509 certificate should have rsaEncryption'
  console.log cert

  dsa_pcaPem = fs.readFileSync(fixtures + '/dsa-pca.pem', 'ascii')
  dsa_cert = dcrypt.x509.parse(dsa_pcaPem)
  console.log dsa_cert

  cert = dcrypt.x509.createCert()
  console.log cert
  console.log dcrypt.x509.parse(cert)

  test.done()





#
# Exports
#
#exports.testKAT_sign = testKAT_sign
exports.testx509 = testx509
exports.testNodeCryptoFixtures = testNodeCryptoFixtures
exports.testIssue7_ecdsa_sha1 = testIssue7_ecdsa_sha1
exports.testKeyPairs = testKeyPairs
exports.testRandomBytes = testRandBytes
exports.testHash = testHash
exports.testSign = testSign
exports.testCipher = testCipher
exports.testRSAEncrypt = testRSAEncrypt
exports.testHMAC = testHMAC
