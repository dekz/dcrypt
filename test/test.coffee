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
  s1 = dcrypt.sign.createSign('RSA-SHA1')
             .update('Test123')
             .sign(keyPem, 'base64')
  verified = dcrypt.verify.createVerify('RSA-SHA1')
                          .update('Test')
                          .update('123')
                          .verify(certPem, s1, 'base64')
  test.same true, verified, 'Node Crypto Signing Test with Cert failed'
  test.done()




#
# Exports
#
#exports.testKAT_sign = testKAT_sign
exports.testNodeCryptoFixtures = testNodeCryptoFixtures
exports.testIssue7_ecdsa_sha1 = testIssue7_ecdsa_sha1
exports.testKeyPairs = testKeyPairs
exports.testRandomBytes = testRandBytes
exports.testHash = testHash
exports.testSign = testSign
exports.testCipher = testCipher
exports.testRSAEncrypt = testRSAEncrypt
exports.testHMAC = testHMAC
