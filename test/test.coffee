dcrypt = require '../dcrypt'
sys = require 'sys'
crypto = require 'crypto'
assert = require 'assert'
fs = require 'fs'

console.log "Entering test.coffee"
console.log dcrypt

testRandBytes = (test) ->
  size = 16
  test.expect 3
  r = dcrypt.random.randomBytes size 
  test.equal "object", typeof r
  test.notEqual r, [], 'Random bytes are empty'
  test.equal size, r.length, 'Size does not match expected size'
  test.done()

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
  h = dcrypt.hash.createHash("SHA256")
  h.update('test')
  hash1= h.digest(encoding='hex')

  x = crypto.createHash("SHA256")
  x.update('test')
  hash2 = x.digest(encoding='hex')

  test.deepEqual hash1, hash2, 'Digest Interop failure'
  test.done()

testSign = (test) ->
  algo = 'SHA256'
  message = 'this is a test message'

  keys = dcrypt.keypair.newRSA(1024)
  pub = keys.pem_pub
  priv = keys.pem_priv

  nsigner = crypto.createSign algo
  nsigner.update message
  nsig = nsigner.sign priv, output_format='hex'

  signer = dcrypt.sign.createSign algo
  signer.update message
  sig = signer.sign priv, output_format='hex'
  test.deepEqual nsig, sig, 'RSA Signature Interop failure'

  nverif = crypto.createVerify algo
  nverif.update message
  npass = nverif.verify(pub, nsig, signature_format='hex')

  dverif = dcrypt.verify.createVerify algo
  dverif.update message
  dpass = dverif.verify(pub, nsig, signature_format='hex')
  test.same true, dpass, 'RSA signature should have been verified'

  dverif2 = dcrypt.verify.createVerify algo
  dverif2.update message
  dpass = dverif2.verify(pub, 'bad sig', signature_format='hex')
  test.same false, dpass, 'Signature verification should have failed'

  keys = dcrypt.keypair.newECDSA()
  signer = dcrypt.sign.createSign "SHA1"
  signer.update message
  ecsig = signer.sign keys.pem_priv, output_format='hex'

  ecverif = dcrypt.verify.createVerify "SHA1"
  ecverif.update message
  ecpass = ecverif.verify(keys.pem_pub, ecsig, signature_format='hex') 
  test.same true, ecpass, 'ECDSA signature verification failure'

  ec_bad_verif = dcrypt.verify.createVerify "SHA1"
  ec_bad_verif.update message
  ec_bad_pass = ec_bad_verif.verify(keys.pem_pub, 'fake message', signature_format='hex')
  test.same -1, ec_bad_pass, 'ECDSA signature verification should have failed value was, ' + ec_bad_pass

  test.notDeepEqual sig, ecsig, 'Signatures should not be the same'
  test.done()

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

testRSAEncrypt = (test) ->
  key = dcrypt.keypair.newRSA()
  pub = key.pem_pub
  priv = key.pem_priv
  message = 'test message'

  enc = dcrypt.rsa.encrypt(pub, message, 'RSA_PKCS1_PADDING', 'hex')
  clear_msg = dcrypt.rsa.decrypt(priv, enc, 'RSA_PKCS1_PADDING', 'hex')
  test.deepEqual clear_msg, message, 'RSA with PKCS1 PADDING encryption and decryption failure'
  test.done()

testHMAC = (test) ->
  key = 'test key'
  message = 'message for me and you'
  nhm = crypto.createHmac('sha256', key)
  nhm.update message
  n_msg = nhm.digest('hex')

  dhm = dcrypt.hmac.createHmac('sha256', key)
  dhm.update message
  d_msg = dhm.digest('hex')

  test.deepEqual d_msg, n_msg, 'HMAC Interop equal failure'
  test.done()

testIssue7_ecdsa_sha1 = (test) ->
  keys = dcrypt.keypair.newECDSA()
  s = dcrypt.sign.createSign("SHA1")
  s.update('test message')
  signature = s.sign(keys.pem_priv, output='hex')
  console.log signature

  node_s = crypto.createSign("SHA1")
  node_s.update('test message')
  node_sig = node_s.sign(keys.pem_priv, output='hex')
  console.log node_sig

  v = dcrypt.verify.createVerify("SHA1")
  v.update('test message')
  passed = v.verify(keys.pem_pub, signature, signature_format='hex')
  test.done()

exports.testIssue7_ecdsa_sha1 = testIssue7_ecdsa_sha1
exports.testKeyPairs = testKeyPairs
exports.testRandomBytes = testRandBytes
exports.testHash = testHash
exports.testSign = testSign
exports.testCipher = testCipher
exports.testRSAEncrypt = testRSAEncrypt
exports.testHMAC = testHMAC
