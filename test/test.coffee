dcrypt = require '../dcrypt'
sys = require 'sys'
crypto = require 'crypto'
assert = require 'assert'
fs = require 'fs'

console.log "Entering test.coffee"
console.log dcrypt

testRandBytes = ->
  dcrypt.random.randomBytes(16)

testKeyPairs = ->
  rsa = dcrypt.keypair.newRSA()
  ecdsa = dcrypt.keypair.newECDSA()

testHash =  ->
  h = dcrypt.hash.createHash("SHA256")
  h.update('test')
  hash1= h.digest(encoding='hex')

  x = crypto.createHash("SHA256")
  x.update('test')
  hash2 = x.digest(encoding='hex')

  assert.equal hash1, hash2
  console.log "PASS: hash test"

testSign = ->
  algo = 'SHA256'
  message = 'this is a test message'
  pub = fs.readFileSync('pub.pem').toString()
  priv = fs.readFileSync('priv.pem').toString()
  keys = dcrypt.keypair.newRSA(1024)
  pub = keys.pem_pub.toString()
  priv = keys.pem_priv.toString()

  nsigner = crypto.createSign algo
  nsigner.update message
  nsig = nsigner.sign priv, output_format='hex'

  signer = dcrypt.sign.createSign algo
  signer.update message
  sig = signer.sign priv, output_format='hex'
  assert.equal nsig, sig

  nverif = crypto.createVerify algo
  nverif.update message
  npass = nverif.verify(pub, nsig, signature_format='hex')
  dverif = dcrypt.verify.createVerify algo
  dverif.update message
  dpass = dverif.verify(pub, nsig, signature_format='hex')
  #wont pass as the pub key has to be in x509, not jsut a pub key
  assert.equal dpass, true

  dverif2 = dcrypt.verify.createVerify algo
  dverif2.update message
  dpass = dverif2.verify(pub, 'bad sig', signature_format='hex')
  assert.equal dpass, false

  keys = dcrypt.keypair.newECDSA()
  signer = dcrypt.sign.createSign "SHA1"
  signer.update message
  ecsig = signer.sign keys.pem_priv, output_format='hex'

  ecverif = dcrypt.verify.createVerify "SHA1"
  ecverif.update message
  ecpass = ecverif.verify(keys.pem_pub, ecsig, signature_format='hex') 
  assert.equal ecpass, true

  assert.notEqual sig, ecsig
  console.log "PASS: Signature test"

testKeyPairs()
testHash()
testSign()
testRandBytes()

