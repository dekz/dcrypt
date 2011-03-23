dcrypt = require '../dcrypt'
sys = require 'sys'
crypto = require 'crypto'
assert = require 'assert'
fs = require 'fs'

console.log "Entering test.coffee"
console.log dcrypt

testRandBytes = ->
  dcrypt.random.randomBytes(16)

#openssl dgst -sha1 -sign priv.pem -out wscript.sha1 wscript; openssl dgst -sha1 -verify pub.pem -signature wscript.sha1 wscript
testHash =  ->
  h = dcrypt.hash.createHash("SHA256")
  h.update('test')
  hash1= h.digest(encoding='hex')

  x = crypto.createHash("SHA256")
  x.update('test')
  hash2 = x.digest(encoding='hex')

  assert.equal hash1, hash2
  console.log "PASS: hash test #{hash1}" 

testSign = ->
  algo = 'RSA-SHA256'
  message = 'this is a test message'
  pub = fs.readFileSync('pub.pem').toString()
  priv = fs.readFileSync('priv.pem').toString()

  nsigner = crypto.createSign algo 
  nsigner.update message
  nsig = nsigner.sign priv, output_format='hex'
  signer = dcrypt.sign.createSign algo 

  signer.update message
  sig = signer.sign priv, output_format='hex'
  assert.equal nsig, sig
  console.log "PASS: Signature test #{sig}"

  nverif = crypto.createVerify algo
  nverif.update message
  npass = nverif.verify(pub, nsig, signature_format='hex')

  dverif = dcrypt.verify.createVerify algo
  dverif.update message
  dpass = dverif.verify(pub, nsig, signature_format='hex')
  assert.equal dpass, true
  #assert.equal true, nverif.verify(pub, nsig, signature_format='hex')



testInteropWithCrypto = ->
  message = 'this is a test message'
  algo = 'RSA-SHA'
  test = dcrypt.keypair.newRSA()
  
  fs.writeFileSync('pub.pem', test.pem_pub)
  fs.writeFileSync('priv.pem', test.pem_priv)
 # test.pem_pub = fs.readFileSync('pub.pem').toString()
 # test.pem_priv = fs.readFileSync('priv.pem').toString()
  #console.log test

  signer = crypto.createSign algo
  signer.update message
  signature = signer.sign(test.pem_priv, output_format='hex')
  console.log "SIGNATURE IS" + signature

  verify = crypto.createVerify algo
  verify.update message
  passed = verify.verify(test.pem_pub, signature, signature_format='hex')
  #assert.equal passed, true


  cipher = crypto.createCipher("RSA", test.pem_pub)
  ciphertext = cipher.update(message, input_encoding='utf8', output_encoding='hex')
  ciphertext += cipher.final(output_encoding='hex')

  decipher = crypto.createDecipher("RSA", test.pem_priv)
  cleartext = decipher.update(ciphertext, input_encoding='hex', output_encoding='utf8')
  cleartext += decipher.final(output_encoding='utf8')
  console.log cleartext


#testInteropWithCrypto()
testHash()
testSign()
testRandBytes()

