_bindings = require './build/default/dcrypt'

#OpenSSL bindings for Node.js. This module extends what is in node-crypto bringing much needed additional functionality.
Random = _bindings.Random
Hash = _bindings.Hash
Sign = _bindings.Sign
Verify = _bindings.Verify
KeyPair = _bindings.KeyPair
Encode = _bindings.Encode
Cipher = _bindings.Cipher
Decipher = _bindings.Decipher
Rsa = _bindings.Rsa
Hmac = _bindings.Hmac
X509 = _bindings.X509

dcrypt = {}

##Random
#Given a length, randomBytes returns a buffer full of random data. 
dcrypt.random = {}
dcrypt.random.randomBytes = (len) ->
  len = len or 16
  buff = new Buffer len
  rb = new Random()
  rb.randomBytes buff
  return buff

exports.random = dcrypt.random

##Hash
#Create a hash object to digest some messages. Call hash.update(msg) to continually digest new data and hash.final(encoding_type) to receive the final digested message.
dcrypt.hash = Hash
exports.hash = {}
exports.hash.createHash = (hash) ->
  return new Hash hash

##Sign
#Sign a message with a private key. This message can then be verified as coming from that private key with a corresponding public key. This object can take and PKI algorithm type, such as ECDSA and RSA. 
dcrypt.sign = Sign
exports.sign = {}
exports.sign.createSign = (algo) ->
  return (new Sign).init algo

##Verify
#Use verify to verify a signed message came from the associated private key. Verify.final can take either a PEM encoded certificate or a PEM encoded public key. Result of Verify.final is a boolean as to whether it passed or not. 
dcrypt.verify = Verify
exports.verify= {}
exports.verify.createVerify= (algo) ->
  return (new Verify).init algo

##Key Pairs
dcrypt.keypair = KeyPair
exports.keypair = {}
# newRSA takes a size in bytes of the key, as well as a exponent size. Both these arguments are optional and default to 1024 for key and 65537 for exponent by default
exports.keypair.newRSA = (size, exp) ->
  size = size || 1024
  exp = exp || 65537
  return (new KeyPair).newRSA(size, exp)

# newECDSA creates a new ecdsa key pair, if no curve is supplied it uses "secp256k1" as default
exports.keypair.newECDSA = (curve) ->
  curve = curve or "secp256k1"
  return (new KeyPair).newECDSA(curve)

# parseECDSA parses the raw ECDSA parameters from a PEM file's contents
exports.keypair.parseECDSA = (filename, public) ->
  return (new KeyPair).parseECDSA(filename, public)

# parseRSA parses the raw RSA parameters from a PEM file's contents
exports.keypair.parseRSA = (filename, public) ->
  return (new KeyPair).parseRSA(filename, public)

dcrypt.encode = Encode
exports.encode = {}
exports.encode.encodeBase58 = (data) ->
  return (new Encode).encodeBase58(data)

exports.encode.decodeBase58 = (data) ->
  return (new Encode).decodeBase58(data)

##Cipher
dcrypt.cipher = Cipher
exports.cipher = {}
exports.cipher.createCipher = (cipher, key) ->
  return (new Cipher).init(cipher, key)

exports.cipher.createCipheriv = (cipher, key, iv) ->
  return (new Cipher).initiv(cipher, key, iv)

dcrypt.decipher = Decipher
exports.decipher = {}
exports.decipher.createDecipher = (cipher, key) ->
  return (new Decipher).init(cipher, key)

exports.cipher.createDecipheriv = (cipher, key, iv) ->
  return (new Decipher).initiv(cipher, key, iv)

##RSA
#Encrypt a message with a RSA public key and decrypt it with the associated private key. Public key can either be in PEM key format or a PEM certificate. If no padding is chosen PKCS1 padding will be used. If no output encoding is supplied, hex is used.
dcrypt.rsa = Rsa 
exports.rsa = {}
exports.rsa.encrypt = (pem_pub, msg, padding, out_encoding) ->
  out_encoding = out_encoding or 'hex'
  padding = padding or 'RSA_PKCS1_PADDING'
  return (new Rsa).encrypt(pem_pub, msg, padding, out_encoding)

exports.rsa.decrypt = (pem_priv, enc_msg, padding, in_encoding) ->
  out_encoding = out_encoding or 'hex'
  padding = padding or 'RSA_PKCS1_PADDING'
  return (new Rsa).decrypt(pem_priv, enc_msg, padding, in_encoding)

##HMAC
dcrypt.hmac = Hmac
exports.hmac = {}
exports.hmac.createHmac = (hmac, key) ->
  return (new Hmac).init(hmac, key)

##X509
dcrypt.x509 = X509
exports.x509 = {}
exports.x509.parse = (cert) ->
  return (new X509).parse(cert)
exports.x509.createCert = (args) ->
  return (new X509).createCert(args)
