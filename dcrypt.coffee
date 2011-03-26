_bindings = require './build/default/dcrypt'

Random = _bindings.Random
Hash = _bindings.Hash
Sign = _bindings.Sign
Verify = _bindings.Verify
KeyPair = _bindings.KeyPair
Encode = _bindings.Encode

dcrypt = {}

##Random
dcrypt.random = {}
dcrypt.random.randomBytes = (len) ->
  len = len or 16
  buff = new Buffer len
  rb = new Random()
  rb.randomBytes buff
  return buff

exports.random = dcrypt.random

##Hash
dcrypt.hash = Hash
exports.hash = {}
exports.hash.createHash = (hash) ->
  return new Hash hash

##Sign
dcrypt.sign = Sign
exports.sign = {}
exports.sign.createSign = (algo) ->
  return (new Sign).init algo
 
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

dcrypt.encode = Encode
exports.encode = {}
exports.encode.encodeBase58 = (data) ->
  return (new Encode).encodeBase58(data)

exports.encode.decodeBase58 = (data) ->
  return (new Encode).decodeBase58(data)
