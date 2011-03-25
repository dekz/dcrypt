_bindings = require './build/default/dcrypt'
console.log "Inside dcrypt.coffee"
console.log _bindings

#js bindings to the c++ bindings
Random = _bindings.Random
Hash = _bindings.Hash
Sign = _bindings.Sign
Verify = _bindings.Verify
KeyPair = _bindings.KeyPair
Encode = _bindings.Encode

dcrypt = {}

#random
dcrypt.random = {}
dcrypt.random.randomBytes = (len) ->
  buff = new Buffer len
  rb = new Random()
  rb.randomBytes buff
  return buff

exports.random = dcrypt.random

#keypairs
dcrypt.keypair = {}
dcrypt.keypair.newRSA = (keysize, exponent) ->
  keysize = keysize or 1024
  exponent = exponent or 65537
 # test = bindings.rsa_new_keypair(keysize, exponent)

exports.keypair = dcrypt.keypair

#hash
dcrypt.hash = Hash
exports.hash = {}
exports.hash.createHash = (hash) ->
  return new Hash hash

#sign
dcrypt.sign = Sign
exports.sign = {}
exports.sign.createSign = (algo) ->
  return (new Sign).init algo
 
dcrypt.verify = Verify 
exports.verify= {}
exports.verify.createVerify= (algo) ->
  return (new Verify).init algo

dcrypt.keypair = KeyPair
exports.keypair.newRSA = (size, exp) ->
  size = size || 1024
  exp = exp || 65537
  return (new KeyPair).newRSA(size, exp)

exports.keypair.newECDSA = (curve) ->
  curve = curve || "secp256k1"
  return (new KeyPair).newECDSA(curve)

dcrypt.encode = Encode
exports.encode = {}
exports.encode.encodeBase58 = (data) ->
  return (new Encode).encodeBase58(data)

# TODO something is wrong here, coffee script is crying
# exports.encode.decodeBase58 = (data) ->
#   return (new Encode).decodeBase58(data)
