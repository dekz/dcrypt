_bindings = require './build/default/dcrypt'
console.log "Inside dcrypt.coffee"
console.log _bindings

#js bindings to the c++ bindings
Random = _bindings.Random
Hash = _bindings.Hash
Sign = _bindings.Sign
Verify = _bindings.Verify

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

