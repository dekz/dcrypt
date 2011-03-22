_bindings = require './build/default/dcrypt'
console.log _bindings
b = new _bindings.Random()
#bindings = new _bindings.Random()
dcrypt = {}

dcrypt.random = {}
dcrypt.random.randomBytes = (len) ->
  buff = new Buffer len
  b.randomBytes buff
  return buff

dcrypt.keypair = {}
dcrypt.keypair.newRSA = (keysize, exponent) ->
  keysize = keysize or 1024
  exponent = exponent or 65537
 # test = bindings.rsa_new_keypair(keysize, exponent)

exports.random = dcrypt.random
exports.keypair = dcrypt.keypair

