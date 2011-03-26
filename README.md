                                                                 
           _|                                            _|      
       _|_|_|    _|_|_|  _|  _|_|  _|    _|  _|_|_|    _|_|_|_|  
     _|    _|  _|        _|_|      _|    _|  _|    _|    _|      
     _|    _|  _|        _|        _|    _|  _|    _|    _|      
       _|_|_|    _|_|_|  _|          _|_|_|  _|_|_|        _|_|  
                                         _|  _|                  
                                       _|_|    _|                  




dcrypt
=======

Openssl bindings for Node.js. Written in Coffeescript.

* RSA/ECDSA key generation
* Signing and verification using PEM keys, not only certificates
* Random bytes using openssl RAND


Usage
-----
Create a buffer holding 16 bytes of random data:
    buffer = dcrypt.random.randomBytes(16)

Create a new RSA Key Pair - no params is 1024 bytes and 65537 exponent default
    rsa = new dcrypt.keypair.newRSA(1024, 65537)

Create a new ECDSA Key Pair - no params is default secp256k1 curve
    ecdsa = new dcrypt.keypair.newECDSA('secp256k1')

Verify a signature with just a public key in PEM format
    verified = verifer.verify(pem_public, signature, signature_format='hex')
    
 
TODO
----
* x509 certificates
* CSR
