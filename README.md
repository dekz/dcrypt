                                                                 
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
* RSA/ECDSA key primitives from parsing key files
* Random Bytes
* Signing and verification using PEM encoded keys, not just certificates
* Random bytes using openssl RAND
* Hashing
* Encryption and Decryption with all Ciphers supported in OpenSSL, as well as RSA encryption and decryption
* x509 Certificate Reading

Install
-------
    npm install dcrypt


Usage
-----
Create a buffer holding 16 bytes of random data:

    buffer = dcrypt.random.randomBytes(16)
    >> <Buffer 46 65 82 15 c9 db 20 2d ea 2c fc 4c a2 0b 62 6a>

Create a new RSA Key Pair - no params is 1024 bytes and 65537 exponent default

    rsa = new dcrypt.keypair.newRSA(1024, 65537)
    >> { pem_pub: '-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAL3oiAw++hlc1Fo5hgph7uzawpP7H394VrL/UQ5eX96dSD+xznd4HHBH\niv1ev8g7xIdsSCWa2xQ8xsSMiUawWiOp3ioC35xLWzmLthDxY9+WPVSE6XNCODda\njlJ8xmQdoKKy2y1Hd5407SDXiLoBelpx5xgMIA7qLBUX1UmYGxchAgMBAAE=\n-----END RSA PUBLIC KEY-----',
    ...

Create a new ECDSA Key Pair - no params is default secp256k1 curve

    ecdsa = new dcrypt.keypair.newECDSA('secp256k1')
    >> { pem_pub: '-----BEGIN PUBLIC KEY-----\nMIH1MIGuBgcqhkjOPQIBMIGiAgEBMCwGByqGSM49AQECIQD/////////////////\n///////////////////+///8LzAGBAEABAEHBEEEeb5mfvncu6xVoGKVzocLBwKb\n/NstzijZWfKBWxb4F5hIOtp3JqPEZV2k+/wOEQio/Re0SKaFVBmcR9CP+xDUuAIh\nAP////////////////////66rtzmr0igO7/SXozQNkFBAgEBA0IABEi6/jVsROmi\nZGQPulg4uW4//uru4oMtEt5O7KrAtvlGd9cRcCB2CO6DM98hz3QSRvmqa5hl4P1N\nV4+C0CUFDLI=\n-----END PUBLIC KEY-----'
    ...

Verify a signature with just a public key in PEM format

    verified = verifer.verify(pem_public, signature, signature_format='hex')
    >> true

Encrypt and Decrypt with RSA

    enc = dcrypt.rsa.encrypt(pub, 'Hi there RSA', 'RSA_PKCS1_PADDING', 'hex')
    clear_msg = dcrypt.rsa.decrypt(priv, enc, 'RSA_PKCS1_PADDING', 'hex')
    >> 'Hi there RSA'
    
Encrypt a message with AES and a phrase

    cipher = dcrypt.cipher.createCipher('AES-256-cbc', 'This is a key')
    ciphertext = cipher.update('Hello there', 'utf8', 'hex')
    ciphertext += cipher.final('hex')

Decrypt a message with AES and a phrase

    decipher = dcrypt.decipher.createDecipher('AES-256-cbc', 'This is a key')
    cleartext = cipher.update(ciphertext, 'hex', 'utf8')
    cleartext += cipher.final('utf8')
    >> 'Hello there'

Parse a RSA private key file and generate primitives

    keypair.parseRSA(fs.readFileSync('/path/to/rsa.priv'), false)
    >> { pub:
         { n: 'BA5570689BDA43E4DBCE11DD9F33251C0B0E19B52D1B5BB6AEEA6C9EA09543BCC0ACC0DEAF1E416DB2B6E466A6C063FEE2DB7914EFD2B02765999D0D7AED119392AD65CD994195DE7D92B241CA588508BAFA12819F4037F6C7F71E77D2D66B2B9ECE9D2502AB65AB3C5B5D27613F9CA7E067C4496B9B881A62FACC6F68494341',
           e: '010001' }, ...

Parse an x509 certificate

    certPem = fs.readFileSync('test_cert.pem', 'ascii')
    cert = dcrypt.x509.parse(certPem)
    >>  { subject: '/C=UK/ST=Acknack Ltd/L=Rhys Jones/O=node.js/OU=Test TLS Certificate/CN=localhost',
        issuer: '/C=UK/ST=Acknack Ltd/L=Rhys Jones/O=node.js/OU=Test TLS Certificate/CN=localhost',
        version: 3,
        serial: 'a2:f4:50:6f:a6:46:44:8f',
        valid_from: 'Nov 11 09:52:22 2009 GMT',
        valid_to: 'Nov  6 09:52:22 2029 GMT',
        public_key_algo: 'rsaEncryption',
        signature_algorithm: 'sha1WithRSAEncryption', ...
 
TODO
----
* Finish porting HMAC
* x509 certificates
* CSR

Configure Options
-----
Build without ECDSA bindings
    node-waf configure --without-ecdsa=true

INFO
-----
Use OpenSSL 1.0.0
