#include "keypair.h"

Persistent<FunctionTemplate> KeyPair::constructor;

void KeyPair::Initialize(Handle<Object> target) {
  HandleScope scope;

  constructor = Persistent<FunctionTemplate>::New(FunctionTemplate::New(KeyPair::New));
  constructor->InstanceTemplate()->SetInternalFieldCount(1);
  constructor->SetClassName(String::NewSymbol("KeyPair"));

  NODE_SET_PROTOTYPE_METHOD(constructor, "newRSA", New_RSA_KeyPair);
  NODE_SET_PROTOTYPE_METHOD(constructor, "newECDSA", New_ECDSA_KeyPair);
  Local<ObjectTemplate> proto = constructor->PrototypeTemplate();

  target->Set(String::NewSymbol("KeyPair"), constructor->GetFunction());
}

Handle<Value> KeyPair::New(const Arguments &args) {
  HandleScope scope;

  KeyPair *kp = new KeyPair();
  kp->Wrap(args.This());

  return args.This();
}

Handle<Value> KeyPair::New_RSA_KeyPair(const Arguments &args) {
    /*
   * BIGNUM *n //public modulus
   *        *e //public exponent
   *        *d //private exponent
   *        *p //secret prime factor
   *        *q //secret prime factor
   *        *dmp1 // d mod (p-1)
   *        *dmq1 // d mod (q-1)
   *        *iqmp // q^-1 mod p
   */
  HandleScope scope;
  uint size = args[0]->ToNumber()->Value();
  uint exp = args[1]->ToNumber()->Value();
  //prevent infinite loop if number is even
  if (exp % 2 == 0) {
    return ThrowException(Exception::Error(String::New("Number must be odd")));
  }
  RSA* rsa = RSA_generate_key(size, exp, NULL, NULL);
  if (!rsa) {
    return ThrowException(Exception::Error(String::New("Error setting RSA key")));
  }

  Handle<Object> o = Object::New();
  /*Handle<String> n = String::New(BN_bn2hex(rsa->n));
  Handle<String> e = String::New(BN_bn2hex(rsa->e));
  Handle<String> d = String::New(BN_bn2hex(rsa->d));
  Handle<String> p = String::New(BN_bn2hex(rsa->p));
  Handle<String> q = String::New(BN_bn2hex(rsa->q));
  o->Set(String::New("n"), n);
  o->Set(String::New("e"), e);
  o->Set(String::New("d"), d);
  o->Set(String::New("p"), p);
  o->Set(String::New("q"), q);*/
  
  BIO *rsaBIO;
  BUF_MEM* bptr;

  //Get the Public key in PEM format
  rsaBIO = BIO_new(BIO_s_mem());
  int ok = PEM_write_bio_RSAPublicKey(rsaBIO, rsa);
  if (!ok) {
    return ThrowException(Exception::Error(String::New("Error getting PEM format of RSA Public Key")));
  }
  BIO_get_mem_ptr(rsaBIO, &bptr);
  char *buff = (char *) malloc(bptr->length + 1);
  memcpy(buff, bptr->data, bptr->length-1);
  buff[bptr->length-1] = 0;

  Handle<String> pem_pub = String::New(buff);
  o->Set(String::New("pem_pub"), pem_pub);
  delete [] buff;

  //Get the private key in PEM format
  rsaBIO = BIO_new(BIO_s_mem());
  ok = PEM_write_bio_RSAPrivateKey(rsaBIO, rsa, NULL, NULL, 0, NULL, NULL);
  if (!ok) {
    return ThrowException(Exception::Error(String::New("Error getting PEM format of RSA Private Key")));
  }

  BIO_get_mem_ptr(rsaBIO, &bptr);
  buff = (char *) malloc(bptr->length + 1);
  memcpy(buff, bptr->data, bptr->length-1);
  buff[bptr->length-1] = 0;

  Handle<String> pem_priv = String::New(buff);
  o->Set(String::New("pem_priv"), pem_priv);

  delete [] buff;

  BIO_free_all(rsaBIO);
  RSA_free(rsa);
  return scope.Close(o);

}

Handle<Value> KeyPair::New_ECDSA_KeyPair(const Arguments &args) {
  EC_KEY *eckey = EC_KEY_new();
  ASSERT_IS_STRING_OR_BUFFER(args[0]); 

  String::AsciiValue curve(args[0]);

  if (eckey == NULL) {
    return ThrowException(Exception::Error(String::New("Error allocating new ECDSA key")));
  }

  EC_GROUP *ecgroup = NULL;
  ecgroup = EC_GROUP_new_by_curve_name(OBJ_sn2nid(*curve));
  EC_KEY_set_group(eckey,ecgroup);

  if (!EC_KEY_generate_key(eckey)) {
    return ThrowException(Exception::Error(String::New("Error allocating new ECDSA key")));
  }

  if (!EC_KEY_check_key(eckey)) { 
    return ThrowException(Exception::Error(String::New("ECDSA key not valid")));
  }
  Handle<Object> o = Object::New();
  const BIGNUM *priv_key = EC_KEY_get0_private_key(eckey);
  const EC_POINT *pub_key = EC_KEY_get0_public_key(eckey);
  //encode into an unsigned char array
  //i2d_ECPrivateKey(eckey, out);
  //decode from char array
  //d2i_ECPrivateKey(eckey, in, len);
  EC_KEY_free(eckey);
  EC_GROUP_free(ecgroup);
  
}

KeyPair::KeyPair() : ObjectWrap() {
}

KeyPair::~KeyPair() {
}
