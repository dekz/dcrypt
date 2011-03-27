#include "drsa.h"

Persistent<FunctionTemplate> DRSA::constructor;

void DRSA::Initialize(Handle<Object> target) {
  HandleScope scope;

  constructor = Persistent<FunctionTemplate>::New(FunctionTemplate::New(DRSA::New));
  constructor->InstanceTemplate()->SetInternalFieldCount(1);
  constructor->SetClassName(String::NewSymbol("Rsa"));

  NODE_SET_PROTOTYPE_METHOD(constructor, "encrypt", RSAEncrypt);

  Local<ObjectTemplate> proto = constructor->PrototypeTemplate();
  target->Set(String::NewSymbol("Rsa"), constructor->GetFunction());
}


Handle<Value> DRSA::New(const Arguments &args) {
  HandleScope scope;

  DRSA *d = new DRSA();
  d->Wrap(args.This());

  return args.This();
}

//I expect, pub_key, message, padding type 
//Where pub_key probable should be PEM format
Handle<Value> DRSA::RSAEncrypt(const Arguments &args) {
  HandleScope scope;

  ASSERT_IS_STRING_OR_BUFFER(args[0]);
  ASSERT_IS_STRING_OR_BUFFER(args[1]);
  BIO *rsa_bio = BIO_new(BIO_s_mem());
  EVP_PKEY *pkey = EVP_PKEY_new();

  // ssize_t len = DecodeBytes(args[0], BINARY);
  // char *pem_pub = new char[len];
  Local<Object> pub_obj = args[0]->ToObject();
  unsigned char *pem_pub = (unsigned char*) Buffer::Data(pub_obj);
  ssize_t pub_len = Buffer::Length(pub_obj);

  Local<Object> msg_obj = args[1]->ToObject();
  unsigned char *msg = (unsigned char*)Buffer::Data(msg_obj);
  ssize_t msg_len = Buffer::Length(msg_obj);
  

  if (pub_len < 0) return ThrowException(Exception::TypeError(String::New("Bad length of key")));

  RSA *rsa_pub = RSA_new();

  if(!BIO_write(rsa_bio, pem_pub, pub_len)) ThrowException(Exception::TypeError(String::New("Bad write of key")));

   //if this doesn't work use pkey
  int ok = PEM_write_bio_RSAPublicKey(rsa_bio, rsa_pub);
  //should work out the block size to properly allocate
  unsigned char enc[2560] = { 0 };
  int written = RSA_public_encrypt(msg_len, msg, enc, rsa_pub, RSA_PKCS1_OAEP_PADDING);
  EVP_PKEY_free(pkey);
  RSA_free(rsa_pub);
  BIO_free(rsa_bio);
}

DRSA::DRSA() : ObjectWrap() {
}

DRSA::~DRSA() {
}
