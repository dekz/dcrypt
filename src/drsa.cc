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
  char *pem_pub = Buffer::Data(pub_obj);
  size_t pub_len = Buffer::Length(pub_obj);

  Local<Object> msg_obj = args[1]->ToObject();
  char *msg = Buffer::Data(msg_obj);
  size_t msg_len = Buffer::Length(msg_obj);
  

  if (pub_len < 0) {
    return ThrowException(Exception::TypeError(String::New("Bad length of key"))); 
  }

  if (msg_len < 0) {
    return ThrowException(Exception::TypeError(String::New("Bad length of msg")));
  }

  RSA *rsa_pub = RSA_new();

  if(!BIO_write(rsa_bio, pem_pub, pub_len)) return ThrowException(Exception::TypeError(String::New("Bad write of key")));
  fprintf(stderr, "%s\n", pem_pub);
  fprintf(stderr, "%s\n", msg);

   //if this doesn't work use pkey
  rsa_pub = PEM_read_bio_RSAPublicKey(rsa_bio, NULL, NULL, 0);
  if (!rsa_pub) {
    return ThrowException(Exception::TypeError(String::New("Error getting PEM encoded key")));
  }

  // rsa_pub = EVP_PKEY_get1_RSA(pkey);
  //should work out the block size to properly allocate
  unsigned char enc[2560] = { 0 };
  int written = RSA_public_encrypt(msg_len, (unsigned char*) msg, enc, rsa_pub, RSA_PKCS1_OAEP_PADDING);
  fprintf(stderr, "%s\n", enc);

  Local<Value> outString = Encode(enc, written, BINARY);
  EVP_PKEY_free(pkey);
  RSA_free(rsa_pub);
  BIO_free(rsa_bio);
  return scope.Close(outString);
}

DRSA::DRSA() : ObjectWrap() {
}

DRSA::~DRSA() {
}
