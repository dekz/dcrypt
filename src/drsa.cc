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
  // EVP_PKEY *pkey = EVP_PKEY_new();
  RSA *rsa_pub = RSA_new();

  enum encoding enc = ParseEncoding(String::New("binary"));
  ssize_t len = DecodeBytes(args[0], enc);

  char *pem_pub;
  size_t pub_len;
  if (Buffer::HasInstance(args[0])) {
    Local<Object> pub_obj = args[0]->ToObject();
    pem_pub = Buffer::Data(pub_obj);
    pub_len = Buffer::Length(pub_obj);
  } else {
    pem_pub = new char[len];
    ssize_t written = DecodeWrite(pem_pub, len, args[0], enc);
    pub_len = written;
  }

  fprintf(stderr, "%s\n", pem_pub);
  fprintf(stderr, "%d\n", pub_len);

  char *msg;
  size_t msg_len;
  len = DecodeBytes(args[1], enc);
  if (Buffer::HasInstance(args[1])) {
    Local<Object> msg_obj = args[1]->ToObject();
    msg = Buffer::Data(msg_obj);
    msg_len = Buffer::Length(msg_obj);
  } else {
    msg = new char[len];
    ssize_t written = DecodeWrite(msg, len, args[1], enc);
    fprintf(stderr, "%s\n", msg);
    msg_len = written;
  }

  if (pub_len < 0) {
    return ThrowException(Exception::TypeError(String::New("Bad length of key"))); 
  }

  if (msg_len < 0) {
    return ThrowException(Exception::TypeError(String::New("Bad length of msg")));
  }

  if(!BIO_write(rsa_bio, pem_pub, pub_len)) return ThrowException(Exception::TypeError(String::New("Bad write of key")));

   //if this doesn't work use pkey
  rsa_pub = PEM_read_bio_RSAPublicKey(rsa_bio, NULL, NULL, 0);
  if (!rsa_pub) {
    return ThrowException(Exception::TypeError(String::New("Error getting PEM encoded key")));
  }
  //should work out the block size to properly allocate
  unsigned char encrypted[2560] = { 0 };
  int written = RSA_public_encrypt(msg_len, (unsigned char*) msg, encrypted, rsa_pub, RSA_PKCS1_OAEP_PADDING);

  char *out_hex;
  int out_hex_len;
  HexEncode(encrypted, written, &out_hex, &out_hex_len);

  Local<Value> outString = Encode(out_hex, out_hex_len, BINARY);
  // EVP_PKEY_free(pkey);
  RSA_free(rsa_pub);
  BIO_free(rsa_bio);
  return scope.Close(outString);
}

DRSA::DRSA() : ObjectWrap() {
}

DRSA::~DRSA() {
}
