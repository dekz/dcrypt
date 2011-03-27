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

  int keysize = RSA_size(rsa_pub);
  unsigned char *encrypted = new unsigned char[keysize];

  int written = RSA_public_encrypt(msg_len, (unsigned char*) msg, encrypted, rsa_pub, RSA_PKCS1_OAEP_PADDING);

  Local<Value> outString;
  String::Utf8Value encoding(args[3]->ToString());

  if (written == 0) {
    outString = String::New("");
  } else if (strcasecmp(*encoding, "hex") == 0) {
    char *out_hex;
    int out_hex_len;
    HexEncode(encrypted, written, &out_hex, &out_hex_len);
    outString = Encode(out_hex, out_hex_len, BINARY);
  } else if (strcasecmp(*encoding, "base64") == 0) {
    char *out;
    int out_len;
    base64(encrypted, written, &out, &out_len);
    outString = Encode(out, out_len, BINARY);
  } else {
    fprintf(stderr, "unknown encoding \n");
  }

  delete [] encrypted;
  RSA_free(rsa_pub);
  BIO_free(rsa_bio);
  return scope.Close(outString);
}

DRSA::DRSA() : ObjectWrap() {
}

DRSA::~DRSA() {
}
