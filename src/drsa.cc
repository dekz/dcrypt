#include "drsa.h"

Persistent<FunctionTemplate> DRSA::constructor;

void DRSA::Initialize(Handle<Object> target) {
  HandleScope scope;

  constructor = Persistent<FunctionTemplate>::New(FunctionTemplate::New(DRSA::New));
  constructor->InstanceTemplate()->SetInternalFieldCount(1);
  constructor->SetClassName(String::NewSymbol("Rsa"));

  NODE_SET_PROTOTYPE_METHOD(constructor, "encrypt", RSAEncrypt);
  NODE_SET_PROTOTYPE_METHOD(constructor, "decrypt", RSADecrypt);

  Local<ObjectTemplate> proto = constructor->PrototypeTemplate();
  target->Set(String::NewSymbol("Rsa"), constructor->GetFunction());
}


Handle<Value> DRSA::New(const Arguments &args) {
  HandleScope scope;

  DRSA *d = new DRSA();
  d->Wrap(args.This());

  return args.This();
}

//I expect, pub_key, message, padding type, outencoding 
//Where pub_key probably should be PEM format or a CERT
//TODO add cert support(x509)
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

  rsa_pub = PEM_read_bio_RSAPublicKey(rsa_bio, NULL, NULL, 0);
  if (!rsa_pub) {
    return ThrowException(Exception::TypeError(String::New("Error getting PEM encoded key")));
  }
  
  //Get the right padding type from arg 3

  //Encrypt our message
  int keysize = RSA_size(rsa_pub);
  unsigned char *encrypted = new unsigned char[keysize];

  int written = RSA_public_encrypt(msg_len, (unsigned char*) msg, encrypted, rsa_pub, RSA_PKCS1_OAEP_PADDING);

  Local<Value> outString;
  String::Utf8Value encoding(args[3]->ToString());

  //Encode the output in the form given in argument 4
  if (written == 0) {
    outString = String::New("");
  } else if (strcasecmp(*encoding, "hex") == 0) {
    char *out_hex;
    int out_hex_len;
    HexEncode(encrypted, written, &out_hex, &out_hex_len);
    outString = Encode(out_hex, out_hex_len, BINARY);
    delete [] out_hex;
  } else if (strcasecmp(*encoding, "base64") == 0) {
    char *out;
    int out_len;
    base64(encrypted, written, &out, &out_len);
    outString = Encode(out, out_len, BINARY);
    delete [] out;
  } else {
    outString = Encode(encrypted, written, BINARY);
  }

  delete [] encrypted;
  RSA_free(rsa_pub);
  BIO_free(rsa_bio);
  return scope.Close(outString);
}

//Inputs: priv key, ciphertext, padding, input_encoding
Handle<Value> DRSA::RSADecrypt(const Arguments &args) {
  HandleScope scope;

  ASSERT_IS_STRING_OR_BUFFER(args[0]);
  ASSERT_IS_STRING_OR_BUFFER(args[1]);
  BIO *rsa_bio = BIO_new(BIO_s_mem());
  RSA *rsa_priv = RSA_new();

  ssize_t len = DecodeBytes(args[0], BINARY);
  if (len < 0) {
    return ThrowException(Exception::Error(String::New(
            "node`DecodeBytes() failed")));
  }

  char *priv_buf;
  int priv_len;
  if (Buffer::HasInstance(args[0])) {
  } else {
    priv_buf = new char[len];
    priv_len = DecodeWrite(priv_buf, len, args[0], BINARY);
    assert(priv_len == len);
  }

  //NEEDS TO BE DECODED from base64/hex to binary
  char *ct_buf;
  int ct_len;
  len = DecodeBytes(args[1], BINARY);
  String::Utf8Value encoding(args[3]->ToString());
  if (Buffer::HasInstance(args[1])) {
  } else {
    ct_buf = new char[len];
    ct_len = DecodeWrite(ct_buf, len, args[1], BINARY);
    assert(ct_len == len);
  }

  char *ciphertext;
  int ciphertext_len;
  if (strcasecmp(*encoding, "hex") == 0) {
    HexDecode((unsigned char*) ct_buf, ct_len, (char **)&ciphertext, &ciphertext_len);
    ct_buf = ciphertext;
    ct_len = ciphertext_len;
  } else if (strcasecmp(*encoding, "base64") == 0) {
    unbase64((unsigned char*) ct_buf, ct_len, (char **)&ciphertext, &ciphertext_len);
    ct_buf = ciphertext;
    ct_len = ciphertext_len;
  } else {
    //binary
  }

  if (!BIO_write(rsa_bio, priv_buf, priv_len)) {
     return ThrowException(Exception::Error(String::New("Problem reading Private key")));
  }

  rsa_priv = PEM_read_bio_RSAPrivateKey(rsa_bio, NULL, 0, NULL);
  if (!rsa_priv) {
     return ThrowException(Exception::Error(String::New("Problem allocating Private key")));
  }

  int keysize = RSA_size(rsa_priv);
  unsigned char *out_buf = new unsigned char[keysize];
  int written = RSA_private_decrypt(ct_len, (unsigned char*)ct_buf, out_buf, rsa_priv, RSA_PKCS1_OAEP_PADDING);

  if (written < 0) {
     return ThrowException(Exception::Error(String::New("Problem Decrypting Message")));
  }


  Local<Value> outString = Encode(out_buf, written, BINARY);
  return scope.Close(outString);
}

DRSA::DRSA() : ObjectWrap() {
}

DRSA::~DRSA() {
}