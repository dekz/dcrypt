#include "verify.h"

Persistent<FunctionTemplate> Verify::constructor;

void Verify::Initialize(Handle<Object> target) {
  HandleScope scope;

  constructor = Persistent<FunctionTemplate>::New(FunctionTemplate::New(Verify::New));
  constructor->InstanceTemplate()->SetInternalFieldCount(1);
  constructor->SetClassName(String::NewSymbol("Verify"));

  NODE_SET_PROTOTYPE_METHOD(constructor, "init", VerifyInit);
  NODE_SET_PROTOTYPE_METHOD(constructor, "update", VerifyUpdate);
  NODE_SET_PROTOTYPE_METHOD(constructor, "verify", VerifyFinal);
  Local<ObjectTemplate> proto = constructor->PrototypeTemplate();

  target->Set(String::NewSymbol("Verify"), constructor->GetFunction());
  
}

Handle<Value> Verify::New(const Arguments& args) {
  HandleScope scope;

  Verify *verify = new Verify();
  verify->Wrap(args.This());

  return args.This();
}


bool Verify::VerifyInit(const char* verifyType) {
  md = EVP_get_digestbyname(verifyType);
  if(!md) {
    fprintf(stderr, "node-crypto : Unknown message digest %s\n", verifyType);
    return false;
  }
  EVP_MD_CTX_init(mdctx);
  EVP_VerifyInit_ex(mdctx, md, NULL);
  initialised_ = true;
  return true;
}

Handle<Value> Verify::VerifyInit(const Arguments& args) {
  Verify *verify = ObjectWrap::Unwrap<Verify>(args.This());

  HandleScope scope;

  if (args.Length() == 0 || !args[0]->IsString()) {
    return ThrowException(Exception::Error(String::New(
      "Must give verifytype string as argument")));
  }

  String::Utf8Value verifyType(args[0]->ToString());

  bool r = verify->VerifyInit(*verifyType);

  if (!r) {
    return ThrowException(Exception::Error(String::New("VerifyInit error")));
  }

  return args.This();
}


Handle<Value> Verify::VerifyUpdate(const Arguments& args) {
  HandleScope scope;

  Verify *verify = ObjectWrap::Unwrap<Verify>(args.This());

  ASSERT_IS_STRING_OR_BUFFER(args[0]);
  enum encoding enc = ParseEncoding(args[1]);
  ssize_t len = DecodeBytes(args[0], enc);

  if (len < 0) {
    Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
    return ThrowException(exception);
  }

  int r;

  if(Buffer::HasInstance(args[0])) {
    Local<Object> buffer_obj = args[0]->ToObject();
    char *buffer_data = Buffer::Data(buffer_obj);
    size_t buffer_length = Buffer::Length(buffer_obj);

    r = verify->VerifyUpdate(buffer_data, buffer_length);
  } else {
    char* buf = new char[len];
    ssize_t written = DecodeWrite(buf, len, args[0], enc);
    assert(written == len);
    r = verify->VerifyUpdate(buf, len);
    delete [] buf;
  }

  if (!r) {
    Local<Value> exception = Exception::TypeError(String::New("VerifyUpdate fail"));
    return ThrowException(exception);
  }

  return args.This();
}

int Verify::VerifyUpdate(char* data, int len) {
  if (!initialised_) return 0;
  int ok = EVP_VerifyUpdate(mdctx, data, len);
  if (!ok) {
      ThrowException(Exception::Error(String::New("Problem performing VerifyUpdate")));
    
  }
  return 1;
}

Handle<Value> Verify::VerifyFinal(const Arguments& args) {
  HandleScope scope;

  Verify *verify = ObjectWrap::Unwrap<Verify>(args.This());

  ASSERT_IS_STRING_OR_BUFFER(args[0]);
  ssize_t klen = DecodeBytes(args[0], BINARY);

  if (klen < 0) {
    Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
    return ThrowException(exception);
  }

  char* kbuf = new char[klen];
  ssize_t kwritten = DecodeWrite(kbuf, klen, args[0], BINARY);
  assert(kwritten == klen);

  ASSERT_IS_STRING_OR_BUFFER(args[1]);
  ssize_t hlen = DecodeBytes(args[1], BINARY);

  if (hlen < 0) {
    delete [] kbuf;
    Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
    return ThrowException(exception);
  }

  unsigned char* hbuf = new unsigned char[hlen];
  ssize_t hwritten = DecodeWrite((char *)hbuf, hlen, args[1], BINARY);
  assert(hwritten == hlen);
  unsigned char* dbuf;
  int dlen;

  int r=-1;

  if (args.Length() == 2 || !args[2]->IsString()) {
    // Binary
    r = verify->VerifyFinal(kbuf, klen, hbuf, hlen);
  } else {
    String::Utf8Value encoding(args[2]->ToString());
    if (strcasecmp(*encoding, "hex") == 0) {
      // Hex encoding
      HexDecode(hbuf, hlen, (char **)&dbuf, &dlen);
      r = verify->VerifyFinal(kbuf, klen, dbuf, dlen);
       // r = verify->VerifyFinal(kbuf, klen, hbuf, hlen);
       delete [] dbuf;
    } else if (strcasecmp(*encoding, "base64") == 0) {
      // Base64 encoding
      unbase64(hbuf, hlen, (char **)&dbuf, &dlen);
      r = verify->VerifyFinal(kbuf, klen, dbuf, dlen);
      delete [] dbuf;
    } else if (strcasecmp(*encoding, "binary") == 0) {
      r = verify->VerifyFinal(kbuf, klen, hbuf, hlen);
    } else {
      fprintf(stderr, "node-crypto : Verify .verify encoding "
                      "can be binary, hex or base64\n");
    }
  }

  delete [] kbuf;
  delete [] hbuf;

  return scope.Close(Integer::New(r));
}

int Verify::VerifyFinal(char* key_pem, int key_pemLen, unsigned char* sig, int siglen) {
  if (!initialised_) return 0;

  BIO *bp = NULL;
  EVP_PKEY* pkey = EVP_PKEY_new();
  bp = BIO_new_mem_buf(key_pem, key_pemLen);
  
  //TODO rewrite to PUBKEY -> x509 -> RSA -> ECDSA (faster)
  //TODO allow indication of type given to speed up process
  pkey = PEM_read_bio_PUBKEY(bp, NULL, NULL, NULL);
  if (pkey==NULL) {
    RSA *rsa_pub;
    pkey = EVP_PKEY_new();
    bp = BIO_new_mem_buf(key_pem, key_pemLen);
    rsa_pub = RSA_new();
    rsa_pub = PEM_read_bio_RSAPublicKey(bp, NULL, NULL, NULL);
    if (rsa_pub == NULL) {
      RSA_free(rsa_pub);
      //RSA failed, try something else
      //It seems ECDSA is always satisifed in PEM_read_bio_PUBKEY
      EC_KEY *eckey = EC_KEY_new();
      eckey = PEM_read_bio_EC_PUBKEY(bp, NULL, NULL, NULL);
      if (!eckey) {
        EC_KEY_free(eckey);

        X509 *x509 = NULL;
        X509_free(x509);
        bp = BIO_new_mem_buf(key_pem, key_pemLen);
        x509 = PEM_read_bio_X509(bp, NULL, NULL, NULL);
        if (x509 == NULL) {
        } else {
          pkey=X509_get_pubkey(x509);
          X509_free(x509);
        }
      } else {
        EVP_PKEY_set1_EC_KEY(pkey, eckey);
        EC_KEY_free(eckey);
      }
    } else {
      //RSA worked set it up and drop down
      EVP_PKEY_set1_RSA(pkey, rsa_pub);
      RSA_free(rsa_pub);
    }
  }

  if (pkey==NULL) {
    //give up
    BIO_free(bp);
    ERR_print_errors_fp(stderr);
    return 0;
  }

  int r = EVP_VerifyFinal(mdctx, sig, siglen, pkey);

  EVP_PKEY_free(pkey);
  BIO_free(bp);
  EVP_MD_CTX_cleanup(mdctx);
  initialised_ = false;
  return r;
}

Verify::Verify() : ObjectWrap() {
  initialised_ = false;
  mdctx = EVP_MD_CTX_create();
}

Verify::~Verify() {
  EVP_MD_CTX_cleanup(mdctx);
  OPENSSL_free(mdctx);
}
