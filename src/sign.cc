#include "sign.h"

Persistent<FunctionTemplate> Sign::constructor;

void Sign::Initialize(Handle<Object> target) {
  HandleScope scope;

  constructor = Persistent<FunctionTemplate>::New(FunctionTemplate::New(Sign::New));
  constructor->InstanceTemplate()->SetInternalFieldCount(1);
  constructor->SetClassName(String::NewSymbol("Sign"));

  NODE_SET_PROTOTYPE_METHOD(constructor, "init", SignInit);
  NODE_SET_PROTOTYPE_METHOD(constructor, "update", SignUpdate);
  NODE_SET_PROTOTYPE_METHOD(constructor, "sign", SignFinal);
  Local<ObjectTemplate> proto = constructor->PrototypeTemplate();

  target->Set(String::NewSymbol("Sign"), constructor->GetFunction());

}

bool Sign::SignInit(const char *signType) {
  md = EVP_get_digestbyname(signType);
  if(!md) {
    return false;
  }

  EVP_MD_CTX_init(mdctx);
  int ok = EVP_SignInit_ex(mdctx, md, NULL);
  if (!ok) {
    return false;
  }
  initialised_ = true;
  return true;
}

int Sign::SignUpdate(char *data, int len) {
  if (!initialised_) {
    return 0;
  }
  int ok = EVP_SignUpdate(mdctx, data, len);
  if (!ok) {
    return 0;
  }
  return 1;
}

int Sign::SignFinal(unsigned char **md_value, unsigned int *md_len, char *key_pem, int key_pemLen) {
  
  if (!initialised_) return 0;

  BIO *bp = NULL;
  EVP_PKEY* pkey;
  bp = BIO_new(BIO_s_mem());
  if(!BIO_write(bp, key_pem, key_pemLen)) return 0;

  pkey = PEM_read_bio_PrivateKey(bp, NULL, NULL, NULL);
  if (pkey == NULL) {
    fprintf(stderr, "SignFinal: Unable to load public key");
    return 0;
  }

  EVP_SignFinal(mdctx, *md_value, md_len, pkey); 

  EVP_MD_CTX_cleanup(mdctx);
  initialised_ = false;
  EVP_PKEY_free(pkey);
  BIO_free(bp);
  return 1;
}

Sign::Sign() : ObjectWrap() {
  initialised_ = false;
  mdctx = EVP_MD_CTX_create();
}

Handle<Value> Sign::New(const Arguments &args) {
    HandleScope scope;

    Sign *sign = new Sign();
    sign->Wrap(args.This());

    return args.This();
}

Handle<Value> Sign::SignInit(const Arguments &args) {
  HandleScope scope;

  Sign *sign = ObjectWrap::Unwrap<Sign>(args.This());

  if (args.Length() == 0 || !args[0]->IsString()) {
    return ThrowException(Exception::Error(String::New(
      "Must give signtype string as argument")));
  }

  String::Utf8Value signType(args[0]->ToString());
  bool r = sign->SignInit(*signType);

  if (!r) {
    return ThrowException(Exception::Error(String::New("SignInit error")));
  }

  return args.This();
}

Handle<Value> Sign::SignUpdate(const Arguments &args) {
  
  Sign *sign = ObjectWrap::Unwrap<Sign>(args.This());

  HandleScope scope;

  ASSERT_IS_STRING_OR_BUFFER(args[0]);
  enum encoding enc = ParseEncoding(args[1]);
  ssize_t len = DecodeBytes(args[0], enc);

  if (len < 0) {
    Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
    return ThrowException(exception);
  }

  int r;

  if (Buffer::HasInstance(args[0])) {
    Local<Object> buffer_obj = args[0]->ToObject();
    char *buffer_data = Buffer::Data(buffer_obj);
    size_t buffer_length = Buffer::Length(buffer_obj);

    r = sign->SignUpdate(buffer_data, buffer_length);
  } else {
    char* buf = new char[len];
    ssize_t written = DecodeWrite(buf, len, args[0], enc);
    assert(written == len);
    r = sign->SignUpdate(buf, len);
    delete [] buf;
  }

  if (!r) {
    Local<Value> exception = Exception::TypeError(String::New("SignUpdate fail"));
    return ThrowException(exception);
  }

  return args.This();
}  

Handle<Value> Sign::SignFinal(const Arguments &args) {
  
  Sign *sign = ObjectWrap::Unwrap<Sign>(args.This());

  HandleScope scope;

  unsigned char* md_value;
  unsigned int md_len;
  char* md_hexdigest;
  int md_hex_len;
  Local<Value> outString;

  md_len = 8192; // Maximum key size is 8192 bits
  md_value = new unsigned char[md_len];


  ASSERT_IS_STRING_OR_BUFFER(args[0]);
  ssize_t len = DecodeBytes(args[0], BINARY);

  if (len < 0) {
    delete [] md_value;
    Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
    return ThrowException(exception);
  }

  char* buf = new char[len];
  ssize_t written = DecodeWrite(buf, len, args[0], BINARY);
  assert(written == len);

  int r = sign->SignFinal(&md_value, &md_len, buf, len);

  delete [] buf;

  if (md_len == 0 || r == 0) {
    delete [] md_value;
    return scope.Close(String::New(""));
  }

  if (args.Length() == 1 || !args[1]->IsString()) {
    // Binary
    outString = Encode(md_value, md_len, BINARY);
  } else {
    String::Utf8Value encoding(args[1]->ToString());
    if (strcasecmp(*encoding, "hex") == 0) {
      // Hex encoding
      HexEncode(md_value, md_len, &md_hexdigest, &md_hex_len);
      outString = Encode(md_hexdigest, md_hex_len, BINARY);
      delete [] md_hexdigest;
    } else if (strcasecmp(*encoding, "base64") == 0) {
      base64(md_value, md_len, &md_hexdigest, &md_hex_len);
      outString = Encode(md_hexdigest, md_hex_len, BINARY);
      delete [] md_hexdigest;
    } else if (strcasecmp(*encoding, "binary") == 0) {
      outString = Encode(md_value, md_len, BINARY);
    } else {
      outString = String::New("");
      fprintf(stderr, "node-crypto : Sign .sign encoding "
                      "can be binary, hex or base64\n");
    }
  }

  delete [] md_value;
  return scope.Close(outString);
}  

Sign::~Sign() {
  EVP_MD_CTX_cleanup(mdctx);
  OPENSSL_free(mdctx);
}

