#include "cipher.h"

Persistent<FunctionTemplate> Cipher::constructor;

void Cipher::Initialize(Handle<Object> target) {
  HandleScope scope;

  constructor = Persistent<FunctionTemplate>::New(FunctionTemplate::New(Cipher::New));
  constructor->InstanceTemplate()->SetInternalFieldCount(1);
  constructor->SetClassName(String::NewSymbol("Cipher"));

  NODE_SET_PROTOTYPE_METHOD(constructor, "init", CipherInit);
  NODE_SET_PROTOTYPE_METHOD(constructor, "initiv", CipherInitIv);
  NODE_SET_PROTOTYPE_METHOD(constructor, "update", CipherUpdate);
  NODE_SET_PROTOTYPE_METHOD(constructor, "final", CipherFinal);
  Local<ObjectTemplate> proto = constructor->PrototypeTemplate();

  target->Set(String::NewSymbol("Cipher"), constructor->GetFunction());
}

Handle<Value> Cipher::New(const Arguments &args) {
  HandleScope scope;

  Cipher *c = new Cipher();
  c->Wrap(args.This());

  return args.This();
}

Handle<Value> Cipher::CipherInit(const Arguments &args) {
  HandleScope scope;
  Cipher *cipher = ObjectWrap::Unwrap<Cipher>(args.This());

  cipher->incomplete_base64=NULL;

  if (args.Length() <= 1 || !args[0]->IsString() || !args[1]->IsString()) {
    return ThrowException(Exception::Error(String::New(
      "Must give cipher-type, key")));
  }

  ASSERT_IS_STRING_OR_BUFFER(args[1]);
  ssize_t key_buf_len = DecodeBytes(args[1], BINARY);

  if (key_buf_len < 0) {
    Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
    return ThrowException(exception);
  }

  char* key_buf = new char[key_buf_len];
  ssize_t key_written = DecodeWrite(key_buf, key_buf_len, args[1], BINARY);
  assert(key_written == key_buf_len);

  String::Utf8Value cipherType(args[0]->ToString());

  bool r = cipher->CipherInit(*cipherType, key_buf, key_buf_len);

  delete [] key_buf;

  if (!r) {
    return ThrowException(Exception::Error(String::New("CipherInit error")));
  }
  return args.This();
}

bool Cipher::CipherInit(char* cipherType, char* key_buf, int key_buf_len) {
  cipher = EVP_get_cipherbyname(cipherType);
  if(!cipher) {
    fprintf(stderr, "node-crypto : Unknown cipher %s\n", cipherType);
    return false;
  }

  unsigned char key[EVP_MAX_KEY_LENGTH],iv[EVP_MAX_IV_LENGTH];
  int key_len = EVP_BytesToKey(cipher, EVP_md5(), NULL, (unsigned char*) key_buf, key_buf_len, 1, key, iv);

  EVP_CIPHER_CTX_init(ctx);
  EVP_CipherInit(ctx,cipher,(unsigned char *)key,(unsigned char *)iv, true);
  if (!EVP_CIPHER_CTX_set_key_length(ctx,key_len)) {
    fprintf(stderr, "node-crypto : Invalid key length %d\n", key_len);
    EVP_CIPHER_CTX_cleanup(ctx);
    return false;
  }
  initialised_ = true;
  return true;
}

Handle<Value> Cipher::CipherInitIv(const Arguments& args) {
  Cipher *cipher = ObjectWrap::Unwrap<Cipher>(args.This());
  
  HandleScope scope;

  cipher->incomplete_base64=NULL;

  if (args.Length() <= 2 || !args[0]->IsString() || !args[1]->IsString() || !args[2]->IsString()) {
    return ThrowException(Exception::Error(String::New(
      "Must give cipher-type, key, and iv as argument")));
  }

  ASSERT_IS_STRING_OR_BUFFER(args[1]);
  ssize_t key_len = DecodeBytes(args[1], BINARY);

  if (key_len < 0) {
    Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
    return ThrowException(exception);
  }

  ASSERT_IS_STRING_OR_BUFFER(args[2]);
  ssize_t iv_len = DecodeBytes(args[2], BINARY);

  if (iv_len < 0) {
    Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
    return ThrowException(exception);
  }

  char* key_buf = new char[key_len];
  ssize_t key_written = DecodeWrite(key_buf, key_len, args[1], BINARY);
  assert(key_written == key_len);

  char* iv_buf = new char[iv_len];
  ssize_t iv_written = DecodeWrite(iv_buf, iv_len, args[2], BINARY);
  assert(iv_written == iv_len);

  String::Utf8Value cipherType(args[0]->ToString());
    
  bool r = cipher->CipherInitIv(*cipherType, key_buf,key_len,iv_buf,iv_len);

  delete [] key_buf;
  delete [] iv_buf;

  if (!r) {
    return ThrowException(Exception::Error(String::New("CipherInitIv error")));
  }

  return args.This();
}


bool Cipher::CipherInitIv(char* cipherType,
                  char* key,
                  int key_len,
                  char *iv,
                  int iv_len) {
  cipher = EVP_get_cipherbyname(cipherType);
  if(!cipher) {
    fprintf(stderr, "node-crypto : Unknown cipher %s\n", cipherType);
    return false;
  }
  if (EVP_CIPHER_iv_length(cipher)!=iv_len) {
    fprintf(stderr, "node-crypto : Invalid IV length %d\n", iv_len);
    return false;
  }
  EVP_CIPHER_CTX_init(ctx);
  EVP_CipherInit(ctx,cipher,(unsigned char *)key,(unsigned char *)iv, true);
  if (!EVP_CIPHER_CTX_set_key_length(ctx,key_len)) {
    fprintf(stderr, "node-crypto : Invalid key length %d\n", key_len);
    EVP_CIPHER_CTX_cleanup(ctx);
    return false;
  }
  initialised_ = true;
  
}

Handle<Value> Cipher::CipherUpdate(const Arguments& args) {
  Cipher *cipher = ObjectWrap::Unwrap<Cipher>(args.This());

  HandleScope scope;

  ASSERT_IS_STRING_OR_BUFFER(args[0]);

  enum encoding enc = ParseEncoding(args[1]);
  ssize_t len = DecodeBytes(args[0], enc);

  if (len < 0) {
    Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
    return ThrowException(exception);
  }

  unsigned char *out=0;
  int out_len=0, r;
  if (Buffer::HasInstance(args[0])) {
    Local<Object> buffer_obj = args[0]->ToObject();
    char *buffer_data = Buffer::Data(buffer_obj);
    size_t buffer_length = Buffer::Length(buffer_obj);

    r = cipher->CipherUpdate(buffer_data, buffer_length, &out, &out_len);
  } else {
    char* buf = new char[len];
    ssize_t written = DecodeWrite(buf, len, args[0], enc);
    assert(written == len);
    r = cipher->CipherUpdate(buf, len,&out,&out_len);
    delete [] buf;
  }

  if (!r) {
    delete [] out;
    Local<Value> exception = Exception::TypeError(String::New("DecipherUpdate fail"));
    return ThrowException(exception);
  }

  Local<Value> outString;
  if (out_len==0) {
    outString=String::New("");
  } else {
    if (args.Length() <= 2 || !args[2]->IsString()) {
      // Binary
      outString = Encode(out, out_len, BINARY);
    } else {
      char* out_hexdigest;
      int out_hex_len;
      String::Utf8Value encoding(args[2]->ToString());
      if (strcasecmp(*encoding, "hex") == 0) {
        // Hex encoding
        HexEncode(out, out_len, &out_hexdigest, &out_hex_len);
        outString = Encode(out_hexdigest, out_hex_len, BINARY);
        delete [] out_hexdigest;
      } else if (strcasecmp(*encoding, "base64") == 0) {
        // Base64 encoding
        // Check to see if we need to add in previous base64 overhang
        if (cipher->incomplete_base64!=NULL){
          unsigned char* complete_base64 = new unsigned char[out_len+cipher->incomplete_base64_len+1];
          memcpy(complete_base64, cipher->incomplete_base64, cipher->incomplete_base64_len);
          memcpy(&complete_base64[cipher->incomplete_base64_len], out, out_len);
          delete [] out;

          delete [] cipher->incomplete_base64;
          cipher->incomplete_base64=NULL;

          out=complete_base64;
          out_len += cipher->incomplete_base64_len;
        }

        // Check to see if we need to trim base64 stream
        if (out_len%3!=0){
          cipher->incomplete_base64_len = out_len%3;
          cipher->incomplete_base64 = new char[cipher->incomplete_base64_len+1];
          memcpy(cipher->incomplete_base64,
                 &out[out_len-cipher->incomplete_base64_len],
                 cipher->incomplete_base64_len);
          out_len -= cipher->incomplete_base64_len;
          out[out_len]=0;
        }

        base64(out, out_len, &out_hexdigest, &out_hex_len);
        outString = Encode(out_hexdigest, out_hex_len, BINARY);
        delete [] out_hexdigest;
      } else if (strcasecmp(*encoding, "binary") == 0) {
        outString = Encode(out, out_len, BINARY);
      } else {
        fprintf(stderr, "node-crypto : Cipher .update encoding "
                        "can be binary, hex or base64\n");
      }
    }
  }

  if (out) delete [] out;
  return scope.Close(outString);
}


int Cipher::CipherUpdate(char* data, int len, unsigned char** out, int* out_len) {
  if (!initialised_) return 0;
  *out_len=len+EVP_CIPHER_CTX_block_size(ctx);
  *out= new unsigned char[*out_len];

  EVP_CipherUpdate(ctx, *out, out_len, (unsigned char*)data, len);
  return 1;
}

Handle<Value> Cipher::CipherFinal(const Arguments& args) {
  Cipher *cipher = ObjectWrap::Unwrap<Cipher>(args.This());

  HandleScope scope;

  unsigned char* out_value;
  int out_len;
  char* out_hexdigest;
  int out_hex_len;
  Local<Value> outString ;

  int r = cipher->CipherFinal(&out_value, &out_len);

  if (out_len == 0 || r == 0) {
    return scope.Close(String::New(""));
  }

  if (args.Length() == 0 || !args[0]->IsString()) {
    // Binary
    outString = Encode(out_value, out_len, BINARY);
  } else {
    String::Utf8Value encoding(args[0]->ToString());
    if (strcasecmp(*encoding, "hex") == 0) {
      // Hex encoding
      HexEncode(out_value, out_len, &out_hexdigest, &out_hex_len);
      outString = Encode(out_hexdigest, out_hex_len, BINARY);
      delete [] out_hexdigest;
    } else if (strcasecmp(*encoding, "base64") == 0) {
      base64(out_value, out_len, &out_hexdigest, &out_hex_len);
      outString = Encode(out_hexdigest, out_hex_len, BINARY);
      delete [] out_hexdigest;
    } else if (strcasecmp(*encoding, "binary") == 0) {
      outString = Encode(out_value, out_len, BINARY);
    } else {
      fprintf(stderr, "node-crypto : Cipher .final encoding "
                      "can be binary, hex or base64\n");
    }
  }
  delete [] out_value;
  return scope.Close(outString);
}


int Cipher::CipherFinal(unsigned char** out, int *out_len) {
  if (!initialised_) return 0;
  *out = new unsigned char[EVP_CIPHER_CTX_block_size(ctx)];
  EVP_CipherFinal(ctx,*out,out_len);
  EVP_CIPHER_CTX_cleanup(ctx);
  initialised_ = false;
  return 1;
}

Cipher::Cipher() : ObjectWrap() {
  initialised_ = false;
  ctx = EVP_CIPHER_CTX_new();
}

Cipher::~Cipher() {
  EVP_CIPHER_CTX_cleanup(ctx);
  OPENSSL_free(ctx);
}
