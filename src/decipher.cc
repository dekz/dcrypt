#include "decipher.h"

Persistent<FunctionTemplate> Decipher::constructor;

void Decipher::Initialize(Handle<Object> target) {
  HandleScope scope;

  constructor = Persistent<FunctionTemplate>::New(FunctionTemplate::New(Decipher::New));
  constructor->InstanceTemplate()->SetInternalFieldCount(1);
  constructor->SetClassName(String::NewSymbol("Decipher"));

  NODE_SET_PROTOTYPE_METHOD(constructor, "init", DecipherInit);
  NODE_SET_PROTOTYPE_METHOD(constructor, "initiv", DecipherInitIv);
  NODE_SET_PROTOTYPE_METHOD(constructor, "update", DecipherUpdate);
  NODE_SET_PROTOTYPE_METHOD(constructor, "final", DecipherFinal);
  NODE_SET_PROTOTYPE_METHOD(constructor, "finaltol", DecipherFinalTolerate);

  Local<ObjectTemplate> proto = constructor->PrototypeTemplate();

  target->Set(String::NewSymbol("Decipher"), constructor->GetFunction());
}

Handle<Value> Decipher::New(const Arguments &args) {
  HandleScope scope;

  Decipher *c = new Decipher();
  c->Wrap(args.This());

  return args.This();
}

bool Decipher::DecipherInit(char* cipherType, char* key_buf, int key_buf_len) {
  cipher = EVP_get_cipherbyname(cipherType);

  if(!cipher) {
    fprintf(stderr, "node-crypto : Unknown cipher %s\n", cipherType);
    return false;
  }

  unsigned char key[EVP_MAX_KEY_LENGTH],iv[EVP_MAX_IV_LENGTH];
  int key_len = EVP_BytesToKey(cipher,
                               EVP_md5(),
                               NULL,
                               (unsigned char*)(key_buf),
                               key_buf_len,
                               1,
                               key,
                               iv);

  EVP_CIPHER_CTX_init(ctx);
  EVP_CipherInit(ctx,
                 cipher,
                 (unsigned char*)(key),
                 (unsigned char *)(iv),
                 false);
  if (!EVP_CIPHER_CTX_set_key_length(ctx,key_len)) {
    fprintf(stderr, "node-crypto : Invalid key length %d\n", key_len);
    EVP_CIPHER_CTX_cleanup(ctx);
    return false;
  }
  initialised_ = true;
  return true;
}


Handle<Value> Decipher::DecipherInit(const Arguments& args) {
  Decipher *cipher = ObjectWrap::Unwrap<Decipher>(args.This());
  
  HandleScope scope;

  cipher->incomplete_utf8=NULL;
  cipher->incomplete_hex_flag=false;

  if (args.Length() <= 1 || !args[0]->IsString() || !args[1]->IsString()) {
    return ThrowException(Exception::Error(String::New(
      "Must give cipher-type, key as argument")));
  }

  ASSERT_IS_STRING_OR_BUFFER(args[1]);
  ssize_t key_len = DecodeBytes(args[1], BINARY);

  if (key_len < 0) {
    Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
    return ThrowException(exception);
  }

  char* key_buf = new char[key_len];
  ssize_t key_written = DecodeWrite(key_buf, key_len, args[1], BINARY);
  assert(key_written == key_len);

  String::Utf8Value cipherType(args[0]->ToString());
    
  bool r = cipher->DecipherInit(*cipherType, key_buf,key_len);

  delete [] key_buf;

  if (!r) {
    return ThrowException(Exception::Error(String::New("DecipherInit error")));
  }

  return args.This();
}


Handle<Value> Decipher::DecipherInitIv(const Arguments& args) {
  Decipher *cipher = ObjectWrap::Unwrap<Decipher>(args.This());
  
  HandleScope scope;

  cipher->incomplete_utf8=NULL;
  cipher->incomplete_hex_flag=false;

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
    
  bool r = cipher->DecipherInitIv(*cipherType, key_buf,key_len,iv_buf,iv_len);

  delete [] key_buf;
  delete [] iv_buf;

  if (!r) {
    return ThrowException(Exception::Error(String::New("DecipherInitIv error")));
  }

  return args.This();
}

bool Decipher::DecipherInitIv(char* cipherType,
                    char* key,
                    int key_len,
                    char *iv,
                    int iv_len) {
  cipher = EVP_get_cipherbyname(cipherType);
  if(!cipher) {
    fprintf(stderr, "node-crypto : Unknown cipher %s\n", cipherType);
    return false;
  }
  if (EVP_CIPHER_iv_length(cipher) != iv_len) {
    fprintf(stderr, "node-crypto : Invalid IV length %d\n", iv_len);
    return false;
  }
  EVP_CIPHER_CTX_init(ctx);
  EVP_CipherInit(ctx,
                 cipher,
                 (unsigned char*)(key),
                 (unsigned char *)(iv),
                 false);
  if (!EVP_CIPHER_CTX_set_key_length(ctx,key_len)) {
    fprintf(stderr, "node-crypto : Invalid key length %d\n", key_len);
    EVP_CIPHER_CTX_cleanup(ctx);
    return false;
  }
  initialised_ = true;
  return true;
}

int Decipher::DecipherUpdate(char* data, int len, unsigned char** out, int* out_len) {
  if (!initialised_) return 0;
  *out_len=len+EVP_CIPHER_CTX_block_size(ctx);
  *out= new unsigned char[*out_len];

  EVP_CipherUpdate(ctx, *out, out_len, (unsigned char*)data, len);
  return 1;
}

Handle<Value> Decipher::DecipherUpdate(const Arguments& args) {
  HandleScope scope;

  Decipher *cipher = ObjectWrap::Unwrap<Decipher>(args.This());

  ASSERT_IS_STRING_OR_BUFFER(args[0]);

  ssize_t len = DecodeBytes(args[0], BINARY);
  if (len < 0) {
      return ThrowException(Exception::Error(String::New(
          "node`DecodeBytes() failed")));
  }

  char* buf;
  // if alloc_buf then buf must be deleted later
  bool alloc_buf = false;
  if (Buffer::HasInstance(args[0])) {
    Local<Object> buffer_obj = args[0]->ToObject();
    char *buffer_data = Buffer::Data(buffer_obj);
    size_t buffer_length = Buffer::Length(buffer_obj);

    buf = buffer_data;
    len = buffer_length;
  } else {
    alloc_buf = true;
    buf = new char[len];
    ssize_t written = DecodeWrite(buf, len, args[0], BINARY);
    assert(written == len);
  }

  char* ciphertext;
  int ciphertext_len;

  if (args.Length() <= 1 || !args[1]->IsString()) {
    // Binary - do nothing
  } else {
    String::Utf8Value encoding(args[1]->ToString());
    if (strcasecmp(*encoding, "hex") == 0) {
      // Hex encoding
      // Do we have a previous hex carry over?
      if (cipher->incomplete_hex_flag) {
        char* complete_hex = new char[len+2];
        memcpy(complete_hex, &cipher->incomplete_hex, 1);
        memcpy(complete_hex+1, buf, len);
        if (alloc_buf) {
          delete [] buf;
          alloc_buf = false;
        }
        buf = complete_hex;
        len += 1;
      }
      // Do we have an incomplete hex stream?
      if ((len>0) && (len % 2 !=0)) {
        len--;
        cipher->incomplete_hex=buf[len];
        cipher->incomplete_hex_flag=true;
        buf[len]=0;
      }
      HexDecode((unsigned char*)buf, len, (char **)&ciphertext, &ciphertext_len);

      if (alloc_buf) {
        delete [] buf;
      }
      buf = ciphertext;
      len = ciphertext_len;
      alloc_buf = true;

    } else if (strcasecmp(*encoding, "base64") == 0) {
      unbase64((unsigned char*)buf, len, (char **)&ciphertext, &ciphertext_len);
      if (alloc_buf) {
        delete [] buf;
      }
      buf = ciphertext;
      len = ciphertext_len;
      alloc_buf = true;

    } else if (strcasecmp(*encoding, "binary") == 0) {
      // Binary - do nothing

    } else {
      fprintf(stderr, "node-crypto : Decipher .update encoding "
                      "can be binary, hex or base64\n");
    }
  }

  unsigned char *out=0;
  int out_len=0;
  int r = cipher->DecipherUpdate(buf, len, &out, &out_len);

  if (!r) {
    delete [] out;
    Local<Value> exception = Exception::TypeError(String::New("DecipherUpdate fail"));
    return ThrowException(exception);
  }

  Local<Value> outString;
  if (out_len==0) {
    outString=String::New("");
  } else if (args.Length() <= 2 || !args[2]->IsString()) {
    outString = Encode(out, out_len, BINARY);
  } else {
    enum encoding enc = ParseEncoding(args[2]);
    if (enc == UTF8) {
      // See if we have any overhang from last utf8 partial ending
      if (cipher->incomplete_utf8!=NULL) {
        char* complete_out = new char[cipher->incomplete_utf8_len + out_len];
        memcpy(complete_out, cipher->incomplete_utf8, cipher->incomplete_utf8_len);
        memcpy((char *)complete_out+cipher->incomplete_utf8_len, out, out_len);
        delete [] out;

        delete [] cipher->incomplete_utf8;
        cipher->incomplete_utf8 = NULL;

        out = (unsigned char*)complete_out;
        out_len += cipher->incomplete_utf8_len;
      }
      // Check to see if we have a complete utf8 stream
      int utf8_len = LengthWithoutIncompleteUtf8((char *)out, out_len);
      if (utf8_len<out_len) { // We have an incomplete ut8 ending
        cipher->incomplete_utf8_len = out_len-utf8_len;
        cipher->incomplete_utf8 = new unsigned char[cipher->incomplete_utf8_len+1];
        memcpy(cipher->incomplete_utf8, &out[utf8_len], cipher->incomplete_utf8_len);
      }
      outString = Encode(out, utf8_len, enc);
    } else {
      outString = Encode(out, out_len, enc);
    }
  }

  if (out) delete [] out;

  if (alloc_buf) delete [] buf;
  return scope.Close(outString);

}



int Decipher::DecipherFinal(unsigned char** out, int *out_len, bool tolerate_padding) {
  if (!initialised_) return 0;
  *out = new unsigned char[EVP_CIPHER_CTX_block_size(ctx)];
  if (tolerate_padding) {
    local_EVP_DecryptFinal_ex(ctx,*out,out_len);
  } else {
    EVP_CipherFinal(ctx,*out,out_len);
  }
  EVP_CIPHER_CTX_cleanup(ctx);
  initialised_ = false;
  return 1;
}


Handle<Value> Decipher::DecipherFinal(const Arguments& args) {
  HandleScope scope;

  Decipher *cipher = ObjectWrap::Unwrap<Decipher>(args.This());

  unsigned char* out_value;
  int out_len;
  Local<Value> outString;

  int r = cipher->DecipherFinal(&out_value, &out_len, false);

  if (out_len == 0 || r == 0) {
    return scope.Close(String::New(""));
  }


  if (args.Length() == 0 || !args[0]->IsString()) {
    outString = Encode(out_value, out_len, BINARY);
  } else {
    enum encoding enc = ParseEncoding(args[0]);
    if (enc == UTF8) {
      // See if we have any overhang from last utf8 partial ending
      if (cipher->incomplete_utf8!=NULL) {
        char* complete_out = new char[cipher->incomplete_utf8_len + out_len];
        memcpy(complete_out, cipher->incomplete_utf8, cipher->incomplete_utf8_len);
        memcpy((char *)complete_out+cipher->incomplete_utf8_len, out_value, out_len);

        delete [] cipher->incomplete_utf8;
        cipher->incomplete_utf8=NULL;

        outString = Encode(complete_out, cipher->incomplete_utf8_len+out_len, enc);
        delete [] complete_out;
      } else {
        outString = Encode(out_value, out_len, enc);
      }
    } else {
      outString = Encode(out_value, out_len, enc);
    }
  }
  delete [] out_value;
  return scope.Close(outString);
}

Handle<Value> Decipher::DecipherFinalTolerate(const Arguments& args) {
  Decipher *cipher = ObjectWrap::Unwrap<Decipher>(args.This());

  HandleScope scope;

  unsigned char* out_value;
  int out_len;
  Local<Value> outString ;

  int r = cipher->DecipherFinal(&out_value, &out_len, true);

  if (out_len == 0 || r == 0) {
    delete [] out_value;
    return scope.Close(String::New(""));
  }


  if (args.Length() == 0 || !args[0]->IsString()) {
    outString = Encode(out_value, out_len, BINARY);
  } else {
    enum encoding enc = ParseEncoding(args[0]);
    if (enc == UTF8) {
      // See if we have any overhang from last utf8 partial ending
      if (cipher->incomplete_utf8!=NULL) {
        char* complete_out = new char[cipher->incomplete_utf8_len + out_len];
        memcpy(complete_out, cipher->incomplete_utf8, cipher->incomplete_utf8_len);
        memcpy((char *)complete_out+cipher->incomplete_utf8_len, out_value, out_len);

        delete [] cipher->incomplete_utf8;
        cipher->incomplete_utf8 = NULL;

        outString = Encode(complete_out, cipher->incomplete_utf8_len+out_len, enc);
        delete [] complete_out;
      } else {
        outString = Encode(out_value, out_len, enc);
      }
    } else {
      outString = Encode(out_value, out_len, enc);
    }
  }
  delete [] out_value;
  return scope.Close(outString);
}





Decipher::Decipher() : ObjectWrap() {
  initialised_ = false;
  ctx = EVP_CIPHER_CTX_new();
}

Decipher::~Decipher() {
  EVP_CIPHER_CTX_cleanup(ctx);
  OPENSSL_free(ctx);
}


// local decrypt final without strict padding check
// to work with php mcrypt
// see http://www.mail-archive.com/openssl-dev@openssl.org/msg19927.html
int local_EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx,
                              unsigned char *out,
                              int *outl) {
  int i,b;
  int n;

  *outl=0;
  b=ctx->cipher->block_size;

  if (ctx->flags & EVP_CIPH_NO_PADDING) {
    if(ctx->buf_len) {
      EVPerr(EVP_F_EVP_DECRYPTFINAL,EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH);
      return 0;
    }
    *outl = 0;
    return 1;
  }

  if (b > 1) {
    if (ctx->buf_len || !ctx->final_used) {
      EVPerr(EVP_F_EVP_DECRYPTFINAL,EVP_R_WRONG_FINAL_BLOCK_LENGTH);
      return(0);
    }

    if (b > (int)(sizeof(ctx->final) / sizeof(ctx->final[0]))) {
      EVPerr(EVP_F_EVP_DECRYPTFINAL,EVP_R_BAD_DECRYPT);
      return(0);
    }

    n=ctx->final[b-1];

    if (n > b) {
      EVPerr(EVP_F_EVP_DECRYPTFINAL,EVP_R_BAD_DECRYPT);
      return(0);
    }

    for (i=0; i<n; i++) {
      if (ctx->final[--b] != n) {
        EVPerr(EVP_F_EVP_DECRYPTFINAL,EVP_R_BAD_DECRYPT);
        return(0);
      }
    }

    n=ctx->cipher->block_size-n;

    for (i=0; i<n; i++) {
      out[i]=ctx->final[i];
    }
    *outl=n;
  } else {
    *outl=0;
  }

  return(1);
}



