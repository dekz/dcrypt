#include "hash.h"

Persistent<FunctionTemplate> Hash::constructor;

void Hash::Initialize(Handle<Object> target) {
  HandleScope scope;

  constructor = Persistent<FunctionTemplate>::New(FunctionTemplate::New(Hash::New));
  constructor->InstanceTemplate()->SetInternalFieldCount(1);
  constructor->SetClassName(String::NewSymbol("Hash"));

  NODE_SET_PROTOTYPE_METHOD(constructor, "update", Hash::HashUpdate);
  NODE_SET_PROTOTYPE_METHOD(constructor, "digest", Hash::HashDigest);
  Local<ObjectTemplate> proto = constructor->PrototypeTemplate();

  target->Set(String::NewSymbol("Hash"), constructor->GetFunction());

}

Handle<Value> Hash::New(const Arguments &args) {
  HandleScope scope;

  if (args.Length() == 0 || !args[0]->IsString()) {
    return ThrowException(Exception::Error(String::New(
      "Must give hashtype string as argument")));
  }

  Hash *hash = new Hash();
  hash->Wrap(args.This());

  String::Utf8Value hashType(args[0]->ToString());

  hash->HashInit(*hashType, args);

  return args.This();
}

bool Hash::HashInit(const char *hashType, const Arguments &args) {
  md = EVP_get_digestbyname(hashType);
  if(!md) {
    fprintf(stderr, "Unknown message digest %s\n", hashType);
    return false;
  }

  EVP_MD_CTX_init(mdctx);
  int ok = EVP_DigestInit_ex(mdctx, md, NULL);

  if (!ok) {
    ThrowException(Exception::Error(String::New("Error Initilisaing digest from openssl"))); 
  }

  initialised_ = true;
  return true;
}

int Hash::HashUpdate(char* data, int len) {
  // if (!initialised_) return 0;
  if (!initialised_) {
   int ok = EVP_DigestInit_ex(mdctx, md, NULL); 
   if (!ok) {
     ThrowException(Exception::Error(String::New("Error reinit ctx")));
     return 0;
   }
   initialised_ = true;
  }

  int ok = EVP_DigestUpdate(mdctx, data, len);
  if (!ok) {
    ThrowException(Exception::Error(String::New("Error Updating digest from openssl"))); 
  }
  return 1;
}

Handle<Value> Hash::HashUpdate(const Arguments &args) {
  HandleScope scope;

  Hash *hash = ObjectWrap::Unwrap<Hash>(args.This());

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
    r = hash->HashUpdate(buffer_data, buffer_length);
  } else {
    char* buf = new char[len];
    ssize_t written = DecodeWrite(buf, len, args[0], enc);
    assert(written == len);
    r = hash->HashUpdate(buf, len);
    delete[] buf;
  }

  if (!r) {
    Local<Value> exception = Exception::TypeError(String::New("HashUpdate fail"));
    return ThrowException(exception);
  }

  return args.This();
}

Handle<Value> Hash::HashDigest(const Arguments &args) {
  HandleScope scope;

  Hash *hash = ObjectWrap::Unwrap<Hash>(args.This());

  if (!hash->initialised_) {
    return ThrowException(Exception::Error(String::New("Not initialized")));
  }

  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len;

  EVP_DigestFinal_ex(hash->mdctx, md_value, &md_len);
  EVP_MD_CTX_cleanup(hash->mdctx);
  hash->initialised_ = false;

  if (md_len == 0) {
    return scope.Close(String::New(""));
  }

  Local<Value> outString;

  if (args.Length() == 0 || !args[0]->IsString()) {
    // Binary
    outString = Encode(md_value, md_len, BINARY);
  } else {
    String::Utf8Value encoding(args[0]->ToString());
    if (strcasecmp(*encoding, "hex") == 0) {
      // Hex encoding
      char* md_hexdigest;
      int md_hex_len;
      HexEncode(md_value, md_len, &md_hexdigest, &md_hex_len);
      outString = Encode(md_hexdigest, md_hex_len, BINARY);
      delete [] md_hexdigest;
    } else if (strcasecmp(*encoding, "base64") == 0) {
      char* md_hexdigest;
      int md_hex_len;
      base64(md_value, md_len, &md_hexdigest, &md_hex_len);
      outString = Encode(md_hexdigest, md_hex_len, BINARY);
      delete [] md_hexdigest;
    } else if (strcasecmp(*encoding, "binary") == 0) {
      outString = Encode(md_value, md_len, BINARY);
    } else {
      fprintf(stderr, "node-crypto : Hash .digest encoding "
                      "can be binary, hex or base64\n");
    }
  }

  return scope.Close(outString);
}

Hash::Hash() : ObjectWrap() {
  initialised_ = false;
  mdctx = EVP_MD_CTX_create();
}

Hash::~Hash() {}
