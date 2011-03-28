#include "hmac.h"

Persistent<FunctionTemplate> Hmac::constructor;

void Hmac::Initialize(Handle<Object> target) {
  HandleScope scope;

  constructor = Persistent<FunctionTemplate>::New(FunctionTemplate::New(Hmac::New));
  constructor->InstanceTemplate()->SetInternalFieldCount(1);
  constructor->SetClassName(String::NewSymbol("Hmac"));

  NODE_SET_PROTOTYPE_METHOD(constructor, "init", HmacInit);
  NODE_SET_PROTOTYPE_METHOD(constructor, "update", HmacUpdate);
  NODE_SET_PROTOTYPE_METHOD(constructor, "digest", HmacDigest);
  Local<ObjectTemplate> proto = constructor->PrototypeTemplate();

  target->Set(String::NewSymbol("Hmac"), constructor->GetFunction());
}

bool Hmac::HmacInit(char* hashType, char* key, int key_len) {
  md = EVP_get_digestbyname(hashType);
  if(!md) {
    fprintf(stderr, "node-crypto : Unknown message digest %s\n", hashType);
    return false;
  }

  HMAC_CTX_init(ctx);
  HMAC_Init(ctx, key, key_len, md);
  // HMAC_Init_ex(&ctx2, key, key_len, md, NULL);
  initialised_ = true;
  return true;
}

Handle<Value> Hmac::HmacInit(const Arguments& args) {
  Hmac *hmac = ObjectWrap::Unwrap<Hmac>(args.This());

  HandleScope scope;

  if (args.Length() == 0 || !args[0]->IsString()) {
    return ThrowException(Exception::Error(String::New(
      "Must give hashtype string as argument")));
  }

  ASSERT_IS_STRING_OR_BUFFER(args[1]);
  ssize_t len = DecodeBytes(args[1], BINARY);

  if (len < 0) {
    Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
    return ThrowException(exception);
  }

  char* buf = new char[len];
  ssize_t written = DecodeWrite(buf, len, args[1], BINARY);
  assert(written == len);

  String::Utf8Value hashType(args[0]->ToString());

  bool r = hmac->HmacInit(*hashType, buf, len);

  delete [] buf;

  if (!r) {
    return ThrowException(Exception::Error(String::New("hmac error")));
  }

  return args.This();
}


int Hmac::HmacUpdate(char* data, int len) {
  if (!initialised_) return 0;
  HMAC_Update(ctx, (unsigned char*)data, len);
  return 1;
}

Handle<Value> Hmac::HmacUpdate(const Arguments& args) {
  Hmac *hmac = ObjectWrap::Unwrap<Hmac>(args.This());

  HandleScope scope;

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

    r = hmac->HmacUpdate(buffer_data, buffer_length);
  } else {
    char* buf = new char[len];
    ssize_t written = DecodeWrite(buf, len, args[0], enc);
    assert(written == len);
    r = hmac->HmacUpdate(buf, len);
    delete [] buf;
  }

  if (!r) {
    Local<Value> exception = Exception::TypeError(String::New("HmacUpdate fail"));
    return ThrowException(exception);
  }

  return args.This();
}

Handle<Value> Hmac::HmacDigest(const Arguments& args) {
  Hmac *hmac = ObjectWrap::Unwrap<Hmac>(args.This());

  HandleScope scope;

  unsigned char* md_value;
  unsigned int md_len;
  char* md_hexdigest;
  int md_hex_len;
  Local<Value> outString ;

  int r = hmac->HmacDigest(&md_value, &md_len);

  if (md_len == 0 || r == 0) {
    return scope.Close(String::New(""));
  }

  if (args.Length() == 0 || !args[0]->IsString()) {
    // Binary
    outString = Encode(md_value, md_len, BINARY);
  } else {
    String::Utf8Value encoding(args[0]->ToString());
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
      fprintf(stderr, "node-crypto : Hmac .digest encoding "
                      "can be binary, hex or base64\n");
    }
  }
  delete [] md_value;
  return scope.Close(outString);
}


int Hmac::HmacDigest(unsigned char** md_value, unsigned int *md_len) {
  if (!initialised_) return 0;
  *md_value = new unsigned char[EVP_MAX_MD_SIZE];
  HMAC_Final(ctx, *md_value, md_len);
  HMAC_CTX_cleanup(ctx);
  initialised_ = false;
  return 1;
}

Handle<Value> Hmac::New(const Arguments &args) {
  HandleScope scope;

  Hmac *hmac = new Hmac();
  hmac->Wrap(args.This());

  return args.This();
}


Hmac::Hmac() : ObjectWrap() {
  initialised_ = false;
  //FIXME
  ctx = (HMAC_CTX *)OPENSSL_malloc(sizeof(HMAC_CTX)*2);
}

Hmac::~Hmac() {
  HMAC_CTX_cleanup(ctx);
  OPENSSL_free(ctx);
}
