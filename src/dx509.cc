#include "dx509.h"
Persistent<FunctionTemplate> DX509::constructor;

void DX509::Initialize(Handle<Object> target) {
  HandleScope scope;

  constructor = Persistent<FunctionTemplate>::New(FunctionTemplate::New(DX509::New));
  constructor->InstanceTemplate()->SetInternalFieldCount(1);
  constructor->SetClassName(String::NewSymbol("X509"));

  NODE_SET_PROTOTYPE_METHOD(constructor, "parse", parseCert);
  Local<ObjectTemplate> proto = constructor->PrototypeTemplate();

  target->Set(String::NewSymbol("X509"), constructor->GetFunction());
}

Handle<Value> DX509::New(const Arguments &args) {
  HandleScope scope;
  DX509 *x = new DX509();
  x->Wrap(args.This());
  return args.This();
}

Handle<Value> DX509::parseCert(const Arguments &args) {
  HandleScope scope;
  DX509 *dx509 = ObjectWrap::Unwrap<DX509>(args.This());

  ASSERT_IS_STRING_OR_BUFFER(args[0]);

  ssize_t cert_len = DecodeBytes(args[0], BINARY);
  char* cert_buf = new char[cert_len];
  ssize_t written = DecodeWrite(cert_buf, cert_len, args[0], BINARY);
  assert(cert_len = written);
  X509 *x = dx509->load_cert(cert_buf, cert_len, 1);

  //node symbols
  Persistent<String> subject_symbol    = NODE_PSYMBOL("subject");
  Persistent<String> issuer_symbol     = NODE_PSYMBOL("issuer");
  Persistent<String> valid_from_symbol = NODE_PSYMBOL("valid_from");
  Persistent<String> valid_to_symbol   = NODE_PSYMBOL("valid_to");
  Persistent<String> fingerprint_symbol   = NODE_PSYMBOL("fingerprint");
  Persistent<String> name_symbol       = NODE_PSYMBOL("name");
  Persistent<String> version_symbol    = NODE_PSYMBOL("version");
  Persistent<String> ext_key_usage_symbol = NODE_PSYMBOL("ext_key_usage");
  Persistent<String> signature_symbol = NODE_PSYMBOL("signature_type");
  Local<Object> info = Object::New();

  //subject name
  char *details = X509_NAME_oneline(X509_get_subject_name(x), 0, 0);
  info->Set(subject_symbol, String::New(details));

  details = X509_NAME_oneline(X509_get_issuer_name(x), 0, 0);
  info->Set(issuer_symbol, String::New(details));
  OPENSSL_free(details);

  BIO *bio_stderr = BIO_new_fp(stderr, BIO_NOCLOSE);

  char buf [256];
  //valid from
  BIO* bio = BIO_new(BIO_s_mem());
  ASN1_TIME_print(bio, X509_get_notBefore(x));
  memset(buf, 0, sizeof(buf));
  BIO_read(bio, buf, sizeof(buf) - 1);
  info->Set(valid_from_symbol, String::New(buf));


  //Not before
  ASN1_TIME_print(bio, X509_get_notAfter(x));
  memset(buf, 0, sizeof(buf));
  BIO_read(bio, buf, sizeof(buf)-1);
  info->Set(valid_to_symbol, String::New(buf));
  

  // delete [] buf;
  X509_free(x);
  if (bio != NULL) BIO_free(bio);
  return scope.Close(info);
}

X509* DX509::load_cert(char *cert, int cert_len, int format) {
  BIO *bp = BIO_new_mem_buf(cert, cert_len);
  X509 *x = NULL;
  if (format == 0) {
    x = d2i_X509_bio(bp, NULL);
  } else if (format == 1) {
    x = PEM_read_bio_X509_AUX(bp, NULL, NULL, NULL);
  }

  if (x == NULL) {
    // ERR_print_errors(stderr);
  }
  if (bp != NULL) {
    BIO_free(bp);
  }
  return x;
}

DX509::DX509() : ObjectWrap() {
}

DX509::~DX509() {
}
