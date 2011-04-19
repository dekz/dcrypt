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
  Persistent<String> serial_symbol    = NODE_PSYMBOL("serial");
  Persistent<String> subject_symbol    = NODE_PSYMBOL("subject");
  Persistent<String> issuer_symbol     = NODE_PSYMBOL("issuer");
  Persistent<String> valid_from_symbol = NODE_PSYMBOL("valid_from");
  Persistent<String> valid_to_symbol   = NODE_PSYMBOL("valid_to");
  Persistent<String> fingerprint_symbol   = NODE_PSYMBOL("fingerprint");
  Persistent<String> name_symbol       = NODE_PSYMBOL("name");
  Persistent<String> version_symbol    = NODE_PSYMBOL("version");
  Persistent<String> ext_key_usage_symbol = NODE_PSYMBOL("ext_key_usage");
  Persistent<String> signature_algo_symbol = NODE_PSYMBOL("signature_algorithm");
  Persistent<String> signature_symbol = NODE_PSYMBOL("signature");
  Persistent<String> pubkey_symbol = NODE_PSYMBOL("public_key");
  Persistent<String> public_key_algo = NODE_PSYMBOL("public_key_algo");
  Local<Object> info = Object::New();

  //subject name
  char *details = X509_NAME_oneline(X509_get_subject_name(x), 0, 0);
  info->Set(subject_symbol, String::New(details));

  //issuer name
  details = X509_NAME_oneline(X509_get_issuer_name(x), 0, 0);
  info->Set(issuer_symbol, String::New(details));
  OPENSSL_free(details);

  char buf [256];
  BIO* bio = BIO_new(BIO_s_mem());
  memset(buf, 0, sizeof(buf));
  X509_CINF *ci = x->cert_info;

  //Serial
  i2a_ASN1_INTEGER(bio, X509_get_serialNumber(x));
  BIO_read(bio, buf, sizeof(buf)-1);
  info->Set(serial_symbol, String::New(buf));

  //Version
  long l;
  l = X509_get_version(x)+1;
  info->Set(version_symbol, Integer::New(l));
  
  //valid from
  ASN1_TIME_print(bio, X509_get_notBefore(x));
  BIO_read(bio, buf, sizeof(buf)-1);
  info->Set(valid_from_symbol, String::New(buf));

  //Not before
  ASN1_TIME_print(bio, X509_get_notAfter(x));
  BIO_read(bio, buf, sizeof(buf)-1);
  info->Set(valid_to_symbol, String::New(buf));

  //Public Key info
  int wrote = i2a_ASN1_OBJECT(bio, ci->key->algor->algorithm);
  BIO_read(bio, buf, sizeof(buf)-1);
  buf[wrote] = '\0';
  info->Set(public_key_algo, String::New(buf));

  //Signature Algorithm
  wrote = i2a_ASN1_OBJECT(bio, ci->signature->algorithm);
  BIO_read(bio, buf, sizeof(buf)-1);
  buf[wrote] = '\0';
  info->Set(signature_algo_symbol, String::New(buf));
  
  //Signature
  BIO *sig_bio = BIO_new(BIO_s_mem());
  ASN1_STRING *sigh = x->signature; 
  unsigned char *s;
  unsigned int n1 = sigh->length;
  s = sigh->data;
  for (int i=0; i<n1; i++) {
    BIO_printf(sig_bio, "%02x%s", s[i], ((i+1) == n1) ? "":":");
  }
  char sig_buf [n1*3];
  BIO_read(sig_bio, sig_buf, sizeof(sig_buf)-1);
  info->Set(signature_symbol, String::New(sig_buf));

  //finger print
  int j;
  unsigned int n;
  unsigned char md[EVP_MAX_MD_SIZE];
  const EVP_MD *fdig = EVP_sha1();
  if (X509_digest(x, fdig, md, &n)) {
    const char hex[] = "0123456789ABCDEF";
    char fingerprint[EVP_MAX_MD_SIZE*3];
    for (j=0; j<n; j++) {
      fingerprint[3*j] = hex[(md[j] & 0xf0) >> 4];
      fingerprint[(3*j)+1] = hex[(md[j] & 0x0f)];
      fingerprint[(3*j)+2] = ':';
    }

    if (n > 0) {
      fingerprint[(3*(n-1))+2] = '\0';
    } else {
      fingerprint[0] = '\0';
    }
    info->Set(fingerprint_symbol, String::New(fingerprint));
  } else {
    fprintf(stderr, "Digest bad\n");
  }
 
  //Extensions
  STACK_OF(ASN1_OBJECT) *eku = (STACK_OF(ASN1_OBJECT) *)X509_get_ext_d2i(
      x, NID_ext_key_usage, NULL, NULL);
  if (eku != NULL) {
    Local<Array> ext_key_usage = Array::New();

    for (int i = 0; i < sk_ASN1_OBJECT_num(eku); i++) {
      memset(buf, 0, sizeof(buf));
      OBJ_obj2txt(buf, sizeof(buf) - 1, sk_ASN1_OBJECT_value(eku, i), 1);
      ext_key_usage->Set(Integer::New(i), String::New(buf));
    }
    sk_ASN1_OBJECT_pop_free(eku, ASN1_OBJECT_free);
    info->Set(ext_key_usage_symbol, ext_key_usage);
  }

  EVP_PKEY *pkey;
  pkey = X509_get_pubkey(x);
  BIO *key_bio = BIO_new(BIO_s_mem());
  int ok = PEM_write_bio_PUBKEY(key_bio, pkey);
  if (ok) {
    BUF_MEM *bptr;
    BIO_get_mem_ptr(key_bio, &bptr);
    char *pub_buf = (char *)malloc(bptr->length +1);
    memcpy(pub_buf, bptr->data, bptr->length-1);
    pub_buf[bptr->length-1] = 0;
    info->Set(pubkey_symbol, String::New(pub_buf));
    delete [] pub_buf;
    BIO_free(key_bio);
  }


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
