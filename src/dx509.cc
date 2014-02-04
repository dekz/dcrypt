#include "dx509.h"
Persistent<FunctionTemplate> DX509::constructor;

void DX509::Initialize(Handle<Object> target) {
  HandleScope scope;

  constructor = Persistent<FunctionTemplate>::New(FunctionTemplate::New(DX509::New));
  constructor->InstanceTemplate()->SetInternalFieldCount(1);
  constructor->SetClassName(String::NewSymbol("X509"));

  NODE_SET_PROTOTYPE_METHOD(constructor, "parse", parseCert);
  NODE_SET_PROTOTYPE_METHOD(constructor, "createCert", createCert);
  NODE_SET_PROTOTYPE_METHOD(constructor, "signCert", signCert);
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
  //Clean me up
  //load_cert is loading into the dx509 private x509, but is also returning the same object it should only do the former
  int ok = dx509->load_cert(cert_buf, cert_len, 1, &dx509->x509_);
  X509* x = dx509->x509_;

  EVP_PKEY *pkey;
  pkey = X509_get_pubkey(x);

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
  Persistent<String> pubkey_pem_symbol = NODE_PSYMBOL("public_key_pem");
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

  //Version
  long l;
  l = X509_get_version(x)+1;
  info->Set(version_symbol, Integer::New(l));

  //Serial
  //ASN1_INTEGER *bs = X509_get_serialNumber(x);
  //for (int i = 0; i< bs->length; i++) {
  //  BIO_printf(bio, "%02x%s", bs->data[i], ((i+1 == bs->length)? "": ":"));
  //}
  //BIO_read(bio, buf, sizeof(buf)-1);
  ASN1_INTEGER *asn1_i = X509_get_serialNumber(x);
  BIGNUM *bignum = ASN1_INTEGER_to_BN(asn1_i, NULL);
  char *hex = BN_bn2hex(bignum);
  info->Set(serial_symbol, String::New(hex));

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

  //Public Key Info cont.
  //Setup a key info subobject
  Local<String> pub_str;
  BIO *key_info_bio = BIO_new(BIO_s_mem());
  if (pkey->type == EVP_PKEY_DSA) {
    DSA *dsa = EVP_PKEY_get1_DSA(pkey);
    pub_str = String::New("");

    DSA_free(dsa);
  } else if (pkey->type == EVP_PKEY_RSA) {
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    int mod_len = BN_num_bits(rsa->n);

    size_t buf_len = 0;    
    dx509->update_buf_len(rsa->n, &buf_len);
    // dx509->update_buf_len(rsa->e, &buf_len);

    unsigned char *m = (unsigned char *) OPENSSL_malloc(buf_len+10);
    int n;
    n=BN_bn2bin(rsa->n,&m[0]);
    //00: out the front
    BIO_printf(key_info_bio, "%02x:", 0);
    for (int i=0; i<n; i++) {
      BIO_printf(key_info_bio, "%02x%s", m[i],((i+1) == n) ? "":":");
    }
    char key_info_buf[(n+1)*3];
    BIO_read(key_info_bio, key_info_buf, sizeof(key_info_buf)-1);
    key_info_buf[sizeof(key_info_buf)-1]=NULL;
    pub_str = String::New(key_info_buf);
    OPENSSL_free(m);

    RSA_free(rsa);
  } else if (pkey->type == EVP_PKEY_EC) {
#ifndef WITH_ECDSA
    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    pub_str = String::New("");

    EC_KEY_free(ec_key);
#endif
  } else {
    pub_str = String::New("");
  }
  if (key_info_bio != NULL) BIO_free(key_info_bio);

  info->Set(pubkey_symbol, pub_str);

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
  if (n1>0) {
    s = sigh->data;
    for (int i=0; i<n1; i++) {
      BIO_printf(sig_bio, "%02x%s", s[i], ((i+1) == n1) ? "":":");
    }
    char sig_buf [n1*3];
    BIO_read(sig_bio, sig_buf, sizeof(sig_buf)-1);
    info->Set(signature_symbol, String::New(sig_buf));
  } else {
    info->Set(signature_symbol, String::New(""));
  }

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

  //Pub key in pem format
  BIO *key_bio = BIO_new(BIO_s_mem());
  ok = PEM_write_bio_PUBKEY(key_bio, pkey);
  if (ok) {
    BUF_MEM *bptr;
    BIO_get_mem_ptr(key_bio, &bptr);
    char *pub_buf = (char *)malloc(bptr->length +1);
    memcpy(pub_buf, bptr->data, bptr->length-1);
    pub_buf[bptr->length-1] = 0;
    info->Set(pubkey_pem_symbol, String::New(pub_buf));
    delete [] pub_buf;
    BIO_free(key_bio);
  }

  EVP_PKEY_free(pkey);
  delete [] cert_buf;
  if (bio != NULL) BIO_free(bio);
  return scope.Close(info);
}

int DX509::load_cert(char *cert, int cert_len, int format, X509** x509p) {
  BIO *bp = BIO_new_mem_buf(cert, cert_len);
  X509* x;
  if ((x509p == NULL) || (*x509p == NULL)) {
    x = X509_new();
  } else {
    x = *x509p;
  }

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
  x509_ = x;
  *x509p = x;
  return 1;
}

int DX509::load_private_key(char *pkey_buf, int pkey_len, EVP_PKEY **pkey) {
  BIO *bp = BIO_new_mem_buf(pkey_buf, pkey_len);
  EVP_PKEY *key;

  key = PEM_read_bio_PrivateKey(bp, NULL, NULL, NULL);

  if (key == NULL) {
    // ERR_print_errors(stderr);
  }
  if (bp != NULL) {
    BIO_free(bp);
  }
  *pkey = key;
  return 1;
}

DX509::DX509() : ObjectWrap() {
  //x509_ = X509_new();
}

DX509::~DX509() {
  //fprintf(stderr, "Destructor called\n");
  X509_free(x509_);
}

int DX509::update_buf_len(const BIGNUM *b, size_t *pbuflen) {
	size_t i;
	if (!b)
		return 0;
	if (*pbuflen < (i = (size_t)BN_num_bytes(b)))
			*pbuflen = i;
}

Handle<Value> DX509::createCert(const Arguments &args) {
  HandleScope scope;
  DX509 *dx509 = ObjectWrap::Unwrap<DX509>(args.This());
  if (args.Length()<4) {
    return ThrowException(Exception::Error(String::New("createCert requires 4 arguments.")));
  }
  // .createCert(bitSize, days, subject, extensions);
  int bitSize = args[0]->Int32Value();
  int days = args[1]->Int32Value();
  Local<Object> subject = args[2]->ToObject();
  Local<Object> extensions = args[3]->ToObject();

  X509 *x = NULL;
  EVP_PKEY *pkey = NULL;
  int ok = dx509->make_cert(&x, 0, bitSize, &pkey, days);

  Local<Array> subject_keys = subject->GetPropertyNames();
  for (int i=0,l=subject_keys->Length();i<l;i++) {
    String::Utf8Value key(subject_keys->Get(Integer::New(i)));
    String::Utf8Value value(subject->Get(String::New(*key)));
    dx509->add_entry(x, *key, *value);
  }
 
  Handle<Array> ext_keys = extensions->GetPropertyNames();
  for (int i=0,l=ext_keys->Length();i<l;i++) {
    String::Utf8Value key(ext_keys->Get(i));
    String::Utf8Value value(extensions->Get(String::New(*key)));
    dx509->add_ext(x, *key, *value);
  }

  BUF_MEM *bptr;

  BIO *bp = BIO_new(BIO_s_mem());
  ok =PEM_write_bio_X509(bp, x);
  Local<String> x509_str = String::New("");
  if (ok) {
    BIO_get_mem_ptr(bp, &bptr);
    char *x509_buf = (char *) malloc(bptr->length+1);
    memcpy(x509_buf, bptr->data, bptr->length-1);
    x509_buf[bptr->length-1] = 0;
    x509_str = String::New(x509_buf);
    free(x509_buf);
  }
  if (bp != NULL) BIO_free(bp);

  bp = BIO_new(BIO_s_mem());
  ok = PEM_write_bio_PrivateKey(bp, pkey, NULL, NULL, 0, NULL, NULL);
  Local<String> pkey_str = String::New("");
  if (ok) {
    BIO_get_mem_ptr(bp, &bptr);
    char *pkey_buf = (char *) malloc(bptr->length+1);
    memcpy(pkey_buf, bptr->data, bptr->length-1);
    pkey_buf[bptr->length-1] = 0;
    pkey_str = String::New(pkey_buf);
    free(pkey_buf);
  }
  if (bp != NULL) BIO_free(bp);

  dx509->x509_ = x;
  if (pkey != NULL) EVP_PKEY_free(pkey);

  Local<Object> cert_obj = Object::New();
  cert_obj->Set(String::New("x509"), x509_str);
  cert_obj->Set(String::New("pkey"), pkey_str);

  return scope.Close(cert_obj);
}

Handle<Value> DX509::signCert(const Arguments &args) { /* ca, ca_pkey */
  HandleScope scope;
  DX509 *dx509 = ObjectWrap::Unwrap<DX509>(args.This());

  ssize_t ca_cert_len = DecodeBytes(args[0], BINARY);
  char* ca_cert_buf = new char[ca_cert_len];
  ssize_t written = DecodeWrite(ca_cert_buf, ca_cert_len, args[0], BINARY);
  assert(ca_cert_len = written);

  ssize_t ca_pkey_len = DecodeBytes(args[1], BINARY);
  char* ca_pkey_buf = new char[ca_pkey_len];
  written = DecodeWrite(ca_pkey_buf, ca_pkey_len, args[1], BINARY);
  assert(ca_pkey_len = written);

  X509 * saved_cert = dx509->x509_;
  X509 * ca = NULL;
  int ok = dx509->load_cert(ca_cert_buf, ca_cert_len, 1, &ca);
  dx509->x509_ = saved_cert;

  EVP_PKEY *ca_pkey = NULL;
  ok = dx509->load_private_key(ca_pkey_buf, ca_pkey_len, &ca_pkey);

  ok = dx509->sign_cert(&dx509->x509_, ca, ca_pkey);

  if (ca != NULL) X509_free(ca);
  if (ca_pkey != NULL) EVP_PKEY_free(ca_pkey);

  BUF_MEM *bptr;
  BIO *bp = BIO_new(BIO_s_mem());
  ok =PEM_write_bio_X509(bp, dx509->x509_);

  Local<String> x509_str = String::New("");
  if (ok) {
    BIO_get_mem_ptr(bp, &bptr);
    char *x509_buf = (char *) malloc(bptr->length+1);
    memcpy(x509_buf, bptr->data, bptr->length-1);
    x509_buf[bptr->length-1] = 0;
    x509_str = String::New(x509_buf);
    free(x509_buf);
  }
  if (bp != NULL) BIO_free(bp);

  return scope.Close(x509_str);
}

int DX509::make_cert(X509 **x509p, int type, long bits, EVP_PKEY **pkeyp, int days) {
  X509 *x;
  EVP_PKEY *pk;
  RSA *rsa;
  X509_NAME *name = NULL;

  //Use the key we're given, if we aren't given one then allocate
  if ((pkeyp == NULL) || (*pkeyp == NULL)) {
    if ((pk = EVP_PKEY_new()) == NULL) {
      return -1;
    }
  } else {
    pk = *pkeyp;
  }

  //Setup or use given x509
  if ((x509p == NULL) || (*x509p == NULL)) {
    if ((x=X509_new()) == NULL) {
      return -1;
    }
  } else {
    x = *x509p;
  }

  rsa=RSA_generate_key(bits, RSA_F4, NULL, NULL);
  if (!EVP_PKEY_assign_RSA(pk, rsa)) {
    return -1;
  }
  rsa = NULL;
  X509_set_version(x, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(x), 65535);
  X509_gmtime_adj(X509_get_notBefore(x), 0);
  X509_gmtime_adj(X509_get_notAfter(x), (long)60*60*24*days);
  X509_set_pubkey(x, pk);
 
  *x509p = x;
  *pkeyp = pk;
  return 1;
}

void DX509::add_entry(X509 *x509, const char* key, const char* value) {
  X509_NAME *name = X509_get_subject_name(x509);
  X509_NAME_add_entry_by_txt(name, key, MBSTRING_UTF8, (const unsigned char*)value, -1, -1, 0);
}

int DX509::add_ext(X509 *cert, char*key, char *value) {
  X509_EXTENSION *ex;
  X509V3_CTX ctx;
  /* This sets the 'context' of the extensions. */
  /* No configuration database */
  X509V3_set_ctx_nodb(&ctx);
  /* Issuer and subject certs: both the target since it is self signed,
   * no request and no CRL
   */
  X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
  ex = X509V3_EXT_conf(NULL, &ctx, key, value); // is this UTF8? I hope so. XXX
  if (!ex)
    return 0;

  X509_add_ext(cert,ex,-1);
  X509_EXTENSION_free(ex);
  return 1;
}


int DX509::sign_cert(X509 **cert, X509 *ca, EVP_PKEY *ca_pkey) {
  EVP_PKEY *pk;
  X509_NAME *ca_name = NULL;

  ca_name = X509_get_subject_name(ca);
  X509_set_issuer_name(*cert, ca_name);

  if (!X509_sign(*cert, ca_pkey, EVP_sha1())) {
    return -1;
  }
  return 1;
}
