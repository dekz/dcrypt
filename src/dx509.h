#ifndef __NODE_DCRYPT_X509_H__
#define __NODE_DCRYPT_X509_H__

#include <v8.h>
#include <node.h>
#include <node_object_wrap.h>
#include <node_buffer.h>

#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "common.h"

using namespace v8;
using namespace node;

class DX509: node::ObjectWrap {
  public:
    static Persistent<FunctionTemplate> constructor;
    static void Initialize(Handle<Object> target);
    // int mkcert(X509 **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days);
    // int add_ext(X509 *cert, int nid, char *value);
    // int parseCert();
    int load_cert(char *cert, int cert_len, int format, X509** x509p);
    DX509();

  protected:
    static Handle<Value> parseCert(const Arguments &args);
    static Handle<Value> New(const Arguments &args);
    static Handle<Value> createCert(const Arguments &args);
    ~DX509();

  private:
    int update_buf_len(const BIGNUM *b, size_t *pbuflen);
    int make_cert(X509 **x509p, int type, long bits, EVP_PKEY **pkeyp, int days);
    X509* x509_;
};
#endif

