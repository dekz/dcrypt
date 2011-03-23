#ifndef __NODE_DCRYPT_VERIFY_H__
#define __NODE_DCRYPT_VERIFY_H__

#include <v8.h>
#include <node.h>
#include <node_object_wrap.h>
#include <node_buffer.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "common.h"


using namespace v8;
using namespace node;

class Verify : node::ObjectWrap {
  public:
    static Persistent<FunctionTemplate> constructor;
    static void Initialize(Handle<Object> target);
    bool VerifyInit(const char *verifyType);
    int VerifyUpdate(char *data, int len);
    int VerifyFinal(char *key_pem, int key_pemLen, unsigned char *sig, int sigLen);
    Verify();

  protected:
    static Handle<Value> New(const Arguments &args);
    static Handle<Value> VerifyInit(const Arguments& args);
    static Handle<Value> VerifyUpdate(const Arguments& args);
    static Handle<Value> VerifyFinal(const Arguments& args);
    ~Verify();
  
  private:
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    bool initialised_;
    
};

#endif

