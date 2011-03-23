#ifndef __NODE_DCRYPT_SIGN_H__
#define __NODE_DCRYPT_SIGN_H__

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

class Sign: node::ObjectWrap {
  public:
    static Persistent<FunctionTemplate> constructor;
    static void Initialize(Handle<Object> target);
    bool SignInit(const char *signType);
    int SignUpdate(char *data, int len);
    int SignFinal(unsigned char **md_value, unsigned int *md_len, char *key_pem, int key_pemLen);
    Sign();
    
  protected:
    static Handle<Value> New(const Arguments &args);
    static Handle<Value> SignInit(const Arguments &args);
    static Handle<Value> SignUpdate(const Arguments &args);
    static Handle<Value> SignFinal(const Arguments &args);

  private:
    ~Sign();
    EVP_MD_CTX *mdctx; 
    const EVP_MD *md; 
    bool initialised_;
};

#endif
