#ifndef __NODE_DCRYPT_HMAC_H__
#define __NODE_DCRYPT_HMAC_H__

#include <v8.h>
#include <node.h>
#include <node_object_wrap.h>
#include <node_buffer.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "common.h"

using namespace v8;
using namespace node;


class Hmac: node::ObjectWrap {
  public:
    static Persistent<FunctionTemplate> constructor;
    static void Initialize(Handle<Object> target);
    int HmacDigest(unsigned char **md_value, unsigned int *md_len);
    bool HmacInit(char *hashType, char *key, int key_len);
    int HmacUpdate(char *data, int len);
    Hmac();
  protected:
    static Handle<Value> New(const Arguments &args);
    static Handle<Value> HmacInit(const Arguments &args);
    static Handle<Value> HmacUpdate(const Arguments &args);
    static Handle<Value> HmacDigest(const Arguments &args);

  private:
    ~Hmac();
    HMAC_CTX *ctx;
    const EVP_MD *md;
    bool initialised_;
};
#endif
