#ifndef __NODE_DCRYPT_DRSA_H__
#define __NODE_DCRYPT_DRSA_H__

#include <v8.h>
#include <node.h>
#include <node_object_wrap.h>
#include <node_buffer.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "common.h"

using namespace v8;
using namespace node;

class DRSA: node::ObjectWrap {
  public:
    static Persistent<FunctionTemplate> constructor;
    static void Initialize(Handle<Object> target);

    DRSA();

  protected:
    static Handle<Value> New(const Arguments &args);
    static Handle<Value> RSAEncrypt(const Arguments &args);
    static Handle<Value> RSADecrypt(const Arguments &args);
  private:
    ~DRSA();
};
#endif
