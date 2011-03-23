#ifndef __NODE_DCRYPT_HASH_H__
#define __NODE_DCRYPT_HASH_H__

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

class Hash: node::ObjectWrap {
  public:
    static Persistent<FunctionTemplate> constructor;
    static void Initialize(Handle<Object> target);
    bool HashInit(const char *hashType, const Arguments &args);
    int HashUpdate(char *data, int len);
    Hash();

  protected:
    static Handle<Value> New(const Arguments &args);
    static Handle<Value> HashUpdate(const Arguments &args);
    static Handle<Value> HashDigest(const Arguments &args);

  private:
    EVP_MD_CTX *mdctx; /* coverity[member_decl] */
    const EVP_MD *md; /* coverity[member_decl] */
    bool initialised_;
    ~Hash();

};

#endif

