//Not happy with this name btw
#ifndef __NODE_DCRYPT_ENCODE_H__
#define __NODE_DCRYPT_ENCODE_H__

#include <v8.h>
#include <node.h>
#include <node_object_wrap.h>
#include <node_buffer.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "common.h"

using namespace v8;
using namespace node;

class Encode: node::ObjectWrap {
  public:
    static Persistent<FunctionTemplate> constructor;
    static void Initialize(Handle<Object> target);
    Encode();
    static const char* pszBase58() {
      return "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"; 
    }

  protected:
    static Handle<Value> New(const Arguments &args);
    static Handle<Value> EncodeBase58(const Arguments &args);
    static Handle<Value> DecodeBase58(const Arguments &args);

  private:
    ~Encode();
};
#endif
    
  

