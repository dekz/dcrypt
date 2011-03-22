#ifndef __NODE_DCRYPT_RANDOM_H__
#define __NODE_DCRYPT_RANDOM_H__

#include <v8.h>
#include <node.h>
#include <node_object_wrap.h>
#include <node_buffer.h>
#include <openssl/rand.h>
#include <openssl/err.h>

using namespace v8;
using namespace node;

class Random: node::ObjectWrap {
  public:
    static Persistent<FunctionTemplate> constructor;
    static void Initialize(Handle<Object> target);
    static Handle<Value> New(const Arguments &args);
    static Handle<Value> RandBytes(const Arguments &args);

    Random();
  private:
    ~Random();
};

#endif
