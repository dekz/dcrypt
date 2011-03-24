#include "common.h"
#include "random.h"
#include "hash.h"
#include "sign.h"
#include "verify.h"
#include "keypair.h"

#include <v8.h>
#include <node.h>
#include <node_object_wrap.h>

using namespace v8;
using namespace node;

extern "C" {
  static void init(Handle<Object> target) {
    Random::Initialize(target);
    Hash::Initialize(target);
    Sign::Initialize(target);
    Verify::Initialize(target);
    KeyPair::Initialize(target);
  }
  NODE_MODULE(dcrypt, init);
}

