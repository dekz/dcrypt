#include "random.h"

Persistent<FunctionTemplate> Random::constructor;

void Random::Initialize(Handle<Object> target) {
  HandleScope scope;

  constructor = Persistent<FunctionTemplate>::New(FunctionTemplate::New(Random::New));
  constructor->InstanceTemplate()->SetInternalFieldCount(1);
  constructor->SetClassName(String::NewSymbol("Random"));

  NODE_SET_PROTOTYPE_METHOD(constructor, "randomBytes", RandBytes);

  Local<ObjectTemplate> proto = constructor->PrototypeTemplate();

  target->Set(String::NewSymbol("Random"), constructor->GetFunction());

  return;
}

Handle<Value> Random::New(const Arguments &args) {
  HandleScope scope;

  Random* r = new Random();
  r->Wrap(args.This());

  return scope.Close(args.This());
}

Handle<Value> Random::RandBytes(const Arguments &args) {
  HandleScope scope;

  if (!Buffer::HasInstance(args[0])) {
    return ThrowException(Exception::TypeError(String::New("First argument must be of type buffer")));
  }

  Local<Object> buf = args[0]->ToObject();
  char *data = Buffer::Data(buf);
  size_t len = Buffer::Length(buf);

  switch (RAND_bytes((unsigned char*) data, len)) {
    case -1:
      return ThrowException(Exception::Error(String::New("RAND does not support this operation")));
    case 0:
      //get the error code from openssl
      unsigned long code = ERR_get_error();
      return ThrowException(Exception::Error(String::New(ERR_error_string(code, NULL))));
  }

  return scope.Close(Integer::NewFromUnsigned(len));
}

Random::Random() : ObjectWrap() {}
Random::~Random() {}

