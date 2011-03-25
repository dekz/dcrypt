#include "encode.h"

Persistent<FunctionTemplate> Encode::constructor; 

void Encode::Initialize(Handle<Object> target){
  HandleScope scope;

  constructor = Persistent<FunctionTemplate>::New(FunctionTemplate::New(Encode::New));
  constructor->InstanceTemplate()->SetInternalFieldCount(1);
  constructor->SetClassName(String::NewSymbol("Encode"));
  
  NODE_SET_PROTOTYPE_METHOD(constructor, "encodeBase58", EncodeBase58);
  NODE_SET_PROTOTYPE_METHOD(constructor, "decodeBase58", DecodeBase58);
  Local<ObjectTemplate> proto = constructor->PrototypeTemplate();

  target->Set(String::NewSymbol("Encode"), constructor->GetFunction());
}

Handle<Value> Encode::New(const Arguments &args) {
  HandleScope scope;

  Encode *enc = new Encode();
  enc->Wrap(args.This());

  return scope.Close(args.This());
}

Handle<Value> Encode::EncodeBase58(const Arguments &args) {
}

Handle<Value> Encode::DecodeBase58(const Arguments &args) {
}

Encode::Encode() : ObjectWrap() {
}

Encode::~Encode() {
}
