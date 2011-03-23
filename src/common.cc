#include "common.h"

void HexEncode(unsigned char *md_value,
                      int md_len,
                      char** md_hexdigest,
                      int* md_hex_len) {
  *md_hex_len = (2*(md_len));
  *md_hexdigest = new char[*md_hex_len + 1];
  for (int i = 0; i < md_len; i++) {
    snprintf((char *)(*md_hexdigest + (i*2)), 3, "%02x",  md_value[i]);
  }
}

void HexDecode(unsigned char *input,
                      int length,
                      char** buf64,
                      int* buf64_len) {
  *buf64_len = (length/2);
  *buf64 = new char[length/2 + 1];
  char *b = *buf64;
  for(int i = 0; i < length-1; i+=2) {
    b[i/2]  = (hex2i(input[i])<<4) | (hex2i(input[i+1]));
  }
}

void base64(unsigned char *input, int length, char** buf64, int* buf64_len) {
  BIO *b64 = BIO_new(BIO_f_base64());
  BIO *bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  int len = BIO_write(b64, input, length);
  assert(len == length);
  int r = BIO_flush(b64);
  assert(r == 1);

  BUF_MEM *bptr;
  BIO_get_mem_ptr(b64, &bptr);

  *buf64_len = bptr->length;
  *buf64 = new char[*buf64_len+1];
  memcpy(*buf64, bptr->data, *buf64_len);
  char* b = *buf64;
  b[*buf64_len] = 0;

  BIO_free_all(b64);
}
