// structs from crypto/ec/ec_lcl.h:

typedef struct ec_extra_data_st {
  struct ec_extra_data_st *next;
  void *data;
  void *(*dup_func)(void *);
  void (*free_func)(void *);
  void (*clear_free_func)(void *);
} EC_EXTRA_DATA; /* used in EC_GROUP */

struct ec_key_st {
  int version;
  
  EC_GROUP *group;
  
  EC_POINT *pub_key;
  BIGNUM   *priv_key;
  
  unsigned int enc_flag;
  point_conversion_form_t conv_form;
  
  int references;
  
  EC_EXTRA_DATA *method_data;
};
