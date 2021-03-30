#include <stdlib.h>
#include <stdio.h>

#include "hblk_crypto.h"

EC_KEY *ec_from_pub(uint8_t const pub[EC_PUB_LEN]){
  
  EC_KEY *key = NULL;
  EC_POINT *pubKey = NULL;
  const EC_GROUP *group = NULL;
  BN_CTX *ctx;
  char *buf;
  int i;

  buf = malloc(sizeof(char) * (EC_PUB_LEN));

  for(i=0;i<EC_PUB_LEN;i++){
    buf[i] = (char)pub[i];
  }

  key = EC_KEY_new_by_curve_name(EC_CURVE);

  if(key == NULL)
    return NULL;

  group = EC_KEY_get0_group(key);

  if(group == NULL){
    EC_KEY_free(key);
    return NULL;
  }
 
  pubKey = EC_POINT_new(group);
  ctx = BN_CTX_new();

  EC_POINT_hex2point(group, buf, pubKey, ctx);
  
  if(pubKey == NULL){
    EC_KEY_free(key);
    BN_CTX_free(ctx);
    return NULL;
  }

  EC_KEY_set_public_key(key, pubKey);
  EC_POINT_free(pubKey);
  BN_CTX_free(ctx);
  return key;
}
