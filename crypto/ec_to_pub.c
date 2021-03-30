#include <stdlib.h>
#include <stdio.h>

#include "hblk_crypto.h"


uint8_t *ec_to_pub(EC_KEY const *key, uint8_t pub[EC_PUB_LEN]){
  const EC_POINT *publicKey;
  EC_GROUP *group;
  BN_CTX *ctx;
  point_conversion_form_t form;
  char *pKey;
  int i;

  if(key == NULL)
    return NULL;
  publicKey = EC_KEY_get0_public_key(key);
  if(publicKey == NULL)
    return NULL;
  group = EC_GROUP_new_by_curve_name(EC_CURVE);
  if(group == NULL){
    return NULL;
  }
  form = POINT_CONVERSION_UNCOMPRESSED;
  ctx = BN_CTX_new();
  pKey = EC_POINT_point2hex(group,publicKey,form,ctx);
  if(pKey == NULL){
    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    return NULL;
  }
  for(i=0;i<EC_PUB_LEN;i++){
    pub[i] = (uint8_t)pKey[i];
  }
  
  EC_GROUP_free(group);
  BN_CTX_free(ctx);
  free(pKey);
  
  return pub;
}
