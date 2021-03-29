#include <stdlib.h>
#include <stdio.h>

#include "hblk_crypto.h"


uint8_t *ec_to_pub(EC_KEY const *key, uint8_t pub[EC_PUB_LEN]){
  EC_POINT const *publicKey;
  EC_GROUP const *group;
  BN_CTX *ctx;
  point_conversion_form_t form;
  char const *pKey;
  int i;

  if(key == NULL)
    return NULL;
  publicKey = EC_KEY_get0_public_key(key);
  if(publicKey == NULL)
    return NULL;
  group = EC_KEY_get0_group(key);
  if(group == NULL)
    return NULL;
  form = POINT_CONVERSION_UNCOMPRESSED;
  ctx = BN_CTX_new();
  pKey = EC_POINT_point2hex(group,publicKey,form,ctx);
  if(pKey == NULL)
    return NULL;
  for(i=0;i<EC_PUB_LEN;i++){
    pub[i] = (uint8_t)pKey[i];
  }
  return pub;
}
