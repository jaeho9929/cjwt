#include <jwt.h>
#include <stdlib.h>
#include <stdio.h>

const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3Mi"
"OiJmaWxlcy5jeXBocmUuY29tIiwic3ViIjoidXNlcjAif"
"Q.dLFbrHVViu1e3VD1yeCd9aaLNed-bfXhSsF0Gh56fBg";
unsigned char key256[32] = "012345678901234567890123456789XY";

int main(void)
{
  jwt_t *jwt = NULL;
  int ret = -1;
  const char *val = NULL;

  ret = jwt_new(&jwt);
  if (ret < 0)
    goto done;

  ret = jwt_add_grant(jwt, "user", "michael");
  if (ret < 0)
    goto done;
  ret = jwt_add_grant(jwt, "role", "admin");
  if (ret < 0)
    goto done;

  ret = jwt_set_alg(jwt, JWT_ALG_HS256, key256, sizeof(key256));
  if (ret < 0)
    goto done;

  val = jwt_get_grant(jwt, "user");
  printf("%s\n", val);
  val = jwt_get_grant(jwt, "role");
  printf("%s\n", val);

  jwt_t *jwt2 = NULL;
  ret = jwt_decode(&jwt2, token, key256, sizeof(key256));
  if (ret < 0)
    goto done;
  val = jwt_get_grant(jwt2, "iss");
  printf("%s\n", val);

  FILE *fp = NULL;
  fp = fopen("store.txt", "a");
  if (fp < 0)
    goto done;

  jwt_encode_fp(jwt2, fp);

done:
  if (fp)
    fclose(fp);
  if (jwt2)
    jwt_free(jwt2);
  if (jwt)
    jwt_free(jwt);
  return 0;
}
