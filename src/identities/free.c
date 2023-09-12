#include <stddef.h>

#include "./identities.h"

void
free_identity(identity *id)
{
  free(id->nonces);
  free(id->public_keys);
  free(id->secret_keys);
  free(id);
}
