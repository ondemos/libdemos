#include <stddef.h>

#include "./proof.h"

void
free_proof(ownership_proof *p)
{
  free(p->ownership_ladder_artifacts);
  free(p);
}
