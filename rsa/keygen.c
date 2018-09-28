#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include "keygen.h"
#include "math.h"

#define RAND_LIMITS 65535
/*key generation functions */
struct keygen_t keygen(void)
{ 
  srand(time(0));
  unsigned int p,q, prime = (rand()/RAND_LIMITS)%RAND_LIMITS;
  unsigned long phi, e = 2, n;
  double d = 0;
  struct keygen_t key;
  
  /* Getting prime number */
  p = findNxtPrime(prime);
  q = findNxtPrime(p+2);
  n = p*q;
  /* finding e and d value for rsa*/
  phi = (p-1)*(q-1);
  while(gcd(phi,e)!=1) e++;
  d = mod_inverse(e, phi);

  printf("Prime No.    -> p: %u q: %u\n",p, q);
  printf("n, phi Value -> n: %lu phi: %lu\n",n, phi);
  printf("e, d Value   -> e: %lu d: %.2f\n", e, d);
  printf("d<phi-> %d\n", d<phi);
  key.pub.val = e, key.pub.n = n;
  key.pri.val = d, key.pri.n = n;
  return key;
}
