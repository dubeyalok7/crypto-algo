#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <math.h>
#include "math.h"

#define MAX_SIZE 4000
/* Checking for prime number */
int isPrime(long long n)
{
    if (n <= 1)  return 0;
    if (n <= 3)  return 1;

    if (n%2 == 0 || n%3 == 0) return 0;

    for (int i=5; i*i<=n; i=i+6)
        if (n%i == 0 || n%(i+2) == 0)
           return 0;

    return 1;
}

/* GCD function */
long long gcd(long long a, long long b)
{
  if(a==0)
    return b;
  return gcd(b%a,a);
}

/*Finding next prime number from num provided by rand() */
long long findNxtPrime(long long num)
{
  if(0 == num%2)
    num+=1;
  while(!isPrime(num)) num+=2;
  return num;
}

/* Calculating mod inverse (a^-1)mod n */
double mod_inverse(unsigned long a, unsigned long m)
{
  int m0 = m;
  int y = 0, x =1;

  if(m==1)
    return 0;

  while(a>1)
  {
    // q is quotient
    int q = a/m;
    int t = m;

    //m is remainder now, process same as
    //Euclid's algo
    m = a%m, a = t;
    t = y;

    //update y and x
    y = x - q*y;
    x =t;
  }

  //make x positive
  if(x <0)
    x += m0;
  return x;
}

/* Calculating (a^x mod n) value where x is +ve no. */
static long long _mod_util(long long a,unsigned long long *buff, long long x, int n)
{
  /* [(a mod n)*(b mod n)] mod n = (a*b)mod n */
  if(x<0)
    return 1;
  if(x<MAX_SIZE){
    if(buff[x]){
      return buff[x];
    }
    else {
      if(x == 0){
        buff[x] = 1;
        return buff[x];
      }
      if(x == 1){
        buff[x] =  a%n;
        return buff[x];
      }
      buff[x] = ((_mod_util(a, buff, x/2, n)*_mod_util(a, buff, x - x/2,n))%(long long)n);
      return buff[x];
    }
  }
  return ((_mod_util(a, buff, x/2, n)*_mod_util(a, buff, x - x/2,n))%(long long)n);
}

long long mod_cal(long long a, long long x, int n)
{
  unsigned long long buff[MAX_SIZE]={0};
  return _mod_util(a, buff, x, n);
}
