#ifndef KEYGEN_H
#define KEYGEN_H

#define MSG_LIMIT 1024

struct key_t
{
  long long val;
  long long n;
};

struct keygen_t
{
  struct key_t pub;
  struct key_t pri;
};

struct keygen_t keygen(void);
int encrypt(long long *emsg, const char * msg,struct key_t pub, size_t len);
int decrypt(char *dmsg, const long long * cipher,struct key_t pri, size_t len);
long long mod_cal(long long a, long long x, int n);

#endif
