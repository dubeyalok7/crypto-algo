#include <stdint.h>
int is_prime(uint8_t n)
{
    if(n<=0) return 0;
    if(n<=3) return 1;

    if(n%2==0 || n%3 ==0) return 0;

    for(int i =5; i*i <=n; i+=6)
        if(n%i==0 || n%(i+2)==0)
            return 0;
    return 1;
}
