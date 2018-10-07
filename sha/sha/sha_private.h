#ifndef _SHA_PRIVATE_H_
#define _SHA_PRIVATE_H_

#ifndef USE_MODIFIED_MACROS
#define SHA_Ch(x,y,z)           (((x)&(y))^((~(x))&(z)))
#define SHA_Maj(x,y,z)          (((x)&(y))^((y)&(z))^((x)&(z)))
#else
#define SHA_ch(x,y,z)           (((x)&((y)^(z)))^(z))
#define SHA_Maj(x,y,z)          (((x)&((y)|(z)))|((y)&(z)))
#endif

#define SHA_Parity(x,y,z)       ((x)^(y)^(z))

#endif /* _SHA_PRIVATE_H_ */
