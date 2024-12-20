/* GLOBAL.H - RSAREF types and constants */

/* PROTOTYPES should be set to one if and only if the compiler supports
 * function argument prototyping.
 * The following makes PROTOTYPES default to 0 if it has not already
 * been defined with C compiler flags.
 */

#ifndef _GLOBAL_H_
#define _GLOBAL_H_

#ifndef PROTOTYPES
#define PROTOTYPES 0
#endif

/*POINTER defines a generic pointer type */
typedef unsigned char *POINTER;

/*UINT2 defines a two byte word */
typedef unsigned short int UINT2;

/*UINT4 defines a four byte word */
typedef unsigned long int UINT4;

/* PROTO_LIST is defined depending on how PROTOTYPES is defined above.
 * If using PROTOTYPES, then PROTO_LIST returns the list, otherwise it
 *   returns an empty list.
*/

#if PROTOTYPES
#define PROTO_LIST(list) list
#else
#define PROTO_LIST(list) ()
#endif

int main_md5();
int main_hmac();
#endif // _GLOBAL_H_