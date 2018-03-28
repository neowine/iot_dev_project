/*

 * Implementation of the Secure Hashing Algorithm (SHA-256)

 *

 * Generates a 256 bit message digest. It should be impossible to come

 * come up with two messages that hash to the same value ("collision free").

 *

 * For use with byte-oriented messages only. Could/Should be speeded

 * up by unwinding loops in shs_transform(), and assembly patches.

 */



#include <stdio.h>

#include "miracl.h"


mr_unsign32 length[2];
mr_unsign32 H[8];
mr_unsign32 w[80];

#define H0 0x6A09E667L
#define H1 0xBB67AE85L
#define H2 0x3C6EF372L
#define H3 0xA54FF53AL
#define H4 0x510E527FL
#define H5 0x9B05688CL
#define H6 0x1F83D9ABL
#define H7 0x5BE0CD19L


static const mr_unsign32 K[64]={
0x428a2f98L,0x71374491L,0xb5c0fbcfL,0xe9b5dba5L,0x3956c25bL,0x59f111f1L,0x923f82a4L,0xab1c5ed5L,
0xd807aa98L,0x12835b01L,0x243185beL,0x550c7dc3L,0x72be5d74L,0x80deb1feL,0x9bdc06a7L,0xc19bf174L,
0xe49b69c1L,0xefbe4786L,0x0fc19dc6L,0x240ca1ccL,0x2de92c6fL,0x4a7484aaL,0x5cb0a9dcL,0x76f988daL,
0x983e5152L,0xa831c66dL,0xb00327c8L,0xbf597fc7L,0xc6e00bf3L,0xd5a79147L,0x06ca6351L,0x14292967L,
0x27b70a85L,0x2e1b2138L,0x4d2c6dfcL,0x53380d13L,0x650a7354L,0x766a0abbL,0x81c2c92eL,0x92722c85L,
0xa2bfe8a1L,0xa81a664bL,0xc24b8b70L,0xc76c51a3L,0xd192e819L,0xd6990624L,0xf40e3585L,0x106aa070L,
0x19a4c116L,0x1e376c08L,0x2748774cL,0x34b0bcb5L,0x391c0cb3L,0x4ed8aa4aL,0x5b9cca4fL,0x682e6ff3L,
0x748f82eeL,0x78a5636fL,0x84c87814L,0x8cc70208L,0x90befffaL,0xa4506cebL,0xbef9a3f7L,0xc67178f2L};


#define PAD  0x80

#define ZERO 0



/* functions */



#define S(n,x) (((x)>>n) | ((x)<<(32-n)))

#define R(n,x) ((x)>>n)



#define Ch(x,y,z)  ((x&y)^(~(x)&z))

#define Maj(x,y,z) ((x&y)^(x&z)^(y&z))

#define Sig0(x)    (S(2,x)^S(13,x)^S(22,x))

#define Sig1(x)    (S(6,x)^S(11,x)^S(25,x))

#define theta0(x)  (S(7,x)^S(18,x)^R(3,x))

#define theta1(x)  (S(17,x)^S(19,x)^R(10,x))


static void shs_transform()
{ /* basic transformation step */

    mr_unsign32 a,b,c,d,e,f,g,h,t1,t2;

    int j;



    for (j=16;j<64;j++)

    {

        w[j]=theta1(w[j-2])+w[j-7]+theta0(w[j-15])+w[j-16];

    }

    a=H[0]; b=H[1]; c=H[2]; d=H[3];

    e=H[4]; f=H[5]; g=H[6]; h=H[7];



    for (j=0;j<64;j++)

    { /* 64 times - mush it up */

        t1=h+Sig1(e)+Ch(e,f,g)+K[j]+w[j];

        t2=Sig0(a)+Maj(a,b,c);

        h=g; g=f; f=e;

        e=d+t1;

        d=c;

        c=b;

        b=a;

        a=t1+t2;

    }

    H[0]+=a; H[1]+=b; H[2]+=c; H[3]+=d;

    H[4]+=e; H[5]+=f; H[6]+=g; H[7]+=h;

}



void shs256_init_mcu_frm()
{ /* re-initialise */

    int i;

    for (i=0;i<64;i++) w[i]=0L;

    length[0]=length[1]=0L;

    H[0]=H0;

    H[1]=H1;

    H[2]=H2;

    H[3]=H3;

    H[4]=H4;

    H[5]=H5;

    H[6]=H6;

    H[7]=H7;

}



void shs256_process_mcu_frm(int byte)

{ /* process the next message byte */

    int cnt;

    cnt=(int)((length[0]/32)%16);

    w[cnt]<<=8;
    w[cnt]|=(mr_unsign32)(byte&0xFF);

    length[0]+=8;
    if (length[0]==0L) { length[1]++; length[0]=0L; }
    if ((length[0]%512)==0) shs_transform();
}


void shs256_hash_mcu_frm(unsigned char *hash)
{ // pad message and finish - supply digest
    int i;
    unsigned char SHA_PAD;
    mr_unsign32 len0,len1;
    len0=length[0];
    len1=length[1];
    SHA_PAD = 0x80; // Fixed Data
    shs256_process_mcu_frm(SHA_PAD);
    while ((length[0]%512)!=448) shs256_process_mcu_frm(ZERO);
    w[14]=len1;
    w[15]=len0;

    shs_transform();
    for (i=0;i<32;i++)
    { // convert to bytes
        hash[i]=((H[i/4]>>(8*(3-i%4))) & 0xffL);
    }
    shs256_init_mcu_frm();
}
