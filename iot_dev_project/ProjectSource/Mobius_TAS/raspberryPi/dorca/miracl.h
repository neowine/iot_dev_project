#define mr_unsign32 unsigned int

//typedef struct {
extern mr_unsign32 length[2];
extern mr_unsign32 H[8];
extern mr_unsign32 W[80];
//} sha256;

//typedef sha256 sha;

extern void shs256_init_mcu_frm() ;
extern void shs256_hash_mcu_frm(unsigned char []) ;
extern void shs256_process_mcu_frm(int ) ;

