//**************************************************************************
//* Instruction
//**************************************************************************
unsigned char ADDR_NOR_W = { 0x31 };
unsigned char ADDR_NOR_R = { 0x21 };
unsigned char COMM_NOR_W = { 0x11 };
unsigned char COMM_NOR_R = { 0x01 };
unsigned char MIDR_INCDEC[2] = {0xED,0x20};
unsigned char MIDR_CNT0[2] = {0xED,0x00};
unsigned char MIDR_CNT1[2] = {0xED,0x10};
unsigned char ADDR_SUPER_PW[2] = {0xED,0x80};
unsigned char ADDR_DETOUR_PW[2] = {0xED,0xC0};
unsigned char ADDR_DESTORY0_PW[2] = {0xEE,0x00};
unsigned char ADDR_DESTORY1_PW[2] = {0xEE,0x40};
unsigned char ADDR_EEPROM_PW[2] = {0xEE,0x80};
unsigned char ADDR_UID_PW[2] = {0xEE,0xC0};
#define R402
#ifdef R402
unsigned char ADDR_SUPER_PW_CNT[2] = {0xEF,0xB0};
unsigned char ADDR_DETOUR_PW_CNT[2] = {0xEF,0xF0};
unsigned char ADDR_DESTORY0_PW_CNT[2] = {0xF0,0x30};
unsigned char ADDR_DESTORY1_PW_CNT[2] = {0xF0,0x70};
unsigned char ADDR_EEPROM_PW_CNT[2] = {0xF0,0xB0};
unsigned char ADDR_UID_PW_CNT[2] = {0xF0,0xF0};
#else
unsigned char ADDR_SUPER_PW_CNT[2] = {0xED,0x90};
unsigned char ADDR_DETOUR_PW_CNT[2] = {0xED,0xD0};
unsigned char ADDR_DESTORY0_PW_CNT[2] = {0xEE,0x10};
unsigned char ADDR_DESTORY1_PW_CNT[2] = {0xEE,0x50};
unsigned char ADDR_EEPROM_PW_CNT[2] = {0xEE,0x90};
unsigned char ADDR_UID_PW_CNT[2] = {0xEE,0x90};

#endif

unsigned char ADDR_SUPER_PW_CNT_PAGE[2] = {0xEF,0x80};
unsigned char ADDR_DETOUR_PW_CNT_PAGE[2] = {0xEF,0xC0};
unsigned char ADDR_DESTORY0_PW_CNT_PAGE[2] = {0xF0,0x00};
unsigned char ADDR_DESTORY1_PW_CNT_PAGE[2] = {0xF0,0x40};
unsigned char ADDR_EEPROM_PW_CNT_PAGE[2] = {0xF0,0x80};
unsigned char ADDR_UID_PW_CNT_PAGE[2] = {0xF0,0xC0};
unsigned char ADDR_EE_KEY_AES_x0[2] = {0xE9,0x00};
unsigned char ADDR_EE_KEY_AES_x1[2] = {0xE9,0x40};
unsigned char ADDR_EE_KEY_AES_x2[2] = {0xE9,0x80};
unsigned char ADDR_EE_KEY_AES_x3[2] = {0xE9,0xC0};
unsigned char ADDR_EE_KEY_RS_x3[2] = {0xEA,0xC0};// 
unsigned char ADDR_EE_MEM_BKUP[2] = {0xEF,0x40};
unsigned char ADDR_EE_SEED_KEY[2] = {0xEC,0x00};
unsigned char EE_MEM_BKUP_RSFLAG[2] = {0xEF,0x00};
//**************************************************************************
//* Instruction End
//**************************************************************************


//**************************************************************************
//* Register Address
//**************************************************************************

unsigned char RG_BT_LOGIC_SEL[2] = {0x0C,0xA1};

unsigned char RG_ST0_OPMODE[2]        = { 0x06, 0x04 };
unsigned char RG_EET_CTRL[2]          = { 0x06, 0xB0 };
unsigned char RG_EET_OPMODE[2]        = { 0x06, 0xB1 };
unsigned char RG_EET_BYOB_LEN[2]      = { 0x06, 0xB2 };
unsigned char RG_EET_BYOB_ADDR_LSB[2] = { 0x06, 0xB3 };
unsigned char RG_ST1_RND_OPMODE[2] = {0x06,0x08};
unsigned char RG_AES_CTRL[2] = {0x06,0x35};
unsigned char RG_OKA_CTRL[2] = {0x06,0x3C};
unsigned char RG_ST1_MIDR_OPMODE[2] = {0x06,0x0B};
unsigned char RG_RNDGEN_USER[2] = {0x07,0x00};
unsigned char RG_SUPER_WIRE_PW0[2] = {0x06,0x60};
unsigned char RG_EE_KEY_AES_CTRL [2] = {0x06,0x20};
unsigned char RG_PERM_GET_CTRL [2] = {0x06,0x26};
unsigned char RG_ST2_SYMCIP_OPMODE  [2] = {0x06,0x19};
unsigned char RG_PERM_GET_CTRL1   [2] = {0x06,0x27};
unsigned char RG_PERM_RELEASE   [2] = {0x06,0x28};
unsigned char RG_ST1_OKA_OPMODE[2] = {0x06,0x0A};
unsigned char RG_ST1_SYMCIP_OPMODE[2] = {0x06,0x09};
unsigned char RG_ST3_SYMCIP_RSCREATE_OPMODE[2] = {0x06,0x1D};
unsigned char RG_ST3_SYMCIP_KEYLOAD_OPMODE[2] = {0x06,0x1F};
unsigned char RG_FFFF[2] = {0x0F,0xFF};
unsigned char RG_EE_USER_ZONE_SEL[2] = {0x06,0x1A};
unsigned char RG_PERM_GET_EE_RD_PRE_SP[2] = {0x06,0x29};
unsigned char RG_EE_CFG_RD_RG_EEBUF_ST[2] = {0x06,0x1C};
unsigned char RG_MCUAuthResult [2] = {0x07,0x20};
unsigned char RG_ST2_SYMCIP_SHAAuth_CMP_DP [2] = {0x07,0x21};
unsigned char RG_EETEST_BYOB_ADDR_LSB[2] = {0x06,0xB3};

unsigned char RG_SHA_CTRL[2] = {0x06,0x38};
unsigned char RG_ST1_STDSPI_OPMODE [2] = {0x06,0x06};


unsigned char RG_EEBUF100[2] = {0x01,0x00};
unsigned char RG_EEBUF300[2] = {0x03,0x00};
unsigned char RG_EEBUF310[2] = {0x03,0x10};
unsigned char RG_EEBUF320[2] = {0x03,0x20};
unsigned char RG_EEBUF330[2] = {0x03,0x30};
unsigned char RG_EEBUF400[2] = {0x04,0x00};
unsigned char RG_EEBUF410[2] = {0x04,0x10};
unsigned char RG_EEBUF420[2] = {0x04,0x20};
unsigned char RG_EEBUF430[2] = {0x04,0x30};
unsigned char RG_EEBUF500[2] = {0x05,0x00};
unsigned char RG_EEBUF510[2] = {0x05,0x10};
//unsigned char RG_EEBUF510[2] = {0x05,0x10};
unsigned char	RG_ACCESS[2] = { 0x06,01};
unsigned char RG_SLEEP_TIMER_MSB[2] = {0x06,0x50};
unsigned char RG_SLEEP_TIMER_LSB[2] = {0x06,0x51};
unsigned char RG_KL_CTRL[2] ={0x06,0x22};
unsigned char RG_RSCREATE_CTRL[2] = {0x06,0x23};
unsigned char RG_MEM_TEST_OPMODE[2]   = { 0x06, 0xB5 };
unsigned char RG_ST1_MEM_TEST_OPMODE[2] = {0x06,0x0E};
unsigned char A_MIDR[2] = {0xED,0x00};
unsigned char A_EE_MEM_BKUP_RSFLAG[2] = {0xEF,0x00};
unsigned char A_EE_MEM_BKUP_CTRL[2] = {0xEF,0x01};
unsigned char RG_BIST_MODE[2] = {0x07,0x22};
unsigned char RG_EE_BI_NO[2] = {0x07,0x23};
unsigned char RG_MB_ERROR_BIT[2] = {0x07,0x24};
unsigned char RG_SRAM_BIST_RESULT[2] = {0x07,0x25};
unsigned char RG_SHAAUTH_CTRL[2] = {0x06,0x24};
unsigned char RG_SOFT_RESET[2] = {0x06,0x00};				
/////////////////////////////////////////////////DEBUG REGISTER/////////////////////////////////////////////////////
unsigned char RG_ST0_CUR[2]                         ={0x0C,0x00};
unsigned char RG_CHK_RSFLAG[2]                      ={0x0C,0x01};
unsigned char RG_ST1_CHK_RSFLAG_CUR[2]              ={0x0C,0x02};
unsigned char RG_ST1_PON_READ_CUR[2]                ={0x0C,0x03};
unsigned char RG_STCM0_CUR[2]                       ={0x0C,0x04};
unsigned char RG_ST1_STDSPI_CUR[2]                  ={0x0C,0x05};
unsigned char RG_ST1_EE_CFG_CUR[2]                  ={0x0C,0x06};
unsigned char RG_ST1_RND_CUR[2]                     ={0x0C,0x07};
unsigned char RG_ST1_SYMCIP_CUR[2]                  ={0x0C,0x08};
unsigned char RG_ST1_OKA_CUR[2]                     ={0x0C,0x09};
unsigned char RG_ST1_MIDR_CUR[2]                    ={0x0C,0x0A};
unsigned char RG_ST1_PERM_GET_CUR[2]                ={0x0C,0x0B};
unsigned char RG_ST1_EEP_OW_CTRL_CUR[2]             ={0x0C,0x0C};
unsigned char RG_ST1_MEM_TEST_CUR[2]                ={0x0C,0x0D};
unsigned char RG_ST2_EEP_OW_CTRL_CUR[2]             ={0x0C,0x0E};
unsigned char RG_ST2_SYMCIP_OPMODE_AES_CUR[2]       ={0x0C,0x0F};
unsigned char RG_ST2_OKA_OKA2_CUR[2]                ={0x0C,0x10};
unsigned char RG_ST2_STDSPI_SHA_CUR[2]              ={0x0C,0x11};
unsigned char RG_ST2_SYMCIP_SHAAuth_CUR[2]          ={0x0C,0x12};
unsigned char RG_ST2_RND_CUR[2]                     ={0x0C,0x13};
unsigned char RG_ST3_RND_CUR[2]                     ={0x0C,0x14};
unsigned char RG_ST3_SYMCIP_AES_CUR[2]              ={0x0C,0x15};
unsigned char RG_ST3_SYMCIP_KEYLOAD_CUR[2]          ={0x0C,0x16};
unsigned char RG_ST3_SYMCIP_RSCREATE_CUR[2]         ={0x0C,0x17};

//**************************************************************************
//* Register Address End
//**************************************************************************

//**************************************************************************
//* RG_EET_OPMODE Register Value
//**************************************************************************
unsigned int STEM_WRITE_MAIN_AUTO = 0x0D;
unsigned int STEM_READ_MAIN = 0x02;
//**************************************************************************
//* RG_EET_OPMODE Register Value End
//**************************************************************************

//**************************************************************************
//* RG_MEM_TEST_OPMODE Register Value
//**************************************************************************
unsigned int ST1_MEM_TEST_RG_EEBUF_WR = 0x02;
unsigned int ST1_MEM_TEST_EE_WRRD_EN = 0x03 ;
unsigned int ST1_MEM_TEST_EE_WR_EN = 0x03;
unsigned int ST1_MEM_TEST_STANDBY = 0x01;
unsigned int ST1_MEM_TEST_EE_BIST =0x05;
unsigned char A_EEPROM[2] = {0x00,0x00};
unsigned char A_EEPROM_FFC0[2] = {0xff,0xc0};
//**************************************************************************
//* RG_MEM_TEST_OPMODE Register Value End
//**************************************************************************

// ENC
unsigned char AES_KEYA0_A0001[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};//AES_FIPS_PUB_197_KEY_128
unsigned char AES_PTA0_A0001[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};// `AES_FIPS_PUB_197_TEXT_128
unsigned char AES_CTA0_A0001[16] = {0x69,0xC4,0xE0,0xD8,0x6A,0x7B,0x04,0x30,0xD8,0xCD,0xB7,0x80,0x70,0xB4,0xC5,0x5A};// ps1A
// ENC
unsigned char AES_KEYA1_A0001[16] = {0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F};//K1
unsigned char AES_PTA1_A0001[16] = {0x69,0xC4,0xE0,0xD8,0x6A,0x7B,0x04,0x30,0xD8,0xCD,0xB7,0x80,0x70,0xB4,0xC5,0x5A};// ps1A
unsigned char AES_CTA1_A0001[16] = {0xC4,0x9A,0x78,0x46,0xC6,0xEA,0xE7,0xE4,0xCC,0xAF,0x6C,0xA9,0xD4,0xC4,0xE4,0x98};// ps2A
// DEC
unsigned char AES_KEYA2_A0001[16] = {0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20};// K2
unsigned char AES_CTA2_A0001[16] = {0x0E,0x9E,0xC0,0xE7,0x85,0x29,0x23,0x75,0xC3,0x90,0x64,0x1C,0x62,0x01,0x9D,0xBD};// ps2B
unsigned char AES_PTA2_A0001[16] = {0xE4,0x4B,0x37,0x11,0x15,0x22,0x9A,0xC2,0xC6,0x55,0x6A,0xB9,0x19,0xF4,0x52,0xA3};// ps1B
// ENC
unsigned char AES_KEYA3_A0001[16] = {0x8D,0x8F,0xD7,0xC9,0x7F,0x59,0x9E,0xF2,0x1E,0x98,0xDD,0x39,0x69,0x40,0x97,0xF9};// ps1A ^ ps1B
unsigned char AES_PTA3_A0001[16] = {0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F};// PAT00_3
unsigned char AES_CTA3_A0001[16] = {0xFF,0xF5,0x32,0xB1,0x93,0xFD,0xC3,0x9F,0xDE,0xE2,0xD3,0x4C,0x32,0xCE,0x8D,0x5};// FK
// ENC
unsigned char AES_KEYA4_A0001[16] = {0xFF,0xF5,0x32,0xB1,0x93,0xFD,0xC3,0x9F,0xDE,0xE2,0xD3,0x4C,0x32,0xCE,0x8D,0x5};
unsigned char AES_PTA4_0_A0001[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
unsigned char AES_CTA4_0_A0001[16] = {0x1A,0xF1,0xBE,0x44,0x5A,0x00,0xFF,0xBF,0x16,0xA4,0x55,0xCA,0xC2,0xE2,0xDB,0xA8};
// DEC
//unsigned char AES_KEYA4_A0001[16] = {0x8F,0xFF,0x53,0x2B,0x19,0x3F,0xDC,0x39,0xFD,0xEE,0x2D,0x34,0xC3,0x2C,0xE8,0xD5};
unsigned char AES_CTA4_1_A0001[16] = {0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F};
unsigned char AES_PTA4_1_A0001[16] = {0x5B,0x64,0xA9,0x8A,0x47,0x02,0x82,0x9A,0x4D,0x2B,0x29,0x43,0x1F,0xDB,0x0E,0xCD};
// ENC
//unsigned char AES_KEYA4_A0001[16] = {0x8F,0xFF,0x53,0x2B,0x19,0x3F,0xDC,0x39,0xFD,0xEE,0x2D,0x34,0xC3,0x2C,0xE8,0xD5};
unsigned char AES_PTA4_2_A0001[16] = {0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F};
unsigned char AES_CTA4_2_A0001[16] = {0xA3,0xF8,0x4F,0x04,0xC1,0x85,0x7C,0xAA,0x60,0x72,0x2A,0x41,0xD1,0x00,0x97,0x2E};

unsigned char AES_KEYA0_A0002[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};// `AES_FIPS_PUB_197_KEY_128
unsigned char AES_PTA0_A0002[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};// `AES_FIPS_PUB_197_TEXT_128
unsigned char AES_CTA0_A0002[16] = {0x69,0xC4,0xE0,0xD8,0x6A,0x7B,0x04,0x30,0xD8,0xCD,0xB7,0x80,0x70,0xB4,0xC5,0x5A};// ps1A

unsigned char AES_KEYA1_A0002[16] = {0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F};// K1
unsigned char AES_PTA1_A0002[16] = {0x69,0xC4,0xE0,0xD8,0x6A,0x7B,0x04,0x30,0xD8,0xCD,0xB7,0x80,0x70,0xB4,0xC5,0x5A};// ps1A
unsigned char AES_CTA1_A0002[16] = {0xC4,0x9A,0x78,0x46,0xC6,0xEA,0xE7,0xE4,0xCC,0xAF,0x6C,0xA9,0xD4,0xC4,0xE4,0x98};// ps2A

unsigned char AES_KEYA2_A0002[16] = {0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20};// K2
unsigned char AES_CTA2_A0002[16] = {0x0E,0x9E,0xC0,0xE7,0x85,0x29,0x23,0x75,0xC3,0x90,0x64,0x1C,0x62,0x01,0x9D,0xBD};// ps2B
unsigned char AES_PTA2_A0002[16] = {0xE4,0x4B,0x37,0x11,0x15,0x22,0x9A,0xC2,0xC6,0x55,0x6A,0xB9,0x19,0xF4,0x52,0xA3};//

unsigned char AES_KEYA3_A0002[16] = {0x8D,0x8F,0xD7,0xC9,0x7F,0x59,0x9E,0xF2,0x1E,0x98,0xDD,0x39,0x69,0x40,0x97,0xF9};// ps1A ^ ps1B
unsigned char AES_PTA3_A0002[16] = {0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F};// PAT00_3
unsigned char AES_CTA3_A0002[16] = {0x8F,0xFF,0x53,0x2B,0x19,0x3F,0xDC,0x39,0xFD,0xEE,0x2D,0x34,0xC3,0x2C,0xE8,0xD5};// FK

unsigned char AES_KEYA4_A0002[16] = {0x8F,0xFF,0x53,0x2B,0x19,0x3F,0xDC,0x39,0xFD,0xEE,0x2D,0x34,0xC3,0x2C,0xE8,0xD5};
unsigned char AES_PTA4_0_A0002[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
unsigned char AES_CTA4_0_A0002[16] = {0x1A,0xF1,0xBE,0x44,0x5A,0x00,0xFF,0xBF,0x16,0xA4,0x55,0xCA,0xC2,0xE2,0xDB,0xA8};

unsigned char AES_PTA4_1_0_A0002[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};//
unsigned char AES_CTA4_1_0_A0002[16] = {0x1A,0xF1,0xBE,0x44,0x5A,0x00,0xFF,0xBF,0x16,0xA4,0x55,0xCA,0xC2,0xE2,0xDB,0xA8};

//unsigned char AES_KEYA4_A0002[16] = {0x8F,0xFF,0x53,0x2B,0x19,0x3F,0xDC,0x39,0xFD,0xEE,0x2D,0x34,0xC3,0x2C,0xE8,0xD5};
unsigned char AES_CTA4_1_A0002[16] = {0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F};
unsigned char AES_PTA4_1_A0002[16] = {0x5B,0x64,0xA9,0x8A,0x47,0x02,0x82,0x9A,0x4D,0x2B,0x29,0x43,0x1F,0xDB,0x0E,0xCD};

unsigned char AES_CTA4_1_1_A0002[16] = {0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5A,0x5B,0x5C,0x5D,0x5E,0x5F};
unsigned char AES_PTA4_1_1_A0002[16] = {0x54,0x77,0xF5,0xB6,0xFE,0x8E,0x11,0x7A,0x6E,0x5B,0xE8,0xF5,0xF3,0x89,0x93,0x39};

//unsigned char AES_KEYA4_A0002[16] = {0x8F,0xFF,0x53,0x2B,0x19,0x3F,0xDC,0x39,0xFD,0xEE,0x2D,0x34,0xC3,0x2C,0xE8,0xD5};
unsigned char AES_PTA4_2_A0002[16] = {0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F};
unsigned char AES_CTA4_2_A0002[16] = {0xA3,0xF8,0x4F,0x04,0xC1,0x85,0x7C,0xAA,0x60,0x72,0x2A,0x41,0xD1,0x00,0x97,0x2E};

unsigned char AES_PTA4_1_2_A0002[16] = {0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6A,0x6B,0x6C,0x6D,0x6E,0x6F};
unsigned char AES_CTA4_1_2_A0002[16] = {0xD8,0xB3,0xE7,0x7C,0x7C,0xBA,0xEE,0x77,0xB1,0x2A,0x65,0x27,0xA6,0xAE,0x6F,0xE5};
//unsigned char AES_CTA1_A0001[16] = {0xC4,0x9A,0x78,0x46,0xC6,0xEA,0xE7,0xE4,0xCC,0xAF,0x6C,0xA9,0xD4,0xC4,0xE4,0x98};// ps2A

unsigned char TV0E0002_PAT0[64] = {0x3f,0x3e,0x3d,0x3c,0x3b,0x3a,0x39,0x38,0x37,0x36,0x35,0x34,0x33,0x32,0x31,0x30,0x2f,0x2e,0x2d,0x2c,0x2b,0x2a,0x29,0x28,0x27,0x26,0x25,0x24,0x23,0x22,0x21,0x20,0x1f,0x1e,0x1d,0x1c,0x1b,0x1a,0x19,0x18,0x17,0x16,0x15,0x14,0x13,0x12,0x11,0x10,0x0f,0x0e,0x0d,0x0c,0x0b,0x0a,0x09,0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01,0x00};
unsigned char TV0E0002_PAT1[64] = {0x3f,0x3e,0x3d,0x3c,0x3b,0x3a,0x39,0x38,0x37,0x36,0x35,0x34,0x33,0x32,0x31,0x30,0x2f,0x2e,0x2d,0x2c,0x2b,0x2a,0x29,0x28,0x27,0x26,0x25,0x24,0x23,0x22,0x21,0x20,0x1f,0x1e,0x1d,0x1c,0x1b,0x1a,0x19,0x18,0x17,0x16,0x15,0x14,0x13,0x12,0x11,0x10,0x0f,0x0e,0x0d,0x0c,0x0b,0x0a,0x09,0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01,0x00};



unsigned char	AES_KEYA0_A0051[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
unsigned char	AES_PTA0_A0051[] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
unsigned char	AES_KEYA1_A0051[] = {0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F};
unsigned char   AES_PTA4_0_A0051[] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
unsigned char   AES_CTA4_0_A0051[] = {0x3E,0x91,0x45,0x12,0x9E,0x88,0xC1,0x9B,0xAB,0xF8,0xC8,0x19,0x0A,0xAC,0x5F,0x9F};
unsigned char   AES_CTA4_1_A0051[] = {0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F};
unsigned char   AES_PTA4_1_A0051[] = {0x70,0x92,0x37,0x6A,0x18,0xB2,0xC0,0x0C,0x2A,0x31,0x47,0x03,0x57,0x80,0x56,0x8F};
unsigned char   AES_PTA4_2_A0051[] = {0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F};
unsigned char 	AES_CTA4_2_A0051[] = {0xD6,0x5B,0xE5,0x6B,0xEC,0x12,0xD5,0x8C,0x43,0x7E,0x9B,0x54,0xEC,0xCD,0x34,0x48};




#define SPI1_WRITE_DATA 0x61
#define SPI1_READ_DATA  0x71
#define	Set_ECC_q	0x01
#define	Set_ECC_a	0x02
#define	Set_ECC_b	0x03
#define	Set_ECC_xG	0x04
#define	Set_ECC_yG	0x05
#define	Set_ECC_n	0x06
#define	Set_Curve	0x07
#define   SLEEP           0x08
#define DEEP_SLEEP 0x09

#define	Set_ECDH_PrivateKey	0x11
#define	Set_ECDH_PrivateKey_PUF	0x12
#define	Create_ECHD_PublicKey	0x13
#define	Set_ECDH_PublicKey_X 	0x14
#define	Set_ECDH_PublicKey_Y 	0x15
#define	Get_ECDH_PublicKey_X 	0x16
#define	Get_ECDH_PublicKey_Y 	0x17
#define	Create_ECHD_KEY 	0x18
#define	Get_ECDH_KEY_X 	0x19
#define	Get_ECDH_KEY_Y 	0x20


#define Set_ECDSA_PrivateKey 0x41
#define Set_ECDSA_PrivateKey_PUF  0x42
#define Set_ECDSA_K_RND 0x43
#define Set_ECDSA_K_RND_PUF 0x44
#define Set_ECDSA_Public_Key_Xq 0x45
#define Set_ECDSA_Public_Key_Yq 0x46
#define Create_ECDSA_Public_Key 0x47
#define Get_ECDSA_Public_Key_Xq 0x48
#define Get_ECDSA_Public_Key_Yq 0x49
#define Set_ECDSA_r 0x50
#define Set_ECDSA_s 0x51
#define Get_ECDSA_r 0x52
#define Get_ECDSA_s 0x53
#define Create_ECDSA_Sign 0x54
#define Set_ECDSA_h 0x55
#define Get_ECDSA_h 0x56
#define Get_ECDSA_Result 0x57
#define Do_ECDSA_Verify 0x58
		
#define	Set_RSA_Prime_q	0x81
#define	Set_RSA_Prime_p	0x82
#define	Set_RSA_PublicExpo	0x83
#define	Set_RSA_PrivateKey_d	0x84
#define	Set_RSA_PlainText_M	0x85
#define	Set_RSA_CipherText_C	0x86
#define	Get_RSA_CipherText_C	0x87
#define	Set_RSA_Modulus_n	0x88
#define	Get_RSA_PlainText_M	0x89
#define	Get_RSA_PublicExpo	0x90
#define	Get_RSA_PrivateKed_d	


#define	Get_RSA_Modulus_n	0x92
#define	Create_RSA_Key	0x93
#define	Encrypt_RSA	0x94
#define	Decrypt_RSA	0x95
#define SIZE_ECDH_256   0xA0
#define SIZE_ECDH_521   0xA1
#define SIZE_ECDSA_256  0xA2
#define SIZE_ECDSA_521  0xA3
#define SIZE_RSA_2048   0xA4




typedef enum {
		BKUP_EE_SUPER_PASS = 0,
		BKUP_EE_DETOUR_PASS,
		BKUP_EE_DESTORY0_PASS,
		BKUP_EE_DESTORY1_PASS,
		BKUP_EE_EEPROM_PASS,
		BKUP_EE_UID_PASS,
		BKUP_EE_SUPER_PASS_CNT,
		BKUP_EE_DETOUR_PASS_CNT,
		BKUP_EE_DESTORY0_PASS_CNT,
		BKUP_EE_DESTORY1_PASS_CNT,
		BKUP_EE_EEPROM_PASS_CNT,
		BKUP_EE_UID_PASS_CNT
}BKUP_TYPE;

typedef enum {
	TYPE_TX = 0,
	TYPE_RX
}TRANS_TYPE;
typedef enum {
	RG_PERM_SUPER_PASS = 5,
	RG_PERM_DETOUR_PASS = 4,
	RG_PERM_DESTORY0_PASS = 3,
	RG_PERM_DESTORY1_PASS= 2,
	RG_PERM_EEPROM_PASS= 1,
	RG_PERM_UID_PASS = 0
}PERM_TYPE;

typedef enum {
	A_EE_CONFIG_NW =0,
	A_EE_CONFIG_FAC,
	A_EE_CONFIG_UID,
	A_EE_SEED_KEY,
	A_EE_CONFIG_USER,
	A_EE_CONFIG_LOCK,
	A_EE_MEM_TEST,
	A_EE_MIDR
}CONFIG_TYPE;	

typedef enum {
F_EE_MEM_BKUP_RSFLAG =0,
F_EE_MEM_BKUP_NOTUSE 
}BKUP_FLAG;