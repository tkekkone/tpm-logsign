#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <tss/tss_error.h>
#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>
#include <openssl/sha.h>

#define DBG(message, tResult) printf("Line%d, %s)%s returned 0x%08x. %s.\n", __LINE__ , __func__ ,message, tResult,(char *)Trspi_Error_String(tResult))

int closeTPM(TSS_HCONTEXT hContext);
void hashAndExtendPCR(BYTE *data, UINT32 pcrIndex);
int extendPCR(unsigned char *data, UINT32 pcrIndex);
void extendFileContentToPCR(const char *filename, UINT32 pcrIndex);
int readPCRS();
void readAPCR(UINT32 index, BYTE **PCRresult);
void appendHash(unsigned char *data, unsigned char *hash);
void createAttestorFile(UINT32 pcrIndex, char *nonce_, BYTE **validationdata, UINT32 *validlength);
void sign();
int signData(BYTE *prgbData, UINT32 pubKeyLength, BYTE **signature, BYTE **signatureInHex);
int writeSyslog(int priority, const char *text);
