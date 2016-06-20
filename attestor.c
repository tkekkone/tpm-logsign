#include "attestor.h"
#include "server.h"
#include "http.h"
#include <sys/stat.h>
#include <syslog.h>
#include "syslogsigner.h"

#define TSS_UUID_SIGN {0, 0, 0, 0, 0, {0, 0, 0, 0, 2, 11}}
#define SIGN 1
#define VERIFY 2
#define LISTEN 3
#define FILESIGNER 4
#define NOTSPECIFIED 0


TSS_HTPM hTPM;
TSS_HCONTEXT hContext;
TSS_HKEY hSRK=0;
char *filename, *keyfilename, *sigfilename;
UINT32 verbose = 0;



int readPCRS(){
	UINT32 j ,subCap, respDataLength, numPcrs;
	TSS_RESULT result;
	BYTE *rgbNumPcrs, *PCR;
	// Redefine sub capability
	subCap = TSS_TPMCAP_PROP_PCR;
	   // Retrieve number of PCR's 
	result = Tspi_TPM_GetCapability(hTPM,TSS_TPMCAP_PROPERTY, sizeof(UINT32),(BYTE *)&subCap, &respDataLength, &rgbNumPcrs);
	   if (result != TSS_SUCCESS) {
		return 1;
	   }
	   if (respDataLength != sizeof(UINT32)) {
		return 1;
	   }
	numPcrs = *(UINT32 *)rgbNumPcrs;
	for(j=0;j<numPcrs;j++){ //all pcrs
		readAPCR(j, &PCR);	
	}
	return 0;
}

void readAPCR(UINT32 index, BYTE **PCRresult){
	UINT32 i, respDataLength;
	TSS_RESULT result;
	BYTE *value;
	result = Tspi_TPM_PcrRead (hTPM, index, &respDataLength, &value);
		if(result != TSS_SUCCESS)
			printf("PCR %i READ fail\n", index);	
		else{
			printf( "PCR %i length %i value: ", index, respDataLength);
			for (i = 0; i < respDataLength; i++){
				printf("%02x", value[i] & 0xff);
			}
			*PCRresult = value;
			printf("\n");
		}
}

TSS_UUID createSigningkey(){
	
	UINT32 pubKeyLength;
	BYTE *pubKey;
	TSS_HKEY hSigning_Key;
	TSS_RESULT result;
	TSS_FLAG initFlags;
	TSS_UUID SIGNING_UUID = TSS_UUID_SIGN;
	TSS_UUID SRK_UUID=TSS_UUID_SRK;
	FILE *fout;
	// We are going to create a Signing
	// Here I determine the key will be a Signing key of 2048 bits, nonmigratable, with no authorization.
	initFlags = TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048 | TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE;
	// Create the key object
	result=Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,initFlags, &hSigning_Key);
	if(result!=0x00000000 || verbose == TRUE) DBG("Tspi_Context_CreateObjectSigningKey",result);
	// Now I finally create the key, with the SRK as its parent.
	printf("Creating key... this may take some time\n");
	result=Tspi_Key_CreateKey(hSigning_Key,hSRK, 0);
	if(result!=0x00000000 || verbose == TRUE) DBG("Create Key", result);
	// Once created, I register the key blob so I can retrieve it later
	result=Tspi_Context_RegisterKey(hContext,hSigning_Key, TSS_PS_TYPE_SYSTEM, SIGNING_UUID, TSS_PS_TYPE_SYSTEM, SRK_UUID);
	if(result!=0x00000000 || verbose == TRUE) DBG("Registerkey",result);
	if(result==0x00002008){//already registerd
		TSS_HKEY hRegistered_key;
		result=Tspi_Context_UnregisterKey(hContext, TSS_PS_TYPE_SYSTEM, SIGNING_UUID, &hRegistered_key);
		DBG("Unregisterkey",result);
		result=Tspi_Context_RegisterKey(hContext,hSigning_Key, TSS_PS_TYPE_SYSTEM, SIGNING_UUID, TSS_PS_TYPE_SYSTEM, SRK_UUID);
		DBG("Retry Registerkey",result);
		}
		
	result=Tspi_Key_LoadKey(hSigning_Key,hSRK);
	if(result!=0x00000000 || verbose == TRUE) DBG("LoadKey",result);
	result =Tspi_Key_GetPubKey(hSigning_Key, &pubKeyLength, &pubKey);
	//write pubkey to file
	fout=fopen("verifykey.dat", "w");
	write(fileno(fout), pubKey,pubKeyLength);
	return SIGNING_UUID;
}
/**
Verify the signature in a file given as 
cli parameter -v. 
-k parameter identifies the key used in verification.
-v original data file
-g signature

*/
int verifySignature(){
	TSS_RESULT result;
	TSS_HHASH hHashToVerify;
	UINT32 fileLength;
	FILE *fin;
	BYTE *fileToVerify, *pubVerifyKey, *signatureToVerify;
	TSS_FLAG initFlags;
	TSS_HKEY hVerify_Key;
	int validationResult = TRUE;
	struct stat st;
	
	printf("File to verify: %s\nFile with key: %s\nFile with signature: %s\n", filename, keyfilename, sigfilename);
	
	// Create a Hash Object so as to have something to compare the signature to
	// Create a generic Hash object //
	result= Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_HASH, TSS_HASH_SHA1, &hHashToVerify); 
	if(result!=0x00000000 || verbose == TRUE)
		DBG("Create Hashobject", result);	
	stat(filename, &st);
	fileLength = st.st_size;
	fileToVerify = malloc(fileLength);
	fin=fopen(filename, "r");// file to verify
	read(fileno(fin),fileToVerify,fileLength);
	fclose(fin);
	printf("File content: %s\n", fileToVerify);
	
	// Hash the data using SHA1//
	result=Tspi_Hash_UpdateHashValue(hHashToVerify,fileLength,fileToVerify);
	if(result!=0x00000000 || verbose == TRUE)
		DBG("Hash in the public key", result);
	
	// We are going to create a Verify key
	pubVerifyKey = malloc(284);
	fin=fopen(keyfilename, "r");
	read(fileno(fin),pubVerifyKey,284);
	fclose(fin);
	initFlags= TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048 | TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE;
	result=Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,initFlags, &hVerify_Key);
	if(result!=0x00000000 || verbose == TRUE) DBG("Tspi_Context_CreateObjectVerify_Key",result);
	result=Tspi_SetAttribData(hVerify_Key,TSS_TSPATTRIB_KEY_BLOB,TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,284,pubVerifyKey);	
	if(result!=0x00000000 || verbose == TRUE) DBG("SetPubKeyinVerify_Key", result);
	
	// Read in signature and verify it
	signatureToVerify = malloc(256);
	fin=fopen(sigfilename, "r"); //signature to verify
	read(fileno(fin), signatureToVerify, 256);
	fclose(fin);
	
	
	result=Tspi_Hash_VerifySignature(hHashToVerify,hVerify_Key,256,signatureToVerify);	
	if(result!=0x00000000){
		validationResult = FALSE;
		DBG("Verify", result);
		}
	if(verbose == TRUE)
		DBG("Verify", result);
	
	free(signatureToVerify);
	free(fileToVerify);
	free(pubVerifyKey);
	return validationResult;
}

void sign(){
	char *prgbData;
	BYTE *signature, *hex;
	FILE *fin, *fout;
	struct stat st;
	UINT32 pubKeyLength, signatureLength;
	
	fin=fopen(filename,"r");
	stat(filename, &st);
	pubKeyLength = st.st_size;		
	if(!fin){
		printf("no file\n");
		return;		
		}	
	prgbData = malloc(pubKeyLength);
	read(fileno(fin),prgbData,pubKeyLength);
	
	signatureLength = signData(prgbData, pubKeyLength, &signature, &hex);	
	
	free(prgbData);	
	// Write the resultant signature to a file called Signature.dat
	if(sigfilename)
		fout=fopen(sigfilename, "w");			
	else
		fout=fopen("Signature.dat", "w");				
	
	write(fileno(fout),signature,signatureLength);
	
	fclose(fout);
	fclose(fin);
}


int signData(BYTE *prgbData, UINT32 pubKeyLength, BYTE **signature, BYTE **signatureInHex){
	TSS_HKEY hSigning_Key;
	TSS_RESULT result;
	UINT32 ulSignatureLength;	
	TSS_HOBJECT hHashToSign;	
	int i;
	BYTE* buf;
	
	buf = malloc(3);
	*signature = malloc(257);
	*signatureInHex = malloc(513);
	TSS_UUID SIGNING_UUID = TSS_UUID_SIGN;
	
	//SIGNING_UUID = createSigningkey();
	// Get the Signing key handle from the standard UUID
	result=Tspi_Context_GetKeyByUUID(hContext,TSS_PS_TYPE_SYSTEM,SIGNING_UUID,&hSigning_Key);
	if(result!=0x00000000 || verbose == TRUE)
		DBG("Get Key byUUID",result);

	// Load the private key into the TPM using its handle
	result=Tspi_Key_LoadKey(hSigning_Key,hSRK);
	if(result!=0x00000000 || verbose == TRUE) DBG("Load Key", result);

	// Create a Hash Object so as to have something to sign so we create a generic Hash object //
	result=Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_HASH, TSS_HASH_SHA1, &hHashToSign);
	if(result!=0x00000000 || verbose == TRUE) DBG("Create Hash object", result);
	
	//printf("data to hash: %s\n\n",prgbData);
	// Hash the data using SHA1//
	result=Tspi_Hash_UpdateHashValue(hHashToSign,pubKeyLength,prgbData);
	//printf("length: %i file: %s\n", pubKeyLength, prgbData);
	if(result!=0x00000000 || verbose == TRUE) DBG("Hash in the data", result);

	
	// Sign the resultant hash object
	result=Tspi_Hash_Sign(hHashToSign,hSigning_Key,&ulSignatureLength,signature);
	
	if(result!=0x00000000 || verbose == TRUE) DBG("Sign",result);
	
	stpcpy(*signatureInHex, "");
	//printf("signaturebinary: %s\n\n",signature);
	
	for(i=0;i<ulSignatureLength;i++){
		sprintf(buf, "%02x", (*signature)[i]);
		strcat(*signatureInHex, buf);			
		}
	
	return ulSignatureLength;
}

void createAttestorFile(UINT32 pcrIndex, char *nonce_, BYTE **validationdata, UINT32 *validlength){
	TSS_RESULT result;
	TSS_HOBJECT hObject;
	TSS_VALIDATION data;
	TSS_HKEY signKey;
	TSS_FLAG initFlags;
	TSS_UUID SRK_UUID=TSS_UUID_SRK;
	TSS_UUID signkeyuuid = {0, 0, 0, 0, 0, {0, 0, 0, 0, 2, 10}};
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_PCRS, 0, &hObject);
	if ( result == TSS_SUCCESS )
		{
		DBG("PCROBJ",result);
		}
	else{
		DBG("PCROBJ fail",result);
	}
	initFlags =TSS_KEY_TYPE_SIGNING|TSS_KEY_SIZE_2048|TSS_KEY_NO_AUTHORIZATION|TSS_KEY_NOT_MIGRATABLE;
	result=Tspi_Context_CreateObject(hContext,TSS_OBJECT_TYPE_RSAKEY,initFlags,&signKey );
		if(result!=0x00000000 || verbose == TRUE) DBG("CreateObject",result);
	result = Tspi_SetAttribUint32(signKey,TSS_TSPATTRIB_KEY_INFO,TSS_TSPATTRIB_KEYINFO_ENCSCHEME,TSS_SS_RSASSAPKCS1V15_SHA1);
		if(result!=0x00000000 || verbose == TRUE) DBG("SetAttribUint",result);	
	result=Tspi_Key_CreateKey(signKey,hSRK, 0);
		if(result!=0x00000000 || verbose == TRUE) DBG("CreateKey",result);	
	result=Tspi_Context_RegisterKey(hContext,signKey,TSS_PS_TYPE_SYSTEM,signkeyuuid,TSS_PS_TYPE_SYSTEM,SRK_UUID);
		if(result!=0x00000000 || verbose == TRUE) DBG("RegisterKey",result);	
	result=Tspi_Context_GetKeyByUUID(hContext,TSS_PS_TYPE_SYSTEM,signkeyuuid,&signKey);
		if(result!=0x00000000 || verbose == TRUE) DBG("GetKeyByUUID",result);	
	result = Tspi_Key_LoadKey(signKey, hSRK);
		if(result!=0x00000000 || verbose == TRUE) DBG("LoadKey",result);	
	//Quote
	/*
	TSS_VERSION versionInfo;
	UINT32 ulExternalDataLength;
	BYTE* rgbExternalData;
	UINT32 ulDataLength;
	BYTE* rgbData;
	UINT32 ulValidationLength;
	BYTE* rgbValdationData;
	*/
	
	int NONCESIZE = 20;
	char nonce[NONCESIZE];
	strcat(nonce, (char *)nonce_);

	nonce[NONCESIZE-1] = '\0';
	data.ulExternalDataLength = NONCESIZE;
	data.rgbExternalData = (BYTE *)nonce;
	result = Tspi_PcrComposite_SelectPcrIndex(hObject, pcrIndex);	
        	if(result!=0x00000000 || verbose == TRUE) DBG("SelectPcrIndex",result);
	result = Tspi_TPM_Quote(hTPM, signKey, hObject, &data);
        	if(result!=0x00000000 || verbose == TRUE) DBG("Quote",result);
	*validationdata = data.rgbData;
	printf("length: %i", data.ulDataLength);
	*validlength = data.ulDataLength;
}

int extendPCR(unsigned char *hash, UINT32 pcrIndex){
	TSS_RESULT result;
	UINT32 pcrLength, i;
	BYTE *pcrValue;
	printf("Extending ");
	for (i = 0; i < 20; i++){
		printf("%02x", hash[i] & 0xff);
	}	
	printf(" to PCR %i", pcrIndex);
	result = Tspi_TPM_PcrExtend(hTPM, pcrIndex, 20, hash, NULL, &pcrLength, &pcrValue);
	if(result!=0x00000000 || verbose == TRUE) DBG("Extend PCR ",result);
	for (i = 0; i < pcrLength; i++){
		printf("%02x", pcrValue[i] & 0xff);
	}
	
	return 0;
}

void hashAndExtendPCR(BYTE *data, UINT32 pcrIndex){
	printf("data is: %s", data);	
	unsigned char hash[SHA_DIGEST_LENGTH];
	size_t length = sizeof(data);
	SHA1(data, length, hash);
	extendPCR(hash, pcrIndex);	

}

void extendFileContentToPCR(const char *filename, UINT32 pcrIndex){
	FILE *file;
	file = fopen(filename, "r");	
	UINT32 blocksize = 0,i;
	char c;	
	unsigned char hash[SHA_DIGEST_LENGTH+1] = {0};
	unsigned char hashable[65] = {0};
	hashable[64] = '\0';
	hash[SHA_DIGEST_LENGTH] = '\0';
	if(file){
		while ((c = getc(file)) != EOF){
			if (blocksize == 64){
				blocksize = 0;				
				appendHash(hashable, hash);			
			}			
			hashable[blocksize] = c;			
			blocksize++;						
		}
		appendHash(hashable, hash);
		printf("hash of the file: ");
		for (i = 0; i < 20; i++){
			printf("%02x", hash[i] & 0xff);
		}
		printf("\n");
	}
	else{
		return;
	}
	fclose(file);
	extendPCR(hash, pcrIndex);
	return;
}

void appendHash(unsigned char *data, unsigned char *hash){
	unsigned char *combination = malloc(sizeof(unsigned char) * 85);
	memcpy(combination+64, hash, 20);
	memcpy(combination, data, 64);
	SHA1(combination, 84, hash);
	free(combination);
	return;
}


int closeTPM(TSS_HCONTEXT hContext){
	TSS_RESULT result;
	Tspi_Context_FreeMemory(hContext, NULL);
	result=Tspi_Context_Close(hContext);
	if(result!=0x00000000 || verbose == TRUE) DBG("Close context", result);
	return 0;
}



void initTPM(){
	TSS_HPOLICY hSRKPolicy=0;
	TSS_RESULT result;
	TSS_UUID SRK_UUID=TSS_UUID_SRK;
	BYTE wks[20]; //For the well known secret
	memset(wks,0,20);

	result = Tspi_Context_Create( &hContext);
	if(result!=0x00000000 || verbose == TRUE) DBG("Create Context",result);
	result = Tspi_Context_Connect(hContext, NULL);
	if(result!=0x00000000 || verbose == TRUE) DBG("Context_Connect",result);
	// Get the TPM handle
	result=Tspi_Context_GetTpmObject(hContext,&hTPM);
	if(result!=0x00000000 || verbose == TRUE) DBG("Get TPM Handle",result);
	// Get the SRK handle
	result=Tspi_Context_LoadKeyByUUID(hContext,TSS_PS_TYPE_SYSTEM,SRK_UUID,&hSRK);
	if(result!=0x00000000 || verbose == TRUE) DBG("Got the SRK handle", result);
	//Get the SRK policy
	result = Tspi_GetPolicyObject(hSRK,TSS_POLICY_USAGE,&hSRKPolicy);
	if(result!=0x00000000 || verbose == TRUE) DBG("Got the SRK policy",result);
	//Then set the SRK policy to be the well known secret
	result=Tspi_Policy_SetSecret(hSRKPolicy,TSS_SECRET_MODE_SHA1,20,wks);
	//Note: TSS SECRET MODE SHA1 says ”Don’t hash this.
	// Use the 20 bytes as they are.
	if(result!=0x00000000 || verbose == TRUE) DBG("Set the SRK secret in its policy",result);
	//extendFileContentToPCR("listing2.txt");
}

int cliParser(int argc, char **argv){
	int mode = 0;
	int i;
	for (i = 0; i < argc; ++i)
		{
			if(argv[i][0]=='-'){
				switch(argv[i][1]){
					case 's': //action sign. file as parameter
						//printf ("parameter s: %s\n", argv[i+1]);
						filename = argv[i+1];
						if(mode!=NOTSPECIFIED){
							printf("Invalid command. Two action commands given(-v, -s -l)\n");
							return 0;						
						}						
						mode = SIGN;				
						break;
					case 'v': //action verify. file as parameter, needs key -k and signature -g
						//printf ("parameter v: %s\n", argv[i+1]);
						filename = argv[i+1];
						if(mode!=NOTSPECIFIED){
							printf("Invalid command. Two action commands given(-v, -s -l)\n");
							return 0;						
						}
						mode = VERIFY;
						break;
					case 'k': //key file
						//printf ("parameter k: %s\n", argv[i+1]);
						keyfilename = argv[i+1];
						break;
					case 'g': //signature file
						//printf ("parameter g: %s\n", argv[i+1]);
						sigfilename = argv[i+1];
						break;
					case 'f': //file listener mode
						printf ("parameter f");
						mode = FILESIGNER;
						break;
					case 'd':
						verbose = TRUE;
						break;
					case 'l':
						if(mode!=NOTSPECIFIED){
							printf("Invalid command. Two action commands given(-v, -s -l)\n");
							return 0;						
						}
						mode = LISTEN;
						break;
				}
			}
			//printf("argv[%d]: %s\n", i, argv[i]);
		}
	return mode;
	
}

int writeSyslog(int priority, const char *text){
	setlogmask (LOG_UPTO (LOG_NOTICE));
	openlog ("tpmsigner", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);	
	syslog (priority, text);
	closelog ();
}



int main(int argc,char **argv)
{	
	writeSyslog(LOG_NOTICE, "Program launched");
	int mode = cliParser(argc, argv);
	printf("mode: %c", mode);
	int result = 0;
	initTPM();
	switch(mode){
		case SIGN:
			sign();
			break;
		case VERIFY:
			result = verifySignature();
			switch(result){
			case TRUE:
				printf("Validation successful\n");
				break;
			default:
				printf("Validation failed\n");
				break;	
			}
			break;
		case LISTEN:
			start();
			break;
		case FILESIGNER:
			printf("filesigner\n");
			syslogmonitor();
			break;			
		default:
			printf("Usage:\n"
			"-s Sign. File as parameter. Can take -g to specify output file for signature.\n"
			"-v Verify. File to be verified as parameter. Also needs -g and -k.\n"
			"-k Key file.\n"
			"-g Siganture file.\n"
			"-l Start attestation server.\n"
			"-f Start listening and signing log files.\n"
			"Examples:\nSign: \"tpmtool -s file.txt\"\n"
			"Verify: \"tpmtool -v file.txt -g signature.dat -k key.dat\"\n");
			break;
	}
	
	
	//BYTE *data;
	//UINT32 length = 0;
	//createAttestorFile(14, "abcdefghijklmnopqrstuvw", &data, &length);
	//printf("length %i\n", length);
	
	
	//start();
	//extendPCR((BYTE *)"aaaaaaaaaaaaaaaaaaaa", hTPM, (UINT32)14);
	//readPCRS();
	//return closeTPM(hContext);
	
	return 0;

}  //main
