/*
* pam_safebox.c
* 
* Dynamic library that uses the portuguese citizen card
* to authenticate a user already registered in Safebox
* 
* Authors: Miguel Vicente
*		   Joel Pinheiro
*
* References: pam_PTEIDCC.c by Andre Zuquete
*             Base64Decode.c https://gist.github.com/barrysteyn/4409525
*/


#define PAM_DEBUG

#include <sys/param.h>

#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <memory.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <unistd.h>
//#include <base64.h>
#define PAM_SM_AUTH
//#define CC_KPUB_FILE	"/etc/CC/keys"
//#define PAM_SM_ACCOUNT
//#define	PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <security/pam_client.h>
#include <security/_pam_macros.h>

#include "pteidlib.h"
#include "cryptoki.h"
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include "CCkpubFile.h"

static int calcDecodeLength(const char* b64input) { //Calculates the length of a decoded base64 string
	int len = strlen(b64input);
	int padding = 0;
	 
	if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
	padding = 2;
	else if (b64input[len-1] == '=') //last char is =
	padding = 1;
	 
	return (int)len*0.75 - padding;
} 
static int Base64Decode(char* b64message, char** buffer,int length) { //Decodes a base64 encoded string
	BIO *bio, *b64;
	int decodeLen = length,//calcDecodeLength(b64message),
	len = 0;
	*buffer = (char*)malloc(decodeLen+1);
	FILE* stream = fmemopen(b64message, strlen(b64message), "r");
	 
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_fp(stream, BIO_NOCLOSE);
	bio = BIO_push(b64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
	len = BIO_read(bio, *buffer, strlen(b64message));
	//Can test here if len == decodeLen - if not, then return an error
	(*buffer)[len] = '\0';
	 
	BIO_free_all(bio);
	fclose(stream);
	 
	return (0); //success
} 
char *unbase64(unsigned char *input, int length)
{
  BIO *b64, *bmem;

  char *buffer = (char *)malloc(length);
  memset(buffer, 0, length);

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new_mem_buf(input, length);
  bmem = BIO_push(b64, bmem);

  BIO_read(bmem, buffer, length);

  BIO_free_all(bmem);
  return buffer;
}

static int Safebox_verifyChallenge(pam_handle_t * pamh, RSA * pubKey, 
	const char * challenge, const char * signature)
{
	int fd;
    int i,n;
    CK_RV ret;
    CK_MECHANISM mechanism;
    CK_ULONG signatureLen = 20; //sha digest length
    CK_BYTE * sign;
    SHA_CTX ctx;
    unsigned char digest[SHA_DIGEST_LENGTH];
    //unsigned char * decodedSignature;
   	//unsigned char * decodedChallenge;

    //Base64Decode(challenge,&decodedChallenge);
   // decodedChallenge = (unsigned char *) unbase64(challenge,64);
   // decodedSignature = (unsigned char *) unbase64(signature,175);
    D(("Decoded digest: %s",challenge));

    //Base64Decode(signature,&decodedSignature);
    D(("Decoded Signature: %s",signature));

    //SHA1_Init ( &ctx );
    //SHA1_Update ( &ctx, challenge, strlen(challenge) );
   // SHA1_Final ( digest, &ctx );

    if (RSA_verify ( NID_sha1, challenge, 20, signature, 128, pubKey ) == 1) {
		D(("PTEID CC authentication: success!"));
		return CKR_OK;
    }

    D(("PTEID CC authentication: failure (signature not validated!"));

    return PAM_AUTHTOK_ERR;

}

static int Safebox_login( pam_handle_t * pamh,  
		const char* signature, const char * challenge)
{
	struct pubkey_t * pubkey;
    long ret;
    int i;
    unsigned char * keyN, *ccmod;
    unsigned char * keyE, *ccexp;
    //pubKeys = CC_loadKeys ( (char *) kpubfile );
    

    pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &ccmod,"modulus");    
	if(strlen(ccmod) == 0)
		return PAM_AUTH_ERR;
	keyN = (unsigned char*) malloc (257);
   	strncpy( keyN, ccmod, 256);
    keyN[256] = '\0';
    D(("Received mod: %s \n", keyN));

	pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &ccexp,"exponent");
	if(strlen(ccexp) == 0)
		return PAM_AUTH_ERR;
	keyE = (unsigned char*) malloc (20);
    strncpy (keyE, ccexp, 19 );
	D(("Received exp: %s \n", keyE));

	RSA * key = RSA_new ();
    BN_hex2bn ( &key->e, keyE );
	BN_hex2bn ( &key->n, keyN );

	ret = Safebox_verifyChallenge ( pamh, key, challenge,signature);
    
    if (ret == CKR_OK){
    	printf ( "pinta" );
    	return PAM_SUCCESS;
    }else if (ret < 0) {
        printf ( "PTEID CC error" );
    }

    return PAM_AUTH_ERR;
    /*for (i = 0; pubKeys[i].username != 0; i++) {
        if (strcmp ( pubKeys[i].username, pwd->pw_name ) == 0) {
	    RSA * key = RSA_new ();
	    BN_hex2bn ( &key->e, pubKeys[i].e );
	    BN_hex2bn ( &key->n, pubKeys[i].n );

	    D(("Found public key for user %s", pwd->pw_name));

	    ret = Safebox_verifyChallenge ( pamh, key, challenge,signature);
	    if (ret == CKR_OK)
	    	return PAM_SUCCESS;
	    else if (ret < 0) {
	        printf ( "PTEID CC error" );
	    }

	    return PAM_AUTH_ERR;
	}
    }*/
    return PAM_AUTHINFO_UNAVAIL;
}



PAM_EXTERN int
pam_sm_authenticate ( pam_handle_t *pamh, int flags, int argc,
			const char *argv[] )
{
	int retval;
	const char *user, *prompt;
	unsigned char * data,*data2,*flag;
	char *signature,*challenge;
	retval = pam_get_user ( pamh, &user, NULL );
	if (retval != PAM_SUCCESS)
		return retval;
 
	D(("Got user: %s", user));

	

	pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &data,"signature");
	if(strlen(data) == 0)
		return PAM_AUTH_ERR;
	signature = (unsigned char*) malloc(128);
	//signature = (unsigned char*) unbase64(data, 175);
	D(("Received Signature: %s \n", data));
	Base64Decode(data,&signature,175);

	pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &data2,"challenge");	
	if(strlen(data2) == 0)
		return PAM_AUTH_ERR;
	challenge = (unsigned char*) malloc (20);
	//challenge = (unsigned char*) unbase64 (data2, 29);
	D(("Received digest: %s \n", data2));
	Base64Decode(data2,&challenge,29);
    
    /*char *p;
    p = strtok(data, "-");
    if(p)
    	challenge = p;//printf("%s\n", p);
    D(("Received challenge: %s \n", challenge));

    p = strtok(NULL, "-");
    if(p)
        signature = p;//printf("%s\n", p);
    D(("Received Signature: %s \n", signature));*/

	return Safebox_login ( pamh,  signature,challenge);
}

/*
* Credentials management
*/

PAM_EXTERN int
pam_sm_setcred ( pam_handle_t *pamh, int flags, int argc,
			const char *argv[] )
{
    return PAM_SUCCESS;
}

/*
* Account management
*/

pam_sm_acct_mgmt ( pam_handle_t *pamh, int flags, int argc,
			const char *argv[] )
{
    return PAM_SUCCESS;
}

/*
* Password management
*/

PAM_EXTERN int
pam_sm_chauthtok ( pam_handle_t *pamh, int flags, int argc,
			const char *argv[] )
{
    return (PAM_SERVICE_ERR);
}