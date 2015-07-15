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

//#include "pteidlib.h"
//#include "cryptoki.h"
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
//#include "CCkpubFile.h"

static int calcDecodeLength(const char* b64input) { //Calculates the length of a decoded base64 string
	int len = strlen(b64input);
	int padding = 0;
	 
	if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
	padding = 2;
	else if (b64input[len-1] == '=') //last char is =
	padding = 1;
	 
	return (int)len*0.75 - padding;
}
static int Base64Decode(char* b64message, char** buffer) { //Decodes a base64 encoded string
	BIO *bio, *b64;
	int decodeLen = calcDecodeLength(b64message),
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

PAM_EXTERN int
pam_sm_authenticate ( pam_handle_t *pamh, int flags, int argc,
			const char *argv[] )
{
	int retval;
	const char *user, *prompt;
	char *data,*data2,*flag;
	char * pwdt,*pwds;
	retval = pam_get_user ( pamh, &user, NULL );
	if (retval != PAM_SUCCESS)
		return retval;
 
	D(("Got user: %s", user));

	D(("cenas"));
	pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &data,"attempt");
	if(data == NULL)
		return PAM_AUTH_ERR;
	Base64Decode(data,&pwdt);
	D(("Attempted Password: %s \n", pwdt));

	pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &data2,"storedpassword");
	Base64Decode(data2,&pwds);
	if(strlen(data2) == 0)
		return PAM_AUTH_ERR;
	D(("Stored Password: %s \n", pwds));

	if(strcmp(pwdt,pwds) == 0){
		D(("PTEID CC authentication: success!"));
		return PAM_SUCCESS;
	}

	return PAM_AUTH_ERR;
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