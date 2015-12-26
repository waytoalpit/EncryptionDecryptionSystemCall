/*  
 *  FILE:       sys_xcrypt.h
 *  AUTHOR:     Alpit Gupta
 *  Solar:		110451714
 *  DESCRIPTION:  header file to include the structure
 */

#define __NR_xcrypt 359 
typedef struct syscallargs 
{
	char *infile;		// Input file provided for encryption/decryption 		
	char *outfile;		// Output file provided for decryption/encryption
	char *keybuf;		// keybuffer to hold password provide by user
	int keylen;         // password or keybuffer length    
	int flags;			// flag to indicate whether to perform encryption or decryption.
} sysargs;


