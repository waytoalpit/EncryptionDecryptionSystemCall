/*  
 *  FILE:       xcipher.c
 *  AUTHOR:     Alpit Gupta
 *  DESCRIPTION:  User space to make system call
 */

#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "sys_xcrypt.h"
#include <unistd.h>
#include <string.h>
#include <openssl/md5.h>

int main(int argc, char *argv[])
{

	int c;
	int ret= 0;
	int encrypt=0;
	int decrypt=0;
	int pwdFlag=0;
	char *pwd;

	// Argument structure data type
	sysargs arg;

	// Hask key technique: default length of 128 bits
	unsigned char md[MD5_DIGEST_LENGTH];
	
	// parsing command line argument to the user level variables
	while ((c = getopt(argc, argv, "edp:h")) != -1)
	{ 
	  	switch(c)
	  	{
	  	// encryption	
		case 'e':
		     encrypt = 1;
		     break;
		// decryption
		case 'd':
		     decrypt = 1;
		     break;
		// password
		case 'p':
		     pwdFlag = 1;
		     pwd=optarg;
		     break;
		// help
		case 'h':
		     fprintf(stdout, "Usage: {-e|-d} [-c ARG] {-p PASSWORD} [-h HELP] infile outfile\n");
			 return -1;

		default:
		      break;
		}
	}

	if (encrypt == 0 && decrypt == 0) 
	{
		fprintf(stderr, "Error: None of the encryption or decryption type has been specified\n");
		return -1;
	}

	if (encrypt == 1 && decrypt == 1) 
	{
		fprintf(stderr, "Error: Both encrypt and decrypt flag has been specified\n");
		return -1;
	}

	if(pwdFlag==0)
	{
		fprintf(stderr, "Error: Password has not been entered\n");
		return -1;
	}

	if(strlen(pwd)<6)
	{
		fprintf(stderr, "Error: Password length should be greater than 6 characters\n");
		return -1;
	}
	
	if(optind+2!=argc)
	{
		fprintf(stderr, "Error: Input or output file name has not been specified\n");
		return -1;
	}

	// copying input file name
	arg.infile = argv[optind];

	// copying output file name 
	arg.outfile = argv[optind + 1];

	// copying flag value
	arg.flags = (encrypt == 1) ? 1 : 0;	

    // MD5 Hask key conversion 
    MD5((const unsigned char*)pwd, strlen(pwd), md);
	arg.keybuf= (char*)md;

	// length would be same as MD5 hash value 128 bits
	arg.keylen =  MD5_DIGEST_LENGTH;

    // actual system call from user space
    ret = syscall(__NR_xcrypt,&arg);
    
    // return value is handled below
    if (ret != 0)
    {
        perror("Error");
		return -1;
	}

	return ret;
}
