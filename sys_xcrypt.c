/*  
 *  FILE:       sys_xcrypt.c
 *  AUTHOR:     Alpit Gupta
 *  Solar:     110451714
 *  DESCRIPTION:  Implementations of encryption/decryption using System call
 */

#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <asm/uaccess.h>
#include <asm/string.h>
#include "sys_xcrypt.h"
#include <linux/kernel.h>
#include <asm/string.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <crypto/hash.h>


asmlinkage extern long (*sysptr)(void *arg);

#define MAX_FILE_LENGTH 254
#define AES_BLOCK_SIZE 16
char *aes_iv = "alpitkumarguptaa";

// check if valid input has been passed to the system call
long isValidInput(void *arg)
{
        // return value for isValidInput function
        long ret=0;

        sysargs *pt=(sysargs *) arg;

        // check pointer of structure along with its read access for its size
        if(pt==NULL || unlikely(!access_ok(VERIFY_READ, pt, sizeof(sysargs))))
        {
            ret=-EACCES;
            goto input_fail;
        }
        
        // check null and read access for input file
        if(pt->infile==NULL || unlikely(!access_ok(VERIFY_READ, pt->infile, sizeof(pt->infile))))
        {
            ret=-EACCES;
            goto input_fail;
        }
        
        // check null and read access for output file
        if(pt->outfile==NULL || unlikely(!access_ok(VERIFY_READ, pt->outfile, sizeof(pt->outfile))))
        {
            ret=-EACCES;
            goto input_fail;
        }
        
        // check null and read access for keybuffer 
        if(pt->keybuf==NULL || unlikely(!access_ok(VERIFY_READ, pt->keybuf, sizeof(pt->keylen))))
        {
            ret=-EACCES;
            goto input_fail;
        }
        
        // check for maximum file name length of input file
        if(strlen(pt->infile)>MAX_FILE_LENGTH)
        {
            ret=-ENAMETOOLONG;
            goto input_fail;
        }
        
        // check for maximum file name length of output file
        if(strlen(pt->outfile)>MAX_FILE_LENGTH)
        {
            ret=-ENAMETOOLONG;
            goto input_fail;
        }
        
    input_fail:
        return ret;
}

// copy data from user to kernel space
long copyData(sysargs *arg, sysargs *k_arg)
{

        // return value for copyData function
    	long ret=0;

        // memory allocation to store input file name
    	k_arg->infile = kmalloc(strlen(arg->infile) + 1, GFP_KERNEL);

        // copy input file name from user to kernel space if memory is allocated successfully
    	if(k_arg->infile)
        {
    		ret=copy_from_user(k_arg->infile, arg->infile, strlen(arg->infile));
    		if(ret!=0)
            {
                ret=-EFAULT;
                goto infile_fail;
            }
        }
    	else
        {   
            ret=-ENOMEM;    
            goto infile_fail;
        }
    	
        // memory allocation to store output file name
    	k_arg->outfile = kmalloc(strlen(arg->outfile) + 1, GFP_KERNEL);

        // copy output file name from user to kernel space if memory is allocated successfully
    	if(k_arg->outfile)
        {
    		ret=copy_from_user(k_arg->outfile, arg->outfile, strlen(arg->outfile));
    		if(ret!=0)
            {
                ret=-EFAULT;
                goto outfile_fail;
            }
        }
    	else
        {
            ret=-ENOMEM;    
            goto outfile_fail;
        }
    	
        // memory allocation to store keybuffer
    	k_arg->keybuf = kmalloc(strlen(arg->keybuf) + 1, GFP_KERNEL);

        // copy keybuffer from user to kernel space if memory is allocated successfully
    	if(k_arg->keybuf)
        {
    		ret=copy_from_user(k_arg->keybuf, arg->keybuf, strlen(arg->keybuf));
    		if(ret!=0)
            {
                ret=-EFAULT;
                goto keybuf_fail;
            }
    	}
    	else
        {
            ret=-ENOMEM;    
            goto keybuf_fail;
        }
    	
        // copy keylength from user to kernel space if memory is allocated successfully
    	ret=copy_from_user(&k_arg->keylen, &arg->keylen, sizeof(int));
    	if(ret!=0)
        {
            ret=-EFAULT;
            goto keybuf_fail;
        }

        // copy flag value from user to kernel space if memory is allocated successfully
    	ret=copy_from_user(&k_arg->flags, &arg->flags,sizeof(int));
    	if(ret!=0)
        {
            ret=-EFAULT;
            goto keybuf_fail;
        }

        // null termination of below strings
    	k_arg->infile[strlen(arg->infile)] = '\0';

    	k_arg->outfile[strlen(arg->outfile)] = '\0';

    	k_arg->keybuf[strlen(arg->keybuf)] = '\0';

        // return 0 in case of successful copying of all the arguments
    	if(ret == 0)	
    		return ret;					
    	
    keybuf_fail:
        kfree(k_arg->keybuf);
    outfile_fail:
        kfree(k_arg->outfile);
    infile_fail:
        kfree(k_arg->infile);

    return ret;
}

/*
    Actual encryption is performed
    Code has been refernced from http://lxr.free-electrons.com/source/net/ceph/crypto.c
    ceph_aes_encrypt function which eventually call crypto_blkcipher_encrypt api
 */
static int doEncryption(const void *key, int key_len, void *dst, size_t *dst_len, const void *src, size_t src_len)
{
        
    struct scatterlist sg_in[1], sg_out[1];

    // CTR mode has been used to avoid explicit padding
    struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);

    struct blkcipher_desc desc = {.tfm = tfm, .flags = 0};

    long ret=0;

    void *iv;
    int ivsize;

    if(IS_ERR(tfm)) 
    {
        ret = PTR_ERR(tfm);
        goto encrypt_fail;
    }
                                       
    ret = crypto_blkcipher_setkey(tfm, key, key_len);
    iv = crypto_blkcipher_crt(tfm)->iv;
    ivsize = crypto_blkcipher_ivsize(tfm);
    memcpy(iv, aes_iv, ivsize);
    
    //Initialize SG table
    sg_init_table(sg_in, 1);
    sg_init_table(sg_out, 1);

    //Set sg entry to point at given data
    sg_set_buf(sg_in, src, src_len);
    sg_set_buf(sg_out, dst, *dst_len);
    
    // encrypt plaintext
    // method has been refernced from http://lxr.free-electrons.com/source/include/linux/crypto.h#L1333                                                                 
    ret = crypto_blkcipher_encrypt(&desc, sg_out, sg_in, *dst_len);
    crypto_free_blkcipher(tfm);

    if(ret<0) 
    {
        pr_err("doEncryption failed %lu\n", ret);
        goto encrypt_fail;
    }

    encrypt_fail:
        return ret;
}


/*
    Actual decryption is performed
    Argument specified: 
        Code has been refernced from http://lxr.free-electrons.com/source/net/ceph/crypto.c
        ceph_aes_decrypt function which eventually call crypto_blkcipher_decrypt api
 */
static int doDecryption(const void *key, int key_len, void *dst, size_t *dst_len, const void *src, size_t src_len)
{

    struct scatterlist sg_in[1], sg_out[1];

    // CTR mode has been used to avoid explicit padding
    struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);

    struct blkcipher_desc desc = {.tfm = tfm, .flags = 0};

    long ret=0;

    void *iv;
    int ivsize;

    if(IS_ERR(tfm)) 
    {
        ret = PTR_ERR(tfm);
        goto decrypt_fail;
    }
                                       
    ret = crypto_blkcipher_setkey(tfm, key, key_len);
    iv = crypto_blkcipher_crt(tfm)->iv;
    ivsize = crypto_blkcipher_ivsize(tfm);
    memcpy(iv, aes_iv, ivsize);
    
    // Initialize SG table
    sg_init_table(sg_in, 1);
    sg_init_table(sg_out, 1);

    //Set sg entry to point at given data
    sg_set_buf(sg_in, src, src_len);
    sg_set_buf(sg_out, dst, *dst_len);

    // decrypt ciphertext
    // method has been refernced from http://lxr.free-electrons.com/source/include/linux/crypto.h#L1386
    ret = crypto_blkcipher_decrypt(&desc, sg_out, sg_in, *dst_len);
    crypto_free_blkcipher(tfm);

    if(ret<0) 
    {
        pr_err("doDecryption failed %lu\n", ret);
        goto decrypt_fail;
    }

    
    decrypt_fail:
        return ret;
}


// Actual system call Implementation
asmlinkage long xcrypt(void *arg)
{
	
    // Argument structure data type
	sysargs *k_arg=NULL;

    // return value
	long ret=0;

    // read buffer
	char *buf=NULL;

    // secondary buffer used for encryption/decryption
	char *bufTemp=NULL;

    // structure defined to read file
	struct file *filpr;

    mm_segment_t oldfs;

    // bytes read from input fileSize
    int bytesRead;

    // total input file size
    unsigned int fileSize = 0;

    // multiple of PAGE_SIZE
    unsigned int numberOfPageSize = 0;
    
    // use temp file to write data, avoid partial write operation
    char tempOutput[4];

    // structure defined to write to the final output file
    struct file *fileOut;

    // structure defined to write file
    struct file *filpw;

    // bytes wrote to the output file
    long bytesWrite;

    // check if file output file already exists?
    int isExist=0;

    // error occured while file reading or writing, needs to delete the temp file without deleting the previous output file
    int errorReported=0;

    // variables declared to calculate the MD5 hash value of the keybuffer
    struct crypto_shash *md5;
    char *md5_hash = NULL;
    struct shash_desc *desc;
    int cryptSize;

    // dentry and inode are created to unlink output file in case of authentication failure at decryption side
    struct dentry *tmpDentry=NULL;
    struct inode *tmpInode = NULL;

    // checking all arguments passed to the system call, user space
    ret=isValidInput(arg);
	
    // In case of any validation error, return error
	if(ret != 0)
	   goto error_happened;
    
    // new structure created to copy user data to kernel space
	k_arg= kmalloc(sizeof(sysargs), GFP_KERNEL);

    // return error in case of memory not allocated
	if(!k_arg)
	{
	    ret= -ENOMEM;
		goto k_arg_fail;
	}
    
    // memeory filled with constant byte 
	memset(k_arg, 0, sizeof(sysargs));

    // copy data from user to kernel space
	ret= copyData(arg, k_arg);

    // return error in case of any copy failure
	if(ret !=0)
	{
	    ret=-ENOMEM;
		goto k_arg_fail;
	}
	
    // opening input file to read data
    filpr = filp_open(k_arg->infile, O_RDONLY, 0);

    // error occured while opening input file
    if(!filpr || IS_ERR(filpr))
    {
        ret = -ENOENT;
        goto k_arg_fail;
    }
    
    // error if there is no I/O for inout file
    if (!filpr->f_op->read)
    {
        ret = -EIO;
        goto k_arg_fail;
    }

    // check if the file is regular or not?
    if(!S_ISREG(filpr->f_path.dentry->d_inode->i_mode)) 
    {
        ret = -EBADF;
        goto k_arg_fail;
    }

    // check if the output file already exists?
    fileOut= filp_open(k_arg->outfile, O_RDONLY, 0);

    // error occured while opening output file
    if(fileOut && !IS_ERR(fileOut))
    {
        isExist=1;    

        // check if the file is regular or not?
        if(!S_ISREG(fileOut->f_path.dentry->d_inode->i_mode)) 
        {
            ret = -EBADF;
            goto k_arg_fail;
        }

    }
    
    // If file is not present, create a new output file
    if(!fileOut || IS_ERR(fileOut))
    {
        fileOut= filp_open(k_arg->outfile, O_WRONLY|O_CREAT, 0);

        // error occured while opening output file
        if(!fileOut || IS_ERR(fileOut))
        {
            ret = -ENOENT;
            goto k_arg_fail;
        } 

        // check for the write access of output file
        if (!fileOut->f_op->write)
        {
            ret = -EROFS;
            goto k_arg_fail;
        }

        // check if the file is regular or not?
        if(!S_ISREG(fileOut->f_path.dentry->d_inode->i_mode)) 
        {
            ret = -EBADF;
            goto k_arg_fail;
        }
        
    }

    // check for input and output file, it should not be the same
    if((filpr->f_path.dentry->d_inode->i_sb == fileOut->f_path.dentry->d_inode->i_sb) && 
        (filpr->f_path.dentry->d_inode->i_ino ==  fileOut->f_path.dentry->d_inode->i_ino)) 
    {
        ret = -EINVAL;
        goto k_arg_fail;
    }
    
    // creating temp output file name
    tempOutput[0]='t';
    tempOutput[1]='m';
    tempOutput[2]='p';
    tempOutput[3]='\0';

    // opening output file to write data
    filpw = filp_open(tempOutput, O_WRONLY|O_CREAT, 0);

    // error occured while opening output file
    if(!filpw || IS_ERR(filpw))
    {
        ret = -ENOENT;
        goto k_arg_fail;
    }     

    // error is there is no write access
    if (!filpw->f_op->write)
    {
        ret = -EROFS;
        goto k_arg_fail;
    }

    // set permission for output file same as input file
	filpw->f_path.dentry->d_inode->i_mode =  filpr->f_path.dentry->d_inode->i_mode;

    // buffer space allocated to hold read data from inut file
	buf= (char *) kmalloc(PAGE_SIZE, GFP_KERNEL);

    // set error and return in case of insufficient memory
	if(buf == NULL)
    {
        ret=-ENOMEM;
        goto buf_fail;
    }

    // memeory filled with constant byte 
    memset(buf, 0, PAGE_SIZE);

    // buffer space allocated to hold encrypted/decrypted data
    bufTemp= (char *) kmalloc(PAGE_SIZE, GFP_KERNEL);

    // set error and return in case of insufficient memory
	if(bufTemp == NULL)
    {
        ret=-ENOMEM;
        goto buf_fail;
    }

    // memeory filled with constant byte 
    memset(bufTemp, 0, PAGE_SIZE);
    
    // read file pointer set to zero location
    filpr->f_pos = 0;

    // write file pointer set to zero location
    filpw->f_pos = 0;
    
    // all address belongs to kernel space, so no translation is required
    oldfs = get_fs();
    set_fs(KERNEL_DS);

    // calculation of input file size
    fileSize = (unsigned int)filpr->f_path.dentry->d_inode->i_size;

    // Integral number of PAGE_SIZE out of total file size
    numberOfPageSize=fileSize/PAGE_SIZE;
    
    // calculate MD5 value again of keybuffer not to expose it to the intruders
    // Below code has been refernced from http://lxr.fsl.cs.sunysb.edu/linux/source/include/crypto/hash.h#L753
    // method crypto_shash_digest impl
    md5 = crypto_alloc_shash("md5", 0, 0);
    if (md5 == NULL) 
    {
        ret = -ENOMEM;
        goto k_arg_fail;
    }

    // cryptSize will be calculated
    cryptSize = sizeof(struct shash_desc) + crypto_shash_descsize(md5);
    desc = kmalloc(cryptSize, GFP_KERNEL);
    if (!desc) 
    {
        ret = -ENOMEM;
        goto k_arg_desc;
    }
    memset(desc, 0, cryptSize);
        
    md5_hash = kmalloc(AES_BLOCK_SIZE, GFP_KERNEL);
    if (!md5_hash) 
    {
        ret = -ENOMEM;
        goto k_arg_md5_hash;
    }
    memset(md5_hash, 0, AES_BLOCK_SIZE);
        
    desc->tfm = md5;
    desc->flags = 0x0;
    
    // calculate message digest for buffer
    ret = crypto_shash_digest(desc,(const char *) k_arg->keybuf,AES_BLOCK_SIZE,md5_hash);
    if (ret)
    {
        ret = -EINVAL;
        goto k_arg_md5_hash;
    }
    
    // zeroize and free the message digest handle    
    crypto_free_shash(md5);

    // do encryption only when input file size is greater than 0
    if(k_arg->flags==1 && fileSize>0)
    {
    	filpw->f_pos = 0;

        // First write the MD5 hash key to the output file
        bytesWrite = filpw->f_op->write(filpw, md5_hash, AES_BLOCK_SIZE, &filpw->f_pos);

        // loop for the integral value of PAGE_SIZE
    	while(numberOfPageSize>0)
    	{
            // read file for each chunk of PAGE_SIZE
        	bytesRead = filpr->f_op->read(filpr, buf, PAGE_SIZE, &filpr->f_pos);

            // exit in case of any file read error
            if(bytesRead<0)
            {
                errorReported=1;
                ret=-EIO;
                goto file_close;
            }

            // actual data encryption for each chunk of PAGE_SIZE using CTR mode technique
        	doEncryption(k_arg->keybuf, AES_BLOCK_SIZE, bufTemp, &bytesRead, buf, PAGE_SIZE);

            // write encrypted data for each chunk of PAGE_SIZE
        	bytesWrite = filpw->f_op->write(filpw, bufTemp, PAGE_SIZE, &filpw->f_pos);

            // exit in case of any file write error
            if(bytesWrite<0)
            {
                errorReported=1;
                ret=-EIO;
                goto file_close;
            }

        	memset(buf, 0, PAGE_SIZE);
    		memset(bufTemp, 0, PAGE_SIZE);	
        	numberOfPageSize=numberOfPageSize-1;
    	}	

        // calculating remaining data, less tha PAGE_SIZE
    	numberOfPageSize=fileSize-(numberOfPageSize*PAGE_SIZE);

        // read the remaining data from input file
    	bytesRead = filpr->f_op->read(filpr, buf, numberOfPageSize, &filpr->f_pos);

        // exit in case of read file error
        if(bytesRead<0)
        {
            errorReported=1;
            ret=-EIO;
            goto file_close;
        }   

        // encrypt the data read from input file
    	doEncryption(k_arg->keybuf, AES_BLOCK_SIZE, bufTemp, &bytesRead, buf, bytesRead);

        // write the encrypted data to the output file
    	bytesWrite = filpw->f_op->write(filpw, bufTemp, bytesRead, &filpw->f_pos);

        // exit in case of any file write error
        if(bytesWrite<0)
        {
            errorReported=1;
            ret=-EIO;
            goto file_close;
        }

    	memset(buf, 0, PAGE_SIZE);
		memset(bufTemp, 0, PAGE_SIZE);
    }

    // do decryption only if file size greater than 0
    if(k_arg->flags==0 && fileSize>0)
    {

        filpr->f_pos = 0;

        // read the first 16 bytes for MD5 hash key, needs to authentication of same key
    	bytesRead = filpr->f_op->read(filpr, buf, AES_BLOCK_SIZE, &filpr->f_pos);
        
        // check if MD5 key calculated here matches with the one we get from file
    	if (memcmp(md5_hash, buf, AES_BLOCK_SIZE) == 0)
    	{
            memset(buf, 0, PAGE_SIZE);
    	    filpw->f_pos = 0;

            // loop for the integral value of PAGE_SIZE
    	    while(numberOfPageSize>0)
    	    {
                // read file for each chunk of PAGE_SIZE
    	    	bytesRead = filpr->f_op->read(filpr, buf, PAGE_SIZE, &filpr->f_pos);

                // exit in case of any file read error
    	    	if(bytesRead<0)
                {
                    errorReported=1;
                    ret=-EIO;
                    goto file_close;
                } 

                // decrypt the data read from input file
                doDecryption(k_arg->keybuf, AES_BLOCK_SIZE, bufTemp, &bytesRead, buf, PAGE_SIZE);
    	    	
                // write the decrypted data to the output file
                bytesWrite = filpw->f_op->write(filpw, bufTemp, PAGE_SIZE, &filpw->f_pos);

                // exit in case of any file write error
                if(bytesWrite<0)
                {
                    errorReported=1;
                    ret=-EIO;
                    goto file_close;
                }

    	    	memset(buf, 0, PAGE_SIZE);
    			memset(bufTemp, 0, PAGE_SIZE);	
    	    	numberOfPageSize=numberOfPageSize-1;
    	    }	

            // remaining data, less tha PAGE_SIZE
    	    numberOfPageSize=fileSize-(numberOfPageSize*PAGE_SIZE);

            // read the remaining data from the input file
            bytesRead = filpr->f_op->read(filpr, buf, numberOfPageSize, &filpr->f_pos);

            // exit in case of any file read error
            if(bytesRead<0)
            {
                errorReported=1;
                ret=-EIO;
                goto file_close;
            }
            
            // decrypt the data read from the input file
    	    doDecryption(k_arg->keybuf, AES_BLOCK_SIZE, bufTemp, &bytesRead, buf, bytesRead);

            // write the decrypted data to the output file
    	    bytesWrite = filpw->f_op->write(filpw, bufTemp, bytesRead, &filpw->f_pos);

            // exit in case of any file write error
            if(bytesWrite<0)
            {
                errorReported=1;
                ret=-EIO;
                goto file_close;
            }

    	    memset(buf, 0, PAGE_SIZE);
    		memset(bufTemp, 0, PAGE_SIZE);
    	}

        // exit and delete the temp file in case of decryption key mismatch
    	else
    	{
            errorReported=1;
    		ret =-EPERM;

            if(isExist==0)
            {
                tmpDentry = fileOut->f_path.dentry;
                tmpInode = fileOut->f_path.dentry->d_parent->d_inode;

                // delete/unlink the temp output file
                if (tmpDentry != NULL && tmpInode != NULL)
                    vfs_unlink(tmpInode, tmpDentry, NULL);
            }

            goto file_close;
    	}
    	
    }

    // dentry and inode of the temp file
    tmpDentry = filpw->f_path.dentry;
    tmpInode = tmpDentry->d_parent->d_inode;

    // rename the temp file to the output file in case of successful encryption/decryption
    vfs_rename(tmpInode, tmpDentry, fileOut->f_path.dentry->d_parent->d_inode,fileOut->f_path.dentry, NULL, 0);

    file_close:
    {

        // error reported in case of any read, encryption, decryption and write error
        if(errorReported==1)
        {
            tmpDentry = filpw->f_path.dentry;
            tmpInode = tmpDentry->d_parent->d_inode;

            // delete/unlink the temp output file
            if (tmpDentry != NULL && tmpInode != NULL)
                vfs_unlink(tmpInode, tmpDentry, NULL);

        }
        
        filp_close(filpw, NULL);
        filp_close(filpr, NULL);
        filp_close(fileOut, NULL);
    }


// resources getting free, most important task
k_arg_md5_hash:
    kfree(md5_hash);
k_arg_desc:    
    kfree(desc);
buf_fail:
    kfree(buf); 
    kfree(bufTemp);
k_arg_fail:
	kfree(k_arg);
error_happened:
	return ret;

}

static int __init init_sys_xcrypt(void)
{
        printk("installed new sys_xcrypt module\n");
        if (sysptr == NULL)
                sysptr = xcrypt;
        return 0;
}

static void  __exit exit_sys_xcrypt(void)
{
        if (sysptr != NULL)
                sysptr = NULL;
        printk("removed sys_xcrypt module\n");
}

module_init(init_sys_xcrypt);
module_exit(exit_sys_xcrypt);
MODULE_LICENSE("GPL");
