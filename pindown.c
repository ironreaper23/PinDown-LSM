/**
 * PinDOWN implementation
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/smp_lock.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/ext2_fs.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/kd.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <asm/ioctls.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/quota.h>
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>
#include <linux/sysctl.h>
#include <linux/audit.h>
#include <linux/string.h>

#define MAX_PATHLEN 128

typedef struct pindown_security_t {
  char bprm_pathname[MAX_PATHLEN];
  u32 pathlen;
} pindown_security_t;


MODULE_LICENSE("GPL");

#define INITCONTEXTLEN 100
#define XATTR_SAMPLE_SUFFIX "pindown"
#define XATTR_NAME_SAMPLE XATTR_SECURITY_PREFIX XATTR_SAMPLE_SUFFIX

extern struct security_operations *security_ops;
	
/* Function: get_inode_policy(@inode, @name)
 * Description:
 *  - Utility function for getting the pathname policy from an inode
 *  - returns pointer to allocated string (needs deallocation)
 * Input:
 *  @inode	: the inode
 *  @name	: xattr name to lookup
 * Output:
 *  - returns allocated string of pathname
 *  - NULL indicates error or not found
 *  - return value needs to be kfree()'d after this call if not NULL
 */
char *get_inode_policy(struct inode *inode, const char *name)
{
    	int rc = -1;
	char *pathname = NULL;
	struct dentry *dentry;
	int len = 0;

	/* Make sure this inode supports the functions we need */
	if (!inode || !inode->i_op || !inode->i_op->getxattr) {
		goto out;
	}

	/* getxattr requires a dentry */
	dentry = d_find_alias(inode);
	if (!dentry) {
		goto out;
	}

	/* Try default length */
	len = INITCONTEXTLEN;
	pathname = (char*)kmalloc(sizeof(char)*len, GFP_KERNEL);
	if (!pathname) {
		dput(dentry);
		goto out;
	}
	rc = inode->i_op->getxattr(dentry, name, pathname, len*sizeof(char));

	if (rc == -ERANGE) {
		/* Need a larger buffer. Query for the right size */
		rc = inode->i_op->getxattr(dentry, name, NULL, 0);
		//rgetxattr does - retrieves the value of the extended attribute identified by name and associated with the given path in the filesystem.
		if (rc < 0) { /* could not get size */
		       	dput(dentry);
			kfree(pathname);
			pathname = NULL;
			goto out;
		}

		/* start over with correct size */
		kfree(pathname);
		len = rc / sizeof(char);
		pathname = (char*)kmalloc(sizeof(char)*len, GFP_KERNEL);
		if (!pathname) {
			rc = -ENOMEM;
			dput(dentry);
			goto out;
		}
		rc = inode->i_op->getxattr(dentry, name, pathname, len*sizeof(char));
	}
	dput(dentry);

	if (rc < 0) {
		kfree(pathname);
		pathname = NULL;
		goto out;
	}

out:
	return pathname;
}

/* Function: pindown_inode_permission(@inode, @mask, @nd)
 * Description:
 *  - LSM Hook .inode_permission()
 *  - Performs the main access control check on files
 * Input:
 *  @inode	: pointer to the inode (object) of the lookup
 *  @mask	: permission mask of the lookup (not used at all)
 *  @nd		: ?? (not used at all)
 * Output:
 *  - returns 0 for access granted, -EACCES for permission denied
 */
int pindown_inode_permission(struct inode *inode, int mask, struct nameidata *nd)
{

        //Initial default allow. Change to default deny once implemented. 
	int rc = 0;
	pindown_security_t *sec = NULL;
	char *inode_policy = NULL;

	/* Don't check this if it is a directory */
	if ((inode->i_mode & S_IFMT) == S_IFDIR) {
		rc = 0;
		goto out;
	}

	/* Get the process security info */		
	sec = current->security;
	//printk(KERN_INFO "Pindown: sec->bprm_pathname:%s \n",sec->bprm_pathname);
	
	/* Get the inode policy */
	inode_policy = get_inode_policy(inode,"security.pindown");
	//printk(KERN_INFO "Pindown: inode_policy:%s \n",inode_policy);
		

    /* Compare process security info to inode policy */

    // pinup 547 & check_permission_type 433
   //as given in the question, validation is required only when "security.pindown" is mentioned, so give access to other files that arent pinned
	if(!inode_policy){
		//printk(KERN_INFO " Pindown: Security allowed for no inode policy, security policy not set \n");
		rc = 0; 
		goto out;

	}
	//if there is no pathname set , deny access 
	if ((!sec) || (sec->bprm_pathname[0] == '\0')){
		printk(KERN_INFO " Pindown: Security Denied for no pathname\n");
		rc = -EACCES; // access denied 
		goto out;
	}
	rc = 0; //set default allow 
	if ((strlen(inode_policy) < MAX_PATHLEN) && (strcmp(inode_policy,sec->bprm_pathname)==0)){
        rc=0;
        printk(KERN_INFO "Pindown: String compare match, inode_policy - %s \n , bprm - %s\n",inode_policy, sec->bprm_pathname );
    }
    else{
        rc = -EACCES;
        printk(KERN_INFO "Pindown: String compare didnt match, inode_policy - %s \n , bprm - %s\n",inode_policy, sec->bprm_pathname );
        goto out;
    }

out:
	// if inode is not null delete it before returning
	if (inode_policy){
		kfree(inode_policy);
	}
	return rc;
}


/* Function: pindown_task_alloc_security(@p)
 * Description:
 *  - LSM Hook .task_alloc_security()
 *  - Allocates @p->security to store the path
 * Input:
 *  @p	    : pointer to the child task_struct
 * Output:
 *  - @p->security is allocated
 *  - returns 0 if successful
 */
int pindown_task_alloc_security(struct task_struct * p)
{
	int err = 0;
	pindown_security_t *sec = NULL;
	pindown_security_t *parent_sec = current->security; // Parent security set 
	int len;

	sec = (pindown_security_t *)kmalloc(sizeof(pindown_security_t), GFP_KERNEL);
	if (sec == NULL) {
		err = -ENOMEM;
		goto out;
	} 

	/* When we fork, we are still the same application as our
	 * parent, therefore, it is appropriate to copy the 
	 * parent's digest. On exec(), the digest will be set to 
	 * the new application binary with pindown_bprm_set_security()
	 */

	if (!parent_sec){
		sec->bprm_pathname[0]='\0';
		sec->pathlen = 0;
	}
	else{
		// set the child's pathname to be same as parent path name
		len = strlen(parent_sec->bprm_pathname);
		if (len < MAX_PATHLEN){
			strcpy(sec->bprm_pathname,parent_sec->bprm_pathname); //using strcpy since the bprm pathlen buffer is large enough as MAX_PATHLEN
			sec->pathlen = len;
		}
		else { //same as given above methods
			err = -ENOMEM;
			goto out;
		}
	}
	p->security = sec; //task struct p is allocated
	return 0;	

out:
	return err;
}


/* Function: pindown_task_free_security(@p)
 * Description:
 *  - LSM Hook .task_free_security()
 *  - Deallocates @p->security
 * Input:
 *  @p	    : pointer to the child task_struct
 * Output:
 *  - @p->security is deallocated
 */
void pindown_task_free_security(struct task_struct * p)
{
	pindown_security_t *sec;
	if (!p->security) {
		return;
	}
	sec = p->security;
	kfree(sec);
	p->security = NULL;
	return;
}

/* Function: pindown_bprm_set_security(@bprm)
 * Description:
 *  - LSM Hook .bprm_set_security()
 *  - Sets @current->security to the path of the binary
 * Input:
 *  @bprm   : pointer to a binary being loaded by the kernel
 * Output:
 *  - @current->security is set to the path of the binary
 *  - return 0 if the hook is successful and permission is granted
 */
int pindown_bprm_set_security(struct linux_binprm * bprm)
{
	int rc = 0;
	pindown_security_t *sec = current->security; // intializing with the current security
	int len;

	if (sec == NULL) {
		rc = pindown_task_alloc_security(current);
	} 
	/* Set the pathname from the exec()'d binary filename */
	if (!rc) {
	   if (!bprm || !bprm->filename) {
		   sec->bprm_pathname[0] = '\0';
		   sec->pathlen = 0;
	   }
	   else{
		   len = strlen (bprm->filename)
		   if(len < MAX_PATHLEN){
			   strcpy(sec->bprm_pathname,bprm->filename);
			   sec->pathlen = len;
		   }
	   }
	}
	return rc;
}


static struct security_operations pindown_ops = {
	.task_alloc_security =		pindown_task_alloc_security,
	.task_free_security =		pindown_task_free_security,
	.bprm_set_security =		pindown_bprm_set_security,
	.inode_permission =		pindown_inode_permission,
};

static __init int pindown_init(void)
{
	if (register_security (&pindown_ops)) {
		printk("Pindown: Unable to register with kernel.\n");
		return 0;
	}
	printk(KERN_INFO "pindown:  Initializing from this point ................................................................................\n");
	return 0;
}

static __exit void pindown_exit(void)
{
	printk(KERN_INFO "pindown: Exiting.\n");
	unregister_security(&pindown_ops);
}

module_init(pindown_init);
module_exit(pindown_exit);
