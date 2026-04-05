#include <asm-generic/errno-base.h>
#include <linux/fs.h>
#include <linux/gfp_types.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/miscdevice.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#ifdef pr_fmt
	#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

MODULE_AUTHOR("VulnX");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("A dummy module");

#define MAX_ALLOC	1024
#define CHUNK_SIZE	256

enum commands {
	CMD_ALLOC	= 0x1000,
	CMD_FREE	= 0x1001,
	CMD_READ	= 0x1002,
	CMD_WRITE	= 0x1003,
};

typedef struct {
	unsigned int idx;
	char *buffer;
} req_t;

struct kmem_cache *cachep;

static int vuln_open(struct inode *inode, struct file *fp)
{
	void **allocated_chunks;

	allocated_chunks = kzalloc(MAX_ALLOC * sizeof(*allocated_chunks), GFP_KERNEL);
	if (!allocated_chunks)
		return -ENOMEM;
	fp->private_data = allocated_chunks;
	return 0;
}

static int vuln_close(struct inode *inode, struct file *fp)
{
	void **allocated_chunks;

	allocated_chunks = fp->private_data;
	if (!allocated_chunks)
		return -EINVAL;
	for (int i = 0 ; i < MAX_ALLOC ; i++) {
		if (allocated_chunks[i]) {
			kfree(allocated_chunks[i]);
			allocated_chunks[i] = NULL;
		}
	}
	kfree(allocated_chunks);
	return 0;
}

static long vuln_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
	void **allocated_chunks;
	req_t req;

	allocated_chunks = fp->private_data;
	if (!allocated_chunks)
		return -EINVAL;

	if (copy_from_user(&req, (void *)arg, sizeof(req)))
		return -EINVAL;

	switch (cmd) {
	case CMD_ALLOC:
		if (req.idx > MAX_ALLOC)
			return -EINVAL;
		if (allocated_chunks[req.idx])
			return -EEXIST;
		allocated_chunks[req.idx] = kmem_cache_alloc(cachep, GFP_KERNEL);
		if (!allocated_chunks[req.idx])
			return -ENOMEM;
		pr_info("allocated_chunks[%d] = %#lx\n", req.idx,
			 (unsigned long)allocated_chunks[req.idx]);
		break;
	case CMD_FREE:
		if (req.idx >= MAX_ALLOC)
			return -EINVAL;
		if (!allocated_chunks[req.idx])
			return -EINVAL;
		kmem_cache_free(cachep, allocated_chunks[req.idx]);
		// --- vuln
		// allocated_chunks[req.idx] = NULL;
		// --- vuln
		break;
	case CMD_READ:
		if (req.idx >= MAX_ALLOC)
			return -EINVAL;
		if (!allocated_chunks[req.idx])
			return -EINVAL;
		if (copy_to_user(req.buffer, allocated_chunks[req.idx],
			CHUNK_SIZE))
			return -EINVAL;
		break;
	case CMD_WRITE:
		if (req.idx >= MAX_ALLOC)
			return -EINVAL;
		if (!allocated_chunks[req.idx])
			return -EINVAL;
		if (copy_from_user(allocated_chunks[req.idx], req.buffer,
			CHUNK_SIZE))
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

struct file_operations fops = {
	.open = vuln_open,
	.release = vuln_close,
	.unlocked_ioctl = vuln_ioctl,
	.owner = THIS_MODULE,
};

struct miscdevice misc = {
	.fops = &fops,
	.name = KBUILD_MODNAME,
	.mode = 0444,
};

static int __init vuln_init(void)
{
	int ret;

	ret = misc_register(&misc);
	if (ret) {
		pr_err("Failed to register misc device\n");
		return ret;
	}
	cachep = kmem_cache_create("vuln_cache", CHUNK_SIZE, 0, SLAB_NO_MERGE, NULL);
	if (!cachep) {
		pr_err("Failed to allocate vuln_cache\n");
		return -ENOMEM;
	}
	pr_info("Module loaded successfully, cachep = %#lx\n", (unsigned long)cachep);
	return 0;
}

static void __exit vuln_exit(void)
{
	kmem_cache_destroy(cachep);
	misc_deregister(&misc);
	pr_info("Removing module...\n");
}

module_init(vuln_init);
module_exit(vuln_exit);