#include <linux/init.h>		/* __init and __exit macroses */
#include <linux/kernel.h>	/* KERN_INFO macros */
#include <linux/module.h>	/* required for all kernel modules */
#include <linux/moduleparam.h>	/* module_param() and MODULE_PARM_DESC() */

#include <linux/fs.h>		/* struct file_operations, struct file */
#include <linux/miscdevice.h>	/* struct miscdevice and misc_[de]register() */
#include <linux/mutex.h>	/* mutexes */
#include <linux/string.h>	/* memchr() function */
#include <linux/slab.h>		/* kzalloc() function */
#include <linux/sched.h>	/* wait queues */
#include <linux/uaccess.h>	/* copy_{to,from}_user() */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Valentine Sinitsyn <valentine.sinitsyn@gmail.com>");
MODULE_DESCRIPTION("In-kernel phrase reverser");

static unsigned long buffer_size = 8192;
module_param(buffer_size, ulong, (S_IRUSR | S_IRGRP | S_IROTH));
MODULE_PARM_DESC(buffer_size, "Internal buffer size");

struct buffer {
	wait_queue_head_t read_queue;
	struct mutex lock;
	char *data, *end;
	char *read_ptr;
	unsigned long size;
};

static struct buffer *buffer_alloc(unsigned long size)
{
	struct buffer *buf = NULL;

	buf = kzalloc(sizeof(*buf), GFP_KERNEL);
	if (unlikely(!buf))
		goto out;

	buf->data = kzalloc(size, GFP_KERNEL);
	if (unlikely(!buf->data))
		goto out_free;

	init_waitqueue_head(&buf->read_queue);

	mutex_init(&buf->lock);

	/* It's unused for now, but may appear useful later */
	buf->size = size;

 out:
	return buf;

 out_free:
	kfree(buf);
	return NULL;
}

static void buffer_free(struct buffer *buffer)
{
	kfree(buffer->data);
	kfree(buffer);
}

static inline char *reverse_word(char *start, char *end)
{
	char *orig_start = start, tmp;

	for (; start < end; start++, end--) {
		tmp = *start;
		*start = *end;
		*end = tmp;
	}

	return orig_start;
}

static char *reverse_phrase(char *start, char *end)
{
	char *word_start = start, *word_end = NULL;

	while ((word_end = memchr(word_start, ' ', end - word_start)) != NULL) {
		reverse_word(word_start, word_end - 1);
		word_start = word_end + 1;
	}

	reverse_word(word_start, end);

	return reverse_word(start, end);
}

static int reverse_open(struct inode *inode, struct file *file)
{
	struct buffer *buf;
	int err = 0;

	/*
	 * Real code can use inode to get pointer to the private
	 * device state.
	 */

	buf = buffer_alloc(buffer_size);
	if (unlikely(!buf)) {
		err = -ENOMEM;
		goto out;
	}

	file->private_data = buf;

 out:
	return err;
}

static ssize_t reverse_read(struct file *file, char __user * out,
			    size_t size, loff_t * off)
{
	struct buffer *buf = file->private_data;
	ssize_t result;

	if (mutex_lock_interruptible(&buf->lock)) {
		result = -ERESTARTSYS;
		goto out;
	}

	while (buf->read_ptr == buf->end) {
		mutex_unlock(&buf->lock);
		if (file->f_flags & O_NONBLOCK) {
			result = -EAGAIN;
			goto out;
		}
		if (wait_event_interruptible
		    (buf->read_queue, buf->read_ptr != buf->end)) {
			result = -ERESTARTSYS;
			goto out;
		}
		if (mutex_lock_interruptible(&buf->lock)) {
			result = -ERESTARTSYS;
			goto out;
		}
	}

	size = min(size, (size_t) (buf->end - buf->read_ptr));
	if (copy_to_user(out, buf->read_ptr, size)) {
		result = -EFAULT;
		goto out_unlock;
	}

	buf->read_ptr += size;
	result = size;

 out_unlock:
	mutex_unlock(&buf->lock);
 out:
	return result;
}

static ssize_t reverse_write(struct file *file, const char __user * in,
			     size_t size, loff_t * off)
{
	struct buffer *buf = file->private_data;
	ssize_t result;

	if (size > buffer_size) {
		result = -EFBIG;
		goto out;
	}

	if (mutex_lock_interruptible(&buf->lock)) {
		result = -ERESTARTSYS;
		goto out;
	}

	if (copy_from_user(buf->data, in, size)) {
		result = -EFAULT;
		goto out_unlock;
	}

	buf->end = buf->data + size;
	buf->read_ptr = buf->data;

	if (buf->end > buf->data)
		reverse_phrase(buf->data, buf->end - 1);

	wake_up_interruptible(&buf->read_queue);

	result = size;
 out_unlock:
	mutex_unlock(&buf->lock);
 out:
	return result;
}

static int reverse_close(struct inode *inode, struct file *file)
{
	struct buffer *buf = file->private_data;

	buffer_free(buf);

	return 0;
}

static struct file_operations reverse_fops = {
	.owner = THIS_MODULE,
	.open = reverse_open,
	.read = reverse_read,
	.write = reverse_write,
	.release = reverse_close,
	.llseek = noop_llseek
};

static struct miscdevice reverse_misc_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "reverse",
	.fops = &reverse_fops
};

static int __init reverse_init(void)
{
	if (!buffer_size)
		return -1;

	misc_register(&reverse_misc_device);
	printk(KERN_INFO
	       "reverse device has been registered, buffer size is %lu bytes\n",
	       buffer_size);

	return 0;
}

static void __exit reverse_exit(void)
{
	misc_deregister(&reverse_misc_device);
	printk(KERN_INFO "reverse device has been unregistered\n");
}

module_init(reverse_init);
module_exit(reverse_exit);
