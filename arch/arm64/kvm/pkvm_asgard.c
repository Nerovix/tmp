// SPDX-License-Identifier: GPL-2.0

#include <linux/fs.h>
#include <linux/kvm_host.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/pkvm_asgard.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

/* 用户态测试入口：把控制命令转发到 host->EL2 hypercall。 */
static long pkvm_asgard_ioctl(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
	switch (cmd) {
	case PKVM_ASGARD_IOC_SET_HOST_DMA_DOMAIN: {
		u32 domain;

		if (copy_from_user(&domain, (void __user *)arg, sizeof(domain)))
			return -EFAULT;
		return pkvm_revpt_set_host_dma_domain(domain);
	}
	case PKVM_ASGARD_IOC_RECHECK_LEDGER:
		/* 保留全量复检能力（旧 sync 语义）。 */
		return pkvm_revpt_sync();
	case PKVM_ASGARD_IOC_CAPTURE_BASELINE:
		/* 新语义：锁定时刻并重建 rev_pt 初始状态（来自页表遍历）。 */
		return pkvm_revpt_capture_baseline();
	case PKVM_ASGARD_IOC_GET_VIOLATIONS: {
		/* 从 EL2 拿快照，再拷回用户态。 */
		struct pkvm_asgard_violation_query q;
		struct pkvm_asgard_violation *kbuf = NULL;
		u32 copied = 0, total = 0;
		int ret;

		if (copy_from_user(&q, (void __user *)arg, sizeof(q)))
			return -EFAULT;

		if (q.capacity) {
			kbuf = kvmalloc_array(q.capacity, sizeof(*kbuf), GFP_KERNEL);
			if (!kbuf)
				return -ENOMEM;
		}

		ret = pkvm_revpt_get_violations(kbuf, q.capacity, &copied, &total);
		if (ret)
			goto out;

		if (copied && copy_to_user((void __user *)(uintptr_t)q.user_buf,
					   kbuf, copied * sizeof(*kbuf))) {
			ret = -EFAULT;
			goto out;
		}

		q.copied = copied;
		q.total = total;
		if (copy_to_user((void __user *)arg, &q, sizeof(q)))
			ret = -EFAULT;
out:
		kvfree(kbuf);
		return ret;
	}
	default:
		return -ENOTTY;
	}
}

static const struct file_operations pkvm_asgard_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = pkvm_asgard_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = pkvm_asgard_ioctl,
#endif
};

static struct miscdevice pkvm_asgard_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "pkvm_asgard",
	.fops = &pkvm_asgard_fops,
};

static int __init pkvm_asgard_init(void)
{
	return misc_register(&pkvm_asgard_miscdev);
}

static void __exit pkvm_asgard_exit(void)
{
	misc_deregister(&pkvm_asgard_miscdev);
}

module_init(pkvm_asgard_init);
module_exit(pkvm_asgard_exit);
MODULE_LICENSE("GPL");
