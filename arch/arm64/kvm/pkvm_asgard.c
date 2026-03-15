// SPDX-License-Identifier: GPL-2.0

#include <linux/fs.h>
#include <linux/kvm_host.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/pkvm_asgard.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include <asm/kvm_mmu.h>

#define PKVM_ASGARD_MAX_IOCTL_VIOLATIONS 256U

/* 用户态测试入口：把控制命令转发到 host->EL2 hypercall。 */
static long pkvm_asgard_ioctl(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
	switch (cmd) {
	case PKVM_ASGARD_IOC_START_TEST: {
		struct pkvm_asgard_test_cfg *cfg;
		int ret;
		int share_ret;

		cfg = kmalloc(sizeof(*cfg), GFP_KERNEL);
		if (!cfg)
			return -ENOMEM;
		if (copy_from_user(cfg, (void __user *)arg, sizeof(*cfg))) {
			kfree(cfg);
			return -EFAULT;
		}

		share_ret = kvm_share_hyp(cfg, cfg + 1);
		if (share_ret) {
			kfree(cfg);
			return share_ret;
		}

		ret = pkvm_revpt_start_test(cfg);
		kvm_unshare_hyp(cfg, cfg + 1);
		kfree(cfg);
		return ret;
	}
	case PKVM_ASGARD_IOC_SYNC_TEST:
		return pkvm_revpt_sync_test();
	case PKVM_ASGARD_IOC_GET_VIOLATIONS: {
		/* 从 EL2 拿快照，再拷回用户态。 */
		struct pkvm_asgard_violation_query q;
		struct pkvm_asgard_violation *kbuf = NULL;
		u32 *copied;
		u32 *total;
		bool kbuf_shared = false;
		bool copied_shared = false;
		bool total_shared = false;
		int ret;

		if (copy_from_user(&q, (void __user *)arg, sizeof(q)))
			return -EFAULT;
		if (q.capacity > PKVM_ASGARD_MAX_IOCTL_VIOLATIONS)
			return -E2BIG;

		copied = kmalloc(sizeof(*copied), GFP_KERNEL);
		total = kmalloc(sizeof(*total), GFP_KERNEL);
		if (!copied || !total) {
			kfree(copied);
			kfree(total);
			return -ENOMEM;
		}

		if (q.capacity) {
			kbuf = kmalloc_array(q.capacity, sizeof(*kbuf), GFP_KERNEL);
			if (!kbuf) {
				kfree(copied);
				kfree(total);
				return -ENOMEM;
			}
		}

		ret = kvm_share_hyp(copied, copied + 1);
		if (ret)
			goto out;
		copied_shared = true;

		ret = kvm_share_hyp(total, total + 1);
		if (ret)
			goto out;
		total_shared = true;

		if (q.capacity) {
			ret = kvm_share_hyp(kbuf, kbuf + q.capacity);
			if (ret)
				goto out;
			kbuf_shared = true;
		}

		ret = pkvm_revpt_get_violations(kbuf, q.capacity, copied, total);
		if (ret)
			goto out;

		if (*copied && copy_to_user((void __user *)(uintptr_t)q.user_buf,
					   kbuf, (*copied) * sizeof(*kbuf))) {
			ret = -EFAULT;
			goto out;
		}

		q.copied = *copied;
		q.total = *total;
		if (copy_to_user((void __user *)arg, &q, sizeof(q)))
			ret = -EFAULT;
out:
		if (kbuf_shared)
			kvm_unshare_hyp(kbuf, kbuf + q.capacity);
		if (total_shared)
			kvm_unshare_hyp(total, total + 1);
		if (copied_shared)
			kvm_unshare_hyp(copied, copied + 1);
		kfree(kbuf);
		kfree(copied);
		kfree(total);
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
