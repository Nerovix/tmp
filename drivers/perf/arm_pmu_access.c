/*
 * Enable user-mode access to ARM performance monitoring counter.
 *
 * Code mostly borrowed from jerinjacobk <jerinjacobk@gmail.com>.
 * https://github.com/jerinjacobk/armv8_pmu_cycle_counter_el0
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/smp.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

static ssize_t arm_pmu_access_show(char *arg, size_t size);
static ssize_t arm_pmu_access_read(struct file *f, char __user *ubuf, size_t count, loff_t *pos);

enum pmu_access_ctls {
	PMCCNTR,
	COUNT,
};

struct pmu_access_cfg {
	const char	*name;
	ssize_t		(*show)(char *arg, size_t size);
};

static struct pmu_access_cfg pmu_access_ctls[COUNT] = {
	[PMCCNTR] = {
		.name	= "PMU_ACCESS",
		.show	= arm_pmu_access_show,
	}
};

static const struct file_operations pmu_access_fops = {
	.owner		= THIS_MODULE,
	.read		= arm_pmu_access_read,
	.llseek		= generic_file_llseek,
};

static struct miscdevice pmu_access_dev = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= "pmuserenr",
	.fops		= &pmu_access_fops
};
DEFINE_MUTEX(pmu_access_lock);

static void arm_pmu_access_enable_cycle_counter(void *data)
{
	u64 val;

	/* Disable cycle counter overflow interrupt */
	asm volatile("msr pmintenclr_el1, %0" : : "r" ((u64)(1 << 31)));
	/* Enable cycle counter */
	asm volatile("msr pmcntenset_el0, %0" :: "r" BIT(31));
	/* Enable user-mode access to cycle counters. */
	asm volatile("msr pmuserenr_el0, %0" : : "r"(BIT(0) | BIT(2)));
	/* Clear cycle counter and start */
	asm volatile("mrs %0, pmcr_el0" : "=r" (val));
	val |= (BIT(0) | BIT(2));
	isb();
	asm volatile("msr pmcr_el0, %0" : : "r" (val));
	val = BIT(27);
	asm volatile("msr pmccfiltr_el0, %0" : : "r" (val));
}

static void arm_pmu_access_disable_cycle_counter(void* data)
{
	/* Disable cycle counter */
	asm volatile("msr pmcntenset_el0, %0" :: "r" (0 << 31));
	/* Disable user-mode access to counters. */
	asm volatile("msr pmuserenr_el0, %0" : : "r"((u64)0));
}

static ssize_t arm_pmu_access_show(char *arg, size_t size)
{
	u64 val;
	int ret;

	asm volatile("mrs %0, pmuserenr_el0" : "=r" (val));
	ret = snprintf(arg, size, "PMUSERENR_EL0=%1d\n",
		       ((val & (BIT(0) | BIT(2))) != 0 ? 1 : 0));
	return (ret < size) ? ret : size;
}

static ssize_t arm_pmu_access_read(struct file *f, char __user *ubuf, size_t count, loff_t *pos)
{
	char *buf, *cur;
	ssize_t size;
	int i;

	if (*pos > 0)
		return 0;
	if (count > PAGE_SIZE)
		return -E2BIG;
	buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (buf == NULL)
		return -ENOMEM;
	cur = buf;

	mutex_lock(&pmu_access_lock);
	for (i = 0; i < COUNT; i++) {
		if (pmu_access_ctls[i].show == NULL)
			continue;

		size = pmu_access_ctls[i].show(cur, count);
		if (size < 0) {
			goto err_free;
		}
		cur += size;
		count -= size;
	}
	mutex_unlock(&pmu_access_lock);
	size = simple_read_from_buffer(ubuf, count, pos, buf, cur - buf);

err_free:
	kfree(buf);

	return size;
}

static int __init arm_pmu_access_init(void)
{
	int ret;

	/* Enable user-mode access to cycle counters. */
	ret = misc_register(&pmu_access_dev);
	if (ret) {
		pr_err("failed to register pmu_access misc device\n");
        goto err_register;
	}

	on_each_cpu(arm_pmu_access_enable_cycle_counter, NULL, 1);

	pr_info("enabled user-mode access to PMU cycle counters\n");

	return 0;

err_register:
	return ret;
}
module_init(arm_pmu_access_init);

static void __exit arm_pmu_access_exit(void)
{
	on_each_cpu(arm_pmu_access_disable_cycle_counter, NULL, 1);

	misc_deregister(&pmu_access_dev);
}
module_exit(arm_pmu_access_exit);

MODULE_DESCRIPTION("Enable user-mode access to ARM performance monitoring counter");
