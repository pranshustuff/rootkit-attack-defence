// ftrace_detector.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/moduleloader.h> /* for module_from_addr */
#include <linux/errno.h>
#include <linux/types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chatgpt (example)");
MODULE_DESCRIPTION("Heuristic detector for ftrace-style prologue hooks (e.g. getdents64 rootkits)");
MODULE_VERSION("0.1");

static char *target_sym = "__x64_sys_getdents64";
module_param(target_sym, charp, 0444);
MODULE_PARM_DESC(target_sym, "Kernel symbol to check for patching (default __x64_sys_getdents64)");

#define PROLOGUE_NBYTES 16

static int read_kernel_bytes(void *addr, void *buf, size_t n)
{
    int ret;
    ret = probe_kernel_read(buf, addr, n);
    return ret;
}

static void inspect_symbol(const char *sym)
{
    unsigned long addr;
    unsigned char prologue[PROLOGUE_NBYTES];
    int err;
    void *target = NULL;
    int i;

    addr = kallsyms_lookup_name(sym);
    if (!addr) {
        pr_warn("ftrace_detector: symbol '%s' not found.\n", sym);
        return;
    }

    pr_info("ftrace_detector: symbol '%s' at %pK\n", sym, (void *)addr);

    err = read_kernel_bytes((void *)addr, prologue, sizeof(prologue));
    if (err) {
        pr_warn("ftrace_detector: probe_kernel_read failed for %pK (err=%d)\n", (void *)addr, err);
        return;
    }

    pr_debug("ftrace_detector: prologue bytes:");
    for (i = 0; i < 8; ++i)
        pr_debug(" %02x", prologue[i]);
    pr_debug("\n");

    /*
     * Heuristics:
     *  - 0xE9 <rel32>  : JMP rel32  -> target = addr + 5 + rel32
     *  - 0xE8 <rel32>  : CALL rel32 -> target = addr + 5 + rel32
     *
     * Many ftrace implementations patch the prologue with a call/jmp to trampoline.
     */
    if (prologue[0] == 0xE9 || prologue[0] == 0xE8) {
        int32_t rel;
        unsigned long dest;

        /* make sure we have at least 5 bytes */
        memcpy(&rel, &prologue[1], sizeof(rel));
        dest = addr + 5 + (long)rel;
        target = (void *)dest;

        pr_warn("ftrace_detector: %s at %pK begins with %s (rel32 -> %pK)\n",
                sym,
                (void *)addr,
                prologue[0] == 0xE9 ? "JMP" : "CALL",
                target);

        /* check if dest lies inside a module */
#ifdef CONFIG_MODULES
        {
            struct module *m = module_from_addr(target);
            if (m) {
                pr_alert("ftrace_detector: hook target %pK is inside module '%s' (base %pK). suspicious!\n",
                         target, m->name, m->module_core);
            } else {
                pr_info("ftrace_detector: hook target %pK is NOT inside a module (likely kernel text / ftrace trampoline).\n", target);
            }
        }
#else
        pr_info("ftrace_detector: module support not available in kernel build; cannot check module_from_addr().\n");
#endif
        return;
    }

    /*
     * Additional quick checks:
     *  - Indirect absolute jump using opcode 0xFF 0x25 (rip-relative)
     *  - Many unmodified kernel function prologues begin with (on x86_64):
     *      push rbp (0x55) / mov rbp,rsp (0x48 0x89 0xe5)
     *    But kernel functions vary — do not assume a single canonical prologue.
     */

    if (prologue[0] == 0xFF && prologue[1] == 0x25) {
        /* opcode: FF 25 <disp32> -> jump [rip + disp32] -> load 64-bit address from memory */
        int32_t disp;
        unsigned long indir_ptr;
        unsigned long dest_addr = 0;
        memcpy(&disp, &prologue[2], sizeof(disp));
        indir_ptr = addr + 6 + disp; /* address where destination pointer is stored */
        if (probe_kernel_read(&dest_addr, (void *)indir_ptr, sizeof(dest_addr)) == 0) {
            pr_warn("ftrace_detector: indirect jmp at %pK -> pointer at %pK -> target %pK\n",
                    (void *)addr, (void *)indir_ptr, (void *)dest_addr);
#ifdef CONFIG_MODULES
            {
                struct module *m = module_from_addr((void *)dest_addr);
                if (m) {
                    pr_alert("ftrace_detector: indirect hook target %pK is inside module '%s'. suspicious!\n",
                             (void *)dest_addr, m->name);
                }
            }
#endif
            return;
        } else {
            pr_warn("ftrace_detector: failed to read indirect jmp target pointer at %pK\n", (void *)indir_ptr);
            return;
        }
    }

    pr_info("ftrace_detector: no obvious JMP/CALL/indirect-jmp prologue patch detected for %s (first byte 0x%02x)\n",
            sym, prologue[0]);
}

static int __init ftrace_detector_init(void)
{
    pr_info("ftrace_detector: init; checking symbol %s\n", target_sym);
    if (!kallsyms_lookup_name) {
        pr_err("ftrace_detector: kallsyms_lookup_name is not available on this kernel.\n");
        return -ENOSYS;
    }

    inspect_symbol(target_sym);

    pr_info("ftrace_detector: scan complete.\n");
    return 0;
}

static void __exit ftrace_detector_exit(void)
{
    pr_info("ftrace_detector: unloaded.\n");
}

module_init(ftrace_detector_init);
module_exit(ftrace_detector_exit);
