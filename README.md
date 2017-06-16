# MiniFirewall
## Introduction
Mini Firewall is a simple Firewall system for Linux operating system. It employs an exact-match algorithm to filter TCP and UDP packets according to user-specified rules.

Mini Firewall is composed of a user-space program `mfw` and a kernel-space module `mfw_module`. Communications between user space and kernel space go through a (charactor) device file `mfw_file`. Using `mfw` command, a user can specify filtering rules, which consist of some of the following fields:
* Direction: inbound, outbound
* Source: IP address, subnet mask, port number
* Destination: IP address, subnet mask, port number
* Protocol number: TCP(6), UDP(17)

Each created rule is sent to and stored in `mfw_module` module. The module utilizes Netfilter to compare every packets with user-specified rules. When packet fields exactly matches one of the rules, the packat is dropped (filtered).

## Installation
The user-space program `mfw` and the kernel-space module `mfw_module` can be constructed by executing:
```
$ make
```
A (charactor) device file must be created as an interface between the user-space program and the kernel module. A default device number is `100`, so a device file `mfw_file` can be created as follows: (require root permission)
```
$ mknod mfw_file c 100 0
```

## Usage
### Insert kernel module
The kernel module `mfw_module` must be inserted into a kernel of a Linux operating system before running the user-space program `mfw`. This can be done using: (require root permission)
```
$ insmod ./mfw_module.ko
```
### Add / Remove / View rules
A user can add, remove, and view rules by executing `mfw` command as the following examples.

To add a rule that blocks all inbound TCP and UDP packets with port number 55555:
```
$ ./mfw --add --in --d_port 55555
```

To view all configured rules:
```
$ ./mfw --view
```

To remove the above rule:
```
$ ./mfw --remove --in --d_port 55555
```

Note that the add and remove commands require root permission. Additional usage information can be shown by executing:
```
$ ./mfw --help
```
