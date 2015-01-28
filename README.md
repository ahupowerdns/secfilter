# secfilter

NOTE: This is a very crude version of the software, only made available for early criticism. 
We know there are gaping security holes in the implementation & potentially even the idea itself. 
Feedback is very welcome - bert.hubert@powerdns.com!

## What it is

Small demo project how to build interesting sandboxes easily using seccomp-bpf plus
the SECCOMP_RET_TRACE feature, based on standard, shipping, Linux technologies.

Example:

```
$ secfilt --read-only=1 --write-allow=/dev/null bash
$ echo a > b
bash: b: Operation not permitted
```

Further example:
```
$ secfilt --no-outbound-network=1 bash
$ telnet ds9a.nl 25
telnet: could not resolve ds9a.nl/25: Name or service not known
```

And finally:

```
$ secfilt --allowed-netmasks=192.168.1.0/24 bash
$ telnet 192.168.1.2 22
Trying 192.168.1.2...
Connected to 192.168.1.2.
SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2
telnet> q   
Connection closed.

$ ssh ds9a.nl
ssh: Could not resolve hostname ds9a.nl: Name or service not known
```

'secfilter --help' shows further options.

## seccomp-bpf, SECCOMP_RET_TRACE

seccomp-bpf itself can tell the kernel using the BPF language which system
calls are allowed, and it can even do some arithmetic on arguments to determine
what is possible or not.

However, the language is not able to parse strings or otherwise inspect
non-numerical arguments.

Using SECCOMP_RET_TRACE, selected syscalls can be referred to userspace for
inspection using the ptrace mechanism. It is important to note that this
does not mean that a secfilter-wrapped process is being "straced". Only selected
syscalls actually get referred to userspace filtering. As such, there is little
performance overhead in many cases.

## Limitations
The project, for now, only works on recent Linux kernels on 64 bit AMD & Intel architectures.

## Thanks to

This project builds on top of the examples and work by the Chromium
developers, including Kees Cook and Will Drewry. The code you find here merely demonstrates 
their significant contributions to linux security.  Thanks!

