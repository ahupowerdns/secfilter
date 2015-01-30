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
$ secfilt --allowed-netmask=192.168.1.0/24 --allowed-netmask=127.0.0.0/8 bash
$ telnet 192.168.1.2 22
Trying 192.168.1.2...
Connected to 192.168.1.2.
SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2
telnet> q   
Connection closed.

$ ssh ds9a.nl
ssh: Could not resolve hostname ds9a.nl: Name or service not known
```

'secfilt --help' shows further options:

```
  -h [ --help ]                  produce help message
  -c [ --config ] arg            configuration file
  --allow-write arg              only write here
  --mainstream-network-families  only allow AF_UNIX, AF_INET, AF_INET6 and 
                                 AF_NETLINK
  --no-outbound-network arg (=0) no outgoing network connections
  --allowed-netmask arg          only allow access to these masks
  --allowed-port arg             allow access to this port
  --read-only arg (=0)           be read-only
```

Sample configuration files can be found
[here](https://github.com/ahupowerdns/secfilter/tree/master/samples), 
contributions welcome.

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

More about seccomp-bpf can be found on http://outflux.net/teach-seccomp/

An interesting paper and research software exploiting the same principles
can be found via http://pdos.csail.mit.edu/mbox/

## Limitations

The project, for now, only works on recent Linux kernels on 64 bit AMD & Intel architectures.

## Thanks to

This project builds on top of the examples and work by the Chromium
developers, including Kees Cook and Will Drewry. The code you find here merely demonstrates 
their significant contributions to linux security.  Thanks!

