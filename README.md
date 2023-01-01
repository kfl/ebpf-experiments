eBPF Experimental Code
======================

This repository (will eventually) contains some short guides and small
snippets of eBPF and code interacting with eBPF,


Files
-----

 * `Vagrantfile` for setting up an Ubuntu 22.04 LTS VM with various
   development tools.
   
   The `Vagrantfile` install various tools that you may, or may not,
   be interested in. For instance, both GHC and `bpftools` (which
   requires a full git clone of the Linux source tree). So read
   through the `Vagrant.configure` part and comment out what you are
   not interested in.
   
 * `samples/socketfilter.c` is a short sample intended to illustrate:
    
    1. a lightweight to load some eBPF bytecode into the kernel,
       attach it to a socket, and trigger it so that the bytecode
       runs.
    2. How to set up some shared memory (an array map) between
       user-space and kernel-space.
   
    Uses `bpf_insn.h`.
    
 * `bpf_insn.h` eBPF instruction mini library in the form of some C
   macros for writing eBPF bytecode almost like an assembler.
 
   Copied from the Linux source tree: `linux/samples/bpf/bpf_insn.h`,
   see license in the file.
