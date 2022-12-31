# -*- mode: ruby -*-
# vi: set ft=ruby :

# First we define some (multiline) strings corresponding to each task in the provisioning

$setup_dev_tools = <<-'SCRIPT'
set -xe
export NEEDRESTART_MODE=a
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update
apt-get -qq upgrade -y
apt-get -qq install -y -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold" \
        apt-transport-https ca-certificates curl \
        software-properties-common \
        strace binutils binutils-dev build-essential \
        bash-completion git \
        python3-dev python3-pip \
        clang llvm gcc-bpf \
        net-tools wget lsb-release \
        libbpf-dev \
        libffi-dev libffi8ubuntu1 libgmp-dev libgmp10 libncurses-dev libncurses5 libtinfo5 \
        debhelper libssl-dev libelf-dev libudev-dev libpci-dev \
        gawk flex bison openssl dkms libiberty-dev autoconf \
        cmake

# Allow unprivileged user to run (some) eBPF programs
# sysctl -w kernel.unprivileged_bpf_disabled=0
echo "kernel.unprivileged_bpf_disabled=0" > /etc/sysctl.d/42-ebpf-yolo.conf
service procps restart

systemctl restart networkd-dispatcher.service
#needrestart -r a
SCRIPT


# Install ubpf-vm as a normal user
$setup_ubpf = <<-'SCRIPT'
git clone https://github.com/iovisor/ubpf.git
cd ubpf
make -C vm
sudo make -C vm install #place in /usr/local/lib/
sudo ldconfig
mkdir -p ~/bin
cp vm/test ~/bin/ubpf-vm
SCRIPT


$setup_gdb = <<-'SCRIPT'
set -xe
cat <<'EOF' > .gdbinit
# Settings
set disassembly-flavor intel
set disable-randomization off
set pagination off
set follow-fork-mode child

# History
set history filename ~/.gdbhistory
set history save
set history expansion

# Output format
set output-radix 0x10
EOF
SCRIPT

$setup_ghc = <<-'SCRIPT'
    set -xe
    echo "Warning, installing cabal takes several minutes"
    curl --proto '=https' --tlsv1.2 -sSf https://get-ghcup.haskell.org | \
         BOOTSTRAP_HASKELL_NONINTERACTIVE=1 \
         BOOTSTRAP_HASKELL_MINIMAL=1 \
         BOOTSTRAP_HASKELL_ADJUST_BASHRC=1 \
         sh
    source $HOME/.ghcup/env
    ghcup upgrade
    ghcup install ghc
    ghcup set ghc
    ghcup install cabal
    cabal update
    ghcup install stack
    stack config set system-ghc --global true
SCRIPT

$setup_bpftools = <<-'SCRIPT'
    git clone -b v6.1 https://github.com/torvalds/linux.git --depth 1
    (cd linux/tools/bpf/bpftool && \
     make && cp bpftool $HOME/.local/bin)
SCRIPT


$msg = <<~MSG
------------------------------------------------------
The eBPF Experiments VM is ready

Get ssh access with the command
    vagrant ssh

The files in the current directory can be found
in the /vagrant directory
------------------------------------------------------
MSG

Vagrant.configure(2) do |config|
  # Every Vagrant virtual environment requires a box to build off
  # of. We build of Ubuntu 22.04 (Jammy Jellyfish)
  config.vm.box = "ubuntu/jammy64"


  config.vm.hostname = "eBPF-Experiments"
#  config.vm.network "forwarded_port", guest: 22, host: 2222,
#                    host_ip: "127.0.0.1", id: 'ssh'
  config.vm.provider "virtualbox" do |vb|
    vb.name = "eBPF Experiments"
    vb.memory = "8192"
    vb.cpus = 8
   end


  # Install some useful tools
  config.vm.provision :shell, name: "Install basic tools", inline: $setup_dev_tools

  config.vm.provision "shell", name: "Make ./local/bin for the normal user", privileged: false, inline: <<-SHELL
    set -xe
    mkdir -p $HOME/.local/bin
    export PATH=$HOME/.local/bin:/usr/local/bin:$PATH
    echo 'export PATH=$HOME/.local/bin:/usr/local/bin:$PATH' >> $HOME/.bashrc
  SHELL


  # Install ubpf-vm for the normal user
  config.vm.provision :shell, name: "Set up ubpf for the normal user",
                      privileged: false, inline: $setup_ubpf

  # Add minimal .gdbinit
  config.vm.provision :shell, name: "Add minimal .gdbinit for the normal user",
                      privileged: false, inline: $setup_gdb

  # Setup GHC
  config.vm.provision "shell", name: "Setting up ghcup (etc) for the normal user", privileged: false, inline: $setup_ghc


  # Download and compile bpftools
  #config.vm.provision "shell", name: "Download and compile bpftools", privileged: false, inline: $setup_bpftools

  config.vm.provision "shell", name: "Compile ebpf-tools", privileged: false, inline: <<-SHELL
   source $HOME/.ghcup/env
   git clone https://github.com/kfl/ebpf-tools.git
   (cd ebpf-tools && cabal build)
  SHELL


  config.vm.post_up_message = $msg

end
