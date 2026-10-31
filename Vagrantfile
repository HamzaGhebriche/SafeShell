# Disposable Debian VM. The source is copied in, not mounted from the host.
Vagrant.configure("2") do |config|
  config.vm.box = "debian/bookworm64"
  config.vm.synced_folder ".", "/vagrant", disabled: true
  config.vm.provider "virtualbox" do |vb|
    vb.memory = 2048
    vb.cpus = 2
  end
  config.vm.provision "shell", inline: <<-SHELL
    set -eu
    apt-get update
    apt-get install -y bubblewrap libseccomp2 python3 python3-pytest python3-venv build-essential
    install -d -o vagrant -g vagrant /home/vagrant/safeshell
  SHELL
end
