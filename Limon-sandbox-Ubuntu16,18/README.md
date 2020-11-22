### Installation and Configuration of Limon Sandbox on Ubuntu 18.04
Limon is an opensource sandbox written in python by KA Monnappa. It performs static, dynamic and memory analysis of Linux malware. One can download limon sandbox from this link: https://github.com/monnappa22/Limon.
Limon internally depends on various opensource tools for the proper execution of malware. Some tools are installed on Host machines and some on virtual machine. It uses VMWare Workstation Pro for execution of malware on virtual machines. More details of this software can be found at :  https://cysinfo.com/setting-up-limon-sandbox-for-analyzing-linux-malwares/
This document provides detailed steps to install and configure Limon on Ubuntu 18.04 LTS. 
##### System Configuration of Host Machine is as follows:
###### Operating System: Ubuntu 18.04.5 LTS
###### Memory: 6 GB
###### Processor: Intel® Core™ i5-3210M CPU @ 2.50GHz × 4

### Steps for installation of tools on Host Machine:
#### Vmware Workstation Pro
- Use this link https://www.vmware.com/in/products/workstation-pro/workstation-pro-evaluation.html to download Vmware Workstation 15.5 Pro. This is a paid software. Trial version is for 30 days
- Install prerequisites 

	`apt-get install build-essential`
- Follow the instructions from installation wizard after executing this command:

	`bash VMware-Workstation-Full-15.5.1-15018445.x86_64.bundle`
- Enter serial number or leave blank for trial
- Start VMWare Workstation and install virtual machine with Ubuntu 18/16 operating system
Download yara version 3.110 from : 
#### YARA
- Download yara package version 3.110 from  https://github.com/virustotal/yara/releases/tag/v3.11.0
- Install yara ( https://yara.readthedocs.io/en/stable/gettingstarted.html)

	`tar -zxf yara-4.0.0.tar.gz`

	`cd yara-4.0.0`

	`./bootstrap.sh`

	`apt-get install automake libtool make gcc pkg-config`

	`apt-get install flex bison`

	`./configure`

	`make`

	`make install`

#### SSDEEP
- Install ssdeep ( https://zoomadmin.com/HowToInstall/UbuntuPackage/ssdeep)

	`sudo apt-get update -y` 

	`sudo apt-get install -y ssdeep` 

#### SYSDIG
- Install Sysdig (https://github.com/draios/sysdig/wiki/How-to-Install-Sysdig-for-Linux)

	`curl -s https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public | sudo apt-key add - ` 

	`sudo curl -s -o /etc/apt/sources.list.d/draios.list https://s3.amazonaws.com/download.draios.com/stable/deb/draios.list`  

	`sudo apt-get update`

#### INETSIM
- Install inetsim (https://www.howtoinstall.me/ubuntu/18-04/inetsim/)
 
 ` sudo apt update`
	
	`sudo apt install inetsim`

#### INSTALL FOLLOWING PACKAGES

`sudo -H pip2 install openpyxl`

`sudo -H pip2 install ujson`

`sudo -H pip2 install pycrypto`

`sudo -H pip2 install distorm3`

`sudo -H pip2 install pytz`    

#### VOLATILITY
- Install volalitity (https://github.com/volatilityfoundation/volatility/wiki/Installation#dependencies)

	`git clone https://github.com/volatilityfoundation/volatility.git`

	`apt-get install pcregrep libpcre++-dev python-dev -y`

	`cd volatility`

	`python setup.py`

- Open /etc/inetsim/inetsim.conf

add `service_bind_address 172.16.185.1` #ip address for vnmet8

`dns_default_ip 172.16.185.1`

### Steps for installation of tools on Analysis Machine:
- Set Root password and enable graphical root login ()
https://www.technhit.in/enable-root-user-ubuntu-16-04-1-lts/ )

	`passwd root`

	`nano /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf`

	`greeter-show-manual-login=true`

Restart and login as root

#### PHP

`apt-get install php`

#### Install packages to run 32 bit executable on 64 bit Ubuntu system

`dpkg --add-architecture i386`

#### Add default gateway 172.16.185.1 (VMNET8) to analysis machine

`sudo route add default gw  172.16.185.1 eth0`

#### Install following packages 
`sudo -H pip2 install openpyxl

`sudo -H pip2 install ujson`

`sudo -H pip2 install pycrypto`

`sudo -H pip2 install distorm3`

`sudo -H pip2 install pytz`    

#### VOLATILITY
Install volalitity ( https://github.com/volatilityfoundation/volatility/wiki/Installation#dependencies)

`git clone https://github.com/volatilityfoundation/volatility.git`

`apt-get install pcregrep libpcre++-dev python-dev -y`

`cd volatility`

`python setup.py`

#### PREPARE LINUX PROFILE FOR ANALYSIS MACHINE
(https://github.com/volatilityfoundation/volatility/wiki/Linux)

`apt-get install dwarfdump`

`apt-get install build-essential`

`apt-get install linux-headers-4.15.0-96-generic` #kernel version no

`cd volatility/tools/linux`

`make`

`head module.dwarf`

`zip volatility/volatility/plugins/overlays/linux/Ubuntu1204.zip volatility/tools/linux/module.dwarf /boot/System.map-3.2.0-23-generic`

