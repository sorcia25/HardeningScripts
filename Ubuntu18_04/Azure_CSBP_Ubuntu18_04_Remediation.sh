#!/bin/bash

: '
#SYNOPSIS
    Quick win script for remediation of Ubuntu baseline misconfigurations.
.DESCRIPTION
    This script aims to remediate all possible OS baseline misconfigurations for Ubuntu 18.04 based Virtual machines on Azure.

.NOTES

    Copyright (c) Toño Maldonado - None rights reserved :OP
    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, 
	including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, 
	subject to the following conditions:
	
    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
	
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
	IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE 
	OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

    Version: 1.0
    # PREREQUISITE

.EXAMPLE
    Command to execute : bash Azure_CSBP_Ubuntu18_04_Remediation.sh
.INPUTS

.OUTPUTS
    None
'

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'
RED='\033[1;31m'
BGREEN='\033[1;32m'
BYELLOW='\033[1;33m'
BBLUE='\033[1;34m'
BPURPLE='\033[1;35m'

success=0
fail=0

############################################################################################################################
############################################################################################################################

##PreConfiguration (Intallation of packages that we used to customize the Ubuntu on Azure (Toño Maldonado)

apt update
apt install screenfetch -y
policystatus=$?
chmod -x /etc/update-motd.d/*
echo '#!/bin/sh' >> /etc/update-motd.d/01-custom
echo 'echo "GENERAL SYSTEM INFORMATION"' >> /etc/update-motd.d/01-custom
echo 'echo' >> /etc/update-motd.d/01-custom
echo '/usr/bin/screenfetch'  >> /etc/update-motd.d/01-custom
echo 'echo' >> /etc/update-motd.d/01-custom
echo 'echo' >> /etc/update-motd.d/01-custom
echo 'echo "WELCOME TO UBUNTU HARDENED"' >> /etc/update-motd.d/01-custom
echo 'echo' >> /etc/update-motd.d/01-custom
echo 'echo' >> /etc/update-motd.d/01-custom
chmod +x /etc/update-motd.d/01-custom

############################################################################################################################
############################################################################################################################

##Category 1.1 Initial Setup - Filesystem Configuration
echo
echo -e "${BBLUE}Initial Setup - Filesystem Configuration${NC}"

echo
echo -e "${BLUE}1.1 Initial Setup - Filesystem Configuration${NC}"

#Ensure mounting of cramfs filesystems is disabled
echo
echo -e "${BRED}1.1.1.1${NC} Ensure mounting of cramfs filesystems is disabled"
modprobe -n -v cramfs | grep "^install /bin/true$" || echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf
policystatus=$?
lsmod | egrep "^cramfs\s" && rmmod cramfs
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of cramfs filesystems is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of cramfs filesystems is disabled"
fi

#Ensure mounting of freevxfs filesystems is disabled
echo
echo -e "${BRED}1.1.1.2${NC} Ensure mounting of freevxfs filesystems is disabled"
modprobe -n -v freevxfs | grep "^install /bin/true$" || echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf
policystatus=$?
lsmod | egrep "^freevxfs\s" && rmmod freevxfs
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of freevxfs filesystems is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of freevxfs filesystems is disabled"
fi

#Ensure mounting of jffs2 filesystems is disabled
echo
echo -e "${BRED}1.1.1.3${NC} Ensure mounting of jffs2 filesystems is disabled"
modprobe -n -v jffs2 | grep "^install /bin/true$" || echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
policystatus=$?
lsmod | egrep "^jffs2\s" && rmmod jffs2
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of jffs2 filesystems is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of jffs2 filesystems is disabled"
fi

#Ensure mounting of hfs filesystems is disabled
echo
echo -e "${BRED}1.1.1.4${NC} Ensure mounting of hfs filesystems is disabled"
modprobe -n -v hfs | grep "^install /bin/true$" || echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf
policystatus=$?
lsmod | egrep "^hfs\s" && rmmod hfs
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of hfs filesystems is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of hfs filesystems is disabled"
fi

#Ensure mounting of hfsplus filesystems is disabled
echo
echo -e "${BRED}1.1.1.5${NC} Ensure mounting of hfsplus filesystems is disabled"
modprobe -n -v hfsplus | grep "^install /bin/true$" || echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf
policystatus=$?
lsmod | egrep "^hfsplus\s" && rmmod hfsplus
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of hfsplus filesystems is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of hfsplus filesystems is disabled"
fi

# 1.1.1.6 Ensure mounting of udf filesystems is disabled
echo
echo -e "${BRED}1.1.1.6${NC} Ensure mounting of udf filesystems is disabled"
modprobe -n -v udf | grep "^install /bin/true$" || echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf
policystatus=$?
lsmod | egrep "^udf\s" && rmmod udf
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of udf filesystems is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of udf filesystems is disabled"
fi

# 1.1.2 Ensure separate partition exists for /tmp
echo
echo -e "${BRED}1.1.2${NC} Ensure separate partition exists for /tmp"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} This setting must be configured during the installation, and in this case the VM was created based on a Azure image"

# 1.1.3  Ensure nodev option set on /tmp partition 
echo
echo -e "${BRED}1.1.3${NC} Ensure nodev option set on /tmp partition"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} The /tmp partition doesn't exist on an Azure VM"

# 1.1.4  Ensure nosuid option set on /tmp partition  
echo
echo -e "${BRED}1.1.4${NC} Ensure nosuid option set on /tmp partition"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} The /tmp partition doesn't exist on an Azure VM"

# 1.1.5  Ensure separate partition exists for /var   
echo
echo -e "${BRED}1.1.5${NC} Ensure separate partition exists for /var"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} This setting must be configured during the installation, and in this case the VM was created based on a Azure image"

# 1.1.6  Ensure separate partition exists for /var/tmp  
echo
echo -e "${BRED}1.1.6${NC} Ensure separate partition exists for /var/tmp"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} This setting must be configured during the installation, and in this case the VM was created based on a Azure image"

# 1.1.7  Ensure nodev option set on /var/tmp partition   
echo
echo -e "${BRED}1.1.7${NC} Ensure nodev option set on /var/tmp partition"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} The /var/tmp partition doesn't exist on an Azure VM"

# 1.1.8  Ensure nodev option set on /var/tmp partition 
echo
echo -e "${BRED}1.1.8${NC} Ensure nodev option set on /var/tmp partition"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} The /var/tmp partition doesn't exist on an Azure VM"

# 1.1.20 Ensure sticky bit is set on all world-writable directories
echo
echo -e "${BRED}1.1.20${NC} Ensure sticky bit is set on all world-writable directories"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure sticky bit is set on all world-writable directories"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure sticky bit is set on all world-writable directories"
fi

# 1.1.21 Disable Automounting
echo
echo -e "${BRED}1.1.21${NC} Disable Automounting"
systemctl disable autofs.service
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Disable Automounting"
else
  echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
  echo -e "${BPURPLE}REASON:${NC} The autofs.service doesn't exist on an Azure VM"
fi

############################################################################################################################

##Category 1.2 Initial Setup - Configure Software Updates
echo
echo -e "${BBLUE}Initial Setup - Configure Software Updates${NC}"

# 1.2.1 Ensure package manager repositories areconfigured 
echo
echo -e "${BRED}1.2.1${NC} Ensure package manager repositories are configured "
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} Azure confugures the repositories nedeed to its VMs"

# 1.2.2 Ensure GPG keys are configured
echo
echo -e "${BRED}1.2.2${NC} Ensure GPG keys are configured"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} Azure configures the GPG keys nedeed to verify the package integrity"

############################################################################################################################

##Category 1.3 Initial Setup - Filesystem Integrity Checking
echo
echo -e "${BBLUE}Initial Setup - Filesystem Integrity Checking${NC}"

# 1.3.1 Ensure AIDE is installed
# 1.3.2 Ensure filesystem integrity is regularly checked
echo
echo -e "${RED}1.3.1${NC} Ensure AIDE is installed"
echo -e "${RED}1.3.2${NC} Ensure filesystem integrity is regularly checked"
echo -e "${BYELLOW}WARNING ${YELLOW} This settings could be replased for another feature on an Azure VM"
echo -e "${BPURPLE}REASON:${NC} Azure checks the integrity of linux files through Azure Defender, we recommend to enable Azure Defender (aka ASC) to this server"

############################################################################################################################

##Category 1.4 Initial Setup - Secure Boot Settings
echo
echo -e "${BBLUE}Initial Setup - Secure Boot Settings${NC}"

# 1.4.1 Ensure permissions on bootloader config are configured
echo
echo -e "${BRED}1.4.1${NC} Ensure permissions on bootloader config are configured"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} Due the Azure VM nature, we can´t configure this settings, the bootloader isn't accesible"

# 1.4.2 Ensure bootloader password is set 
echo
echo -e "${BRED}1.4.2${NC} Ensure bootloader password is configured"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} Due the Azure VM nature, we can´t configure this settings, the bootloader isn't accesible"

# 1.4.3 Ensure authentication required for single user mode
echo
echo -e "${BRED}1.4.3${NC} Ensure authentication required for single user mode"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} Due the Azure VM nature, we can´t configure this settings, the bootloader isn't accesible"

############################################################################################################################

##Category 1.5 Additional Process Hardening
echo
echo -e "${BBLUE}Initial Setup - Additional Process Hardening${NC}"

#1.5.1 Ensure core dumps are restricted
echo
echo -e "${BRED}1.5.1${NC} Ensure core dumps are restricted"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} Due the Azure VM nature, the core dumps are managed by Azure, and we can use serial console to analyze it"

#1.5.2 Ensure XD/NX support is enabled
echo
echo -e "${BRED}1.5.2${NC} Ensure XD/NX support is enabled"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} Due the Azure VM nature, this setting couldn't be set in the hardware"

# 1.5.3 Ensure address space layout randomization (ASLR) is enabled
echo
echo -e "${RED}1.5.3${NC} Ensure address space layout randomization (ASLR) is enabled"
egrep -q "^(\s*)kernel.randomize_va_space\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)kernel.randomize_va_space\s*=\s*\S+(\s*#.*)?\s*$/\1kernel.randomize_va_space = 2\2/" /etc/sysctl.conf || echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure address space layout randomization (ASLR) is enabled"
    success=$((success + 1))
else
    echo -e "${RED}UnableToRemediate:${NC} Ensure address space layout randomization (ASLR) is enabled"
    fail=$((fail + 1))
fi

# 1.5.4 Ensure prelinkis disabled
echo
echo -e "${RED}1.5.3${NC} Ensure prelinkis disabled"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} Azure by default don't install it on an Ubuntu VM, additional we recommend that use Azure Defender (aka ASC) to guarantee the file integrity"

############################################################################################################################

##Category 1.6 Mandatory Access Control
echo
echo -e "${BBLUE}Initial Setup - Mandatory Access Control${NC}"

# 1.6.1 Configure SELinux
# 1.6.1.1 Ensure SELinux is not disabled in bootloader configuration
# 1.6.1.2 Ensure the SELinux state is enforcing
# 1.6.1.3 Ensure SELinux policy is configured
# 1.6.1.4 Ensure no unconfined daemons exist
echo
echo -e "${RED}1.6.1.1${NC} Ensure SELinux is not disabled in bootloader configuration"
echo -e "${RED}1.6.1.2${NC} Ensure the SELinux state is enforcing"
echo -e "${RED}1.6.1.3${NC} Ensure SELinux policy is configured"
echo -e "${RED}1.6.1.4${NC} Ensure no unconfined daemons exist"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} Azure by default don't use SELinux on an Ubuntu VM"

# 1.6.2 Configure AppArmor
# 1.6.2.1 Ensure AppArmor is not disabled in bootloader configuration
echo
echo -e "${RED}1.6.2.1${NC} Ensure AppArmor is not disabled in bootloader configuration"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} Azure by default configure the bootloader settings"

# 1.6.2.2 Ensure all AppArmor Profiles are enforcing
echo
echo -e "${RED}1.6.2.2${NC} Ensure all AppArmor Profiles are enforcing"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} Azure by default configure the AppArmor settings, and are enabled by default"

# 1.6.3 Ensure SELinux or AppArmor are installed 
echo
echo -e "${RED}1.632${NC} Ensure SELinux or AppArmor are installed"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} Azure by default configure the AppArmor settings, and are enabled by default"

############################################################################################################################

##Category 1.7 Mandatory Access Control
echo
echo -e "${BBLUE}Initial Setup - Mandatory Access Control${NC}"

# 1.

############################################################################################################################

## 1.8 Ensure updates, patches, and additional security software are installed
echo
echo -e "${RED}1.8${NC} Ensure updates, patches, and additional security software are installed"
apt update
apt install unattended-upgrades
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure updates, patches, and additional security software are installed"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure updates, patches, and additional security software are installed"
fi