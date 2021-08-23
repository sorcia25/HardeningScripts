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

##Category 1 Initial Setup
echo "1 Initial Setup" >> /etc/hardening.log
##Category 1.1 Initial Setup - Filesystem Configuration
echo
echo -e "${BBLUE}Initial Setup - Filesystem Configuration${NC}"
echo " 1.1 Initial Setup - Filesystem Configuration" >> /etc/hardening.log

# 1.1.1 Disable unused filesystems
echo
echo "  1.1.1 Initial Setup - Filesystem Configuration - Disable unused filesystems" >> /etc/hardening.log

# 1.1.1.1 Ensure mounting of cramfs filesystems is disabled
echo
echo -e "${BRED}1.1.1.1${NC} Ensure mounting of cramfs filesystems is disabled"
modprobe -n -v cramfs | grep "^install /bin/true$" || echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf
policystatus=$?
lsmod | egrep "^cramfs\s" && rmmod cramfs
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of cramfs filesystems is disabled"
  echo "   1.1.1.1 Remediated: Ensure mounting of cramfs filesystems is disabled" >> /etc/hardening.log
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of cramfs filesystems is disabled"
  echo "   1.1.1.1 UnableToRemediate: Ensure mounting of cramfs filesystems is disabled" >> /etc/hardening.log
fi

# 1.1.1.2 Ensure mounting of freevxfs filesystems is disabled
echo
echo -e "${BRED}1.1.1.2${NC} Ensure mounting of freevxfs filesystems is disabled"
modprobe -n -v freevxfs | grep "^install /bin/true$" || echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf
policystatus=$?
lsmod | egrep "^freevxfs\s" && rmmod freevxfs
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of freevxfs filesystems is disabled"
  echo "   1.1.1.2 Remediated: Ensure mounting of freevxfs filesystems is disabled" >> /etc/hardening.log
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of freevxfs filesystems is disabled"
  echo "   1.1.1.2 UnableToRemediate: Ensure mounting of freevxfs filesystems is disabled" >> /etc/hardening.log
fi

# 1.1.1.3 Ensure mounting of jffs2 filesystems is disabled
echo
echo -e "${BRED}1.1.1.3${NC} Ensure mounting of jffs2 filesystems is disabled"
modprobe -n -v jffs2 | grep "^install /bin/true$" || echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
policystatus=$?
lsmod | egrep "^jffs2\s" && rmmod jffs2
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of jffs2 filesystems is disabled"
  echo "   1.1.1.3 Remediated: Ensure mounting of jffs2 filesystems is disabled" >> /etc/hardening.log
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of jffs2 filesystems is disabled"
  echo "   1.1.1.3 UnableToRemediate: Ensure mounting of jffs2 filesystems is disabled" >> /etc/hardening.log
fi

# 1.1.1.4 Ensure mounting of hfs filesystems is disabled
echo
echo -e "${BRED}1.1.1.4${NC} Ensure mounting of hfs filesystems is disabled"
modprobe -n -v hfs | grep "^install /bin/true$" || echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf
policystatus=$?
lsmod | egrep "^hfs\s" && rmmod hfs
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of hfs filesystems is disabled"
  echo "   1.1.1.4 Remediated: Ensure mounting of hfs filesystems is disabled" >> /etc/hardening.log
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of hfs filesystems is disabled"
  echo "   1.1.1.4 UnableToRemediate: Ensure mounting of hfs filesystems is disabled" >> /etc/hardening.log
fi

# 1.1.1.5 Ensure mounting of hfsplus filesystems is disabled
echo
echo -e "${BRED}1.1.1.5${NC} Ensure mounting of hfsplus filesystems is disabled"
modprobe -n -v hfsplus | grep "^install /bin/true$" || echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf
policystatus=$?
lsmod | egrep "^hfsplus\s" && rmmod hfsplus
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of hfsplus filesystems is disabled"
  echo "   1.1.1.5 Remediated: Ensure mounting of hfsplus filesystems is disabled" >> /etc/hardening.log
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of hfsplus filesystems is disabled"
  echo "   1.1.1.5 UnableToRemediate: Ensure mounting of hfsplus filesystems is disabled" >> /etc/hardening.log
fi

# 1.1.1.6 Ensure mounting of udf filesystems is disabled
echo
echo -e "${BRED}1.1.1.6${NC} Ensure mounting of udf filesystems is disabled"
modprobe -n -v udf | grep "^install /bin/true$" || echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf
policystatus=$?
lsmod | egrep "^udf\s" && rmmod udf
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of udf filesystems is disabled"
  echo "   1.1.1.6 Remediated: Ensure mounting of udf filesystems is disabled" >> /etc/hardening.log
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of udf filesystems is disabled"
  echo "   1.1.1.6 UnableToRemediate: Ensure mounting of udf filesystems is disabled" >> /etc/hardening.log
fi

# 1.1.2 Ensure separate partition exists for /tmp
echo
echo -e "${BRED}1.1.2${NC} Ensure separate partition exists for /tmp"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} This setting must be configured during the installation, and in this case the VM was created based on a Azure image"
echo "  1.1.2 NothingToRemediate: Ensure separate partition exists for /tmp - This setting must be configured during the installation, and in this case the VM was created based on a Azure image" >> /etc/hardening.log

# 1.1.3 Ensure nodev option set on /tmp partition
echo
echo -e "${BRED}1.1.3${NC} Ensure nodev option set on /tmp partition"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} The /tmp partition doesn't exist on an Azure VM"
echo "  1.1.3 NothingToRemediate: Ensure nodev option set on /tmp partition - The /tmp partition doesn't exist on an Azure VM" >> /etc/hardening.log

# 1.1.4 Ensure nosuid option set on /tmp partition
echo
echo -e "${BRED}1.1.4${NC} Ensure nosuid option set on /tmp partition"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} The /tmp partition doesn't exist on an Azure VM"
echo "  1.1.4 NothingToRemediate: Ensure nosuid option set on /tmp partition - The /tmp partition doesn't exist on an Azure VM" >> /etc/hardening.log

# 1.1.5 Ensure separate partition exists for /var
echo
echo -e "${BRED}1.1.5${NC} Ensure separate partition exists for /var"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} This setting must be configured during the installation, and in this case the VM was created based on a Azure image"
echo "  1.1.5 NothingToRemediate: Ensure separate partition exists for /var - This setting must be configured during the installation, and in this case the VM was created based on a Azure image" >> /etc/hardening.log

# 1.1.6 Ensure separate partition exists for /var/tmp
echo
echo -e "${BRED}1.1.6${NC} Ensure separate partition exists for /var/tmp"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} This setting must be configured during the installation, and in this case the VM was created based on a Azure image"
echo "  1.1.6 NothingToRemediate: Ensure separate partition exists for /var/tmp - This setting must be configured during the installation, and in this case the VM was created based on a Azure image" >> /etc/hardening.log

# 1.1.7 Ensure nodev option set on /var/tmp partition
echo
echo -e "${BRED}1.1.7${NC} Ensure nodev option set on /var/tmp partition"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} This setting must be configured during the installation, and in this case the VM was created based on a Azure image"
echo "  1.1.7 NothingToRemediate: Ensure nodev option set on /var/tmp partition - This setting must be configured during the installation, and in this case the VM was created based on a Azure image" >> /etc/hardening.log

# 1.1.8 Ensure nosuid option set on /var/tmp partition
echo
echo -e "${BRED}1.1.8${NC} Ensure nosuid option set on /var/tmp partition"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} This setting must be configured during the installation, and in this case the VM was created based on a Azure image"
echo "  1.1.8 NothingToRemediate: Ensure nosuid option set on /var/tmp partition - This setting must be configured during the installation, and in this case the VM was created based on a Azure image" >> /etc/hardening.log

# 1.1.9 Ensure noexec option set on /var/tmp partition
echo
echo -e "${BRED}1.1.9${NC} Ensure noexec option set on /var/tmp partition"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} This setting must be configured during the installation, and in this case the VM was created based on a Azure image"
echo "  1.1.9 NothingToRemediate: Ensure noexec option set on /var/tmp partition - This setting must be configured during the installation, and in this case the VM was created based on a Azure image" >> /etc/hardening.log

# 1.1.10 Ensure separate partition exists for /var/log
echo
echo -e "${BRED}1.1.10${NC} Ensure separate partition exists for /var/log"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} This setting must be configured during the installation, and in this case the VM was created based on a Azure image"
echo "  1.1.10 NothingToRemediate: Ensure separate partition exists for /var/log - This setting must be configured during the installation, and in this case the VM was created based on a Azure image" >> /etc/hardening.log

# 1.1.11 Ensure separate partition exists for /var/log/audit
echo
echo -e "${BRED}1.1.11${NC} Ensure separate partition exists for /var/log/audit"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} This setting must be configured during the installation, and in this case the VM was created based on a Azure image"
echo "  1.1.11 NothingToRemediate: Ensure separate partition exists for /var/log/audit - This setting must be configured during the installation, and in this case the VM was created based on a Azure image" >> /etc/hardening.log

# 1.1.12 Ensure separate partition exists for /home
echo
echo -e "${BRED}1.1.12${NC} Ensure separate partition exists for /home"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} This setting must be configured during the installation, and in this case the VM was created based on a Azure image"
echo "  1.1.12 NothingToRemediate: Ensure separate partition exists for /home - This setting must be configured during the installation, and in this case the VM was created based on a Azure image" >> /etc/hardening.log

# 1.1.13 Ensure nodev option set on /home partition
echo
echo -e "${BRED}1.1.13${NC} Ensure nodev option set on /home partition"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} This setting must be configured during the installation, and in this case the VM was created based on a Azure image"
echo "  1.1.13 NothingToRemediate: Ensure nodev option set on /home partition - This setting must be configured during the installation, and in this case the VM was created based on a Azure image" >> /etc/hardening.log

# 1.1.14 Ensure nodev option set on /dev/shm partition
echo
echo -e "${BRED}1.1.14${NC} Ensure nodev option set on /dev/shm partition"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} This setting must be configured during the installation, and in this case the VM was created based on a Azure image"
echo "  1.1.14 NothingToRemediate: Ensure nodev option set on /dev/shm partition - This setting will be configure in the step 1.1.16" >> /etc/hardening.log

# 1.1.15 Ensure nosuid option set on /dev/shm partition
echo
echo -e "${BRED}1.1.15${NC} Ensure nosuid option set on /dev/shm partition"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} This setting must be configured during the installation, and in this case the VM was created based on a Azure image"
echo "  1.1.15 NothingToRemediate: Ensure nosuid option set on /dev/shm partition - This setting will be configure in the step 1.1.16" >> /etc/hardening.log

# 1.1.16 Ensure noexec option set on /dev/shm partition
echo
echo -e "${BRED}1.1.16${NC} Ensure noexec option set on /dev/shm partition"
echo "tmpfs                   /dev/shm                tmpfs   rw,nosuid,nodev,noexec      0 0" >> /etc/fstab
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure noexec option set on /dev/shm partition"
  echo "  1.1.16 Remediated: Ensure noexec option set on /dev/shm partition" >> /etc/hardening.log
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure noexec option set on /dev/shm partition"
  echo "  1.1.16 UnableToRemediate: Ensure noexec option set on /dev/shm partition" >> /etc/hardening.log
fi

# 1.1.17 Ensure nodev option set on removable media partitions
echo
echo -e "${BRED}1.1.17${NC} Ensure nodev option set on removable media partitions"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} This setting cannot be configured due the Azure VM can't attach media partitions"
echo "  1.1.17 NothingToRemediate: Ensure nodev option set on removable media partitions - This setting cannot be configured due the Azure VM can't attach media partitions" >> /etc/hardening.log

# 1.1.18 Ensure nosuid option set on removable media partitions
echo
echo -e "${BRED}1.1.18${NC} Ensure nosuid option set on removable media partitions"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} This setting cannot be configured due the Azure VM can't attach media partitions"
echo "  1.1.18 NothingToRemediate: Ensure nosuid option set on removable media partitions - This setting cannot be configured due the Azure VM can't attach media partitions" >> /etc/hardening.log

# 1.1.19 Ensure noexec option set on removable media partitions
echo
echo -e "${BRED}1.1.19${NC} Ensure noexec option set on removable media partitions"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} This setting cannot be configured due the Azure VM can't attach media partitions"
echo "  1.1.19 NothingToRemediate: Ensure noexec option set on removable media partitions - This setting cannot be configured due the Azure VM can't attach media partitions" >> /etc/hardening.log

# 1.1.20 Ensure sticky bit is set on all world-writable directories
echo
echo -e "${BRED}1.1.20${NC} Ensure sticky bit is set on all world-writable directories"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure sticky bit is set on all world-writable directories"
  echo "  1.1.20 Remediated: Ensure sticky bit is set on all world-writable directories" >> /etc/hardening.log
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure sticky bit is set on all world-writable directories"
  echo "  1.1.20 UnableToRemediate: Ensure sticky bit is set on all world-writable directories" >> /etc/hardening.log
fi

# 1.1.21 Disable Automounting
echo
echo -e "${BRED}1.1.21${NC} Disable Automounting"
systemctl disable autofs.service
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Disable Automounting"
  echo "  1.1.21 Remediated: Disable Automounting" >> /etc/hardening.log
else
  echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
  echo -e "${BPURPLE}REASON:${NC} The autofs.service doesn't exist on an Azure VM"
  echo "  1.1.21 UnableToRemediate: Disable Automounting - The autofs.service doesn't exist on an Azure VM" >> /etc/hardening.log
fi

############################################################################################################################

##Category 1.2 Initial Setup - Configure Software Updates
echo
echo -e "${BBLUE}Initial Setup - Configure Software Updates${NC}"
echo " " >> /etc/hardening.log
echo " 1.2 Initial Setup - Configure Software Updates" >> /etc/hardening.log

# 1.2.1 Ensure package manager repositories areconfigured 
echo
echo -e "${BRED}1.2.1${NC} Ensure package manager repositories are configured "
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} Azure configures the repositories nedeed to its VMs"
echo "  1.2.1 NothingToRemediate: Ensure package manager repositories areconfigured - Azure configures the repositories nedeed to its VMs" >> /etc/hardening.log

# 1.2.2 Ensure GPG keys are configured
echo
echo -e "${BRED}1.2.2${NC} Ensure GPG keys are configured"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} Azure configures the GPG keys nedeed to verify the package integrity"
echo "  1.2.2 NothingToRemediate: Ensure GPG keys are configured - Azure configures the GPG keys nedeed to verify the package integrity" >> /etc/hardening.log

############################################################################################################################

##Category 1.3 Initial Setup - Filesystem Integrity Checking
echo
echo -e "${BBLUE}Initial Setup - Filesystem Integrity Checking${NC}"
echo " " >> /etc/hardening.log
echo " 1.3 Initial Setup - Filesystem Integrity Checking" >> /etc/hardening.log

# 1.3.1 Ensure AIDE is installed
# 1.3.2 Ensure filesystem integrity is regularly checked
echo
echo -e "${RED}1.3.1${NC} Ensure AIDE is installed"
echo -e "${RED}1.3.2${NC} Ensure filesystem integrity is regularly checked"
echo -e "${BYELLOW}WARNING ${YELLOW} This settings could be replased for another feature on an Azure VM"
echo -e "${BPURPLE}REASON:${NC} Azure checks the integrity of linux files through Azure Defender, we recommend to enable Azure Defender (aka ASC) to this server"
echo "  1.3.1 NothingToRemediate: Ensure AIDE is installed - Azure checks the integrity of linux files through Azure Defender, we recommend to enable Azure Defender (aka ASC) to this server" >> /etc/hardening.log
echo "  1.3.2 NothingToRemediate: Ensure filesystem integrity is regularly checked - Azure checks the integrity of linux files through Azure Defender, we recommend to enable Azure Defender (aka ASC) to this server" >> /etc/hardening.log

############################################################################################################################

##Category 1.4 Initial Setup - Secure Boot Settings
echo
echo -e "${BBLUE}Initial Setup - Secure Boot Settings${NC}"
echo " " >> /etc/hardening.log
echo " 1.4 Initial Setup - Secure Boot Settings" >> /etc/hardening.log

# 1.4.1 Ensure permissions on bootloader config are configured
echo
echo -e "${BRED}1.4.1${NC} Ensure permissions on bootloader config are configured"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} Due the Azure VM nature, we can´t configure this settings, the bootloader isn't accesible"
echo "  1.4.1 NothingToRemediate: Ensure permissions on bootloader config are configured - Due the Azure VM nature, we can´t configure this settings, the bootloader isn't accesible" >> /etc/hardening.log

# 1.4.2 Ensure bootloader password is set 
echo
echo -e "${BRED}1.4.2${NC} Ensure bootloader password is configured"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} Due the Azure VM nature, we can´t configure this settings, the bootloader isn't accesible"
echo "  1.4.2 NothingToRemediate: Ensure bootloader password is configured - Due the Azure VM nature, we can´t configure this settings, the bootloader isn't accesible" >> /etc/hardening.log

# 1.4.3 Ensure authentication required for single user mode
echo
echo -e "${BRED}1.4.3${NC} Ensure authentication required for single user mode"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} Due the Azure VM nature, we can´t configure this settings, the bootloader isn't accesible"
echo "  1.4.3 NothingToRemediate: Ensure bootloader password is configured - Due the Azure VM nature, we can´t configure this settings, the bootloader isn't accesible" >> /etc/hardening.log

############################################################################################################################

##Category 1.5 Additional Process Hardening
echo
echo -e "${BBLUE}Initial Setup - Additional Process Hardening${NC}"
echo " " >> /etc/hardening.log
echo " 1.5 Initial Setup - Additional Process Hardening" >> /etc/hardening.log

#1.5.1 Ensure core dumps are restricted
echo
echo -e "${BRED}1.5.1${NC} Ensure core dumps are restricted"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} Due the Azure VM nature, the core dumps are managed by Azure, and we can use serial console to analyze it"
echo "  1.5.1 NothingToRemediate: Ensure core dumps are restricted - Due the Azure VM nature, the core dumps are managed by Azure, and we can use serial console to analyze it" >> /etc/hardening.log

#1.5.2 Ensure XD/NX support is enabled
echo
echo -e "${BRED}1.5.2${NC} Ensure XD/NX support is enabled"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} Due the Azure VM nature, this setting couldn't be set in the hardware"
echo "  1.5.2 NothingToRemediate: Ensure XD/NX support is enabled - Due the Azure VM nature, this setting couldn't be set in the hardware" >> /etc/hardening.log

# 1.5.3 Ensure address space layout randomization (ASLR) is enabled
echo
echo -e "${RED}1.5.3${NC} Ensure address space layout randomization (ASLR) is enabled"
egrep -q "^(\s*)kernel.randomize_va_space\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)kernel.randomize_va_space\s*=\s*\S+(\s*#.*)?\s*$/\1kernel.randomize_va_space = 2\2/" /etc/sysctl.conf || echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure address space layout randomization (ASLR) is enabled"
	echo "  1.5.3 Remediated: Ensure address space layout randomization (ASLR) is enabled" >> /etc/hardening.log
	success=$((success + 1))
else
    echo -e "${RED}UnableToRemediate:${NC} Ensure address space layout randomization (ASLR) is enabled"
	echo "  1.5.3 UnableToRemediate: Ensure address space layout randomization (ASLR) is enabled" >> /etc/hardening.log
    fail=$((fail + 1))
fi

# 1.5.4 Ensure prelinkis disabled
echo
echo -e "${RED}1.5.3${NC} Ensure prelinkis disabled"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} Azure by default don't install it on an Ubuntu VM, additional we recommend that use Azure Defender (aka ASC) to guarantee the file integrity"
echo "  1.5.4 NothingToRemediate: Ensure prelinkis disabled - Azure by default don't install it on an Ubuntu VM, additional we recommend that use Azure Defender (aka ASC) to guarantee the file integrity" >> /etc/hardening.log

############################################################################################################################

##Category 1.6 Mandatory Access Control
echo
echo -e "${BBLUE}Initial Setup - Mandatory Access Control${NC}"
echo " " >> /etc/hardening.log
echo " 1.6 Initial Setup - Additional Process Hardening" >> /etc/hardening.log

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
echo "  1.6.1 NothingToRemediate: Configure SELinux - Azure by default don't use SELinux on an Ubuntu VM" >> /etc/hardening.log

# 1.6.2 Configure AppArmor
echo "  1.6.2 Configure AppArmor" >> /etc/hardening.log
# 1.6.2.1 Ensure AppArmor is not disabled in bootloader configuration
echo
echo -e "${RED}1.6.2.1${NC} Ensure AppArmor is not disabled in bootloader configuration"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} Azure by default configure the bootloader settings"
echo "   1.6.2.1 NothingToRemediate: Ensure AppArmor is not disabled in bootloader configuration - Azure by default configure the bootloader settings" >> /etc/hardening.log

# 1.6.2.2 Ensure all AppArmor Profiles are enforcing
echo
echo -e "${RED}1.6.2.2${NC} Ensure all AppArmor Profiles are enforcing"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} Azure by default configure the AppArmor settings, and are enabled by default"
echo "   1.6.2.2 NothingToRemediate: Ensure all AppArmor Profiles are enforcing - Azure by default configure the AppArmor settings, and are enabled by default" >> /etc/hardening.log

# 1.6.2.3 Ensure SELinux or AppArmor are installed
echo
echo -e "${RED}1.6.2.3${NC} Ensure SELinux or AppArmor are installed"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} Azure by default configure the AppArmor settings, and are enabled by default"
echo "   1.6.2.3 NothingToRemediate: Ensure SELinux or AppArmor are installed - Azure by default configure the AppArmor settings, and are enabled by default" >> /etc/hardening.log

############################################################################################################################

##Category 1.7 Mandatory Access Control
echo
echo -e "${BBLUE}Initial Setup - Mandatory Access Control${NC}"
echo " " >> /etc/hardening.log
echo " 1.7 Mandatory Access Control" >> /etc/hardening.log

# 1.7.1 Command Line Warning Banners
echo "  1.7.1 Command Line Warning Banners" >> /etc/hardening.log

# 1.7.1.1 Ensure message of the day is configured properly
echo
echo -e "${RED}1.7.1.1${NC} Ensure message of the day is configured properly"
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
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure message of the day is configured properly"
	echo "   1.7.1.1 Remediated: Ensure message of the day is configured properly" >> /etc/hardening.log
    success=$((success + 1))
else
    echo -e "${RED}UnableToRemediate:${NC} Ensure message of the day is configured properly"
	echo "   1.7.1.1 UnableToRemediate: Ensure message of the day is configured properly" >> /etc/hardening.log
    fail=$((fail + 1))
fi

# 1.7.1.2 Ensure local login warning banner is configured properly
echo
echo -e "${RED}1.7.1.2${NC} Ensure local login warning banner is configured properly"
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure local login warning banner is configured properly"
	echo "   1.7.1.2 Remediated: Ensure local login warning banner is configured properly" >> /etc/hardening.log
    success=$((success + 1))
else
    echo -e "${RED}UnableToRemediate:${NC} Ensure local login warning banner is configured properly"
	echo "   1.7.1.2 UnableToRemediate: Ensure local login warning banner is configured properly" >> /etc/hardening.log
    fail=$((fail + 1))
fi

# 1.7.1.3 Ensure remote login warning banner is configured properly
echo
echo -e "${RED}1.7.1.3${NC} Ensure remote login warning banner is configured properly"
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure remote login warning banner is configured properly"
	echo "   1.7.1.3 Remediated: Ensure remote login warning banner is configured properly" >> /etc/hardening.log
    success=$((success + 1))
else
    echo -e "${RED}UnableToRemediate:${NC} Ensure remote login warning banner is configured properly"
	echo "   1.7.1.3 UnableToRemediate: Ensure remote login warning banner is configured properly" >> /etc/hardening.log
    fail=$((fail + 1))
fi

# 1.7.1.4 Ensure permissions on /etc/motd are configured
echo
echo -e "${RED}1.7.1.4${NC} Ensure permissions on /etc/motd are configured"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} Azure Ubuntu VM doesn't have this file"
echo "   1.7.1.4 NothingToRemediate: Ensure permissions on /etc/motd are configured - Azure Ubuntu VM doesn't have this file" >> /etc/hardening.log

# 1.7.1.5 Ensure permissions on /etc/issue are configured
echo
echo -e "${RED}1.7.1.5${NC} Ensure permissions on /etc/issue are configured"
chown root:root /etc/issue
chmod 644 /etc/issue
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/issue are configured"
	echo "   1.7.1.5 Remediated: Ensure permissions on /etc/issue are configured" >> /etc/hardening.log
    success=$((success + 1))
else
    echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/issue are configured"
	echo "   1.7.1.5 UnableToRemediate: Ensure permissions on /etc/issue are configured" >> /etc/hardening.log
    fail=$((fail + 1))
fi

# 1.7.1.6 Ensure permissions on /etc/issue.net are configured
echo
echo -e "${RED}1.7.1.6${NC} Ensure permissions on /etc/issue.net are configured"
chown root:root /etc/issue.net
chmod 644 /etc/issue.net
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/issue.net are configured"
	echo "   1.7.1.6 Remediated: Ensure permissions on /etc/issue.net are configured" >> /etc/hardening.log
    success=$((success + 1))
else
    echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/issue.net are configured"
	echo "   1.7.1.6 UnableToRemediate: Ensure permissions on /etc/issue.net are configured" >> /etc/hardening.log
    fail=$((fail + 1))
fi

# 1.7.2 Ensure GDM login banner is configured
echo
echo -e "${RED}1.7.2${NC} Ensure GDM login banner is configured"
echo -e "${BGREEN}OK ${YELLOW} This setting isn't applicable for an Azure VM"
echo -e "${BPURPLE}REASON:${NC} Azure Ubuntu VM doesn't have this file"
echo "  1.7.2 NothingToRemediate: Ensure GDM login banner is configured - Azure Ubuntu VM doesn't have this file" >> /etc/hardening.log

############################################################################################################################

##Category 1.8 Ensure updates, patches, and additional security software are installed
echo
echo -e "${RED}1.8${NC} Ensure updates, patches, and additional security software are installed"
echo " " >> /etc/hardening.log
apt-get -s upgrade
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure updates, patches, and additional security software are installed"
  echo "  1.8 Remediated: Ensure updates, patches, and additional security software are installed" >> /etc/hardening.log
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure updates, patches, and additional security software are installed"
  echo " 1.8 UnableToRemediate: Ensure updates, patches, and additional security software are installed" >> /etc/hardening.log
fi

############################################################################################################################
############################################################################################################################
echo " " >> /etc/hardening.log
echo "############################################################################################################################" >> /etc/hardening.log
##Category 2 Services
echo " " >> /etc/hardening.log
echo "2 Services" >> /etc/hardening.log
##Category 2.1 Services - inetd Services
echo
echo -e "${BBLUE}Services - inetd Services${NC}"
echo " 2.1 Services - inetd Services" >> /etc/hardening.log

# 2.1.1 Ensure chargen services are not enabled
echo
echo "  2.1.1 Services - inetd Services - Ensure chargen services are not enabled" >> /etc/hardening.log