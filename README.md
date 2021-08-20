# OS Hardening Scripts
This repository contains a collection of scripts that will help to harden operating system baseline configuration supported by Secnesys.

## Supported Benchmark
* CIS Ubuntu 18.04 benchmark v1.0.0

## How to Use
Example 1: CIS Ubuntu 18.04 benchmark v1.0.0

1. Login to VM/EC2 Instance using SSH
2. Switch user(su) to root with the command   `sudo su`
3. Download/copy bash script to VM/EC2 Instance with the command `wget https://raw.githubusercontent.com/sorcia25/HardeningScripts/main/Ubuntu18_04/CIS_Ubuntu18_04_Benchmark_v1_0_0_Remediation.sh`
4. Run bash script to apply baseline configuration with the command `sh CIS_Ubuntu18_04_Benchmark_v1_0_0_Remediation.sh`

##Caution
The scripts are designed to harden the operating system baseline configurations, Please test it on the test/staging system before applying to the production system.
