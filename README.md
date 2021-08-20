# OS Hardening Scripts
This repository contains a collection of scripts that will help to harden operating system baseline configuration supported by Secnesys.

## Supported Benchmark
* CIS Ubuntu 18.04 benchmark v1.0.0

## How to Use
Example 1: CIS Ubuntu 18.04 benchmark v1.0.0

1. Login to VM/EC2 Instance using SSH
2. Switch user(su) to root with the command   sudo su
3. Download/copy bash script to VM/EC2 Instance with the command wget https://raw.githubusercontent.com/Cloudneeti/os-harderning-scripts/master/Ubuntu18_04/Azure_CSBP_Ubuntu18_04_Remediation.sh
4. Run bash script to apply baseline configuration with the command sh CIS_Ubuntu18_04_Benchmark_v1_0_0_Remediation.sh
