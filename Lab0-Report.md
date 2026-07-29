# Lab 0: Environment Preparation

**Course:** Cloud Computing Security Essentials<br>
**Lab Module:** 0 - Initial Setup<br>
**Date:** 29 July 2026

## Objective

In preparation for the next cloud security lab sessions, set up and verify a local Linux workspace. Verifying container engines, Kubernetes management tools, the AWS command-line interface, and crucial cryptography tools are all part of this setup.

## System Environment

The system validation was executed within an Ubuntu terminal (WSL/Linux shell). The following software suite was assessed:

| Utility | Primary Function | Validated Version |
| :--- | :--- | :--- |
| Docker | Container building and execution | Docker 29.6.2, build dfc4efb |
| AWS CLI | Cloud service administration and interaction | aws-cli/2.36.9, Python/3.14.6, Linux/6.17.0-22-generic, exe/x86_64.ubuntu.24 |
| kind | Local Kubernetes cluster deployment via Docker | kind v0.23.0 |
| kubectl | Kubernetes cluster management | Client v1.36.3; Kustomize v5.8.1 |
| OpenSSL | TLS and cryptographic operations | OpenSSL 3.0.13 (30 Jan 2024) |

## Validation Process and Evidence

## Verification Procedure and Evidence

### 1. Docker

The Docker installation was checked to ensure containerization tools are properly configured to run the lab environment:

```bash
docker --version
```

The command returned Docker version 29.6.2, confirming that the Docker command-line client is successfully installed.

<img width="327" height="72" alt="Screenshot 2026-07-29 192657" src="https://github.com/user-attachments/assets/17f10fe6-42e1-4752-ab04-18ea2084d6a2" />




### 2. AWS Command Line Interface

The AWS CLI installation was checked to verify that the system can communicate with and manage simulated cloud services:

```bash
aws --version
```

The output confirms AWS CLI version 2.36.10 is installed and running with Python 3.14.6 specifically within the WSL2 Ubuntu Linux environment.

<img width="453" height="80" alt="Screenshot 2026-07-29 191018" src="https://github.com/user-attachments/assets/8ca4126f-1277-4ad8-8f88-4e3373413312" />


### 3. kind

The kind utility was checked to ensure the system is capable of spinning up local Kubernetes clusters for testing:

```bash
kind --version
```

The output confirms that kind version 0.23.0 is installed and ready to use.

<img width="185" height="59" alt="Screenshot 2026-07-29 195221" src="https://github.com/user-attachments/assets/9b3f0c3d-ca40-46da-ace7-c1dca7c3adee" />


### 4. kubectl

The kubectl tool was verified to ensure we can issue commands to control and manage the Kubernetes cluster once it is running:

```bash
kubectl version --client
```

The output confirms the kubectl client version v1.36.1 and Kustomize version v5.8.1 are successfully installed.

<img width="216" height="76" alt="Screenshot 2026-07-29 195418" src="https://github.com/user-attachments/assets/620c951a-81b4-432f-a648-42aae3cea9c0" />


### 5. Cryptographic and OTP utilities

Finally, OpenSSL was verified to ensure the environment has the necessary cryptographic and certificate management tools required for later security labs:

```bash
openssl version
```

The output confirms OpenSSL 3.5.4 (built on 30 Sep 2025) is installed and operational.

<img width="467" height="65" alt="Screenshot 2026-07-29 200415" src="https://github.com/user-attachments/assets/00ef7ff7-ebd4-4847-b309-ef826ffa5964" />


## Conclusion

The lab environment's necessary command-line tools have been installed, and their versions have been noted. For upcoming cloud computing security labs, Docker, AWS CLI, kind, kubectl, and OpenSSL are accessible.
