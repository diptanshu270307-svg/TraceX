#!/usr/bin/env python3
"""
deploy_to_ec2.py — Automated deployment script for TraceX Platform to AWS EC2.
Deploys FastAPI Gateway, ML engine, NetworkX topology, and static Command Center.
"""
import os
import sys
import tarfile
import subprocess
import time
import boto3
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(BASE_DIR, ".env"))

INSTANCE_ID = "i-0d2816a1040ae1c1b"
REGION = os.getenv("AWS_REGION", "ap-south-1")
PUBLIC_IP = "13.200.242.110"
OS_USER = "ubuntu"
KEY_PATH = "/tmp/tracex_ec2_key"
ARCHIVE_PATH = "/tmp/tracex_deploy.tar.gz"

def ensure_ssh_key():
    if not os.path.exists(KEY_PATH):
        print("[*] Generating ephemeral deployment key...")
        subprocess.run(["ssh-keygen", "-t", "rsa", "-b", "2048", "-f", KEY_PATH, "-N", ""], check=True)
    with open(KEY_PATH + ".pub", "r") as f:
        return f.read().strip()

def send_instance_connect(pub_key):
    print(f"[*] Sending EC2 Instance Connect public key to {INSTANCE_ID} in {REGION}...")
    ec2 = boto3.client("ec2", region_name=REGION)
    inst = ec2.describe_instances(InstanceIds=[INSTANCE_ID])["Reservations"][0]["Instances"][0]
    az = inst["Placement"]["AvailabilityZone"]

    eic = boto3.client("ec2-instance-connect", region_name=REGION)
    resp = eic.send_ssh_public_key(
        InstanceId=INSTANCE_ID,
        InstanceOSUser=OS_USER,
        SSHPublicKey=pub_key,
        AvailabilityZone=az
    )
    if resp.get("Success"):
        print("[+] EC2 Instance Connect authorized.")
    else:
        raise RuntimeError(f"EC2 Instance Connect failed: {resp}")

def run_ssh(cmd, timeout=120):
    ssh_cmd = [
        "ssh", "-i", KEY_PATH,
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=15",
        f"{OS_USER}@{PUBLIC_IP}",
        cmd
    ]
    res = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
    return res

def create_tarball():
    print(f"[*] Creating deployment tarball at {ARCHIVE_PATH}...")
    if os.path.exists(ARCHIVE_PATH):
        os.remove(ARCHIVE_PATH)

    def filter_func(tarinfo):
        # Exclude pycache, venv, git, ds_store
        name = tarinfo.name
        if any(x in name for x in ["__pycache__", ".venv", ".git", ".DS_Store", "tracex_handoff"]):
            return None
        return tarinfo

    with tarfile.open(ARCHIVE_PATH, "w:gz") as tar:
        items = [
            "gateway",
            "api_export",
            "SIH26",
            "extension",
            ".env",
            "requirements-docker.txt"
        ]
        for item in items:
            p = os.path.join(BASE_DIR, item)
            if os.path.exists(p):
                tar.add(p, arcname=item, filter=filter_func)
                print(f"  + Added: {item}")

    size_mb = os.path.getsize(ARCHIVE_PATH) / (1024 * 1024)
    print(f"[+] Archive created: {size_mb:.2f} MB")

def transfer_tarball():
    print(f"[*] Uploading deployment package to {PUBLIC_IP}:/home/{OS_USER}/...")
    scp_cmd = [
        "scp", "-i", KEY_PATH,
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        ARCHIVE_PATH,
        f"{OS_USER}@{PUBLIC_IP}:/home/{OS_USER}/tracex_deploy.tar.gz"
    ]
    subprocess.run(scp_cmd, check=True)
    print("[+] Package uploaded.")

def provision_remote():
    print("[*] Provisioning EC2 instance (swap, packages, venv, systemd)...")

    remote_script = """#!/bin/bash
set -e

echo '[*] Step 1: Checking Swap space...'
if [ $(free -m | awk '/Swap:/ {print $2}') -eq 0 ]; then
    echo '[+] Creating 2GB swapfile...'
    sudo fallocate -l 2G /swapfile
    sudo chmod 600 /swapfile
    sudo mkswap /swapfile
    sudo swapon /swapfile
    echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
fi

echo '[*] Step 2: Installing system dependencies...'
export DEBIAN_FRONTEND=noninteractive
echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | sudo debconf-set-selections
echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | sudo debconf-set-selections
sudo apt-get update -y
sudo apt-get install -y python3-pip python3-venv iptables iptables-persistent curl libgl1

echo '[*] Step 3: Unpacking codebase...'
mkdir -p /home/ubuntu/tracex
cd /home/ubuntu/tracex
tar -xzf /home/ubuntu/tracex_deploy.tar.gz -C /home/ubuntu/tracex/

echo '[*] Step 4: Setting up Python virtualenv...'
if [ ! -d "/home/ubuntu/tracex/venv" ]; then
    python3 -m venv /home/ubuntu/tracex/venv
fi

/home/ubuntu/tracex/venv/bin/pip install --upgrade pip
/home/ubuntu/tracex/venv/bin/pip install -r /home/ubuntu/tracex/requirements-docker.txt

echo '[*] Step 5: Configuring Systemd Service (tracex.service)...'
sudo bash -c 'cat > /etc/systemd/system/tracex.service << EOF
[Unit]
Description=TraceX Cyber-Forensic Threat Defense Platform
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/tracex
EnvironmentFile=/home/ubuntu/tracex/.env
ExecStart=/home/ubuntu/tracex/venv/bin/python -m uvicorn gateway.main:app --host 0.0.0.0 --port 8000 --workers 1
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF'

echo '[*] Step 6: Setting up Port 80 -> 8000 Redirection...'
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8000 || true
sudo netfilter-persistent save || true

echo '[*] Step 7: Starting and Enabling tracex.service...'
sudo systemctl daemon-reload
sudo systemctl enable tracex.service
sudo systemctl restart tracex.service

sleep 4
sudo systemctl status tracex.service --no-pager
echo '[+] TraceX successfully deployed and running!'
"""

    # Write remote setup script
    setup_file = "/tmp/setup_remote.sh"
    with open(setup_file, "w") as f:
        f.write(remote_script)

    scp_cmd = [
        "scp", "-i", KEY_PATH,
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        setup_file,
        f"{OS_USER}@{PUBLIC_IP}:/home/{OS_USER}/setup.sh"
    ]
    subprocess.run(scp_cmd, check=True)

    print("[*] Executing setup on remote instance (this may take 1-2 minutes for pip installs)...")
    res = run_ssh("chmod +x /home/ubuntu/setup.sh && /home/ubuntu/setup.sh", timeout=300)
    print("STDOUT:\n", res.stdout)
    if res.stderr:
        print("STDERR:\n", res.stderr)
    if res.returncode != 0:
        raise RuntimeError(f"Remote provisioning failed with code {res.returncode}")

def verify_deployment():
    print("[*] Verifying remote HTTP deployment...")
    time.sleep(3)
    urls = [
        f"http://{PUBLIC_IP}:8000/api/scans",
        f"http://{PUBLIC_IP}:8000/api/graph",
        f"http://{PUBLIC_IP}:8000/api/extension/download",
        f"http://{PUBLIC_IP}/login",
        f"http://{PUBLIC_IP}/logout",
        f"http://{PUBLIC_IP}/"
    ]
    for url in urls:
        try:
            res = subprocess.run(["curl", "-s", "-I", "--max-time", "6", url], capture_output=True, text=True)
            first_line = res.stdout.splitlines()[0] if res.stdout else "No response"
            print(f"  + {url} -> {first_line}")
        except Exception as e:
            print(f"  - {url} -> {e}")

def main():
    pub_key = ensure_ssh_key()
    send_instance_connect(pub_key)
    create_tarball()
    # Re-send key in case packaging took time
    send_instance_connect(pub_key)
    transfer_tarball()
    send_instance_connect(pub_key)
    provision_remote()
    verify_deployment()
    print("\n" + "=" * 70)
    print(f"[+] DEPLOYMENT COMPLETE!")
    print(f"[+] Live TraceX Website:           http://{PUBLIC_IP}/")
    print(f"[+] Live TraceX API Gateway:       http://{PUBLIC_IP}:8000/")
    print(f"[+] Extension Download from S3:    https://tracex-forensic-vault-diptanshu.s3.ap-south-1.amazonaws.com/downloads/tracex-sentinel-extension.zip")
    print(f"[+] Extension Download from Web:   http://{PUBLIC_IP}:8000/api/extension/download")
    print("=" * 70)

if __name__ == "__main__":
    main()
