#!/usr/bin/env python3
"""
Cisco XDR Remote Appliance - OVA to QCOW2 Converter
v1.2 - 15-Jan-2026
Author: Steve Holl [sholl@cisco.com]

This script converts a Cisco XDR Remote Appliance OVA to a customized QCOW2 image.

Features:
- Extracts VMDK from OVA archive
- Converts VMDK to QCOW2 format
- Downloads register_remote.py from GitHub
- Sets root password to 'cisco' with forced change on first login
- Places registration script at /root/register_remote.py
- Configures netplan for DHCP on any ethernet interface (works across hypervisors)
- Enables SSH service with root login permitted

Requirements:
- qemu-img (brew install qemu)
- docker (Docker Desktop)
- Python 3.6+

Usage:
    python3 build_qcow2.py <input.ova> [output.qcow2]

Example:
    python3 build_qcow2.py xdr-automation-remote.ova
    python3 build_qcow2.py xdr-automation-remote.ova custom-output.qcow2
"""

import argparse
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

# GitHub raw URL for register_remote.py
GITHUB_SCRIPT_URL = "https://raw.githubusercontent.com/sholl-cisco/xdr-remote-register/main/register_remote.py"

# Docker image for libguestfs
DOCKER_IMAGE = "fedora:39"

# Netplan config that works across all hypervisors (UTM, VMware, KVM, VirtualBox)
NETPLAN_CONFIG = """# Auto-generated netplan config for cross-hypervisor compatibility
# Matches any ethernet interface (enp0s1, ens160, ens3, etc.)
network:
  version: 2
  ethernets:
    all-eth:
      match:
        name: "en*"
      dhcp4: true
"""


def install_requests():
    """Install requests module if not present"""
    try:
        import requests
        return requests
    except ImportError:
        print("[*] Installing 'requests' module...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "requests"])
        import requests
        return requests


def check_dependencies():
    """Check that required system tools are available"""
    print("[*] Checking dependencies...")

    # Check qemu-img
    if not shutil.which("qemu-img"):
        print("[!] ERROR: qemu-img not found", file=sys.stderr)
        print("    Install with: brew install qemu", file=sys.stderr)
        return False

    # Check docker
    if not shutil.which("docker"):
        print("[!] ERROR: docker not found", file=sys.stderr)
        print("    Install Docker Desktop from https://docker.com", file=sys.stderr)
        return False

    # Check docker is running
    result = subprocess.run(
        ["docker", "info"],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print("[!] ERROR: Docker is not running", file=sys.stderr)
        print("    Please start Docker Desktop", file=sys.stderr)
        return False

    print("[+] All dependencies satisfied")
    return True


def extract_ova(ova_path, output_dir):
    """Extract VMDK from OVA archive"""
    print(f"[*] Extracting OVA: {ova_path}")

    vmdk_path = None

    with tarfile.open(ova_path, 'r') as tar:
        for member in tar.getmembers():
            if member.name.endswith('.vmdk'):
                print(f"[*] Found VMDK: {member.name}")
                tar.extract(member, output_dir)
                vmdk_path = os.path.join(output_dir, member.name)
                break

    if not vmdk_path:
        print("[!] ERROR: No VMDK file found in OVA", file=sys.stderr)
        return None

    print(f"[+] Extracted: {vmdk_path}")
    return vmdk_path


def convert_vmdk_to_qcow2(vmdk_path, qcow2_path):
    """Convert VMDK to QCOW2 format"""
    print(f"[*] Converting VMDK to QCOW2...")
    print(f"    Source: {vmdk_path}")
    print(f"    Target: {qcow2_path}")

    result = subprocess.run(
        ["qemu-img", "convert", "-f", "vmdk", "-O", "qcow2", "-p", vmdk_path, qcow2_path],
        capture_output=False
    )

    if result.returncode != 0:
        print("[!] ERROR: qemu-img conversion failed", file=sys.stderr)
        return False

    print("[+] Conversion complete")
    return True


def download_script(requests_module, output_path):
    """Download register_remote.py from GitHub"""
    print(f"[*] Downloading register_remote.py from GitHub...")

    try:
        response = requests_module.get(GITHUB_SCRIPT_URL, timeout=30)
        response.raise_for_status()

        with open(output_path, 'w') as f:
            f.write(response.text)

        print(f"[+] Downloaded to: {output_path}")
        return True
    except Exception as e:
        print(f"[!] ERROR: Failed to download script: {e}", file=sys.stderr)
        return False


def customize_image(qcow2_path, script_path, work_dir):
    """Customize QCOW2 image with Docker + libguestfs"""
    print("[*] Customizing QCOW2 image...")
    print("    - Setting root password to 'cisco'")
    print("    - Forcing password change on first login")
    print("    - Installing register_remote.py to /root/")
    print("    - Configuring netplan for cross-hypervisor DHCP")
    print("    - Enabling SSH with root login")

    # Get absolute paths for Docker volume mount
    qcow2_abs = os.path.abspath(qcow2_path)
    script_abs = os.path.abspath(script_path)
    work_dir = os.path.dirname(qcow2_abs)

    # Copy script to work directory if not already there
    script_in_workdir = os.path.join(work_dir, "register_remote.py")
    if script_abs != script_in_workdir:
        shutil.copy(script_abs, script_in_workdir)

    # Write netplan config to work directory
    netplan_path = os.path.join(work_dir, "99-dhcp-all.yaml")
    with open(netplan_path, 'w') as f:
        f.write(NETPLAN_CONFIG)

    qcow2_name = os.path.basename(qcow2_abs)

    # Build docker command
    docker_cmd = [
        "docker", "run", "--rm", "--privileged",
        "--platform", "linux/amd64",
        "--memory=4g",
        "-e", "LIBGUESTFS_BACKEND=direct",
        "-v", f"{work_dir}:/work",
        DOCKER_IMAGE,
        "bash", "-c",
        f"dnf install -y -q guestfs-tools && "
        f"virt-customize --memsize 512 --no-network "
        f"-a /work/{qcow2_name} "
        f"--copy-in /work/register_remote.py:/root/ "
        f"--chmod 0755:/root/register_remote.py "
        f"--copy-in /work/99-dhcp-all.yaml:/etc/netplan/ "
        f"--chmod 0644:/etc/netplan/99-dhcp-all.yaml "
        f"--root-password password:cisco "
        f"--run-command 'chage -d 0 root' "
        f"--run-command 'systemctl enable ssh' "
        f"--run-command \"sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config\" "
        f"--run-command \"grep -q '^PermitRootLogin' /etc/ssh/sshd_config || echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config\" "
        f"--run-command \"sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config\" "
        f"--run-command \"grep -q '^PasswordAuthentication' /etc/ssh/sshd_config || echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config\" "
        f"--run-command \"rm -f /etc/ssh/sshd_config.d/*cloud* 2>/dev/null; sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true\""
    ]

    print("[*] Running Docker + libguestfs (this may take a few minutes)...")

    result = subprocess.run(
        docker_cmd,
        capture_output=True,
        text=True
    )

    # Cleanup temp files
    if os.path.exists(netplan_path):
        os.unlink(netplan_path)

    if result.returncode != 0:
        print("[!] ERROR: Image customization failed", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        return False

    # Check for success indicators in output
    if "Finishing off" in result.stdout or "Setting passwords" in result.stdout:
        print("[+] Image customization complete")
        return True

    # If we got here without error, assume success
    print("[+] Image customization complete")
    return True


def get_file_size(path):
    """Get human-readable file size"""
    size = os.path.getsize(path)
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def main():
    parser = argparse.ArgumentParser(
        description="Convert Cisco XDR Remote Appliance OVA to customized QCOW2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s xdr-automation-remote.ova
    %(prog)s xdr-automation-remote.ova custom-output.qcow2

The output QCOW2 will have:
    - Root password: cisco (forced change on first login)
    - /root/register_remote.py installed and executable
    - Netplan configured for DHCP on any ethernet interface
        """
    )
    parser.add_argument("ova_file", help="Input OVA file")
    parser.add_argument("output", nargs="?", help="Output QCOW2 file (default: <ova_basename>.qcow2)")

    args = parser.parse_args()

    # Validate input
    if not os.path.exists(args.ova_file):
        print(f"[!] ERROR: OVA file not found: {args.ova_file}", file=sys.stderr)
        sys.exit(1)

    # Determine output path
    if args.output:
        qcow2_path = args.output
    else:
        base = os.path.splitext(os.path.basename(args.ova_file))[0]
        qcow2_path = f"{base}.qcow2"

    print("=" * 70)
    print("Cisco XDR Remote Appliance - OVA to QCOW2 Converter")
    print("=" * 70)
    print(f"Input:  {args.ova_file}")
    print(f"Output: {qcow2_path}")
    print("=" * 70)

    # Check dependencies
    if not check_dependencies():
        sys.exit(1)

    # Install requests module
    requests = install_requests()

    # Get working directory (same as OVA location)
    work_dir = os.path.dirname(os.path.abspath(args.ova_file)) or "."

    # Step 1: Extract OVA
    vmdk_path = extract_ova(args.ova_file, work_dir)
    if not vmdk_path:
        sys.exit(1)

    # Step 2: Convert VMDK to QCOW2
    qcow2_full_path = os.path.join(work_dir, qcow2_path) if not os.path.isabs(qcow2_path) else qcow2_path
    if not convert_vmdk_to_qcow2(vmdk_path, qcow2_full_path):
        sys.exit(1)

    # Step 3: Download script from GitHub
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp:
        script_path = tmp.name

    if not download_script(requests, script_path):
        os.unlink(script_path)
        sys.exit(1)

    # Step 4: Customize image
    if not customize_image(qcow2_full_path, script_path, work_dir):
        os.unlink(script_path)
        sys.exit(1)

    # Cleanup temp script
    os.unlink(script_path)

    # Summary
    print()
    print("=" * 70)
    print("[+] BUILD COMPLETE!")
    print("=" * 70)
    print(f"QCOW2 Image: {qcow2_full_path}")
    print(f"Size:        {get_file_size(qcow2_full_path)}")
    print()
    print("Image Configuration:")
    print("  - Root password:          cisco")
    print("  - Password change:        Required on first login")
    print("  - Registration script:    /root/register_remote.py")
    print("  - Network:                DHCP on any en* interface")
    print("  - SSH:                    Enabled with root login")
    print("=" * 70)


if __name__ == "__main__":
    main()
