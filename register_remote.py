#!/usr/bin/env python3
"""
Cisco XDR/Workflows Remote Appliance Local Registration Script
v1.1 - 10-Oct-2025 - fixed input string corruption issue causing registration to not occur.
v1.0 - 07-Oct-2025 - initial release
Author: Steve Holl [sholl@cisco.com]

This script registers a Cisco XDR/Workflows Remote Appliance by:
1. Reading base64 OVF user-data from a file
2. Extracting values.yaml and ca-key-pair.yaml from cloud-config
3. Automatically cleaning up existing containers
4. Automatically enabling IPv4 forwarding if needed
5. Writing configuration files to /etc/ao-remote/
6. Running the docker-compose-init.sh script
7. Verifying registration and container status

Fully repeatable for lab environments without needing
the user encoded-data into the OVF, which some virtualization
environments don't support

Features:
- **Validates all three certificates (ca.crt, tls.key, tls.crt) are present**
- **Always deletes old extracted certificate PEM files to force fresh extraction**
- Handles base64 padding issues automatically
- Supports plain text or zipped config files
- Detects certificate data in files with empty paths
- Normalizes YAML structure for compatibility
- Detects existing registrations and automatically cleans up

v1.1 Changes:
- REMOVED all interactive prompts - input prompt with pasted text often dropped characters
causing data parsing issues
- ADDED support for zipped config files (.gz, .zip)
- ADDED argparse with proper help documentation
- ADDED --force flag to skip all confirmations
- IMPROVED error messages and validation

Usage:
    # From file
    sudo python3 register_remote.py config.txt
    sudo python3 register_remote.py config.txt.gz

    # From stdin
    cat config.txt | sudo python3 register_remote.py -

    # Show help
    python3 register_remote.py --help
"""

import argparse
import base64
import gzip
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import yaml


class LocalXDRRegistration:
    """Handles local XDR appliance registration"""

    def __init__(self, ovf_base64_string):
        self.ovf_base64 = ovf_base64_string.strip()
        self.cloud_config = None
        self.values_yaml = None
        self.ca_key_pair_yaml = None

    def decode_ovf_string(self):
        """Decode base64 OVF user-data string"""
        print("[*] Decoding OVF user-data string...")
        try:
            # Clean the input - remove whitespace and newlines
            clean_base64 = "".join(self.ovf_base64.split())

            # Try to decode with padding correction
            try:
                decoded = base64.b64decode(clean_base64)
            except Exception:
                # If it fails, try adding padding
                missing_padding = len(clean_base64) % 4
                if missing_padding:
                    clean_base64 += "=" * (4 - missing_padding)
                decoded = base64.b64decode(clean_base64)

            self.cloud_config = yaml.safe_load(decoded)
            print("[+] Successfully decoded cloud-config")
            return True
        except Exception as e:
            print(f"[!] Error decoding OVF string: {e}", file=sys.stderr)
            print(f"[!] Base64 string length: {len(self.ovf_base64)}")
            print(f"[!] First 50 chars: {self.ovf_base64[:50]}")
            return False

    def extract_yaml_files(self):
        """Extract values.yaml and ca-key-pair.yaml from cloud-config"""
        print("[*] Extracting YAML configuration files...")

        if "write_files" not in self.cloud_config:
            print("[!] No write_files section found in cloud-config", file=sys.stderr)
            return False

        # First, show what files are available
        print("[*] Files found in cloud-config:")
        for file_entry in self.cloud_config["write_files"]:
            path = file_entry.get("path", "")
            print(f"    - {path}")

        # Now extract them
        for file_entry in self.cloud_config["write_files"]:
            path = file_entry.get("path", "")
            content = file_entry.get("content", "")

            if "values.yaml" in path:
                self.values_yaml = content
                print(f"[+] Found values.yaml at: {path}")
            elif "ca-key-pair.yaml" in path or "ca_key_pair.yaml" in path:
                self.ca_key_pair_yaml = content
                print(f"[+] Found ca-key-pair.yaml at: {path}")
            elif not path and content:
                # Handle files with missing/empty path - detect by content
                if (
                    "ca.crt:" in content
                    or "tls.key:" in content
                    or "tls.crt:" in content
                ):
                    self.ca_key_pair_yaml = content
                    print(
                        "[+] Found ca-key-pair.yaml (path was empty, detected by certificate content)"
                    )
                elif (
                    "remote_name:" in content
                    or "remote_id:" in content
                    or "mqtt_broker:" in content
                ):
                    self.values_yaml = content
                    print(
                        "[+] Found values.yaml (path was empty, detected by environment content)"
                    )

        if not self.values_yaml or not self.ca_key_pair_yaml:
            print("[!] Missing required YAML files in cloud-config", file=sys.stderr)
            if not self.values_yaml:
                print("[!]   - values.yaml not found")
            if not self.ca_key_pair_yaml:
                print("[!]   - ca-key-pair.yaml not found")
            return False

        return True

    def display_config_info(self):
        """Display configuration information extracted from values.yaml"""
        try:
            values_data = yaml.safe_load(self.values_yaml)
            env = values_data.get("env", {})

            print("\n" + "=" * 70)
            print("XDR Remote Appliance Configuration")
            print("=" * 70)
            print(f"Remote Name:     {env.get('remote_name', 'N/A')}")
            print(f"Remote ID:       {env.get('remote_id', 'N/A')}")
            print(f"MQTT Broker:     {env.get('mqtt_broker', 'N/A')}")
            print(f"Proxy:           {env.get('all_proxy', '(none)')}")
            print("=" * 70 + "\n")
        except Exception as e:
            print(f"[!] Could not parse values.yaml for display: {e}")

    def normalize_ca_key_pair_yaml(self) -> str:
        """Ensure ca-key-pair.yaml has the correct structure for extract_yaml.py

        CRITICAL FIX: This function now properly validates that ALL THREE certificates
        are present (ca.crt, tls.key, tls.crt) and will fail if any are missing.
        """
        if not self.ca_key_pair_yaml:
            return ""

        try:
            ca_data = yaml.safe_load(self.ca_key_pair_yaml)

            # Debug: Show what keys we have in the raw data
            print("[*] Raw certificate data structure:")
            print(f"[*]   Top-level keys: {list(ca_data.keys())}")

            # Determine the structure and extract certificates
            certs = {}

            if "data" in ca_data and isinstance(ca_data["data"], dict):
                # Nested structure: data -> ca.crt, tls.key, tls.crt
                print(
                    f"[*]   Found nested structure with keys: {list(ca_data['data'].keys())}"
                )
                certs = {
                    "ca.crt": ca_data["data"].get("ca.crt", ""),
                    "tls.key": ca_data["data"].get("tls.key", ""),
                    "tls.crt": ca_data["data"].get("tls.crt", ""),
                }
            elif any(key in ca_data for key in ["ca.crt", "tls.key", "tls.crt"]):
                # Flat structure: ca.crt, tls.key, tls.crt at top level
                print("[*]   Found flat structure")
                certs = {
                    "ca.crt": ca_data.get("ca.crt", ""),
                    "tls.key": ca_data.get("tls.key", ""),
                    "tls.crt": ca_data.get("tls.crt", ""),
                }
            else:
                print(
                    "[!] ERROR: Could not find certificate data in ca-key-pair.yaml",
                    file=sys.stderr,
                )
                return ""

            # CRITICAL VALIDATION: Check that all three certificates are present and non-empty
            print("\n[*] Certificate validation:")
            missing_certs = []
            for key in ["ca.crt", "tls.key", "tls.crt"]:
                if certs.get(key) and len(certs[key].strip()) > 0:
                    print(f"[+]   {key}: present ({len(certs[key])} chars)")
                else:
                    print(f"[!]   {key}: MISSING or EMPTY")
                    missing_certs.append(key)

            if missing_certs:
                print(f"\n{'=' * 70}")
                print("[!] CRITICAL ERROR: Missing required certificates!")
                print(
                    f"[!] The following certificates are missing: {', '.join(missing_certs)}"
                )
                print(f"{'=' * 70}")
                print("\n[!] This means the cloud-config from Cisco is incomplete.")
                print("[!] Possible solutions:")
                print(
                    "[!]   1. Check if you copied the full base64 string from Cisco XDR"
                )
                print("[!]   2. Try regenerating the remote in Cisco XDR dashboard")
                print("[!]   3. Contact Cisco support if the issue persists")
                print(f"{'=' * 70}\n")
                sys.exit(1)

            # Create normalized structure with all three certificates
            normalized = {"data": certs}

            print("[+] All certificates validated successfully")
            print("[*] Normalizing ca-key-pair.yaml to expected format")

            # Use width parameter to prevent line wrapping of long base64 strings
            return yaml.dump(normalized, default_flow_style=False, width=float("inf"))

        except Exception as e:
            print(f"[!] Error normalizing ca-key-pair.yaml: {e}", file=sys.stderr)
            import traceback

            traceback.print_exc()
            return ""

    def write_config_files(self):
        """Write YAML files to /etc/ao-remote/"""
        print("\n[*] Writing configuration files to /etc/ao-remote/...")

        target_dir = Path("/etc/ao-remote")

        try:
            # Create directory if it doesn't exist
            target_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(target_dir, 0o700)

            # Write values.yaml
            values_path = target_dir / "values.yaml"
            with open(values_path, "w") as f:
                f.write(self.values_yaml)
            os.chmod(values_path, 0o600)
            print(f"[+] Written: {values_path}")

            # Normalize and write ca-key-pair.yaml
            normalized_ca_key_pair = self.normalize_ca_key_pair_yaml()
            if not normalized_ca_key_pair:
                print("[!] Failed to normalize ca-key-pair.yaml", file=sys.stderr)
                return False

            ca_key_pair_path = target_dir / "ca-key-pair.yaml"
            with open(ca_key_pair_path, "w") as f:
                f.write(normalized_ca_key_pair)
            os.chmod(ca_key_pair_path, 0o600)
            print(f"[+] Written: {ca_key_pair_path}")

            print("[+] Configuration files written successfully\n")

            # CRITICAL: Always delete old extracted certificate files
            # This ensures docker-compose-init.sh will extract fresh certificates
            # from the updated ca-key-pair.yaml instead of using stale files
            cert_dir = Path("/etc/docker-compose/secrets/ao-remote/for-mqtt")
            if cert_dir.exists():
                print("[*] Removing old certificate files to force fresh extraction...")
                subprocess.run(
                    ["rm", "-f", str(cert_dir / "*.pem")],
                    shell=True,
                    check=False,
                )
                print("[+] Old certificate files removed")

            return True

        except PermissionError:
            print("[!] Permission denied. Please run with sudo", file=sys.stderr)
            return False
        except Exception as e:
            print(f"[!] Error writing files: {e}", file=sys.stderr)
            import traceback

            traceback.print_exc()
            return False

    def check_existing_registration(self):
        """Check if containers are already running and automatically clean up"""
        try:
            result = subprocess.run(
                ["docker", "ps", "-q", "-f", "name=xdr-automation"],
                capture_output=True,
                text=True,
            )

            if result.stdout.strip():
                print("\n[!] Existing XDR containers detected")
                print("[*] Automatically stopping and removing containers...")
                subprocess.run(
                    [
                        "docker",
                        "compose",
                        "-f",
                        "/etc/docker-compose/docker-compose.yaml",
                        "down",
                    ],
                    check=False,
                )

                # Also clean up old certificate files
                print("[*] Cleaning up old certificate files...")
                subprocess.run(
                    ["rm", "-rf", "/etc/docker-compose/secrets/ao-remote"],
                    check=False,
                )

                print("[+] Containers stopped and old certificates cleaned")
                return True

            return True

        except Exception as e:
            print(f"[!] Could not check for existing containers: {e}")
            return True  # Don't block registration

    def check_ipv4_forwarding(self):
        """Check if IPv4 forwarding is enabled and automatically enable it"""
        try:
            result = subprocess.run(
                ["sysctl", "net.ipv4.ip_forward"], capture_output=True, text=True
            )

            if "net.ipv4.ip_forward = 0" in result.stdout:
                print("\n[!] IPv4 forwarding is currently disabled")
                print("[*] Automatically enabling IPv4 forwarding...")

                # Enable immediately
                subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)

                # Make it persistent across reboots
                sysctl_conf = "/etc/sysctl.conf"
                with open(sysctl_conf, "r") as f:
                    content = f.read()

                if "net.ipv4.ip_forward=1" not in content:
                    with open(sysctl_conf, "a") as f:
                        f.write("\n# Enable IPv4 forwarding for Docker\n")
                        f.write("net.ipv4.ip_forward=1\n")

                print("[+] IPv4 forwarding enabled")
                return True
            else:
                print("[+] IPv4 forwarding is already enabled")
                return True

        except Exception as e:
            print(f"[!] Could not check IPv4 forwarding: {e}")
            return True  # Don't block registration

    def run_registration(self):
        """Run the docker-compose-init.sh script"""
        init_script = "/usr/local/bin/docker-compose-init.sh"

        if not os.path.exists(init_script):
            print(f"[!] Registration script not found: {init_script}", file=sys.stderr)
            return False

        print("[*] Starting registration process...")
        print("[*] Running: sudo /usr/local/bin/docker-compose-init.sh")
        print("-" * 70)

        try:
            result = subprocess.run(
                ["sudo", init_script], capture_output=False, text=True
            )

            if result.returncode == 0:
                print("\n" + "=" * 70)
                print("[+] Registration completed successfully!")
                print("=" * 70)
                return True
            else:
                print(
                    f"\n[!] Registration script exited with code: {result.returncode}"
                )
                return False

        except Exception as e:
            print(f"[!] Error running registration script: {e}", file=sys.stderr)
            return False

    def verify_registration(self):
        """Verify registration by checking Docker containers"""
        print("\n[*] Verifying registration...")

        try:
            # Check if containers are running
            result = subprocess.run(
                ["docker", "ps", "--format", "table {{.Names}}\t{{.Status}}"],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                print("\nDocker Containers:")
                print(result.stdout)

            # Check Docker Compose status
            result = subprocess.run(
                [
                    "docker",
                    "compose",
                    "-f",
                    "/etc/docker-compose/docker-compose.yaml",
                    "ps",
                ],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                print("\nDocker Compose Services:")
                print(result.stdout)

        except Exception as e:
            print(f"[*] Could not verify: {e}")

        print("\n[*] To view logs, run:")
        print("    docker compose -f /etc/docker-compose/docker-compose.yaml logs -f")


def cleanup_registration():
    """Clean up all registration data and return to pristine state"""
    from datetime import datetime

    print("=" * 70)
    print("Cisco XDR Remote Appliance - Registration Cleanup")
    print("=" * 70)
    print()

    print("[*] This will clean up:")
    print("    - All XDR Docker containers")
    print("    - Configuration files in /etc/ao-remote/")
    print("    - Extracted certificate files")
    print()

    # Step 1: Stop and remove containers
    print("[1/3] Stopping and removing XDR containers...")
    try:
        result = subprocess.run(
            ["docker", "ps", "-q", "-f", "name=xdr-automation"],
            capture_output=True,
            text=True,
        )

        if result.stdout.strip():
            subprocess.run(
                [
                    "docker",
                    "compose",
                    "-f",
                    "/etc/docker-compose/docker-compose.yaml",
                    "down",
                ],
                check=False,
                capture_output=True,
            )
            print("[+] Docker containers stopped and removed")
        else:
            print("[*] No XDR containers found (already clean)")
    except Exception as e:
        print(f"[!] Warning: {e}")

    # Step 2: Remove config files
    print("[2/3] Removing configuration files...")
    config_dir = Path("/etc/ao-remote")
    if config_dir.exists():
        # Create backup
        backup_dir = Path(
            f"/tmp/ao-remote-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        )
        backup_dir.mkdir(parents=True, exist_ok=True)

        try:
            subprocess.run(
                ["cp", "-r", str(config_dir) + "/", str(backup_dir) + "/"],
                check=False,
                capture_output=True,
            )
            print(f"[+] Backup created at: {backup_dir}")
        except:
            pass

        # Remove files
        for file in ["values.yaml", "ca-key-pair.yaml", "ca-key-pair.yaml.backup"]:
            file_path = config_dir / file
            if file_path.exists():
                file_path.unlink()

        # Remove directory if empty
        if not list(config_dir.iterdir()):
            config_dir.rmdir()
            print("[+] Removed /etc/ao-remote/ directory")
    else:
        print("[*] /etc/ao-remote/ not found (already clean)")

    # Step 3: Remove certificate files
    print("[3/3] Removing extracted certificate files...")
    cert_dir = Path("/etc/docker-compose/secrets/ao-remote")
    if cert_dir.exists():
        subprocess.run(["rm", "-rf", str(cert_dir)], check=False, capture_output=True)
        print("[+] Removed certificate directory")
    else:
        print("[*] Certificate directory not found (already clean)")

    print()
    print("=" * 70)
    print("[+] Cleanup completed successfully!")
    print("=" * 70)
    print()
    print("[*] The appliance is now in a clean state")
    print("[*] Ready for re-registration")


def read_config_file(file_path):
    """Read base64 string from file, handling compressed formats"""
    try:
        path = Path(file_path)

        # Handle stdin
        if file_path == "-":
            print("[*] Reading configuration from stdin...")
            content = sys.stdin.read().strip()
            return content

        # Check if file exists
        if not path.exists():
            print(f"[!] File not found: {file_path}", file=sys.stderr)
            return None

        # Handle gzipped files
        if file_path.endswith(".gz"):
            print(f"[*] Reading gzipped configuration from {file_path}...")
            with gzip.open(file_path, "rt") as f:
                content = f.read().strip()
            return content

        # Handle zip files
        if file_path.endswith(".zip"):
            print(f"[*] Reading zipped configuration from {file_path}...")
            with zipfile.ZipFile(file_path, "r") as z:
                # Get first file in zip
                names = z.namelist()
                if not names:
                    print("[!] Zip file is empty", file=sys.stderr)
                    return None
                with z.open(names[0]) as f:
                    content = f.read().decode("utf-8").strip()
            return content

        # Handle plain text files
        print(f"[*] Reading configuration from {file_path}...")
        with open(file_path, "r") as f:
            content = f.read().strip()
        return content

    except Exception as e:
        print(f"[!] Error reading file: {e}", file=sys.stderr)
        return None


def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description="Cisco XDR Remote Appliance Registration & Cleanup Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Registration Examples:
  # Register from plain text config file
  sudo python3 register_remote.py myRemote_config.txt

  # Register from gzipped config file
  sudo python3 register_remote.py myRemote_config.txt.gz

  # Register from zipped config file
  sudo python3 register_remote.py myRemote_config.zip

  # Register from stdin
  cat myRemote_config.txt | sudo python3 register_remote.py -

  # Register with base64 string directly
  sudo python3 register_remote.py "I2Nsb3VkLWNvbmZpZwo..."

Cleanup Example:
  # De-register and clean up artifacts
  sudo python3 register_remote.py --cleanup

Config File Format:
  The config file should contain a single line with the base64-encoded
  cloud-config string obtained from Cisco XDR/Workflows dashboard when creating
  a new remote appliance.

Notes:
  - This script must be run as root (use sudo)
  - Automatically cleans up existing registrations during re-registration
  - Automatically enables IPv4 forwarding if needed
  - No interactive prompts - suitable for automation
  - Validates all three certificates before proceeding
        """,
    )

    parser.add_argument(
        "config",
        nargs="?",
        help='Config file path (plain text, .gz, or .zip), "-" for stdin, or base64 string',
    )

    parser.add_argument(
        "--cleanup", action="store_true", help="Clean up existing registration and exit"
    )

    parser.add_argument("-v", "--version", action="version", version="%(prog)s v1.4")

    args = parser.parse_args()

    # Check if running as root
    if os.geteuid() != 0:
        print("[!] This script must be run as root (use sudo)", file=sys.stderr)
        sys.exit(1)

    # Handle cleanup mode
    if args.cleanup:
        cleanup_registration()
        sys.exit(0)

    # Require config for registration
    if not args.config:
        parser.print_help()
        print(
            "\n[!] Error: config file path is required for registration",
            file=sys.stderr,
        )
        sys.exit(1)

    print("=" * 70)
    print("Cisco XDR Remote Appliance Registration - v1.4")
    print("=" * 70)
    print()

    # Get base64 string from file or argument
    base64_string = None

    # Check if it's a file path or direct base64 string
    if (
        args.config == "-"
        or Path(args.config).exists()
        or args.config.endswith((".gz", ".zip"))
    ):
        # It's a file (or stdin)
        base64_string = read_config_file(args.config)
    else:
        # Assume it's a direct base64 string (legacy support)
        print("[*] Using base64 string from command line argument")
        base64_string = args.config.strip()

    if not base64_string:
        print("[!] No configuration data provided", file=sys.stderr)
        sys.exit(1)

    # Create registrator instance
    registrator = LocalXDRRegistration(base64_string)

    # Step 1: Decode OVF string
    if not registrator.decode_ovf_string():
        sys.exit(1)

    # Step 2: Extract YAML files
    if not registrator.extract_yaml_files():
        sys.exit(1)

    # Step 3: Display configuration
    registrator.display_config_info()

    # Step 4: Check for existing registration (auto-cleanup)
    if not registrator.check_existing_registration():
        print("[!] Failed to clean up existing registration")
        sys.exit(1)

    # Step 5: Check IPv4 forwarding (auto-enable)
    registrator.check_ipv4_forwarding()

    # Step 6: Write configuration files
    if not registrator.write_config_files():
        sys.exit(1)

    # Step 7: Run registration
    if not registrator.run_registration():
        print("\n[!] Registration failed. Check the logs above for errors.")
        sys.exit(1)

    # Step 8: Verify registration
    registrator.verify_registration()

    print("\n[+] Registration process complete!")
    print("\n[*] Next steps:")
    print(
        "    - Monitor logs: docker compose -f /etc/docker-compose/docker-compose.yaml logs -f"
    )
    print("    - Check status: docker ps")
    print("    - Verify connection to MQTT broker in logs")


if __name__ == "__main__":
    main()
