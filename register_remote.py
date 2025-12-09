#!/usr/bin/env python3
"""
Cisco XDR/Workflows Remote Appliance Local Registration Script
v1.1 - 10-Oct-2025 - fixed input string corruption issue causing registration to not occur.
v1.0 - 07-Oct-2025 - initial release
Author: Steve Holl [sholl@cisco.com]

This script registers a Cisco XDR/Workflows Remote Appliance by:
1. Prompting for the base64 OVF user-data string
2. Extracting values.yaml and ca-key-pair.yaml from cloud-config
3. Checking for existing containers and offering to clean up
4. Checking IPv4 forwarding and offering to enable it
5. Writing configuration files to /etc/ao-remote/
6. Running the docker-compose-init.sh script
7. Verifying registration and container status

Features:
- Handles base64 padding issues automatically
- Detects certificate data in files with empty paths
- Normalizes YAML structure for compatibility
- Checks and enables IPv4 forwarding for Docker networking
- Detects existing registrations and offers clean re-registration
- Fully repeatable for lab environments without needing
  the user encoded-data into the OVF, which some virtualization
  environments don't support

Usage (run directly on the appliance):
    sudo python3 register-local.py

Or non-interactive:
    sudo python3 register-local.py <base64_string>
"""

import base64
import os
import subprocess
import sys
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
        """Ensure ca-key-pair.yaml has the correct structure for extract_yaml.py"""
        if not self.ca_key_pair_yaml:
            return ""

        try:
            ca_data = yaml.safe_load(self.ca_key_pair_yaml)

            # Debug: Show what keys we have in the raw data
            print(f"[*] Raw certificate data keys: {list(ca_data.keys())}")

            # Check if it already has the expected structure (data.tls.crt, etc.)
            if "data" in ca_data and "tls.crt" in ca_data["data"]:
                # Already in correct format
                return self.ca_key_pair_yaml

            # If it has the flat structure (ca.crt, tls.key, tls.crt at top level)
            # Transform it to the expected nested structure
            if "ca.crt" in ca_data or "tls.crt" in ca_data or "tls.key" in ca_data:
                normalized = {
                    "data": {
                        "ca.crt": ca_data.get("ca.crt", ""),
                        "tls.crt": ca_data.get("tls.crt", ""),
                        "tls.key": ca_data.get("tls.key", ""),
                    }
                }

                # Debug: Show what we're including
                for key in ["ca.crt", "tls.crt", "tls.key"]:
                    if key in ca_data:
                        print(f"[*]   {key}: present ({len(ca_data[key])} chars)")
                    else:
                        print(f"[!]   {key}: MISSING from source data")

                print("[*] Normalized ca-key-pair.yaml structure to expected format")
                # Use width parameter to prevent line wrapping of long base64 strings
                return yaml.dump(
                    normalized, default_flow_style=False, width=float("inf")
                )

            # Return as-is if we can't determine the structure
            return self.ca_key_pair_yaml

        except Exception as e:
            print(f"[!] Warning: Could not normalize ca-key-pair.yaml: {e}")
            return self.ca_key_pair_yaml if self.ca_key_pair_yaml else ""

    def write_config_files(self):
        """Write YAML files to /etc/ao-remote/"""
        print("[*] Writing configuration files to /etc/ao-remote/...")

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
            ca_key_pair_path = target_dir / "ca-key-pair.yaml"
            with open(ca_key_pair_path, "w") as f:
                f.write(normalized_ca_key_pair)
            os.chmod(ca_key_pair_path, 0o600)
            print(f"[+] Written: {ca_key_pair_path}")

            print("[+] Configuration files written successfully\n")
            return True

        except PermissionError:
            print("[!] Permission denied. Please run with sudo", file=sys.stderr)
            return False
        except Exception as e:
            print(f"[!] Error writing files: {e}", file=sys.stderr)
            return False

    def check_existing_registration(self):
        """Check if containers are already running and offer to clean up"""
        try:
            result = subprocess.run(
                ["docker", "ps", "-q", "-f", "name=xdr-automation"],
                capture_output=True,
                text=True,
            )

            if result.stdout.strip():
                print("\n[!] Existing XDR containers are already running")
                print(
                    "[*] Would you like to stop and remove them before re-registering? (yes/no)"
                )
                response = input("> ").strip().lower()

                if response in ["yes", "y"]:
                    print("[*] Stopping containers...")
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
                    print("[+] Containers stopped and removed")
                    return True
                else:
                    print(
                        "[!] Warning: Registration may fail with existing containers running"
                    )
                    print("[*] Continue anyway? (yes/no)")
                    response = input("> ").strip().lower()
                    return response in ["yes", "y"]

            return True

        except Exception as e:
            print(f"[!] Could not check for existing containers: {e}")
            return True  # Don't block registration

    def check_ipv4_forwarding(self):
        """Check if IPv4 forwarding is enabled and offer to enable it"""
        try:
            result = subprocess.run(
                ["sysctl", "net.ipv4.ip_forward"], capture_output=True, text=True
            )

            if "net.ipv4.ip_forward = 0" in result.stdout:
                print("\n[!] IPv4 forwarding is currently disabled")
                print("[*] Docker containers require IPv4 forwarding for networking")
                print("\nWould you like to enable IPv4 forwarding now? (yes/no)")
                response = input("> ").strip().lower()

                if response in ["yes", "y"]:
                    # Enable immediately
                    subprocess.run(
                        ["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], check=True
                    )

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
                    print("[!] Warning: Containers may not have network connectivity")
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


def get_base64_input():
    """Prompt user for base64 string"""
    print("=" * 70)
    print("Cisco XDR Remote Appliance Registration")
    print("=" * 70)
    print("\nPlease paste the base64 OVF user-data string.")
    print("(It should be a long string starting with 'I2Nsb3VkLWNvbmZpZwo...')")
    print("\nPaste the string and press Enter:")

    base64_string = input("> ").strip()

    if not base64_string:
        print("[!] No input provided", file=sys.stderr)
        return None

    return base64_string


def main():
    # Check if running as root
    if os.geteuid() != 0:
        print("[!] This script must be run as root (use sudo)", file=sys.stderr)
        sys.exit(1)

    # Get base64 string from command line or prompt
    if len(sys.argv) > 1:
        base64_string = sys.argv[1].strip()
        print("[*] Using base64 string from command line argument")
    else:
        base64_string = get_base64_input()
        if not base64_string:
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

    # Step 4: Check for existing registration
    if not registrator.check_existing_registration():
        print("[*] Registration cancelled")
        sys.exit(0)

    # Step 5: Check IPv4 forwarding
    registrator.check_ipv4_forwarding()

    # Step 6: Confirm before proceeding
    print("\nDo you want to proceed with registration? (yes/no)")
    confirm = input("> ").strip().lower()

    if confirm not in ["yes", "y"]:
        print("[*] Registration cancelled")
        sys.exit(0)

    # Step 7: Write configuration files
    if not registrator.write_config_files():
        sys.exit(1)

    # Step 8: Run registration
    if not registrator.run_registration():
        print("\n[!] Registration failed. Check the logs above for errors.")
        sys.exit(1)

    # Step 9: Verify registration
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
