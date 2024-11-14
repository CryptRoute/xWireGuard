### xWireGuard Server Installer

This script automates the installation and configuration of a WireGuard VPN server, WGDashboard, and related dependencies on a Linux system. It is designed to work on Ubuntu (20.10, 20.04, 22.04) and Debian 11, providing users with an interactive and fully configured WireGuard VPN server and management dashboard.

#### Features

- **Automated Installation**: Installs and configures WireGuard, WGDashboard, and other necessary packages.
- **Interactive Setup**: Guides the user through the setup, asking for hostname, username, passwords, and preferred network configuration options.
- **IPv4/IPv6 Configuration**: Supports generation and configuration of both IPv4 and IPv6 addresses.
- **Firewall Configuration**: Sets up UFW rules for WireGuard, dashboard, and SSH access.
- **Automatic Service Management**: Configures WireGuard and dashboard services to run on boot, with monitoring for config changes.
- **IPv6 Support**: Detects and configures IPv6 if available.

#### Requirements

- Supported OS: **Ubuntu 20.10/20.04/22.04 or Debian 11**
- Network Access: Requires internet access to download dependencies.
- User Privileges: Must be run as **root** or with **sudo**.

### Usage

1. **Download the Script**: Clone the repository or download the script file.

   ```bash
   apt update && apt install git -y && git clone https://github.com/cryptroute/xwireguard.git && cd xwireguard
   ```

2. **Make the Script Executable**:

   ```bash
   chmod +x install.sh
   ```

3. **Run the Script**:

   ```bash
   sudo ./install.sh
   ```

4. **Follow the Prompts**: The script will guide you through several prompts to set up the configuration, such as:
   - Hostname
   - Dashboard username and password
   - DNS and port configurations
   - IPv4/IPv6 preferences

### Script Highlights

- **Interface Detection**: Automatically detects the default network interface for configuration.
- **IP Range Selection**: Allows users to select IP ranges for private networks or specify custom ranges.
- **Service and Firewall Setup**: Configures UFW rules and sets up WireGuard to start at boot.
- **Monitoring**: Sets up monitoring scripts to detect changes in WireGuard configuration, applying changes as needed.
- **WGDashboard Installation**: Downloads and installs WGDashboard, a web-based management tool, for easy configuration of WireGuard peers and settings.
- **Crontab Monitoring**: Adds cron jobs to monitor the WireGuard configuration and ensure consistent service.

### Post-Installation

After installation, you can access the WGDashboard interface using the provided IP and port. The dashboard provides management capabilities for WireGuard, including creating and managing peers.

1. **Access Dashboard**: 
   - **URL**: `http://<server_ip>:<dashboard_port>`
   - **Username**: The username provided during installation
   - **Password**: The password specified during installation

2. **Reboot**: The system will automatically reboot after successful installation. You can begin creating WireGuard peers once it’s back up.

### Troubleshooting

- **Failed Services**: If services fail to start, the script provides feedback on the status. Check `systemctl` logs for more details.
- **Firewall Rules**: The script attempts to configure UFW automatically, but ensure your network allows the necessary ports.
- **Re-run Installation**: If you encounter issues, consider re-running the script as root to ensure permissions are not a problem.

### License

This project is licensed under the MIT License.
