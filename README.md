# Automated Network Visualizer

This tool scans your local network, identifies connected devices (brand, type, etc.), and visualizes the network topology in your browser via a webserver hosted on `localhost`. It's particularly useful for network administrators and IT professionals who need to quickly understand their network topology.

> **Note: This is a proof of concept project.** While functional, it's primarily intended to demonstrate the concept of automated network visualization and device discovery. The code is provided as-is, with no guarantees of production readiness or ongoing support.

## Features
- Automatic network scanning (finds all devices on your subnet)
- Identifies device manufacturer and type (where possible)
- Attempts to infer network topology
- Interactive visualization in your browser (using vis.js)
- Support for selecting specific network interfaces
- Real-time network device discovery
- Device categorization and grouping
- Exportable network diagrams

## Requirements
- Python 3.8+
- Windows OS
- Administrator privileges (for full network scanning capabilities)
- Required Python packages (install with `pip install -r requirements.txt`):
  - Flask
  - scapy
  - python-nmap
  - netifaces
  - requests

## Installation
1. Clone this repository:
   ```sh
   git clone https://github.com/yourusername/automated-network-visualizer.git
   cd automated-network-visualizer
   ```

2. Create and activate a virtual environment (recommended):
   ```sh
   python -m venv venv
   .\venv\Scripts\activate
   ```

3. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```

## Usage
1. Run the main script as Administrator:
   ```sh
   # Right-click PowerShell/Command Prompt and select "Run as Administrator"
   python main.py
   ```

2. When prompted, select your network interface:
   - The program will display a list of available network interfaces
   - Choose the interface connected to the network you want to scan
   - For USB Ethernet adapters, look for the interface name containing "USB" or your adapter's name

3. Open your browser and go to [http://localhost:5000](http://localhost:5000)

## Network Interface Selection
- The tool will automatically detect all available network interfaces
- Choose the interface that corresponds to your active network connection
- For USB Ethernet adapters, ensure you select the correct interface
- Virtual interfaces (like VirtualBox adapters) should be avoided unless specifically needed

## Troubleshooting
1. **No devices found:**
   - Ensure you're running as Administrator
   - Check if your firewall is blocking the scan
   - Verify you've selected the correct network interface
   - Confirm your network connection is active

2. **Interface selection issues:**
   - If you don't see your USB Ethernet adapter, try:
     - Reconnecting the adapter
     - Updating the adapter drivers
     - Checking Device Manager for any issues

3. **Visualization problems:**
   - Clear your browser cache
   - Try a different browser
   - Check the console for any JavaScript errors

## Project Structure
```
automated-network-visualizer/
├── main.py              # Main application entry point
├── network_scanner.py   # Network scanning and device discovery
├── requirements.txt     # Python dependencies
├── templates/          # Web interface templates
└── diagrams/          # Generated network diagrams (git-ignored)
```

## Contributing
Feel free to submit issues and enhancement requests!

## License
This project is released under the MIT License, which means:

- You are free to use, modify, distribute, and commercialize this software
- You can use it for any purpose, including commercial applications
- You can modify it to suit your needs
- You can distribute your modified versions
- You can use it in your own projects without attribution (though attribution is appreciated)

The only requirement is that the original license and copyright notice must be included in any substantial portions of the software.

In short: Do whatever you want with it! 🚀

## Notes
- SNMP-based topology inference is limited on most home networks
- For best results, ensure your firewall allows local Python scripts to scan the network
- The tool works best on Windows networks with standard network configurations
- Generated diagrams are stored in the `diagrams/` directory 