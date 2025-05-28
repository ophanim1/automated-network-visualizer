import nmap
import socket
import requests
import os
from datetime import datetime
from netaddr import EUI, mac_unix_expanded
from scapy.all import ARP, Ether, srp, conf, get_if_list, get_if_addr

# Mapping of device keywords to draw.io shape IDs
DEVICE_ICONS = {
    'router': 'shape=mxgraph.cisco.routers.router;html=1;dashed=0;fillColor=#FAFAFA;strokeColor=#005073;strokeWidth=2;verticalLabelPosition=bottom;verticalAlign=top;align=center;',
    'switch': 'shape=mxgraph.cisco.switches.lan_switch;html=1;dashed=0;fillColor=#FAFAFA;strokeColor=#005073;strokeWidth=2;verticalLabelPosition=bottom;verticalAlign=top;align=center;',
    'windows': 'shape=mxgraph.basic.rect;rounded=1;whiteSpace=wrap;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;', # Default rectangle for now, could find a better PC icon later
    'linux': 'shape=mxgraph.basic.rect;rounded=1;whiteSpace=wrap;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;',
    'printer': 'shape=mxgraph.office.printers.printer;html=1;labelPosition=center;verticalLabelPosition=bottom;verticalAlign=top;align=center;overflow=hidden;',
    # Add more mappings as needed (e.g., 'mobile', 'server', 'camera', etc.)
    'unknown': 'shape=mxgraph.basic.rect;rounded=1;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;', # Default/unknown icon
    'default': 'shape=mxgraph.basic.rect;rounded=1;whiteSpace=wrap;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;'
}

def get_device_style(device):
    """Determine draw.io style based on device info"""
    # Prioritize known types or hostnames
    type_lower = device.get('type', '').lower()
    hostname_lower = device.get('hostname', '').lower()
    vendor_lower = device.get('vendor', '').lower()
    ip_addr = device.get('ip', '')

    if ip_addr.endswith('.1'): # Simple heuristic for router/gateway
         return DEVICE_ICONS.get('router', DEVICE_ICONS['default'])
    if 'switch' in type_lower or 'flexfabric' in hostname_lower or 'comware' in hostname_lower or 'switch' in vendor_lower:
        return DEVICE_ICONS.get('switch', DEVICE_ICONS['default'])
    if 'windows' in type_lower or 'windows' in hostname_lower:
        return DEVICE_ICONS.get('windows', DEVICE_ICONS['default'])
    if 'linux' in type_lower:
        return DEVICE_ICONS.get('linux', DEVICE_ICONS['default'])
    if 'printer' in type_lower or 'printer' in hostname_lower or 'printer' in vendor_lower:
         return DEVICE_ICONS.get('printer', DEVICE_ICONS['default'])
    # Fallback to unknown if type/hostname/vendor are not very descriptive
    if not type_lower and not hostname_lower and not vendor_lower: # Check if all are empty/unknown
         return DEVICE_ICONS.get('unknown', DEVICE_ICONS['default'])
    
    return DEVICE_ICONS.get('default', DEVICE_ICONS['default'])

def get_oui_vendor(mac):
    try:
        oui = EUI(mac)
        return oui.oui.registration().org
    except Exception:
        # Fallback to API if local lookup fails
        try:
            resp = requests.get(f'https://api.macvendors.com/{mac}', timeout=2)
            if resp.status_code == 200:
                return resp.text
        except Exception:
            pass
    return 'Unknown'

def get_interface_ip(interface_name):
    """Get IP address for a specific interface"""
    try:
        return get_if_addr(interface_name)
    except Exception as e:
        print(f"Error getting IP for interface {interface_name}: {e}")
        return None

def generate_drawio_diagram(devices, output_dir="diagrams"):
    """Generate a draw.io diagram from network scan results"""
    # Create diagrams directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"network_diagram_{timestamp}.drawio")
    
    # Start building the draw.io XML
    xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<mxfile host="app.diagrams.net" modified="{datetime.now().isoformat()}" agent="Network Visualizer" version="21.6.6" type="device">
  <diagram id="network" name="Network Diagram">
    <mxGraphModel dx="1422" dy="762" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="827" pageHeight="1169" math="0" shadow="0">
      <root>
        <mxCell id="0"/>
        <mxCell id="1" parent="0"/>
"""
    
    # Add devices to the diagram
    router_x = 350
    router_y = 50
    device_start_y = 250
    spacing_x = 250 # Horizontal spacing for devices
    spacing_y = 120 # Vertical spacing between rows of devices
    devices_per_row = 4 # Number of devices per row
    device_width = 200 # Increased width
    device_height = 120 # Increased height

    device_cells = {}
    router_id = None
    non_router_devices = []

    # First, add all devices as nodes and identify the router
    for i, device in enumerate(devices):
        device_ip = device.get('ip', '')
        if not device_ip:
            continue

        device_id = f"device_{i}"
        device_cells[device_ip] = device_id

        # Get device style/icon
        style = get_device_style(device)

        # Build label, filtering out empty parts and adding newline after IP
        device_label_parts = []
        if device_ip:
            device_label_parts.append(device_ip)
        
        other_details = [
            device.get('hostname', ''),
            device.get('vendor', ''),
            device.get('type', '')
        ]
        other_details = list(filter(None, other_details)) # Filter out empty strings

        # Join IP with a newline if there are other details, otherwise just the IP
        if other_details:
             # Use single newline character in XML value
             device_label = device_ip + '\n' + '\n'.join(other_details)
        else:
             device_label = device_ip

        # Check if this is the router based on IP heuristic
        if device_ip.endswith('.1'):
            router_id = device_id
            # Add router cell at the top position with smaller size
            router_width = 80
            router_height = 80
            xml_content += f"""
        <mxCell id="{router_id}" value="{device_label}" style="{style}" vertex="1" parent="1">
          <mxGeometry x="{router_x}" y="{router_y}" width="{router_width}" height="{router_height}" as="geometry"/>
        </mxCell>"""
        else:
            non_router_devices.append({'id': device_id, 'device': device, 'style': style, 'label': device_label})

    # Add non-router devices below the router
    for i, dev_info in enumerate(non_router_devices):
        row = i // devices_per_row
        col = i % devices_per_row

        x = 50 + (col * spacing_x)
        y = device_start_y + (row * spacing_y)

        xml_content += f"""
        <mxCell id="{dev_info['id']}" value="{dev_info['label']}" style="{dev_info['style']}" vertex="1" parent="1">
          <mxGeometry x="{x}" y="{y}" width="{device_width}" height="{device_height}" as="geometry"/>
        </mxCell>"""


    # Add connections (connecting all non-router devices to the router if found)
    if router_id:
        for dev_info in non_router_devices:
            # Add connection from device to router
            xml_content += f"""
        <mxCell id="edge_{dev_info['id']}_{router_id}" value="" style="endArrow=classic;html=1;strokeColor=#333333;" edge="1" parent="1" source="{dev_info['id']}" target="{router_id}">
          <mxGeometry width="50" height="50" relative="1" as="geometry"/>
        </mxCell>"""

    # Close the XML
    xml_content += """
      </root>
    </mxGraphModel>
  </diagram>
</mxfile>"""
    
    # Write the file
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(xml_content)
    
    print(f"\nNetwork diagram saved to: {filename}")
    print("You can open this file with draw.io (diagrams.net)")
    return filename

def scan_network(interface_name="Ethernet 3"):
    # Get local IP and subnet for specified interface
    conf.verb = 0
    print(f"Available interfaces: {get_if_list()}")
    
    # Get IP for specified interface
    ip = get_interface_ip(interface_name)
    if not ip:
        print(f"Could not get IP for interface {interface_name}, falling back to default...")
        ip = socket.gethostbyname(socket.gethostname())
    
    print(f"Using interface: {interface_name}")
    print(f"Local IP detected: {ip}")
    
    if ip.startswith('127.'):
        print("Got localhost IP, trying alternative method...")
        # fallback for some Windows configs
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            print(f"Alternative IP detection successful: {ip}")
        except Exception as e:
            print(f"Alternative IP detection failed: {e}")
        finally:
            s.close()
    
    subnet = ip.rsplit('.', 1)[0] + '.0/24'
    print(f"Scanning subnet: {subnet}")

    # ARP scan
    devices = []
    try:
        print("Starting ARP scan...")
        pkt = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=subnet)
        # Specify the interface for the scan
        ans, _ = srp(pkt, timeout=2, retry=1, iface=interface_name)
        print(f"ARP scan found {len(ans)} responses")
        
        for snd, rcv in ans:
            mac = rcv.sprintf('%Ether.src%')
            ip_addr = rcv.psrc
            vendor = get_oui_vendor(mac)
            print(f"Found device - IP: {ip_addr}, MAC: {mac}, Vendor: {vendor}")
            devices.append({
                'ip': ip_addr,
                'mac': mac,
                'vendor': vendor,
                'type': 'Unknown',
                'hostname': get_hostname(ip_addr)
            })
    except Exception as e:
        print(f'ARP scan error: {e}')

    # Nmap scan for open ports (optional, can be slow)
    try:
        print("Starting Nmap scan...")
        nm = nmap.PortScanner()
        for dev in devices:
            try:
                print(f"Scanning device {dev['ip']} with Nmap...")
                nm.scan(dev['ip'], arguments='-O')
                if dev['ip'] in nm.all_hosts():
                    osmatch = nm[dev['ip']].get('osmatch', [])
                    if osmatch:
                        dev['type'] = osmatch[0]['name']
                        print(f"Device {dev['ip']} identified as: {dev['type']}")
            except Exception as e:
                print(f"Nmap scan error for {dev['ip']}: {e}")
    except Exception as e:
        print(f'Nmap initialization error: {e}')

    print(f"Scan complete. Found {len(devices)} devices total.")
    
    # Generate diagram after scan
    diagram_file = None # Initialize diagram_file
    if devices:
        diagram_file = generate_drawio_diagram(devices)
        print(f"To view the diagram, open {diagram_file} in draw.io")
    
    return devices, diagram_file

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return '' 