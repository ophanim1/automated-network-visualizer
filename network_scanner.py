import nmap
import socket
import requests
import os
import xml.etree.ElementTree as ET
from datetime import datetime
from netaddr import EUI, mac_unix_expanded
from scapy.all import ARP, Ether, srp, conf, get_if_list, get_if_addr
from tqdm import tqdm
import threading
from queue import Queue

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

# Global progress tracking
scan_progress = {
    'current_stage': '',
    'progress': 0,
    'total_stages': 3,  # ARP scan, Nmap scan, Diagram generation
    'stage_progress': 0,
    'stage_total': 100
}

def update_progress(stage, progress, stage_progress=None, stage_total=None):
    """Update the global progress tracking"""
    global scan_progress
    scan_progress['current_stage'] = stage
    scan_progress['progress'] = progress
    if stage_progress is not None:
        scan_progress['stage_progress'] = stage_progress
    if stage_total is not None:
        scan_progress['stage_total'] = stage_total

def get_device_style(device):
    """Determine draw.io style based on device info"""
    # Prioritize known types or hostnames
    # type_lower = device.get('type', '').lower()
    # hostname_lower = device.get('hostname', '').lower()
    # vendor_lower = device.get('vendor', '').lower()
    # ip_addr = device.get('ip', '')

    # if ip_addr.endswith('.1'): # Simple heuristic for router/gateway
    #      return DEVICE_ICONS.get('router', DEVICE_ICONS['default'])
    # if 'switch' in type_lower or 'flexfabric' in hostname_lower or 'comware' in hostname_lower or 'switch' in vendor_lower:
    #     return DEVICE_ICONS.get('switch', DEVICE_ICONS['default'])
    # if 'windows' in type_lower or 'windows' in hostname_lower:
    #     return DEVICE_ICONS.get('windows', DEVICE_ICONS['default'])
    # if 'linux' in type_lower:
    #     return DEVICE_ICONS.get('linux', DEVICE_ICONS['default'])
    # if 'printer' in type_lower or 'printer' in hostname_lower or 'printer' in vendor_lower:
    #      return DEVICE_ICONS.get('printer', DEVICE_ICONS['default'])
    # # Fallback to unknown if type/hostname/vendor are not very descriptive
    # if not type_lower and not hostname_lower and not vendor_lower: # Check if all are empty/unknown
    #      return DEVICE_ICONS.get('unknown', DEVICE_ICONS['default'])

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

def validate_xml(xml_content):
    """Validate XML content before writing to file"""
    try:
        # Try parsing the XML
        ET.fromstring(xml_content)
        return True
    except ET.ParseError as e:
        print(f"XML validation error: {e}")
        return False

def generate_drawio_diagram(devices, output_dir="diagrams"):
    """Generate a draw.io diagram from network scan results"""
    # Progress is now handled in scan_network()
    
    # Create diagrams directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"network_diagram_{timestamp}.drawio")
    
    try:
        # Start building the draw.io XML
        xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<mxfile host="app.diagrams.net" modified="{datetime.now().isoformat()}" agent="Network Visualizer" version="21.6.6" type="device">
  <diagram id="network" name="Network Diagram">
    <mxGraphModel dx="1422" dy="762" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="827" pageHeight="1169" math="0" shadow="0">
      <root>
        <mxCell id="0"/>
        <mxCell id="1" parent="0"/>
"""
        
        # Add devices to the diagram with progress tracking
        router_x = 350
        router_y = 50
        # device_start_y = 250
        # spacing_x = 250
        # spacing_y = 120
        # devices_per_row = 4
        device_width = 200
        device_height = 120

        device_cells = {}
        main_router_id = None # Renamed router_id to main_router_id for clarity

        # Categorize devices
        categorized_devices = {
            'Routers': [],
            'Servers': [],
            'Workstations': [],
            'Switches': [],
            'Printers': [],
            'Phones': [],
            'Unknown': []
        }

        # More specific and prioritized keywords for categorization
        device_category_map = {
            'router': 'Routers',
            'gateway': 'Routers',
            'switch': 'Switches',
            'flexfabric': 'Switches',
            'comware': 'Switches',
            'wireless': 'Switches', # Often access points are categorized with switches
            'ap': 'Switches', # Access Points
            'wlan': 'Switches',
            'server': 'Servers',
            'nas': 'Servers', # Classifying NAS as servers as they provide file services
            'storage': 'Servers', # Classifying storage devices as servers
            'windows': 'Workstations',
            'linux': 'Workstations', # Assuming most Linux devices are workstations for now
            'mac': 'Workstations', # Assuming most Mac devices are workstations for now
            'printer': 'Printers',
            'phone': 'Phones',
            'mobile': 'Phones' # Group mobile devices with phones
        }

        # First, add all devices as nodes and identify the main router
        for i, device in enumerate(devices):
            # Update diagram generation progress (66-100% of total)
            progress = 66 + int((i + 1) / len(devices) * 34)
            update_progress('Generating diagram', progress, i + 1, len(devices))

            device_ip = device.get('ip', '')
            if not device_ip:
                continue

            device_id = f"device_{i}"
            device_cells[device_ip] = device_id
            style = get_device_style(device) # Using default style for now

            # Build label with proper XML escaping
            device_label_parts = []
            if device_ip:
                device_label_parts.append(device_ip)

            other_details = [
                device.get('hostname', ''),
                device.get('vendor', ''),
                device.get('type', '')
            ]
            other_details = [detail for detail in other_details if detail]

            # Properly escape XML special characters
            device_label = device_ip
            if other_details:
                device_label += '\n' + '\n'.join(other_details)
            device_label = device_label.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

            # Determine device category based on prioritized keywords
            assigned_category = 'Unknown'
            device_info_lower = (device.get('type', '') + device.get('hostname', '') + device.get('vendor', '')).lower()

            # Check for specific keywords in order of likely specificity/importance
            for keyword, category in device_category_map.items():
                if keyword in device_info_lower:
                    assigned_category = category
                    break # Assign to the first matching category

            # Special handling for the main router (device ending in .1)
            if device_ip.endswith('.1'):
                assigned_category = 'Routers' # Ensure .1 is always a router
                if main_router_id is None: # Identify the first router as the main one
                    main_router_id = device_id
                    router_width = 80
                    router_height = 80
                    # Add main router cell directly, not in a group
                    xml_content += f"""
        <mxCell id="{main_router_id}" value="{device_label}" style="{style}" vertex="1" parent="1">
          <mxGeometry x="{router_x}" y="{router_y}" width="{router_width}" height="{router_height}" as="geometry"/>
        </mxCell>"""
                else:
                    # Add other routers to the Routers category list
                    categorized_devices['Routers'].append({'id': device_id, 'device': device, 'style': style, 'label': device_label, 'category': assigned_category})
            else:
                 # Add non-.1 devices to their determined category
                 categorized_devices[assigned_category].append({'id': device_id, 'device': device, 'style': style, 'label': device_label, 'category': assigned_category})

        # Add groups and devices to the diagram
        group_start_x = 50
        group_y = 250 # Starting Y position for groups
        group_spacing_x = 50 # Spacing between groups horizontally
        device_spacing_x = 220
        device_spacing_y = 150
        devices_per_row = 3

        current_group_x = group_start_x

        for category, devices_in_category in categorized_devices.items():
            if not devices_in_category or category == 'Routers': # Skip empty categories and the Routers category here, they are handled separately
                continue

            group_id = f"group_{category.lower().replace(' ', '_')}"
            # Calculate group size and position
            num_rows = (len(devices_in_category) + devices_per_row - 1) // devices_per_row # Ceiling division
            group_width = max(devices_per_row * device_spacing_x + 40, device_width + 40) # Add padding
            group_height = num_rows * device_spacing_y + 80 # Add padding for title and bottom space
            group_x = current_group_x

            # Add group cell
            xml_content += f"""
        <mxCell id="{group_id}" value="{category}" style="swimlane;html=1;fontStyle=1;align=center;verticalAlign=middle;startSize=30;fillColor=#e0e0e0;strokeColor=#808080;" vertex="1" parent="1">
          <mxGeometry x="{group_x}" y="{group_y}" width="{group_width}" height="{group_height}" as="geometry"/>
        </mxCell>"""

            # Add devices within the group
            for i, dev_info in enumerate(devices_in_category):
                row = i // devices_per_row
                col = i % devices_per_row
                device_x = 20 + (col * device_spacing_x) # Offset within group
                device_y = 40 + (row * device_spacing_y) # Offset within group

                xml_content += f"""
        <mxCell id="{dev_info['id']}" value="{dev_info['label']}" style="{dev_info['style']}" vertex="1" parent="{group_id}">
          <mxGeometry x="{device_x}" y="{device_y}" width="{device_width}" height="{device_height}" as="geometry"/>
        </mxCell>"""

            # Update X position for the next group
            current_group_x += group_width + group_spacing_x

            # Add connection from group to main router
            if main_router_id:
                 xml_content += f"""
        <mxCell id="edge_{group_id}_{main_router_id}" value="" style="endArrow=classic;html=1;strokeColor=#333333;" edge="1" parent="1" source="{group_id}" target="{main_router_id}">
          <mxGeometry width="50" height="50" relative="1" as="geometry"/>
        </mxCell>"""

        # Add the Routers group separately below the main router if there are other routers
        if categorized_devices['Routers'] and main_router_id:
            router_group_id = "group_routers"
            # Calculate group size and position for the Routers group
            num_routers_in_group = len(categorized_devices['Routers'])
            router_group_width = max((num_routers_in_group * device_spacing_x) + 40, device_width + 40)
            router_group_height = device_spacing_y + 80 # Assuming routers in one row for simplicity
            router_group_x = 50 # Position below the main router, aligned left
            router_group_y = router_y + router_height + 50 # Position below the main router with some spacing

            # Add Routers group cell
            xml_content += f"""
        <mxCell id="{router_group_id}" value="Other Routers" style="swimlane;html=1;fontStyle=1;align=center;verticalAlign=middle;startSize=30;fillColor=#e0e0e0;strokeColor=#808080;" vertex="1" parent="1">
          <mxGeometry x="{router_group_x}" y="{router_group_y}" width="{router_group_width}" height="{router_group_height}" as="geometry"/>
        </mxCell>"""

            # Add other routers within the Routers group
            for i, dev_info in enumerate(categorized_devices['Routers']):
                 device_x = 20 + (i * device_spacing_x) # Horizontal offset within group
                 device_y = 40 # Vertical offset within group

                 xml_content += f"""
        <mxCell id="{dev_info['id']}" value="{dev_info['label']}" style="{dev_info['style']}" vertex="1" parent="{router_group_id}">
          <mxGeometry x="{device_x}" y="{device_y}" width="{device_width}" height="{device_height}" as="geometry"/>
        </mxCell>"""

            # Add connection from Routers group to main router
            xml_content += f"""
        <mxCell id="edge_{router_group_id}_{main_router_id}" value="" style="endArrow=classic;html=1;strokeColor=#333333;" edge="1" parent="1" source="{router_group_id}" target="{main_router_id}">
          <mxGeometry width="50" height="50" relative="1" as="geometry"/>
        </mxCell>"""

        # Close the XML
        xml_content += """
      </root>
    </mxGraphModel>
  </diagram>
</mxfile>"""
        
        # Validate XML before writing
        if not validate_xml(xml_content):
            raise ValueError("Generated XML is invalid")
        
        # Write the file
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(xml_content)
        
        print(f"\nNetwork diagram saved to: {filename}")
        return filename
        
    except Exception as e:
        print(f"Error generating diagram: {e}")
        return None

def scan_device_nmap(ip, nm, results_queue):
    """Scan a single device with Nmap"""
    try:
        # Use -sS (TCP SYN scan) for port scanning along with OS detection
        # -T4 for timing template, -F for fast scan of common ports
        nm.scan(ip, arguments='-sS -O -T4 -F')
        if ip in nm.all_hosts():
            osmatch = nm[ip].get('osmatch', [])
            if osmatch:
                results_queue.put((ip, osmatch[0]['name']))
    except Exception as e:
        print(f"Nmap scan error for {ip}: {e}")

def scan_network(interface_name="Ethernet 3"):
    """Scan the network with progress tracking"""
    global scan_progress
    scan_progress = {
        'current_stage': 'Initializing',
        'progress': 0,
        'total_stages': 3,  # ARP scan, Nmap scan, Diagram generation
        'stage_progress': 0,
        'stage_total': 100
    }
    
    # Get local IP and subnet for specified interface
    conf.verb = 0
    print(f"Available interfaces: {get_if_list()}")
    
    update_progress('Initializing', 0, 0, 100)
    
    # Get IP for specified interface
    ip = get_interface_ip(interface_name)
    if not ip:
        print(f"Could not get IP for interface {interface_name}, falling back to default...")
        ip = socket.gethostbyname(socket.gethostname())
    
    print(f"Using interface: {interface_name}")
    print(f"Local IP detected: {ip}")
    
    if ip.startswith('127.'):
        print("Got localhost IP, trying alternative method...")
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

    # ARP scan with progress tracking
    devices = []
    update_progress('ARP Scan', 0, 0, 100)
    
    try:
        print("Starting ARP scan...")
        pkt = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=subnet)
        ans, _ = srp(pkt, timeout=2, retry=1, iface=interface_name)
        print(f"ARP scan found {len(ans)} responses")
        
        for i, (snd, rcv) in enumerate(ans):
            # Update ARP scan progress (0-33% of total)
            progress = int((i + 1) / len(ans) * 33) if ans else 33
            update_progress('ARP Scan', progress, i + 1, len(ans))
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

    # Nmap scan with parallel processing and progress tracking
    if devices:
        update_progress('Nmap Scan', 33, 0, len(devices))
        print("Starting Nmap scan...")
        
        nm = nmap.PortScanner()
        results_queue = Queue()
        threads = []
        completed_scans = 0
        
        # Start Nmap scans in parallel
        for device in devices:
            thread = threading.Thread(
                target=scan_device_nmap,
                args=(device['ip'], nm, results_queue)
            )
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete and update progress
        for i, thread in enumerate(threads):
            thread.join()
            completed_scans += 1
            # Update Nmap scan progress (33-66% of total)
            progress = 33 + int((completed_scans / len(devices)) * 33)
            update_progress('Nmap Scan', progress, completed_scans, len(devices))
        
        # Process results
        while not results_queue.empty():
            ip, os_type = results_queue.get()
            for device in devices:
                if device['ip'] == ip:
                    device['type'] = os_type
                    print(f"Device {ip} identified as: {os_type}")

    print(f"Scan complete. Found {len(devices)} devices total.")
    
    # Generate diagram after scan
    diagram_file = None
    if devices:
        # Start diagram generation at 66%
        update_progress('Generating diagram', 66, 0, len(devices))
        diagram_file = generate_drawio_diagram(devices)
        if diagram_file:
            # Complete at 100%
            update_progress('Complete', 100, len(devices), len(devices))
            print(f"To view the diagram, open {diagram_file} in draw.io")
    
    return devices, diagram_file

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return '' 