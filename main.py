import os
import json
import threading
import webbrowser
from flask import Flask, render_template, jsonify, request, send_file
from network_scanner import scan_network, generate_drawio_diagram, scan_progress

app = Flask(__name__)

# Store scan results and latest diagram in memory
scan_results = []
latest_diagram = None
is_scanning = False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan')
def api_scan():
    global scan_results, is_scanning
    return jsonify({
        "devices": list(scan_results),
        "is_scanning": is_scanning
    })

@app.route('/api/scan-status')
def scan_status():
    """Get the current scan status and progress"""
    global is_scanning
    return jsonify({
        "is_scanning": is_scanning,
        "progress": scan_progress
    })

@app.route('/api/rescan', methods=['POST'])
def rescan():
    global scan_results, latest_diagram, is_scanning
    
    if is_scanning:
        return jsonify({"status": "error", "message": "Scan already in progress"})
    
    is_scanning = True
    try:
        devices, diagram_file = scan_network()
        scan_results = devices
        latest_diagram = diagram_file
        return jsonify({
            "status": "success",
            "devices": len(scan_results),
            "diagram_file": diagram_file
        })
    except Exception as e:
        print(f"Error during rescan: {e}")
        return jsonify({"status": "error", "message": f"Error during scan: {e}"})
    finally:
        is_scanning = False

@app.route('/api/open-diagram')
def open_diagram():
    global latest_diagram
    if latest_diagram and os.path.exists(latest_diagram):
        # Convert the file path to a URL-friendly format
        file_path = os.path.abspath(latest_diagram).replace('\\', '/') # Use forward slashes
        # Ensure the path starts with a drive letter or similar identifier if on Windows
        if os.name == 'nt' and ':' in file_path:
            file_path = '/' + file_path.replace(':', '|')
        
        # Create a local URL that draw.io can access
        # Use mode=local and the file path directly
        drawio_url = f"https://app.diagrams.net/?libs=general;pmcontainers&clean=1&nav=1&filename=Network_Diagram&edit=_blank&pages=1&title=Network%20Diagram&mode=local#{file_path}"

        return jsonify({
            "status": "success",
            "url": drawio_url
        })
    return jsonify({"status": "error", "message": "No diagram available"})

def initial_scan_thread():
    global scan_results, latest_diagram, is_scanning
    print("Performing initial network scan...")
    is_scanning = True
    try:
        devices, diagram_file = scan_network()
        scan_results = devices
        latest_diagram = diagram_file
        print("Initial scan complete.")
    except Exception as e:
        print(f"Error during initial scan: {e}")
    finally:
        is_scanning = False

if __name__ == '__main__':
    print("Starting Network Visualizer...")
    print("Make sure you're running this as Administrator!")
    
    # Start initial scan in a separate thread
    scan_thread = threading.Thread(target=initial_scan_thread)
    scan_thread.start()
    
    print("Server starting at http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False) # Disable reloader for threading 