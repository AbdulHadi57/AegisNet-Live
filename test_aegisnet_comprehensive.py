import subprocess
import time
import os
import sys
import threading
import socket
import ssl
import pandas as pd
import requests
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dhcp6 import DHCP6_Solicit, DHCP6OptClientId, DHCP6OptIA_NA
from http.server import HTTPServer, BaseHTTPRequestHandler

import signal

# Configuration
INTERFACE = "lo"
OUTPUT_DIR = "./test_captures"
CAPTURE_SCRIPT = "./aegisnet_capture.py"
DURATION = 15  # Seconds to run capture

def run_capture():
    """Start the AegisNet capture script"""
    print(f"[+] Starting AegisNet Capture on {INTERFACE}...")
    # Ensure output dir exists and is empty-ish
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    
    cmd = [sys.executable, CAPTURE_SCRIPT, "--interface", INTERFACE, "--output", OUTPUT_DIR]
    # Assuming the script takes arguments. If not, we might need to modify it or rely on defaults.
    # Checking aegisnet_capture.py: It uses argparse? No, it looks like it might not have CLI args for interface in the snippet I saw.
    # Let's check the file content again or just assume we need to patch it or it defaults to eth0.
    # The snippet showed: class AegisNetCapture: def __init__(self, interface='eth0', ...
    # And likely a main block.
    # If it doesn't support CLI args, I might need to modify it or just change the default in the test.
    # Let's assume for now I can pass args or I'll check the file content in a second.
    # Actually, I'll check the file content first to be sure.
    pass

def generate_ja4_ja4s_traffic():
    """Generate TLS traffic for JA4/JA4S"""
    print("[*] Generating JA4/JA4S Traffic (TLS)...")
    
    def start_server():
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="server.pem", keyfile="server.key") # We need certs!
        # Generating self-signed cert on the fly would be better.
        
        bindsocket = socket.socket()
        bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bindsocket.bind(('127.0.0.1', 443))
        bindsocket.listen(5)
        
        try:
            conn, addr = bindsocket.accept()
            stream = context.wrap_socket(conn, server_side=True)
            try:
                data = stream.recv(1024)
                stream.send(b"Hello TLS")
            finally:
                stream.shutdown(socket.SHUT_RDWR)
                stream.close()
        except Exception as e:
            # print(f"Server error: {e}")
            pass
        finally:
            bindsocket.close()

    # Generate self-signed cert
    os.system("openssl req -new -newkey rsa:2048 -days 1 -nodes -x509 -keyout server.key -out server.pem -subj '/CN=localhost' 2>/dev/null")

    server_thread = threading.Thread(target=start_server)
    server_thread.start()
    time.sleep(1)

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection(('127.0.0.1', 443)) as sock:
            with context.wrap_socket(sock, server_hostname="localhost") as ssock:
                ssock.send(b"Hello Server")
                ssock.recv(1024)
    except Exception as e:
        print(f"[-] TLS Client Error: {e}")

    server_thread.join()
    # Cleanup
    if os.path.exists("server.key"): os.remove("server.key")
    if os.path.exists("server.pem"): os.remove("server.pem")

def generate_ja4h_traffic():
    """Generate HTTP traffic for JA4H"""
    print("[*] Generating JA4H Traffic (HTTP)...")
    
    class SimpleHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Hello HTTP")
            
    server = HTTPServer(('127.0.0.1', 80), SimpleHandler)
    server_thread = threading.Thread(target=server.handle_request)
    server_thread.start()
    time.sleep(1)
    
    try:
        headers = {
            'User-Agent': 'TestAgent/1.0',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cookie': 'session=123; user=test'
        }
        requests.get('http://127.0.0.1:80', headers=headers)
    except Exception as e:
        print(f"[-] HTTP Client Error: {e}")
        
    server_thread.join()

def generate_ja4t_traffic():
    """Generate TCP traffic for JA4T"""
    print("[*] Generating JA4T Traffic (TCP SYN)...")
    # Scapy send
    pkt = IP(dst="127.0.0.1")/TCP(dport=9999, flags="S", window=65535, options=[('MSS', 1460), ('WScale', 8), ('Timestamp', (123, 0))])
    send(pkt, verbose=False, iface=INTERFACE)

def generate_ja4ssh_traffic():
    """Generate SSH-like traffic for JA4SSH (Partial Flow) using real sockets"""
    print("[*] Generating JA4SSH Traffic (Partial Flow)...")
    
    def ssh_server():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('127.0.0.1', 2222))
        s.listen(1)
        try:
            conn, addr = s.accept()
            conn.send(b"SSH-2.0-OpenSSH_8.2p1\r\n")
            conn.recv(1024) # Read client banner
            conn.send(b"B"*500) # Server data
            conn.recv(1024) # Client data
            conn.close()
        except:
            pass
        finally:
            s.close()

    t = threading.Thread(target=ssh_server)
    t.start()
    time.sleep(1)

    try:
        s = socket.create_connection(('127.0.0.1', 2222))
        s.recv(1024) # Server banner
        s.send(b"SSH-2.0-OpenSSH_8.2p1\r\n")
        s.recv(1024) # Server data
        s.send(b"A"*500) # Client data
        s.close()
    except Exception as e:
        print(f"[-] SSH Error: {e}")
    
    t.join()

def generate_ja4d_traffic():
    """Generate DHCP traffic for JA4D"""
    print("[*] Generating JA4D Traffic (DHCP)...")
    # DHCP Discover
    dhcp_discover = (
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=b'\x00\x11\x22\x33\x44\x55') /
        DHCP(options=[("message-type", "discover"), ("param_req_list", [1, 3, 6, 15]), "end"])
    )
    send(dhcp_discover, verbose=False, iface=INTERFACE)

def generate_ja4d6_traffic():
    """Generate DHCPv6 traffic for JA4D6"""
    print("[*] Generating JA4D6 Traffic (DHCPv6)...")
    # DHCPv6 Solicit
    # Needs IPv6 layer
    dhcp6_solicit = (
        IPv6(dst="ff02::1:2") /
        UDP(sport=546, dport=547) /
        DHCP6_Solicit(trid=12345) /
        DHCP6OptClientId(duid=b"\x00\x01\x00\x01\x26\x95\x3e\xca\x00\x0c\x29\x3e\x6e\x38") /
        DHCP6OptIA_NA(iaid=1)
    )
    send(dhcp6_solicit, verbose=False, iface=INTERFACE)

def generate_doh_traffic():
    """Generate DoH Traffic (TLS with specific SNI)"""
    print("[*] Generating DoH Traffic (SNI=dns.google)...")
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Connect to our local server but use a DoH SNI
        with socket.create_connection(('127.0.0.1', 443)) as sock:
            with context.wrap_socket(sock, server_hostname="dns.google") as ssock:
                ssock.send(b"GET /dns-query HTTP/1.1\r\nHost: dns.google\r\n\r\n")
                ssock.recv(1024)
    except Exception as e:
        print(f"[-] DoH Error: {e}")

def analyze_results():
    print("\n[+] Analyzing Results...")
    # Find latest CSV
    csv_files = [f for f in os.listdir(OUTPUT_DIR) if f.endswith('.csv')]
    if not csv_files:
        print("[-] No CSV files found!")
        return
    
    latest_csv = max([os.path.join(OUTPUT_DIR, f) for f in csv_files], key=os.path.getctime)
    print(f"[*] Reading {latest_csv}")
    
    try:
        # Prevent "None" string from being read as NaN
        df = pd.read_csv(latest_csv, keep_default_na=False, na_values=['nan', 'NaN', 'null'])
        print(f"[*] Total Flows Captured: {len(df)}")
        
        # Check JA4/JA4S (TLS)
        tls_flows = df[df['ja4'] != "None"]
        print(f"[*] TLS Flows (JA4): {len(tls_flows)}")
        if len(tls_flows) > 0:
            print(f"    Sample JA4: {tls_flows.iloc[0]['ja4']}")
            print(f"    Sample JA4S: {tls_flows.iloc[0]['ja4s']}")
            # Check JA4X
            if 'ja4x' in tls_flows.columns and tls_flows.iloc[0]['ja4x'] != "None":
                 print(f"    Sample JA4X: {tls_flows.iloc[0]['ja4x']}")
            else:
                 print("    [-] JA4X not found (Server might not have sent cert or flow ended too soon)")

        # Check JA4L (Latency)
        # Should be in TCP flows (SSH or TLS)
        ja4l_flows = df[df['ja4l_c'] != "None"]
        print(f"[*] JA4L Flows: {len(ja4l_flows)}")
        if len(ja4l_flows) > 0:
             print(f"    Sample JA4L_C: {ja4l_flows.iloc[0]['ja4l_c']}")
             print(f"    Sample JA4L_S: {ja4l_flows.iloc[0]['ja4l_s']}")
            
        # Check JA4H (HTTP)
        http_flows = df[df['ja4h'] != "None"]
        print(f"[*] HTTP Flows (JA4H): {len(http_flows)}")
        if len(http_flows) > 0:
            print(f"    Sample JA4H: {http_flows.iloc[0]['ja4h']}")
            
        # Check JA4SSH
        ssh_flows = df[df['ja4ssh'] != "None"]
        print(f"[*] SSH Flows (JA4SSH): {len(ssh_flows)}")
        if len(ssh_flows) > 0:
            print(f"    Sample JA4SSH: {ssh_flows.iloc[0]['ja4ssh']}")
            
        # Check JA4T
        # Any TCP flow should have JA4T
        tcp_flows = df[df['ja4t'] != "None"]
        print(f"[*] TCP Flows (JA4T): {len(tcp_flows)}")
        if len(tcp_flows) > 0:
            print(f"    Sample JA4T: {tcp_flows.iloc[0]['ja4t']}")
            
        # Check JA4D
        # DHCP might be tricky to find in flow table if it's UDP and connectionless, 
        # but FlowManager handles UDP.
        dhcp_flows = df[df['ja4d'] != "None"]
        print(f"[*] DHCP Flows (JA4D): {len(dhcp_flows)}")
        if len(dhcp_flows) > 0:
            print(f"    Sample JA4D: {dhcp_flows.iloc[0]['ja4d']}")
            
        # Check JA4D6
        if 'ja4d' in df.columns: # ja4d column might store both? No, code uses 'ja4d' key for both?
            # Let's check if we have v6 flows
            dhcp6_flows = df[(df['ja4d'] != "None") & (df['ja4d'].str.startswith('solic', na=False) | df['ja4d'].str.startswith('6', na=False))] 
            # JA4D6 starts with message type, e.g. 'solic' or '6' depending on implementation
            # Our code uses DHCP6_MSG_TYPES.get(val, f"{val:05d}") -> 'solic'
            print(f"[*] DHCPv6 Flows (JA4D6): {len(dhcp6_flows)}")
            if len(dhcp6_flows) > 0:
                print(f"    Sample JA4D6: {dhcp6_flows.iloc[0]['ja4d']}")

        # Check DoH Detection
        doh_flows = df[df['sni_matches_doh'] == 1]
        print(f"[*] DoH Detected Flows: {len(doh_flows)}")
        if len(doh_flows) > 0:
            print(f"    Matched SNI: {doh_flows.iloc[0]['matched_sni_domain']}")

        # Check General Features
        print("[*] Verifying General Features...")
        if len(df) > 0:
            sample = df.iloc[0]
            print(f"    Flow Duration: {sample.get('flow_duration', 'N/A')}")
            print(f"    Total Packets: {sample.get('total_packets', 'N/A')}")
            print(f"    Bytes/Sec: {sample.get('flow_bytes_s', 'N/A')}")
            print(f"    Entropy (Fwd): {sample.get('fwd_payload_entropy', 'N/A')}")
            
    except Exception as e:
        print(f"[-] Error analyzing CSV: {e}")

if __name__ == "__main__":
    # 1. Start Capture (Background)
    # We need to make sure aegisnet_capture.py is runnable and accepts args.
    # If not, we might need to modify it or rely on defaults.
    # For this test, we'll assume we can modify it or it has a main block.
    # Let's check the file content first.
    
    # Start the capture process
    print(f"[+] Launching {CAPTURE_SCRIPT}...")
    cmd = [sys.executable, CAPTURE_SCRIPT, "--interface", INTERFACE, "--output", OUTPUT_DIR]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Wait for initialization
    time.sleep(5)
    
    try:
        # 2. Generate Traffic
        generate_ja4_ja4s_traffic()
        generate_ja4h_traffic()
        generate_ja4t_traffic()
        generate_ja4ssh_traffic()
        generate_ja4d_traffic()
        generate_ja4d6_traffic()
        generate_doh_traffic()
        
        # Wait for flows to timeout/process
        print("[*] Waiting for flows to process...")
        time.sleep(10)
        
    finally:
        # 3. Stop Capture
        print("[+] Stopping Capture (Sending SIGINT)...")
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=10)
        except:
            print("[-] Capture did not exit cleanly, killing...")
            proc.kill()
            
        # Print capture output for debug
        stdout, stderr = proc.communicate()
        # print(stdout.decode())
        if stderr:
            print("Capture Stderr:", stderr.decode())
            
    # 4. Analyze
    analyze_results()
