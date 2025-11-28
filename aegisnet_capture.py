#!/usr/bin/env python3
"""
AegisNet Traffic Capture & Feature Extraction
Combines CICFlowMeter features + DoH-specific analysis + Deep packet inspection + JA4 Fingerprinting
Author: AegisNet Team
"""

import subprocess
import pandas as pd
import numpy as np
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.tls.all import * # Ensure TLS layers are loaded
from datetime import datetime
import json
import os
import sys
from collections import defaultdict, deque
import threading
import time
from scipy import stats
import queue
import csv

# Import JA4 utility
try:
    from ja4_utils import get_ja4_fingerprint, get_ja4s_fingerprint, get_ja4h_fingerprint, get_ja4ssh_fingerprint, get_ja4x_fingerprint, get_ja4l_fingerprint, get_ja4t_fingerprint, get_ja4d_fingerprint
except ImportError:
    # Fallback if file not found in path, though it should be there
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from ja4_utils import get_ja4_fingerprint, get_ja4s_fingerprint, get_ja4h_fingerprint, get_ja4ssh_fingerprint, get_ja4x_fingerprint, get_ja4l_fingerprint, get_ja4t_fingerprint, get_ja4d_fingerprint

class FlowManager:
    def __init__(self, flow_timeout=120, activity_timeout=30):
        self.active_flows = {}
        self.finished_flows_queue = queue.Queue()
        self.flow_timeout = flow_timeout # Max duration
        self.activity_timeout = activity_timeout # Max idle time
        self.lock = threading.Lock()
        self.doh_domains = set() # Initialize empty, will be set by AegisNetCapture

    def get_flow_key(self, packet):
        """Generate unique flow identifier (5-tuple) with IPv6 support"""
        src_ip = None
        dst_ip = None
        protocol = None
        src_port = 0
        dst_port = 0

        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto if hasattr(packet[IP], 'proto') else 0
            elif IPv6 in packet:
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
                protocol = packet[IPv6].nh if hasattr(packet[IPv6], 'nh') else 0
            else:
                return None
            
            # Ensure protocol is an integer
            try:
                protocol = int(protocol) if protocol is not None else 0
            except:
                protocol = 0
            
            # Initialize port variables
            src_port = 0
            dst_port = 0
            
            if TCP in packet:
                try:
                    src_port = packet[TCP].sport if packet[TCP].sport is not None else 0
                    dst_port = packet[TCP].dport if packet[TCP].dport is not None else 0
                except:
                    pass
            elif UDP in packet:
                try:
                    src_port = packet[UDP].sport if packet[UDP].sport is not None else 0
                    dst_port = packet[UDP].dport if packet[UDP].dport is not None else 0
                except:
                    pass
            else:
                # No transport layer, skip this packet
                return None
            
            # Ensure ports are integers (handle None or other types)
            try:
                src_port = int(src_port) if src_port is not None else 0
            except:
                src_port = 0
                
            try:
                dst_port = int(dst_port) if dst_port is not None else 0
            except:
                dst_port = 0

            # Bidirectional flow key (smaller IP first to group both directions)
            # If IPs are equal, sort by port
            
            if src_ip is None or dst_ip is None:
                return None
                
            # Ensure IPs are strings
            src_ip = str(src_ip)
            dst_ip = str(dst_ip)
            
            # Final validation - ensure no None values
            if src_port is None or dst_port is None or protocol is None:
                print(f"[DEBUG] None values detected: src_port={src_port}, dst_port={dst_port}, protocol={protocol}", flush=True)
                return None
            
            try:
                if src_ip < dst_ip:
                    flow_tuple = (src_ip, dst_ip, src_port, dst_port, protocol)
                elif src_ip > dst_ip:
                    flow_tuple = (dst_ip, src_ip, dst_port, src_port, protocol)
                else:
                    if src_port <= dst_port:
                        flow_tuple = (src_ip, dst_ip, src_port, dst_port, protocol)
                    else:
                        flow_tuple = (dst_ip, src_ip, dst_port, src_port, protocol)
                
                # Validate all elements are not None
                if any(x is None for x in flow_tuple):
                    print(f"[DEBUG] None in flow_tuple: {flow_tuple}", flush=True)
                    return None
                    
                return flow_tuple
            except TypeError as e:
                print(f"[DEBUG] TypeError in get_flow_key comparison: {e}. src_ip={src_ip} ({type(src_ip)}), dst_ip={dst_ip} ({type(dst_ip)}), src_port={src_port} ({type(src_port)}), dst_port={dst_port} ({type(dst_port)}), protocol={protocol} ({type(protocol)})", flush=True)
                return None
        except Exception as e:
            print(f"[DEBUG] Error generating flow key: {e}", flush=True)
            return None

    def process_packet(self, packet):
        try:
            # Immediate return if packet is None or invalid
            if packet is None:
                return
                
            # print(f"[DEBUG] Processing packet: {packet.summary()}", flush=True)
            
            try:
                flow_key = self.get_flow_key(packet)
            except Exception as e:
                print(f"[!] Error in get_flow_key: {e}", flush=True)
                return
                
            if not flow_key:
                # print("[DEBUG] No flow key", flush=True)
                return
            
            # print(f"[DEBUG] Flow key: {flow_key}", flush=True)

            # Ensure packet.time is float
            try:
                current_time = float(packet.time)
            except:
                current_time = time.time()
            
            with self.lock:
                if flow_key not in self.active_flows:
                    # print("[DEBUG] New flow", flush=True)
                    self.active_flows[flow_key] = {
                        'key': flow_key,
                        'start_time': current_time,
                        'last_seen': current_time,
                        'packets': [], 
                        'packet_data': [], 
                        'ja4': None,
                        'ja4s': None,
                        'ja4h': None,
                        # JA4SSH Stats
                        'ja4ssh_stats': {
                            'client_payloads': [], 'server_payloads': [],
                            'client_packets': 0, 'server_packets': 0,
                            'client_acks': 0, 'server_acks': 0
                        },
                        'ja4ssh': [],  # List of segments (calculated every 200 packets)
                        'ja4ssh_segment_num': 0,  # Current segment number
                        # JA4L Stats
                        'ja4l_timestamps': {'A': None, 'B': None, 'C': None, 'D': None, 'client_ttl': 0, 'server_ttl': 0},
                        'ja4l_c': None, 'ja4l_s': None,
                        # JA4X
                        'ja4x': [],
                        # JA4T/TS/D
                        'ja4t': None, 'ja4ts': None, 'ja4d': None,
                        # SNI tracking
                        'sni_matched': False, 'matched_sni': None
                    }
                
                flow = self.active_flows[flow_key]
                flow['last_seen'] = current_time
                
                # Determine direction (0: forward/client->server, 1: backward/server->client)
                # We assume the first packet seen defines the "client" (src of flow key)
                if IP in packet:
                    direction = 0 if str(packet[IP].src) == flow_key[0] else 1
                elif IPv6 in packet:
                    direction = 0 if str(packet[IPv6].src) == flow_key[0] else 1
                else:
                    direction = 0
                
                # Store simplified packet data
                pkt_len = len(packet)
                
                # Safe payload length extraction
                payload_len = 0
                if TCP in packet:
                    payload_len = len(packet[TCP].payload)
                elif UDP in packet:
                    payload_len = len(packet[UDP].payload)
                    
                # Safe TCP flags extraction
                tcp_flags = 0
                if TCP in packet:
                    tcp_flags = packet[TCP].flags
                    
                # Safe TTL extraction
                ttl = 0
                if IP in packet:
                    ttl = packet[IP].ttl
                elif IPv6 in packet:
                    ttl = packet[IPv6].hlim

                # Safe Window extraction
                window = 0
                if TCP in packet:
                    window = packet[TCP].window
                
                # Extract actual header lengths
                ip_header_len = 0
                tcp_header_len = 0
                if IP in packet:
                    ip_header_len = packet[IP].ihl * 4 if hasattr(packet[IP], 'ihl') else 20
                elif IPv6 in packet:
                    ip_header_len = 40  # IPv6 has fixed 40-byte header
                
                if TCP in packet:
                    tcp_header_len = packet[TCP].dataofs * 4 if hasattr(packet[TCP], 'dataofs') else 20
                
                # Extract SNI from TLS ClientHello (for DoH detection)
                sni = None
                if TLS in packet:
                    try:
                        tls_layer = packet[TLS]
                        if hasattr(tls_layer, 'msg') and tls_layer.msg:
                            for msg in tls_layer.msg:
                                if hasattr(msg, 'ext') and msg.ext:
                                    for ext in msg.ext:
                                        if hasattr(ext, 'servernames') and ext.servernames:
                                            for servername in ext.servernames:
                                                if hasattr(servername, 'servername'):
                                                    sni = servername.servername.decode('utf-8', errors='ignore')
                                                    break
                    except:
                        pass
                
                # Store SNI if found and it matches DoH domains
                if sni and not flow.get('sni_matched'):
                    if sni in self.doh_domains or any(doh_domain in sni for doh_domain in self.doh_domains):
                        flow['sni_matched'] = True
                        flow['matched_sni'] = sni

                pkt_info = {
                    'time': current_time,
                    'len': pkt_len,
                    'dir': direction,
                    'flags': tcp_flags,
                    'window': window,
                    'ttl': ttl,
                    'payload_len': payload_len,
                    'ip_header_len': ip_header_len,
                    'tcp_header_len': tcp_header_len,
                    'payload_bytes': bytes(packet[TCP].payload) if TCP in packet and payload_len > 0 else b''
                }
                flow['packet_data'].append(pkt_info)

                # print("[DEBUG] Packet info stored", flush=True)

                # --- JA4L & JA4T Logic ---
                if TCP in packet:
                    flags = tcp_flags
                    # A: SYN (Client Hello / First Packet)
                    if (flags & 0x02) and not (flags & 0x10): # SYN only
                        if not flow['ja4l_timestamps']['A']:
                            flow['ja4l_timestamps']['A'] = current_time
                            flow['ja4l_timestamps']['client_ttl'] = ttl
                        
                        # JA4T (Client TCP Fingerprint)
                        if not flow['ja4t']:
                            # print("[DEBUG] Calculating JA4T", flush=True)
                            flow['ja4t'] = get_ja4t_fingerprint(packet)
                    
                    # B: SYN-ACK (Server Hello / Response)
                    elif (flags & 0x02) and (flags & 0x10): # SYN+ACK
                        if not flow['ja4l_timestamps']['B']:
                            flow['ja4l_timestamps']['B'] = current_time
                            flow['ja4l_timestamps']['server_ttl'] = ttl
                        
                        # JA4TS (Server TCP Fingerprint)
                        if not flow['ja4ts']:
                            # print("[DEBUG] Calculating JA4TS", flush=True)
                            flow['ja4ts'] = get_ja4t_fingerprint(packet)
                    
                    # C: ACK (Client ACK)
                    elif (flags & 0x10) and not (flags & 0x02): # ACK only
                        # Check if it's the 3rd packet (seq=1, ack=1 usually)
                        # Simplified: First ACK after SYN-ACK
                        if flow['ja4l_timestamps']['B'] and not flow['ja4l_timestamps']['C']:
                             flow['ja4l_timestamps']['C'] = current_time
                             # Calculate JA4L immediately (Partial)
                             # print("[DEBUG] Calculating JA4L (C)", flush=True)
                             ja4l_c, ja4l_s = get_ja4l_fingerprint(flow['ja4l_timestamps'])
                             flow['ja4l_c'] = ja4l_c
                             flow['ja4l_s'] = ja4l_s

                    # D: First Data (Client -> Server)
                    # Must be after C, direction 0, payload > 0
                    if flow['ja4l_timestamps']['C'] and not flow['ja4l_timestamps'].get('D') and direction == 0 and payload_len > 0:
                        flow['ja4l_timestamps']['D'] = current_time
                        # Recalculate JA4L with D
                        # print("[DEBUG] Calculating JA4L (D)", flush=True)
                        ja4l_c, ja4l_s = get_ja4l_fingerprint(flow['ja4l_timestamps'])
                        flow['ja4l_c'] = ja4l_c
                        flow['ja4l_s'] = ja4l_s

                # --- JA4SSH Logic ---
                # Only collect JA4SSH stats for SSH traffic (port 22)
                # JA4SSH is specifically designed for SSH protocol analysis
                if TCP in packet:
                    # Check if this is SSH traffic (port 22)
                    is_ssh = (src_port == 22 or dst_port == 22)
                    
                    if is_ssh:
                        stats = flow['ja4ssh_stats']
                        if direction == 0: # Client
                            stats['client_packets'] += 1
                            if payload_len > 0:
                                stats['client_payloads'].append(payload_len)
                            if flags & 0x10: # ACK
                                stats['client_acks'] += 1
                        else: # Server
                            stats['server_packets'] += 1
                            if payload_len > 0:
                                stats['server_payloads'].append(payload_len)
                            if flags & 0x10: # ACK
                                stats['server_acks'] += 1
                        
                        # Calculate JA4SSH every 200 packets (per JA4SSH spec)
                        # Each 200-packet window creates a new segment
                        if (stats['client_packets'] + stats['server_packets']) == 200:
                             # print(f"[DEBUG] Calculating JA4SSH segment {flow['ja4ssh_segment_num']}", flush=True)
                             ja4ssh_hash = get_ja4ssh_fingerprint(stats)
                             if ja4ssh_hash:
                                 flow['ja4ssh'].append(ja4ssh_hash)
                                 flow['ja4ssh_segment_num'] += 1
                                 # Reset stats for next segment
                                 stats['client_payloads'] = []
                                 stats['server_payloads'] = []
                                 stats['client_packets'] = 0
                                 stats['server_packets'] = 0
                                 stats['client_acks'] = 0
                                 stats['server_acks'] = 0

                # --- JA4X Logic ---
                # Check for Certificates
                # This is expensive, so maybe only check if we haven't found it yet
                if not flow['ja4x'] and TCP in packet and payload_len > 0:
                     # Try to extract JA4X
                     # print("[DEBUG] Calculating JA4X", flush=True)
                     ja4x_list = get_ja4x_fingerprint(packet)
                     if ja4x_list:
                         flow['ja4x'] = ja4x_list

                # --- JA4D Logic ---
                if not flow['ja4d'] and UDP in packet:
                    # Check ports 67/68 (DHCPv4) and 546/547 (DHCPv6)
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                    if sport in [67, 68, 546, 547] or dport in [67, 68, 546, 547]:
                        # print("[DEBUG] Calculating JA4D", flush=True)
                        flow['ja4d'] = get_ja4d_fingerprint(packet)

                # --- JA4/S/H Logic ---
                # Try all three independently
                if not flow['ja4']:
                    # print("[DEBUG] Calculating JA4", flush=True)
                    ja4 = get_ja4_fingerprint(packet)
                    if ja4:
                        flow['ja4'] = ja4
                
                if not flow['ja4s']:
                    # print("[DEBUG] Calculating JA4S", flush=True)
                    ja4s = get_ja4s_fingerprint(packet)
                    if ja4s:
                        flow['ja4s'] = ja4s
                
                if not flow['ja4h']:
                    # print("[DEBUG] Calculating JA4H", flush=True)
                    ja4h = get_ja4h_fingerprint(packet)
                    if ja4h:
                        flow['ja4h'] = ja4h

                # Check for TCP FIN/RST to close flow
                if TCP in packet:
                    flags = packet[TCP].flags
                    if flags & 0x01 or flags & 0x04: # FIN or RST
                        # Mark for closing (maybe wait a bit for ACK?)
                        # For simplicity, we'll let the timeout handler pick it up or close it soon
                        pass
            
            # print("[DEBUG] Packet processed successfully", flush=True)
        except Exception as e:
            print(f"[!] Error in process_packet: {e}", flush=True)
            import traceback
            traceback.print_exc()

    def finalize_flow(self, flow):
        """Finalize flow processing before removal"""
        # JA4SSH Partial Flow Logic
        # If there are remaining packets < 200 that haven't been calculated, add as final segment
        stats = flow['ja4ssh_stats']
        if (stats['client_packets'] > 0 or stats['server_packets'] > 0):
             # print(f"[DEBUG] Finalizing JA4SSH partial segment for flow {flow['key']}", flush=True)
             ja4ssh_hash = get_ja4ssh_fingerprint(stats)
             if ja4ssh_hash:
                 flow['ja4ssh'].append(ja4ssh_hash)

    def check_timeouts(self):
        """Check for expired flows and move them to finished queue"""
        current_time = time.time()
        expired_keys = []
        
        with self.lock:
            for key, flow in self.active_flows.items():
                idle_time = current_time - flow['last_seen']
                duration = current_time - flow['start_time']
                
                if idle_time > self.activity_timeout or duration > self.flow_timeout:
                    expired_keys.append(key)
            
            for key in expired_keys:
                flow = self.active_flows.pop(key)
                self.finalize_flow(flow)
                self.finished_flows_queue.put(flow)
        
        return len(expired_keys)

    def flush_all(self):
        with self.lock:
            # print(f"[DEBUG] Flushing {len(self.active_flows)} active flows")
            for key, flow in self.active_flows.items():
                self.finalize_flow(flow)
                self.finished_flows_queue.put(flow)
            self.active_flows.clear()

class AegisNetCapture:
    def __init__(self, interface='eth0', output_dir='./captures'):
        self.interface = interface
        self.output_dir = output_dir
        self.flow_manager = FlowManager()
        self.running = False
        self.doh_indicators = defaultdict(dict)
        
        # Load DoH servers from JSON config (dynamic loading)
        self.doh_servers = {}  # IP -> Provider mapping
        self.doh_domains = set()  # Known DoH domains
        self.load_doh_config()
        
        # Pass DoH domains to FlowManager
        self.flow_manager.doh_domains = self.doh_domains
        
        os.makedirs(output_dir, exist_ok=True)
    
    def load_doh_config(self):
        """Load DoH servers from JSON config file with performance optimization"""
        try:
            config_path = os.path.join(os.path.dirname(__file__), 'doh_servers.json')
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            # Load only IPv4 addresses for performance (IPv6 optional)
            # Using set for O(1) lookup performance
            for provider_name, provider_data in config['providers'].items():
                for ip in provider_data['ips']:
                    # Only load IPv4 and IPv6 (skip if too many)
                    if ':' not in ip or len(self.doh_servers) < 50:  # Limit to prevent slowdown
                        self.doh_servers[ip] = provider_data['name']
                
                # Store domains for SNI matching
                self.doh_domains.update(provider_data.get('domains', []))
            
            print(f"[+] Loaded {len(self.doh_servers)} DoH server IPs from config")
            print(f"[+] Loaded {len(self.doh_domains)} DoH domains for SNI detection")
            
        except FileNotFoundError:
            print("[!] doh_servers.json not found, using fallback list")
            # Fallback to essential servers only (performance optimized)
            self.doh_servers = {
                '1.1.1.1': 'Cloudflare',
                '1.0.0.1': 'Cloudflare',
                '8.8.8.8': 'Google',
                '8.8.4.4': 'Google',
                '9.9.9.9': 'Quad9',
                '149.112.112.112': 'Quad9',
                '208.67.222.222': 'OpenDNS',
                '208.67.220.220': 'OpenDNS'
            }
            self.doh_domains = {'dns.google', 'cloudflare-dns.com', 'dns.quad9.net'}
        except Exception as e:
            print(f"[!] Error loading DoH config: {e}")
            self.doh_servers = {}
            self.doh_domains = set()
    
    def calculate_features(self, flow):
        """Calculate features for a single flow"""
        packets = flow['packet_data']
        if len(packets) < 2:
            # print(f"[DEBUG] Flow {flow['key']} has only {len(packets)} packets, skipping")
            return None
            
        src_ip, dst_ip, src_port, dst_port, protocol = flow['key']
        
        # Separate forward and backward packets
        fwd_packets = [p for p in packets if p['dir'] == 0]
        bwd_packets = [p for p in packets if p['dir'] == 1]
        
        packet_lengths = [p['len'] for p in packets]
        timestamps = [p['time'] for p in packets]
        inter_arrival_times = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        # Calculate response times
        response_times = []
        for i in range(len(packets) - 1):
            if packets[i]['dir'] == 0 and packets[i+1]['dir'] == 1:
                response_times.append(packets[i+1]['time'] - packets[i]['time'])
        
        # Helper stats functions - using NumPy arrays for efficiency
        def safe_array(l): return np.array(l) if l else np.array([])
        def safe_mean(l): 
            arr = safe_array(l)
            return float(np.mean(arr)) if len(arr) > 0 else 0
        def safe_std(l): 
            arr = safe_array(l)
            return float(np.std(arr)) if len(arr) > 0 else 0
        def safe_max(l): 
            arr = safe_array(l)
            return float(np.max(arr)) if len(arr) > 0 else 0
        def safe_min(l): 
            arr = safe_array(l)
            return float(np.min(arr)) if len(arr) > 0 else 0
        def safe_median(l): 
            arr = safe_array(l)
            return float(np.median(arr)) if len(arr) > 0 else 0
        def safe_var(l): 
            arr = safe_array(l)
            return float(np.var(arr)) if len(arr) > 0 else 0
        def safe_mode(l): 
            if not l: return 0
            return float(stats.mode(l, keepdims=True)[0][0]) if len(l) > 0 else 0
        def safe_skew(l): 
            arr = safe_array(l)
            if len(arr) <= 2 or np.std(arr) == 0:
                return 0
            return float(stats.skew(arr))
        def safe_kurtosis(l):
            arr = safe_array(l)
            if len(arr) <= 2 or np.std(arr) == 0:
                return 0
            return float(stats.kurtosis(arr))
        def safe_cov(l): 
            m = safe_mean(l)
            return safe_std(l) / m if m != 0 else 0
        def safe_percentile(l, p):
            arr = safe_array(l)
            return float(np.percentile(arr, p)) if len(arr) > 0 else 0
        def calc_entropy(data_bytes):
            if not data_bytes or len(data_bytes) == 0:
                return 0
            # Calculate byte frequency
            byte_counts = np.bincount(np.frombuffer(data_bytes, dtype=np.uint8), minlength=256)
            probabilities = byte_counts[byte_counts > 0] / len(data_bytes)
            return float(-np.sum(probabilities * np.log2(probabilities)))
        
        # Additional calculations - using lists for initial extraction, convert to NumPy later
        fwd_lengths = [p['len'] for p in fwd_packets]
        bwd_lengths = [p['len'] for p in bwd_packets]
        fwd_payloads = [p['payload_len'] for p in fwd_packets]
        bwd_payloads = [p['payload_len'] for p in bwd_packets]
        
        fwd_iat = [fwd_packets[i+1]['time'] - fwd_packets[i]['time'] for i in range(len(fwd_packets)-1)]
        bwd_iat = [bwd_packets[i+1]['time'] - bwd_packets[i]['time'] for i in range(len(bwd_packets)-1)]
        
        # Header lengths
        fwd_ip_headers = [p['ip_header_len'] for p in fwd_packets]
        bwd_ip_headers = [p['ip_header_len'] for p in bwd_packets]
        fwd_tcp_headers = [p['tcp_header_len'] for p in fwd_packets]
        bwd_tcp_headers = [p['tcp_header_len'] for p in bwd_packets]
        
        # Calculate entropy from payload bytes
        all_fwd_payload = b''.join([p['payload_bytes'] for p in fwd_packets if p['payload_bytes']])
        all_bwd_payload = b''.join([p['payload_bytes'] for p in bwd_packets if p['payload_bytes']])
        
        # TCP sequence analysis (simplified - detect potential retransmissions)
        # Count packets with same flags in succession as potential duplicates
        fwd_flags = [p['flags'] for p in fwd_packets]
        bwd_flags = [p['flags'] for p in bwd_packets]
        
        # Detect PSH-ACK patterns (common in retransmissions)
        psh_ack_flag = 0x18  # PSH + ACK
        fwd_psh_ack_count = sum(1 for f in fwd_flags if f & psh_ack_flag == psh_ack_flag)
        bwd_psh_ack_count = sum(1 for f in bwd_flags if f & psh_ack_flag == psh_ack_flag)
        
        # TCP flags counts
        fwd_psh = sum(1 for p in fwd_packets if p['flags'] & 0x08)
        fwd_urg = sum(1 for p in fwd_packets if p['flags'] & 0x20)
        bwd_psh = sum(1 for p in bwd_packets if p['flags'] & 0x08)
        bwd_urg = sum(1 for p in bwd_packets if p['flags'] & 0x20)
        
        # Flow bytes/packets per second
        duration = timestamps[-1] - timestamps[0] if timestamps[-1] != timestamps[0] else 0.000001
        
        features = {
            # Flow identifiers
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            
            # JA4+ Fingerprints (9 types)
            'ja4': flow['ja4'] if flow['ja4'] else "None",
            'ja4s': flow['ja4s'] if flow['ja4s'] else "None",
            'ja4h': flow['ja4h'] if flow['ja4h'] else "None",
            'ja4ssh': ";".join(flow['ja4ssh']) if flow['ja4ssh'] else "None",
            'ja4x': ";".join(flow['ja4x']) if flow['ja4x'] else "None",
            'ja4l_c': flow['ja4l_c'] if flow['ja4l_c'] else "None",
            'ja4l_s': flow['ja4l_s'] if flow['ja4l_s'] else "None",
            'ja4t': flow['ja4t'] if flow['ja4t'] else "None",
            'ja4ts': flow['ja4ts'] if flow['ja4ts'] else "None",
            'ja4d': flow['ja4d'] if flow['ja4d'] else "None",

            # === CICFlowMeter Features ===
            # Timestamp features
            'flow_duration': duration,
            
            # Packet count features
            'total_fwd_packets': len(fwd_packets),
            'total_bwd_packets': len(bwd_packets),
            'total_packets': len(packets),
            
            # Packet length statistics - Forward
            'fwd_pkt_len_max': safe_max(fwd_lengths),
            'fwd_pkt_len_min': safe_min(fwd_lengths),
            'fwd_pkt_len_mean': safe_mean(fwd_lengths),
            'fwd_pkt_len_std': safe_std(fwd_lengths),
            
            # Packet length statistics - Backward
            'bwd_pkt_len_max': safe_max(bwd_lengths),
            'bwd_pkt_len_min': safe_min(bwd_lengths),
            'bwd_pkt_len_mean': safe_mean(bwd_lengths),
            'bwd_pkt_len_std': safe_std(bwd_lengths),
            
            # Flow bytes/packets per second
            'flow_bytes_s': sum(packet_lengths) / duration,
            'flow_pkts_s': len(packets) / duration,
            
            # IAT features - Flow
            'flow_iat_mean': safe_mean(inter_arrival_times),
            'flow_iat_std': safe_std(inter_arrival_times),
            'flow_iat_max': safe_max(inter_arrival_times),
            'flow_iat_min': safe_min(inter_arrival_times),
            
            # IAT features - Forward
            'fwd_iat_total': sum(fwd_iat) if fwd_iat else 0,
            'fwd_iat_mean': safe_mean(fwd_iat),
            'fwd_iat_std': safe_std(fwd_iat),
            'fwd_iat_max': safe_max(fwd_iat),
            'fwd_iat_min': safe_min(fwd_iat),
            
            # IAT features - Backward
            'bwd_iat_total': sum(bwd_iat) if bwd_iat else 0,
            'bwd_iat_mean': safe_mean(bwd_iat),
            'bwd_iat_std': safe_std(bwd_iat),
            'bwd_iat_max': safe_max(bwd_iat),
            'bwd_iat_min': safe_min(bwd_iat),
            
            # TCP Flags - Forward
            'fwd_psh_flags': fwd_psh,
            'fwd_urg_flags': fwd_urg,
            'fwd_psh_ack_count': fwd_psh_ack_count,
            
            # TCP Flags - Backward
            'bwd_psh_flags': bwd_psh,
            'bwd_urg_flags': bwd_urg,
            'bwd_psh_ack_count': bwd_psh_ack_count,
            
            # TCP Flags - Total
            'fin_flag_count': sum(1 for p in packets if p['flags'] & 0x01),
            'syn_flag_count': sum(1 for p in packets if p['flags'] & 0x02),
            'rst_flag_count': sum(1 for p in packets if p['flags'] & 0x04),
            'psh_flag_count': sum(1 for p in packets if p['flags'] & 0x08),
            'ack_flag_count': sum(1 for p in packets if p['flags'] & 0x10),
            'urg_flag_count': sum(1 for p in packets if p['flags'] & 0x20),
            'cwe_flag_count': sum(1 for p in packets if p['flags'] & 0x80),
            'ece_flag_count': sum(1 for p in packets if p['flags'] & 0x40),
            
            # Payload statistics
            'fwd_header_len': sum(fwd_ip_headers) + sum(fwd_tcp_headers),
            'bwd_header_len': sum(bwd_ip_headers) + sum(bwd_tcp_headers),
            'fwd_header_len_mean': safe_mean(fwd_tcp_headers),
            'bwd_header_len_mean': safe_mean(bwd_tcp_headers),
            'fwd_payload_bytes': sum(fwd_payloads),
            'bwd_payload_bytes': sum(bwd_payloads),
            
            # Packet length statistics - Overall
            'pkt_len_max': safe_max(packet_lengths),
            'pkt_len_min': safe_min(packet_lengths),
            'pkt_len_mean': safe_mean(packet_lengths),
            'pkt_len_std': safe_std(packet_lengths),
            'pkt_len_var': safe_var(packet_lengths),
            
            # Down/Up ratio
            'down_up_ratio': len(bwd_packets) / len(fwd_packets) if len(fwd_packets) > 0 else 0,
            
            # Average packet size
            'avg_pkt_size': safe_mean(packet_lengths),
            'avg_fwd_segment_size': safe_mean(fwd_lengths),
            'avg_bwd_segment_size': safe_mean(bwd_lengths),
            
            # Bulk statistics (simplified)
            'fwd_bulk_bytes': sum(fwd_payloads),
            'fwd_bulk_packets': len([p for p in fwd_packets if p['payload_len'] > 0]),
            'fwd_bulk_rate': sum(fwd_payloads) / duration,
            'bwd_bulk_bytes': sum(bwd_payloads),
            'bwd_bulk_packets': len([p for p in bwd_packets if p['payload_len'] > 0]),
            'bwd_bulk_rate': sum(bwd_payloads) / duration,
            
            # Subflow features (simplified - treating each flow as single subflow)
            'subflow_fwd_packets': len(fwd_packets),
            'subflow_fwd_bytes': sum(fwd_lengths),
            'subflow_bwd_packets': len(bwd_packets),
            'subflow_bwd_bytes': sum(bwd_lengths),
            
            # Init window bytes (from first packets)
            'init_fwd_win_bytes': fwd_packets[0]['window'] if fwd_packets else 0,
            'init_bwd_win_bytes': bwd_packets[0]['window'] if bwd_packets else 0,
            
            # Active/Idle statistics (simplified)
            'active_mean': safe_mean(inter_arrival_times) if inter_arrival_times else 0,
            'active_std': safe_std(inter_arrival_times) if inter_arrival_times else 0,
            'active_max': safe_max(inter_arrival_times) if inter_arrival_times else 0,
            'active_min': safe_min(inter_arrival_times) if inter_arrival_times else 0,
            'idle_mean': 0,  # Would require more complex analysis
            'idle_std': 0,
            'idle_max': 0,
            'idle_min': 0,
            
            # === DoHLyzer Features ===
            # DoH Detection
            'is_known_doh_server': 1 if (src_ip in self.doh_servers or dst_ip in self.doh_servers) else 0,
            'uses_port_443': 1 if (src_port == 443 or dst_port == 443) else 0,
            'uses_port_853': 1 if (src_port == 853 or dst_port == 853) else 0,
            
            # DNS-specific (when applicable)
            'dns_query_count': 0,  # Would need DNS layer parsing
            'dns_answer_count': 0,
            
            # TLS-specific indicators
            'has_tls': 1 if flow['ja4'] or flow['ja4s'] else 0,
            'has_http': 1 if flow['ja4h'] else 0,
            
            # Response time statistics
            'response_time_mean': safe_mean(response_times),
            'response_time_std': safe_std(response_times),
            'response_time_max': safe_max(response_times),
            'response_time_min': safe_min(response_times),
            
            # === DoHLyzer Additional Statistical Features ===
            # Packet Length Statistics (DoHLyzer)
            'pkt_len_variance': safe_var(packet_lengths),
            'pkt_len_median': safe_median(packet_lengths),
            'pkt_len_mode': safe_mode(packet_lengths),
            'pkt_len_skew_from_median': safe_skew(packet_lengths),
            'pkt_len_cov': safe_cov(packet_lengths),
            
            # Packet Time Statistics (DoHLyzer - IAT)
            'pkt_time_variance': safe_var(inter_arrival_times),
            'pkt_time_median': safe_median(inter_arrival_times),
            'pkt_time_mode': safe_mode(inter_arrival_times),
            'pkt_time_skew_from_median': safe_skew(inter_arrival_times),
            'pkt_time_cov': safe_cov(inter_arrival_times),
            
            # Response Time Statistics (DoHLyzer)
            'response_time_variance': safe_var(response_times),
            'response_time_median': safe_median(response_times),
            'response_time_mode': safe_mode(response_times),
            'response_time_skew_from_median': safe_skew(response_times),
            'response_time_cov': safe_cov(response_times),
            
            # DoHLyzer Flow Bytes Features
            'flow_bytes_sent': sum(fwd_lengths),
            'flow_bytes_received': sum(bwd_lengths),
            'flow_sent_rate': sum(fwd_lengths) / duration,
            'flow_received_rate': sum(bwd_lengths) / duration,
            
            # === Additional CICFlowMeter Features ===
            # Percentiles for packet length
            'pkt_len_percentile_25': safe_percentile(packet_lengths, 25),
            'pkt_len_percentile_75': safe_percentile(packet_lengths, 75),
            'fwd_pkt_len_percentile_25': safe_percentile(fwd_lengths, 25),
            'fwd_pkt_len_percentile_75': safe_percentile(fwd_lengths, 75),
            'bwd_pkt_len_percentile_25': safe_percentile(bwd_lengths, 25),
            'bwd_pkt_len_percentile_75': safe_percentile(bwd_lengths, 75),
            
            # Kurtosis (tailedness)
            'pkt_len_kurtosis': safe_kurtosis(packet_lengths),
            'pkt_time_kurtosis': safe_kurtosis(inter_arrival_times),
            'fwd_iat_kurtosis': safe_kurtosis(fwd_iat),
            'bwd_iat_kurtosis': safe_kurtosis(bwd_iat),
            
            # Payload entropy (encryption/randomness detection)
            'fwd_payload_entropy': calc_entropy(all_fwd_payload),
            'bwd_payload_entropy': calc_entropy(all_bwd_payload),
            
            # Header to payload ratio
            'fwd_header_payload_ratio': sum(fwd_tcp_headers) / sum(fwd_payloads) if sum(fwd_payloads) > 0 else 0,
            'bwd_header_payload_ratio': sum(bwd_tcp_headers) / sum(bwd_payloads) if sum(bwd_payloads) > 0 else 0,
            
            # Packet inter-arrival ratio
            'fwd_bwd_iat_ratio': safe_mean(fwd_iat) / safe_mean(bwd_iat) if safe_mean(bwd_iat) > 0 else 0,
            
            # Average bytes per bulk (continuous data transfer)
            'fwd_avg_bytes_bulk': sum(fwd_payloads) / len([p for p in fwd_packets if p['payload_len'] > 0]) if len([p for p in fwd_packets if p['payload_len'] > 0]) > 0 else 0,
            'bwd_avg_bytes_bulk': sum(bwd_payloads) / len([p for p in bwd_packets if p['payload_len'] > 0]) if len([p for p in bwd_packets if p['payload_len'] > 0]) > 0 else 0,
            
            # Average packets per bulk
            'fwd_avg_packets_bulk': len([p for p in fwd_packets if p['payload_len'] > 0]) / duration,
            'bwd_avg_packets_bulk': len([p for p in bwd_packets if p['payload_len'] > 0]) / duration,
            
            # Average bulk rate
            'fwd_avg_bulk_rate': (sum(fwd_payloads) / duration) if sum(fwd_payloads) > 0 else 0,
            'bwd_avg_bulk_rate': (sum(bwd_payloads) / duration) if sum(bwd_payloads) > 0 else 0,
            
            # SNI matching for DoH detection
            'sni_matches_doh': 1 if flow.get('sni_matched') else 0,
            'matched_sni_domain': flow.get('matched_sni', 'None') if flow.get('matched_sni') else 'None',
        }
        
        return features

    def packet_processor(self):
        """Background thread to process finished flows and write to CSV"""
        max_entries_per_file = 500
        entry_count = 0
        file_counter = 1
        headers = None
        f = None
        writer = None
        output_file = None
        
        try:
            while self.running or not self.flow_manager.finished_flows_queue.empty():
                try:
                    # Get flow from queue
                    flow = self.flow_manager.finished_flows_queue.get(timeout=1)
                    if flow is None:
                        break
                    
                    # Calculate features
                    features = self.calculate_features(flow)
                    if not features:
                        continue
                    
                    # Set headers from first valid flow
                    if headers is None:
                        headers = list(features.keys())
                    
                    # Create new file if needed (first time or reached limit)
                    if f is None or entry_count >= max_entries_per_file:
                        # Close previous file if exists
                        if f is not None:
                            f.close()
                            print(f"[+] Completed {output_file} with {entry_count} entries")
                        
                        # Create new file
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        output_file = os.path.join(self.output_dir, f'aegisnet_live_{timestamp}_part{file_counter}.csv')
                        f = open(output_file, 'w', newline='')
                        writer = csv.DictWriter(f, fieldnames=headers)
                        writer.writeheader()
                        f.flush()
                        
                        print(f"[+] Started writing to {output_file}")
                        entry_count = 0
                        file_counter += 1
                    
                    # Write the row
                    writer.writerow(features)
                    f.flush()
                    entry_count += 1
                    
                except queue.Empty:
                    continue
        finally:
            # Close file when done
            if f is not None:
                f.close()
                if entry_count > 0:
                    print(f"[+] Completed {output_file} with {entry_count} entries")

    def timeout_checker(self):
        """Background thread to check for timeouts"""
        while self.running:
            time.sleep(5)
            expired = self.flow_manager.check_timeouts()
            # if expired > 0:
            #     print(f"[DEBUG] Expired {expired} flows")

    def start_capture(self, duration=None, packet_count=None):
        """Start packet capture"""
        # Determine interface
        if self.interface:
            iface_to_use = self.interface
        else:
            iface_to_use = conf.iface # Default scapy interface
            
        print(f"[*] Starting capture on {iface_to_use}...")
        print(f"[*] Press Ctrl+C to stop...")
        
        self.running = True
        
        # Start processor threads
        proc_thread = threading.Thread(target=self.packet_processor)
        proc_thread.start()
        
        timeout_thread = threading.Thread(target=self.timeout_checker)
        timeout_thread.start()
        
        try:
            # Suppress scapy warnings
            # import logging
            # logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
            
            start_ts = time.time()
            try:
                from scapy.sendrecv import AsyncSniffer
                sniffer = AsyncSniffer(
                    iface=self.interface,
                    prn=self.flow_manager.process_packet,
                    filter="tcp or udp",
                    store=False
                )
                sniffer.start()
                
                # Run for duration or until packet_count
                start_time = time.time()
                while self.running:
                    time.sleep(0.1)
                    if duration and (time.time() - start_time) >= duration:
                        break
                
                sniffer.stop()
                
            except Exception as sniff_error:
                print(f"[!] Sniff error: {sniff_error}", flush=True)
                import traceback
                traceback.print_exc()
            end_ts = time.time()
            if (end_ts - start_ts) < 2:
                print("[!] Warning: Sniffer exited very quickly.")
                print("[!] Try specifying the interface explicitly using -i (e.g., -i eth0)")
            
        except BaseException as e: # Catch SystemExit and KeyboardInterrupt too
            if isinstance(e, KeyboardInterrupt):
                print("\n[*] Stopping capture...")
            else:
                print(f"\n[!] Error: {e}")
                if "Operation not permitted" in str(e) or "EPERM" in str(e):
                    print("[!] Packet capturing requires root privileges.")
                    print("[!] Please run with: sudo python3 aegisnet_capture.py")
        finally:
            self.running = False
            self.flow_manager.flush_all()
            # Signal processor to exit
            self.flow_manager.finished_flows_queue.put(None)
            proc_thread.join()
            timeout_thread.join()
            print("[+] Capture stopped.")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='AegisNet Traffic Capture & Feature Extraction')
    parser.add_argument('-i', '--interface', default=None, help='Network interface (default: auto)')
    parser.add_argument('-d', '--duration', type=int, default=None, help='Capture duration in seconds')
    parser.add_argument('-c', '--count', type=int, default=None, help='Maximum packet count')
    parser.add_argument('-o', '--output', default='./captures', help='Output directory')
    
    args = parser.parse_args()
    
    capture = AegisNetCapture(
        interface=args.interface,
        output_dir=args.output
    )
    
    capture.start_capture(
        duration=args.duration,
        packet_count=args.count
    )

if __name__ == '__main__':
    main()

