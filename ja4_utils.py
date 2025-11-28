import hashlib
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.tls.all import *
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
from scapy.layers.tls.extensions import TLS_Ext_SupportedVersions, TLS_Ext_ServerName, TLS_Ext_ALPN

# Explicitly load layers
load_layer("tls")
load_layer("http")
load_layer("dhcp") # Ensure DHCP is loaded
from scapy.layers.http import HTTPRequest
from scapy.layers.dhcp import DHCP, BOOTP

# Try to import DHCPv6 layers
try:
    from scapy.layers.dhcp6 import DHCP6_Solicit, DHCP6_Advertise, DHCP6_Request, DHCP6_Reply, \
        DHCP6_Confirm, DHCP6_Renew, DHCP6_Rebind, DHCP6_Release, DHCP6_Decline, \
        DHCP6_Reconf, DHCP6_InfoRequest, DHCP6_RelayForward, DHCP6_RelayReply, \
        DHCP6OptClientId, DHCP6OptIA_NA, DHCP6OptIA_TA, DHCP6OptClientFQDN, DHCP6OptOptReq
    HAS_DHCP6 = True
except ImportError:
    HAS_DHCP6 = False

# Try to import X509 layers
try:
    from scapy.layers.x509 import X509_Cert
    from scapy.asn1.asn1 import ASN1_OID
    HAS_X509 = True
except ImportError:
    try:
        from scapy.all import ASN1_OID
        HAS_X509 = True
    except ImportError:
        HAS_X509 = False

# GREASE values to ignore
GREASE_TABLE = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
}

# TCP Option Kind Mapping (Common options)
TCP_OPTION_KIND = {
    'EOL': 0, 'NOP': 1, 'MSS': 2, 'WScale': 3, 'SAckOK': 4, 'SAck': 5,
    'Timestamp': 8, 'AltChkSum': 14, 'AltChkSumOpt': 15
}

# DHCP Message Type Mapping (Option 53)
DHCP_MSG_TYPES = {
    1: "disco", 2: "offer", 3: "reqst", 4: "decln", 5: "dpack",
    6: "dpnak", 7: "relse", 8: "infor", 9: "frenw", 10: "lqery",
    11: "lunas", 12: "lunkn", 13: "lactv", 14: "blklq", 15: "lqdon",
    16: "actlq", 17: "lqsta", 18: "dhtls"
}

# DHCPv6 Message Type Mapping
DHCP6_MSG_TYPES = {
    1: "solic", 2: "adver", 3: "reqst", 4: "cnfrm", 5: "renew",
    6: "rebin", 7: "reply", 8: "reles", 9: "decln", 10: "recfg",
    11: "infor", 12: "rlfor", 13: "rlrep"
}

def sha256_12(s):
    """Compute SHA256 and return first 12 characters."""
    return hashlib.sha256(s.encode()).hexdigest()[:12]

def get_ja4_fingerprint(packet):
    """
    Calculate JA4 fingerprint for a Scapy packet (TLS Client Hello).
    Returns None if not a TLS Client Hello.
    """
    if not packet.haslayer(TLSClientHello):
        return None

    try:
        client_hello = packet[TLSClientHello]
        # print(f"DEBUG: ClientHello fields: {client_hello.fields}")
        # print(f"DEBUG: ClientHello ext: {getattr(client_hello, 'ext', 'N/A')}")
        
        # 1. Protocol (TCP='t', QUIC='q')
        # Assuming TCP for now as Scapy's QUIC support is limited/external
        protocol = 't' 
        if packet.haslayer(UDP):
            protocol = 'q' # Placeholder, likely won't trigger with standard TLS layer

        # 2. TLS Version
        # Scapy parses version as int (e.g., 0x0303 for TLS 1.2)
        version_map = {
            0x0300: "10", # SSL 3.0
            0x0301: "10", # TLS 1.0
            0x0302: "11", # TLS 1.1
            0x0303: "12", # TLS 1.2
            0x0304: "13", # TLS 1.3
        }
        version_val = client_hello.version
        
        # Check supported_versions extension for TLS 1.3
        supported_versions = []
        # Scapy TLS extensions are often in 'ext' field
        exts = getattr(client_hello, 'extensions', getattr(client_hello, 'ext', []))
        
        for ext in exts:
            if isinstance(ext, TLS_Ext_SupportedVersions):
                # Safely access versions
                if hasattr(ext, 'versions'):
                    supported_versions = ext.versions
                break
        
        if supported_versions:
            # Find max version
            max_ver = max(supported_versions)
            if max_ver in version_map:
                version = version_map[max_ver]
            else:
                version = "00"
        else:
            version = version_map.get(version_val, "00")

        # 3. SNI (d = domain, i = ip)
        sni = 'i'
        for ext in exts:
            if isinstance(ext, TLS_Ext_ServerName):
                sni = 'd'
                break

        # 4. Ciphers
        ciphers = client_hello.ciphers
        # Filter GREASE and convert to hex strings
        valid_ciphers = []
        for c in ciphers:
            if c not in GREASE_TABLE:
                valid_ciphers.append(f"{c:04x}")
        
        cipher_len = f"{len(valid_ciphers):02d}"
        sorted_ciphers = sorted(valid_ciphers)
        cipher_hash = sha256_12(",".join(sorted_ciphers))

        # 5. Extensions
        extensions = []
        alpn_val = "00"
        signature_algorithms = []
        
        for ext in exts:
            ext_type = ext.type
            if ext_type in GREASE_TABLE:
                continue
            
            # Add all extensions after GREASE filtering (including SNI and ALPN)
            extensions.append(f"{ext_type:04x}")

            # Extract Signature Algorithms (0x000d)
            if ext_type == 13: # 0x000d
                # Scapy TLS_Ext_SignatureAlgorithms
                if hasattr(ext, 'sig_algs'):
                    for alg in ext.sig_algs:
                        signature_algorithms.append(f"{alg:04x}")

            # Extract ALPN
            if isinstance(ext, TLS_Ext_ALPN):
                # Scapy field might be 'protocol_name_list' or 'protocols'
                alpn_list = getattr(ext, 'protocol_name_list', getattr(ext, 'protocols', []))
                if alpn_list:
                    first_alpn = alpn_list[0]
                    # Handle Scapy ProtocolName object
                    if hasattr(first_alpn, 'protocol'):
                        first_alpn = first_alpn.protocol

                    if hasattr(first_alpn, 'decode'):
                        first_alpn = first_alpn.decode('utf-8', errors='ignore')
                    elif not isinstance(first_alpn, str):
                        # If bytes, try to decode, else hex
                        if isinstance(first_alpn, bytes):
                            try:
                                first_alpn = first_alpn.decode('utf-8')
                            except:
                                first_alpn = first_alpn.hex()
                        else:
                            first_alpn = str(first_alpn)
                    
                    if first_alpn:
                        # Check if alphanumeric
                        is_alnum = all(c.isalnum() or c in "-." for c in first_alpn)
                        if not is_alnum:
                             # Use hex representation of first and last byte if not printable
                             # Or just "99" as per spec?
                             # Spec says: "If the ALPN is not alphanumeric, use '99'."
                             # But ja4.py says: if not printable, use hex.
                             # Let's stick to "99" for now as per my previous logic, or check ja4.py logic.
                             # ja4.py: alpn = x['alpn'] ... if not alpn.isalnum(): alpn = '99'
                             alpn_val = "99"
                        elif len(first_alpn) > 2:
                            alpn_val = f"{first_alpn[0]}{first_alpn[-1]}"
                        else:
                            alpn_val = first_alpn

        ext_len = f"{len(extensions):02d}"
        sorted_extensions = sorted(extensions)
        
        # Append Signature Algorithms to sorted extensions if present
        if signature_algorithms:
             # JA4 logic: sorted_extensions + "_" + signature_algorithms
             # signature_algorithms are NOT sorted in ja4.py, just listed?
             # ja4.py: x['signature_algorithms'] = [ y[2:] for y in get_signature_algorithms(x) ]
             # ... x['sorted_extensions'] = x['sorted_extensions'] + '_' + ','.join(x['signature_algorithms'])
             # Wait, get_signature_algorithms returns them in order.
             sig_alg_str = ",".join(signature_algorithms)
             full_ext_string = ",".join(sorted_extensions) + "_" + sig_alg_str
        else:
             full_ext_string = ",".join(sorted_extensions)

        # Handle empty extensions
        if not sorted_extensions:
            ext_hash = "000000000000"
        else:
            ext_hash = sha256_12(full_ext_string)

        # Construct JA4
        ja4_string = f"{protocol}{version}{sni}{cipher_len}{ext_len}{alpn_val}_{cipher_hash}_{ext_hash}"
        return ja4_string

    except Exception as e:
        print(f"Error calculating JA4: {e}")
        import traceback
        traceback.print_exc()
        return None

def get_ja4s_fingerprint(packet):
    """
    Calculate JA4S fingerprint for a Scapy packet (TLS Server Hello).
    Returns None if not a TLS Server Hello.
    """
    if not packet.haslayer(TLSServerHello):
        return None

    try:
        server_hello = packet[TLSServerHello]
        
        # 1. Protocol
        protocol = 't'
        if packet.haslayer(UDP):
            protocol = 'q'
            
        # 2. Version
        version_map = {
            0x0300: "10", 0x0301: "10", 0x0302: "11", 0x0303: "12", 0x0304: "13"
        }
        version_val = server_hello.version
        final_version = version_map.get(version_val, "00")
        
        # Check supported_versions extension for TLS 1.3
        # Scapy TLS extensions are often in 'ext' field
        exts = getattr(server_hello, 'extensions', getattr(server_hello, 'ext', []))

        for ext in exts:
            if isinstance(ext, TLS_Ext_SupportedVersions):
                # In ServerHello, versions is usually a single value
                ver = ext.versions
                # Scapy might return a list or int depending on version
                if isinstance(ver, list) and len(ver) > 0:
                    ver = ver[0]
                
                if ver in version_map:
                    final_version = version_map[ver]
                break

        # 3. Extension Count & ALPN & Extensions List
        extensions = []
        alpn_val = "00"
        
        for ext in exts:
            ext_type = ext.type
            if ext_type in GREASE_TABLE:
                continue
            
            extensions.append(f"{ext_type:04x}")
            
            if isinstance(ext, TLS_Ext_ALPN):
                 # Scapy field might be 'protocol_name_list' or 'protocols'
                 alpn_list = getattr(ext, 'protocol_name_list', getattr(ext, 'protocols', []))
                 if alpn_list:
                    first_alpn = alpn_list[0]
                    if hasattr(first_alpn, 'decode'):
                        first_alpn = first_alpn.decode('utf-8', errors='ignore')
                    elif not isinstance(first_alpn, str):
                        first_alpn = str(first_alpn)
                        
                    if first_alpn:
                        if len(first_alpn) > 2:
                            alpn_val = f"{first_alpn[0]}{first_alpn[-1]}"
                        else:
                            alpn_val = first_alpn
                        if ord(alpn_val[0]) > 127:
                            alpn_val = "99"

        ext_count = f"{len(extensions):02d}"
        
        # 4. Cipher
        cipher = server_hello.cipher
        cipher_hex = f"{cipher:04x}"
        
        # 5. Extensions Hash (NOT sorted for JA4S)
        if not extensions:
            ext_hash = "000000000000"
        else:
            ext_hash = sha256_12(",".join(extensions))
            
        return f"{protocol}{final_version}{ext_count}{alpn_val}_{cipher_hex}_{ext_hash}"

    except Exception as e:
        return None

def get_ja4h_fingerprint(packet):
    """
    Calculate JA4H fingerprint for a Scapy packet (HTTP Request).
    Returns None if not an HTTP Request.
    """
    if not packet.haslayer(HTTPRequest):
        return None
        
    try:
        http = packet[HTTPRequest]
        
        # 1. Method
        method = "xx"
        if http.Method:
            method = http.Method.decode('utf-8', errors='ignore')[:2].lower()
        
        # 2. Version
        version = "00"
        if http.Http_Version:
            version_str = http.Http_Version.decode('utf-8', errors='ignore')
            if "1.1" in version_str:
                version = "11"
            elif "1.0" in version_str:
                version = "10"
            elif "2.0" in version_str:
                version = "20"
            
        # 3. Cookie & 4. Referer Presence
        cookie_char = 'n'
        referer_char = 'n'
        
        # Scapy fields
        cookie_val = None
        referer_val = None
        
        if http.Cookie:
            cookie_char = 'c'
            cookie_val = http.Cookie.decode('utf-8', errors='ignore')
            
        if http.Referer:
            referer_char = 'r'
            referer_val = http.Referer.decode('utf-8', errors='ignore')
            
        # 5. Headers (Count & Hash)
        # JA4H: Headers in wire order, excluding Cookie and Referer
        ignore_headers = {'Cookie', 'Referer', 'Method', 'Path', 'Http_Version'} 
        # Note: Method, Path, Version are not headers in HTTP/1.1 wire format usually (start line), 
        # but Scapy might treat them as fields. We only want actual headers.
        
        present_headers = []
        
        # Scapy's http.fields is a dictionary, which might NOT preserve wire order in older Python/Scapy versions.
        # However, Scapy's Packet.fields_desc usually defines order.
        # But HTTP headers are dynamic.
        # For reliable wire order, we might need to parse the raw packet payload if Scapy reorders.
        # But for now, we rely on Scapy's order or the order they appear in fields.
        # Actually, Scapy stores headers in fields.
        # Let's try to iterate over the packet fields in order if possible.
        # packet.fields is a dict.
        # packet.field_names might give order? No.
        # In Scapy, HTTP headers are often just fields.
        # Let's assume standard Scapy usage: fields are populated.
        # We will collect all fields that are NOT in ignore list.
        
        # Standard headers in Scapy HTTPRequest
        # We need to be careful about case. JA4H uses lowercase header names.
        
        # Helper to get all headers
        # We iterate over the fields and check if they are headers.
        # Scapy's HTTPRequest has specific fields for common headers.
        # And 'Unknown_Headers' for others.
        
        # Strategy:
        # 1. Collect known headers from fields (if not None)
        # 2. Collect unknown headers
        # 3. Sort? No, JA4H requires wire order.
        # This is a problem with Scapy's dict storage for known headers.
        # We can't guarantee wire order for known headers like 'Host', 'User-Agent' if they are in the dict.
        # We will proceed with a best-effort list based on Scapy's definition order or just alphabetical if we can't know.
        # BUT, JA4H is a fingerprint. Order matters.
        # If we can't get wire order, the fingerprint will be wrong for strict verification.
        # However, for this implementation, we will use a fixed order for known headers (Scapy's definition order) + unknown headers.
        
        # List of potential headers in Scapy HTTPRequest (partial list)
        # We'll just iterate `http.fields` and filter.
        # Note: `http.fields` iteration order depends on insertion order in Python 3.7+.
        # Scapy populates it as it parses. So it SHOULD be close to wire order.
        
        raw_headers = []
        for name, val in http.fields.items():
            if name in ['Method', 'Path', 'Http_Version']:
                continue
            if val is None:
                continue
                
            # Normalize name (Scapy uses underscores, e.g. User_Agent)
            # We need the actual wire name if possible, or convert standard ones.
            # Scapy doesn't store the original case for known headers.
            # JA4H uses lowercase names anyway.
            norm_name = name.replace('_', '-').lower()
            
            if norm_name in ['cookie', 'referer']:
                continue
                
            raw_headers.append(norm_name)
            
        # Handle Unknown_Headers (list of raw bytes usually)
        # e.g. b'My-Header: value'
        if http.Unknown_Headers:
            for h in http.Unknown_Headers:
                if isinstance(h, bytes):
                    h = h.decode('utf-8', errors='ignore')
                if ':' in h:
                    h_name = h.split(':')[0].strip().lower()
                    if h_name not in ['cookie', 'referer']:
                        raw_headers.append(h_name)
                        
        # Header Count
        header_count = min(len(raw_headers), 99)
        header_count_str = f"{header_count:02d}"
        
        # Header Hash
        headers_string = ",".join(raw_headers)
        headers_hash = sha256_12(headers_string) if headers_string else "000000000000"
        
        # 6. Lang
        lang_str = "0000"
        if http.Accept_Language:
            lang_val = http.Accept_Language.decode('utf-8', errors='ignore')
            # Logic: replace - with nothing, ; with , -> split by , -> take first -> take first 4 chars -> pad with 0
            # e.g. "en-US,en;q=0.9" -> "enUS,en,q=0.9" -> "enUS" -> "enUS"
            # e.g. "fr" -> "fr" -> "fr00"
            
            l = lang_val.replace('-', '').replace(';', ',').lower()
            l = l.split(',')[0]
            l = l[:4]
            lang_str = f"{l}{'0'*(4-len(l))}"
            
        # 7. Cookies (Name Hash & Value Hash)
        cookie_names = []
        cookie_values = []
        
        if cookie_val:
            # Parse cookie string: "name=value; name2=value2"
            # Split by ';'
            parts = cookie_val.split(';')
            for p in parts:
                p = p.strip()
                if '=' in p:
                    c_name = p.split('=', 1)[0].strip()
                    cookie_names.append(c_name)
                    cookie_values.append(p)  # Full "name=value" string
                else:
                    # Cookie without value
                    cookie_names.append(p)
                    cookie_values.append(p)
            
            # Sort names and values INDEPENDENTLY (official behavior)
            # This breaks name-value association, which is intentional per official ja4h.py
            cookie_names.sort()
            cookie_values.sort()
            
            cookie_name_hash = sha256_12(",".join(cookie_names))
            cookie_value_hash = sha256_12(",".join(cookie_values))
        else:
            cookie_name_hash = "000000000000"
            cookie_value_hash = "000000000000"

        # Construct JA4H
        # Format: MethodVersionCookieRefererHeaderCountLang_HeaderHash_CookieNameHash_CookieValueHash
        ja4h_string = f"{method}{version}{cookie_char}{referer_char}{header_count_str}{lang_str}_{headers_hash}_{cookie_name_hash}_{cookie_value_hash}"
        
        return ja4h_string
        
    except Exception as e:
        print(f"Error calculating JA4H: {e}")
        return None

def get_ja4ssh_fingerprint(stats):
    """
    Calculate JA4SSH fingerprint from stats.
    stats: dict with keys:
        - client_payloads: list of payload sizes (int)
        - server_payloads: list of payload sizes (int)
        - client_packets: int
        - server_packets: int
        - client_acks: int
        - server_acks: int
    """
    try:
        # Mode (most frequent payload size)
        def get_mode(payloads):
            if not payloads:
                return 0
            return max(set(payloads), key=payloads.count)

        mode_client = get_mode(stats.get('client_payloads', []))
        mode_server = get_mode(stats.get('server_payloads', []))
        
        client_packets = stats.get('client_packets', 0)
        server_packets = stats.get('server_packets', 0)
        client_acks = stats.get('client_acks', 0)
        server_acks = stats.get('server_acks', 0)
        
        return f"c{mode_client}s{mode_server}_c{client_packets}s{server_packets}_c{client_acks}s{server_acks}"
    except Exception as e:
        print(f"Error calculating JA4SSH: {e}")
        return None

def get_ja4x_fingerprint(packet):
    """
    Calculate JA4X fingerprint for a Scapy packet (TLS Certificate).
    Returns a list of JA4X hashes (one for each cert in the chain).
    Format: Hash(IssuerOIDs)_Hash(SubjectOIDs)_Hash(ExtensionOIDs)
    """
    if not HAS_X509:
        return None
        
    # Check for Certificate message
    if not packet.haslayer(TLS):
        return None
        
    # Find TLSCertificate layer
    cert_layer = None
    current = packet
    while current:
        if isinstance(current, TLSCertificate):
            cert_layer = current
            break
        if hasattr(current, 'payload'):
            current = current.payload
        else:
            break
            
    if not cert_layer:
        return None
        
    ja4x_hashes = []
    
    try:
        for i, cert_container in enumerate(cert_layer.certs):
            # cert_container might be a Cert object with .data
            cert_data = cert_container.data if hasattr(cert_container, 'data') else cert_container
            
            # Parse with Scapy X509
            try:
                x509 = X509_Cert(cert_data)
            except Exception:
                continue
                
            # Helper to get hex string of OIDs from a Name object
            def get_oids_hex(name_field):
                hex_str = ""
                if not name_field:
                    return ""
                # Scapy Name object has rdns list
                for rdn in name_field.rdns:
                    for component in rdn.components:
                        oid_str = component.type
                        try:
                            # Convert to ASN1_OID and get bytes
                            oid_bytes = bytes(ASN1_OID(oid_str))
                            hex_str += oid_bytes.hex()
                        except Exception:
                            pass
                return hex_str

            # Helper to get hex string of OIDs from Extensions
            def get_ext_oids_hex(extensions):
                hex_str = ""
                if not extensions:
                    return ""
                for ext in extensions:
                    oid_str = ext.extnID
                    try:
                        oid_bytes = bytes(ASN1_OID(oid_str))
                        hex_str += oid_bytes.hex()
                    except Exception:
                        pass
                return hex_str

            # 1. Issuer OIDs
            issuer_hex = get_oids_hex(x509.tbs_certificate.issuer)
            hash1 = sha256_12(issuer_hex) if issuer_hex else "000000000000"
            
            # 2. Subject OIDs
            subject_hex = get_oids_hex(x509.tbs_certificate.subject)
            hash2 = sha256_12(subject_hex) if subject_hex else "000000000000"
            
            # 3. Extension OIDs
            ext_hex = get_ext_oids_hex(x509.tbs_certificate.extensions)
            hash3 = sha256_12(ext_hex) if ext_hex else "000000000000"
            
            ja4x_hashes.append(f"{hash1}_{hash2}_{hash3}")

    except Exception as e:
        print(f"Error calculating JA4X: {e}")
        
    return ja4x_hashes

def get_ja4l_fingerprint(timestamps):
    """
    Calculate JA4L (Latency) fingerprint.
    timestamps: dict with 'A' (SYN), 'B' (SYN-ACK), 'C' (ACK), 'D' (First Data)
    Returns (JA4L_C, JA4L_S) tuple.
    Format: Latency_TTL_AppLatency
    """
    try:
        t_a = timestamps.get('A')
        t_b = timestamps.get('B')
        t_c = timestamps.get('C')
        t_d = timestamps.get('D')
        
        ja4l_c = "0000_00_0000"
        ja4l_s = "0000_00_0000"
        
        if t_a and t_b:
            # Server Latency: B - A
            latency_s = int(round((t_b - t_a) * 1000000)) # microseconds
            ttl_s = timestamps.get('server_ttl', 0)
            
            # App Latency for Server side? Usually JA4L is client-centric.
            # But if we have D (Client sending data), the server sees it after C?
            # Actually JA4L is defined as:
            # a: One-way TCP latency (B-A for server perspective? No, usually RTT/2 or similar)
            # JA4L (Client): Latency = C - B (Client reaction time)
            # JA4L (Server): Latency = B - A (Server reaction time)
            
            # App Latency (c): One-way application handshake latency.
            # For Client: D - C (Time from ACK to sending Data)
            # For Server: Time from receiving ACK to receiving Data? Or sending response?
            # The spec says "One-way application handshake latency".
            # Let's assume D - C for Client.
            
            app_latency_s = 0
            # Server doesn't usually initiate App data in standard HTTP/TLS immediately after handshake?
            # Usually Client sends ClientHello/Request.
            # So JA4L_S might not have valid App Latency or it's 0.
            
            ja4l_s = f"{latency_s}_{ttl_s}_0000"
            
        if t_b and t_c:
            # Client Latency: C - B
            latency_c = int(round((t_c - t_b) * 1000000))
            ttl_c = timestamps.get('client_ttl', 0)
            
            app_latency_c = 0
            if t_d:
                app_latency_c = int(round((t_d - t_c) * 1000000))
                
            ja4l_c = f"{latency_c}_{ttl_c}_{app_latency_c}"
            
        return ja4l_c, ja4l_s
        
    except Exception as e:
        return None, None

def get_ja4t_fingerprint(packet):
    """
    Calculate JA4T (TCP) fingerprint.
    Works for both SYN (JA4T) and SYN-ACK (JA4TS).
    Format: WindowSize_TCPOptions_MSS_WindowScale
    """
    if not packet.haslayer(TCP):
        return None
    
    try:
        tcp = packet[TCP]
        
        # 1. Window Size
        window_size = tcp.window
        
        # 2. TCP Options & MSS & Window Scale
        options_str_list = []
        mss_val = 0
        window_scale = 0
        
        # Scapy parses options as a list of (name, value) or (kind, value)
        for opt in tcp.options:
            kind = 0
            name = ""
            val = None
            
            if isinstance(opt, tuple):
                name = opt[0]
                val = opt[1]
            else:
                # Some options like EOL/NOP might be just a string or int?
                # Scapy usually normalizes to tuple ('NOP', None)
                name = opt
                
            # Determine Kind
            if isinstance(name, int):
                kind = name
            elif name in TCP_OPTION_KIND:
                kind = TCP_OPTION_KIND[name]
            else:
                # Fallback for unknown names - try to find in Scapy's internal map if needed
                # For now, skip or assume 0? 
                # If we can't map it, we might miss it.
                # But the C code uses the option kind from the wire.
                # Scapy abstracts this.
                # Let's assume standard options.
                pass
                
            options_str_list.append(str(kind))
            
            # Extract Values
            if kind == 2: # MSS
                if isinstance(val, int):
                    mss_val = val
            elif kind == 3: # WScale
                if isinstance(val, int):
                    window_scale = val
                    
        # Format Options String
        tcp_options = "-".join(options_str_list)
        if not tcp_options:
            tcp_options = "00"
            
        # Format Window Scale
        # If 0, use "00". Else use integer string.
        if window_scale == 0:
            wscale_str = "00"
        else:
            wscale_str = str(window_scale)
            
        return f"{window_size}_{tcp_options}_{mss_val}_{wscale_str}"
        
    except Exception as e:
        print(f"Error calculating JA4T: {e}")
        return None

def get_ja4d_fingerprint(packet):
    """
    Calculate JA4D (DHCP) fingerprint.
    Supports DHCPv4 and DHCPv6.
    Format: ProtoIpFqdnType_Size_Options_RequestList
    """
    # Check for DHCPv4
    if packet.haslayer(DHCP):
        try:
            dhcp_options = packet[DHCP].options
            
            # 1. Proto (v4='4')
            proto = '4'
            
            # 2. IP (Requested IP Address - Option 50)
            ip_char = 'n'
            
            # 3. FQDN (Client FQDN - Option 81)
            fqdn_char = 'n'
            
            # 4. Type (Message Type - Option 53)
            type_str = "00000"
            
            # 5. Size (Max DHCP Message Size - Option 57)
            size_str = "0000"
            
            # Helper to get option code from Scapy option
            # Scapy options: [('message-type', 1), ('param_req_list', [1, 3]), 'end']
            
            # We need a reliable Name -> Code map.
            from scapy.layers.dhcp import DHCPOptions
            NAME_TO_CODE = {}
            for k, v in DHCPOptions.items():
                if isinstance(v, str):
                    NAME_TO_CODE[v] = k
                elif hasattr(v, 'name'):
                    NAME_TO_CODE[v.name] = k
                    
            # Add some manual overrides if needed
            NAME_TO_CODE['message-type'] = 53
            NAME_TO_CODE['requested_addr'] = 50
            NAME_TO_CODE['client_FQDN'] = 81
            NAME_TO_CODE['max_dhcp_size'] = 57
            NAME_TO_CODE['param_req_list'] = 55
            
            present_options = []
            request_list_str = "00"
            
            for opt in dhcp_options:
                if opt == 'end':
                    continue
                    
                name = ""
                val = None
                code = 0
                
                if isinstance(opt, tuple):
                    name = opt[0]
                    val = opt[1]
                else:
                    name = opt
                    
                # Get Code
                if isinstance(name, int):
                    code = name
                elif name in NAME_TO_CODE:
                    code = NAME_TO_CODE[name]
                else:
                    continue # Unknown option
                    
                # Process specific options
                if code == 50: # Requested IP
                    ip_char = 'i'
                elif code == 81: # FQDN
                    fqdn_char = 'd'
                elif code == 53: # Message Type
                    if isinstance(val, int):
                        type_str = DHCP_MSG_TYPES.get(val, f"{val:05d}")
                elif code == 57: # Max Size
                    if isinstance(val, int):
                        size_str = f"{min(val, 9999):04d}"
                elif code == 55: # Request List
                    # val should be a list of ints (codes)
                    if isinstance(val, list):
                        # JA4D: hyphen separated list of codes
                        request_list_str = "-".join(str(x) for x in val)
                    elif isinstance(val, bytes):
                         # parse bytes? Scapy usually handles this.
                         pass
                
                # Add to options list (exclude used options)
                # JA4D Spec: "ignoring options 50, 53, 81, and 255"
                # We do NOT exclude 55 (Request List) or 57 (Max Size) from the options list, 
                # even though they are used in other parts, based on the sample "55-57-..."
                if code not in [50, 53, 81, 255]:
                    present_options.append(str(code))
            
            options_str = "-".join(present_options)
            if not options_str:
                options_str = "00"
                
            if not request_list_str:
                request_list_str = "00"
                
            # JA4D Format: TypeSizeIpFqdn_Options_RequestList
            # e.g. reqst1500in_55-57-61-51-12_1-121-3-6-15-108-114-119-252
            return f"{type_str}{size_str}{ip_char}{fqdn_char}_{options_str}_{request_list_str}"
            
        except Exception as e:
            print(f"Error calculating JA4D (v4): {e}")
            return None

    # Check for DHCPv6
    if HAS_DHCP6:
        # Scapy DHCPv6 packets usually start with one of the message types
        # We can check if the packet has any of the DHCPv6 layers
        # Or check UDP ports 546/547
        if packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            if sport in [546, 547] or dport in [546, 547]:
                try:
                    # Find the DHCPv6 layer
                    dhcp6_layer = None
                    msg_type_val = 0
                    
                    # Iterate layers to find DHCPv6 message
                    current = packet
                    while current:
                        # Check if it's a DHCPv6 message layer (has msgtype)
                        if hasattr(current, 'msgtype'):
                            dhcp6_layer = current
                            msg_type_val = current.msgtype
                            break
                        if hasattr(current, 'payload'):
                            current = current.payload
                        else:
                            break
                            
                    if not dhcp6_layer:
                        return None
                        
                    # 1. Proto (v6='6')
                    proto = '6'
                    
                    # 2. IP (IA_NA=3 or IA_TA=4)
                    ip_char = 'n'
                    
                    # 3. FQDN (Client FQDN=39)
                    fqdn_char = 'n'
                    
                    # 4. Type
                    type_str = DHCP6_MSG_TYPES.get(msg_type_val, f"{msg_type_val:05d}")
                    
                    # 5. Size (Client ID length)
                    size_str = "0000"
                    
                    # 6. Options List
                    present_options = []
                    
                    # 7. Request List (ORO=6)
                    request_list_str = "00"
                    
                    # Iterate options (layers following the message)
                    # Scapy DHCPv6 options are layers nested in payload? 
                    # Actually Scapy 2.4.3+ structure: DHCP6_Solicit() / DHCP6OptClientId() / ...
                    # So we iterate .payload
                    
                    opt_current = dhcp6_layer.payload
                    while opt_current:
                        # Check if it's an option layer
                        # Most have 'optcode'
                        if hasattr(opt_current, 'optcode'):
                            code = opt_current.optcode
                            
                            # Process specific options
                            if code == 1: # Client ID
                                # Size is length of DUID?
                                # Use optlen if available (parsed from wire)
                                if hasattr(opt_current, 'optlen') and opt_current.optlen is not None:
                                    size_str = f"{min(opt_current.optlen, 9999):04d}"
                                else:
                                    # Fallback: calculate from layer length minus payload length
                                    # This is tricky because payload might be None or NoPayload
                                    total_len = len(opt_current)
                                    payload_len = len(opt_current.payload) if opt_current.payload else 0
                                    # Option header is 4 bytes (Code + Len)
                                    # So data length = Total - Payload - 4?
                                    # Or just use Total - Payload - 4.
                                    # But len(opt_current) includes header.
                                    # JA4D size is the length of the *value* (DUID).
                                    calc_len = total_len - payload_len - 4
                                    if calc_len < 0: calc_len = 0
                                    size_str = f"{min(calc_len, 9999):04d}"
                                    
                            elif code in [3, 4]: # IA_NA, IA_TA
                                ip_char = 'i'
                            elif code == 39: # Client FQDN
                                fqdn_char = 'd'
                            elif code == 6: # ORO
                                if hasattr(opt_current, 'reqopts'):
                                    reqs = opt_current.reqopts
                                    if isinstance(reqs, list):
                                        request_list_str = "-".join(str(x) for x in reqs)
                                        
                            # Add to options list
                            # JA4D6 Spec sample "8-1-3-39-16-6" includes 1, 3, 39, 6.
                            # So we do NOT exclude them.
                            # We only exclude what? Maybe nothing if Message Type is not an option.
                            # But we should probably exclude internal/padding if any?
                            # For now, include all options found in the list.
                            present_options.append(str(code))
                                
                        if hasattr(opt_current, 'payload'):
                            opt_current = opt_current.payload
                        else:
                            break
                            
                    options_str = "-".join(present_options)
                    if not options_str:
                        options_str = "00"
                        
                    # JA4D6 Format: TypeSizeIpFqdn_Options_RequestList
                    # e.g. solct0014nn_8-1-3-39-16-6_17-23-24-39
                    return f"{type_str}{size_str}{ip_char}{fqdn_char}_{options_str}_{request_list_str}"

                except Exception as e:
                    print(f"Error calculating JA4D (v6): {e}")
                    return None

    return None
