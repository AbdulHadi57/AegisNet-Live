# AegisNet Traffic Capture & Feature Extraction

## Overview
AegisNet is a sophisticated network traffic analysis tool designed to capture packets, reconstruct flows, and extract a rich set of features for security analysis. It combines **CICFlowMeter** statistical features, **DoH (DNS over HTTPS)** detection, and the full suite of **JA4+ Fingerprints**.

## Features

### 1. Traffic Capture & Flow Reconstruction
*   **Bidirectional Flows**: Groups packets into flows based on 5-tuple (Src IP, Dst IP, Src Port, Dst Port, Protocol).
*   **IPv4 & IPv6 Support**: Fully supports both IP versions.
*   **Timeout Management**: Automatically handles flow termination based on idle time or max duration.

### 2. JA4+ Fingerprinting
AegisNet implements the complete JA4+ suite to fingerprint various protocols:

| Fingerprint | Description | Format |
|---|---|---|
| **JA4** | TLS Client | `ProtocolVersionSNICipherLenExtLenALPN_CipherHash_ExtHash` |
| **JA4S** | TLS Server | `ProtocolVersionExtLenALPN_CipherHash_ExtHash` |
| **JA4H** | HTTP Client | `MethodVersionCookieRefererHeaderCountLang_HeaderHash_CookieNameHash_CookieValueHash` |
| **JA4T** | TCP Client | `WindowSize_Options_MSS_WindowScale` |
| **JA4L** | Latency | `Latency_TTL_AppLatency` (Client & Server) |
| **JA4SSH** | SSH Traffic | `ClientModeServerMode_ClientPktsServerPkts_ClientAcksServerAcks` |
| **JA4X** | X.509 Certs | `IssuerHash_SubjectHash_ExtensionHash` |
| **JA4D** | DHCPv4 | `TypeSizeIpFqdn_Options_RequestList` |
| **JA4D6** | DHCPv6 | `TypeSizeIpFqdn_Options_RequestList` |

### 3. Statistical Features (CICFlowMeter)
Extracts over 80 statistical features per flow, including:
*   **Packet Lengths**: Min, Max, Mean, Std, Variance, Percentiles, Skew, Kurtosis.
*   **Inter-Arrival Times (IAT)**: Flow, Forward, Backward IAT statistics.
*   **Throughput**: Bytes/sec, Packets/sec.
*   **TCP Flags**: Counts of FIN, SYN, RST, PSH, ACK, URG, CWE, ECE.
*   **Payload Entropy**: Measures randomness to detect encryption.

### 4. DoH Detection (DoHLyzer)
*   **SNI Matching**: Detects known DoH providers (Google, Cloudflare, etc.) via TLS SNI.
*   **Port Analysis**: Checks for usage of ports 443 and 853.
*   **Statistical Indicators**: Extracts features relevant for ML-based DoH detection.

## Usage

### Prerequisites
*   Python 3.x
*   `scapy`, `pandas`, `numpy`, `scipy`
*   Root privileges (for packet capture)

### Running the Capture
```bash
sudo python3 aegisnet_capture.py -i <interface> -o <output_dir>
```
*   `-i, --interface`: Network interface to listen on (e.g., `eth0`, `wlan0`).
*   `-o, --output`: Directory to save CSV files.
*   `-d, --duration`: (Optional) Capture duration in seconds.

## Testing & Verification

A comprehensive test suite `test_aegisnet_comprehensive.py` is included to verify feature extraction.

### Running the Test
```bash
sudo python3 test_aegisnet_comprehensive.py
```
This script:
1.  Starts `aegisnet_capture.py` in the background on the loopback interface (`lo`).
2.  Generates real traffic for TLS, HTTP, SSH, TCP, and DHCP.
3.  Analyzes the generated CSV to verify fingerprints are correctly calculated.

### Test Results
The implementation has been verified to correctly extract:
*   ✅ **JA4 / JA4S**: Correctly parses TLS ClientHello and ServerHello.
*   ✅ **JA4H**: Correctly parses HTTP methods, headers, and cookies.
*   ✅ **JA4T**: Correctly extracts TCP window and options from SYN packets.
*   ✅ **JA4L**: Correctly calculates latency from TCP 3-way handshake timestamps.
*   ✅ **JA4SSH**: Correctly fingerprints SSH sessions (including partial flows < 200 packets).
*   ✅ **General Features**: Validated flow duration, packet counts, and entropy calculations.

*Note: DHCP (JA4D/JA4D6) and some TLS Certificate (JA4X) features may not trigger on loopback interfaces during testing due to broadcast/multicast limitations, but the logic has been code-reviewed and verified.*
