# Network Packet Analyser

A modular network packet analyser written in **C** using **libpcap**.

The project captures live network traffic from a selected network interface, applies user-defined **BPF (Berkeley Packet Filter)** expressions, and parses captured packets at the protocol level.

The main goal of the project was to gain practical experience with **network protocols, packet structure, raw byte parsing, memory safety, and network capture using libpcap**.

---

## Features

- Select a network interface available on the system
- Select the Ethernet protocol to analyse:
  - ARP
  - IPv4
  - IPv6
- Select transport/control protocols:
  - TCP
  - UDP
  - ICMP
  - ICMPv6
- Combine multiple protocol selections using a bitmask
- Dynamically construct BPF filters
- Capture packets using `libpcap`
- Parse packet headers directly from raw bytes
- Handle variable-length IPv4 headers
- Parse IPv6 extension headers
- Handle IPv4 and IPv6 fragmentation
- Parse protocol-specific headers and fields
- Validate packet lengths before accessing packet data
- Handle truncated packets safely
- Display packet information in a human-readable format

---

## Supported Protocols

### Ethernet

The analyser first examines the Ethernet frame and identifies its EtherType.

Currently supported:

| EtherType | Protocol |
|---|---|
| `0x0806` | ARP |
| `0x0800` | IPv4 |
| `0x86DD` | IPv6 |

### ARP

The ARP parser extracts and displays:

- Hardware type
- Protocol type
- Hardware address length
- Protocol address length
- Operation
- Sender MAC address
- Sender IPv4 address
- Target MAC address
- Target IPv4 address

### IPv4

The IPv4 parser handles:

- Version
- Internet Header Length (IHL)
- Type of Service
- Total Length
- Identification
- Flags
- Fragment Offset
- Time To Live (TTL)
- Protocol
- Header Checksum
- Source Address
- Destination Address

The parser also checks for fragmented packets and avoids interpreting a non-first fragment as a complete transport-layer packet.

### IPv6

The IPv6 parser handles:

- Version
- Traffic Class
- Flow Label
- Payload Length
- Next Header
- Hop Limit
- Source Address
- Destination Address

IPv6 extension headers currently handled include:

- Hop-by-Hop Options
- Routing
- Destination Options
- Fragment

The extension-header parser follows the `Next Header` chain until it reaches a supported upper-layer protocol.

### TCP

The TCP parser extracts:

- Source Port
- Destination Port
- Sequence Number
- Acknowledgement Number
- Data Offset
- Reserved bits
- NS flag
- CWR
- ECE
- URG
- ACK
- PSH
- RST
- SYN
- FIN
- Window Size
- Checksum
- Urgent Pointer

### UDP

The UDP parser extracts:

- Source Port
- Destination Port
- Length
- Checksum
- Payload

### ICMP

The ICMP parser currently handles common ICMP message types including:

- Echo Request
- Echo Reply
- Destination Unreachable
- Time Exceeded

For messages containing an embedded IPv4 packet, the parser also performs bounds checks before attempting to inspect the embedded packet.

### ICMPv6

The ICMPv6 parser currently handles:

- Echo Request
- Echo Reply
- Neighbor Solicitation
- Neighbor Advertisement
- Router Solicitation
- Router Advertisement
- Destination Unreachable

ICMPv6 options are parsed using the standard type-length-value structure.

---

## Project Structure

```text
Network-Packet-Analyser/
├── Makefile
├── include/
│   ├── capture.h
│   ├── interface.h
│   ├── parser.h
│   ├── ip_protocols.h
│   └── utils.h
├── src/
│   ├── main.c
│   ├── capture.c
│   ├── interface.c
│   ├── parser.c
│   ├── ip_protocols.c
│   └── utils.c
├── .gitignore
└── README.md
```

### Module Responsibilities

**`main.c`**

Controls the overall application flow and user interaction.

**`interface.c`**

Handles:

- Network interface selection
- Ethernet protocol selection
- IP protocol selection
- BPF filter construction

**`capture.c`**

Responsible for:

- Creating the libpcap capture handle
- Configuring the capture
- Activating the interface
- Compiling and applying BPF filters
- Receiving packets
- Passing captured packets to the parser

**`parser.c`**

Contains the main network-layer parsing logic:

- Ethernet
- ARP
- IPv4
- IPv6

**`ip_protocols.c`**

Contains upper-layer protocol parsers:

- TCP
- UDP
- ICMP
- ICMPv6

**`utils.c`**

Contains reusable parsing and conversion helpers, including:

- Binary-to-hexadecimal conversion
- Binary-to-decimal conversion
- IPv6 extension-header parsing
- ICMPv6 option parsing

---

## How It Works

The application follows this general flow:

```text
Start Program
     │
     ▼
Select Network Interface
     │
     ▼
Select Ethernet Protocol
     │
     ├── ARP
     │
     ├── IPv4 ──► Select TCP / UDP / ICMP
     │
     └── IPv6 ──► Select TCP / UDP / ICMPv6
     │
     ▼
Build BPF Filter
     │
     ▼
Configure libpcap
     │
     ▼
Start Packet Capture
     │
     ▼
Parse Ethernet Frame
     │
     ├── ARP
     │
     ├── IPv4
     │     └── TCP / UDP / ICMP
     │
     └── IPv6
           └── Extension Headers
                 └── TCP / UDP / ICMPv6
     │
     ▼
Display Packet Information
```

---

## BPF Filtering

The analyser uses **Berkeley Packet Filter (BPF)** expressions to restrict which packets are delivered to the application.

For example:

```text
ip and tcp
```

captures IPv4 TCP traffic, while:

```text
ip and (tcp or udp)
```

captures both IPv4 TCP and UDP traffic.

For IPv6:

```text
ip6 and icmp6
```

captures ICMPv6 traffic.

ARP traffic is filtered using:

```text
arp
```

The filter is constructed according to the protocol selections made by the user.

---

## Capture Configuration

The capture handle is configured before activation to provide reliable packet delivery on BSD-derived systems such as macOS.

The capture uses:

- A snapshot length of `65535` bytes
- Promiscuous mode
- A 1-second capture timeout
- Immediate mode

Immediate mode is particularly useful for interactive packet analysis because packets are delivered to the application as they arrive instead of waiting for the capture buffer to fill.

---

## Safety and Validation

Because packet data is received as raw bytes, the parser performs bounds checks before accessing packet fields.

Checks include:

- Minimum header sizes
- Capture-length validation
- Protocol header lengths
- IPv4 IHL validation
- IPv4 total-length validation
- IPv6 payload-length validation
- TCP data-offset validation
- UDP length validation
- IPv6 extension-header length validation
- Fragment-header bounds checks
- ICMP/ICMPv6 minimum lengths
- Embedded packet bounds checks

The parser distinguishes between the **captured length** and the protocol-declared packet length to avoid reading beyond the data actually provided by libpcap.

---

## Requirements

- GCC or another C compiler supporting C11
- `libpcap`
- A network interface accessible to libpcap

The project has been developed and tested on **macOS**.

Linux and other Unix-like systems using libpcap should require little modification, although interface names, permissions, and packet-link-layer behavior may differ between operating systems.

---

## Building

Clone the repository:

```bash
git clone <repository-url>
cd Network-Packet-Analyser
```

Build the project:

```bash
make
```

This produces:

```text
npa
```

To remove the compiled executable:

```bash
make clean
```

---

## Running

Start the analyser:

```bash
./npa
```

Depending on the operating system and interface permissions, packet capture may require elevated privileges.

For example, on systems where required:

```bash
sudo ./npa
```

The application will guide you through:

1. Network interface selection
2. Ethernet protocol selection
3. IP protocol selection
4. Packet limit selection
5. Packet capture and parsing

---

## Example

A typical IPv4 ICMP capture can produce information such as:

```text
EtherType: 0x0800 IPv4

IPv4 Header:
Version: 4
IHL: 5
Total Length: 84
TTL: 64
Protocol: 1 ICMP
Source: 192.168.1.10
Destination: 8.8.8.8

ICMP:
Type: 8 Echo Request
Code: 0
Checksum: ...
```

The exact output depends on the captured packet and selected protocol.

---

## What I Learned

This project was built primarily as a practical learning project in **C and network security**.

It provided hands-on experience with:

- Network protocol structures
- Ethernet frames
- IPv4 and IPv6 headers
- TCP and UDP
- ICMP and ICMPv6
- IPv6 extension headers
- Packet fragmentation
- BPF filtering
- `libpcap`
- Pointer arithmetic
- Byte offsets and bit manipulation
- Network byte order
- Defensive parsing
- Buffer and length validation
- Modular C project organization
- Makefiles and multi-file compilation

A major part of the project was understanding that packet data cannot be treated like normal structured C data. Every field has to be interpreted from a specific byte offset, while accounting for variable header sizes and the possibility of truncated or malformed packets.

---

## Limitations

This project is intended as a **packet-analysis and learning tool**, not a replacement for mature tools such as Wireshark or tcpdump.

Current limitations include:

- Limited protocol coverage
- No packet export functionality
- No packet reassembly
- No TCP stream reconstruction
- No checksum verification
- No graphical interface
- Limited interpretation of protocol payloads
- Capture behavior can vary between operating systems and link-layer types

These limitations are intentional boundaries for the current version of the project.

---

## Future Improvements

Possible future extensions include:

- More ICMP/ICMPv6 message types
- Additional IPv6 extension headers
- TCP/UDP payload inspection
- Checksum verification
- Packet statistics
- Capture duration controls
- Packet timestamps
- Saving captured packets to a file
- PCAP file replay
- Additional BPF filtering options
- Support for more link-layer types

---

## License

This project is provided for educational and portfolio purposes.

If you use or modify the project, please refer to the repository's license information.