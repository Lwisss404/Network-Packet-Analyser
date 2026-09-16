#include <stdio.h>

#include "ip_protocols.h"

void parseTCP(const u_char *pktd, int payloadStart, int payloadLength, bpf_u_int32 caplen) 
{

    printf("\n");
    // Parse TCP starting at payloadStart
    printf("\n=- TCP Header...");

    int caplength = (int)caplen;

    // minimum header bounds check
    if (caplength < payloadStart + 20) { printf("\nTruncated TCP Header."); return; }

    // source port
    int tcpSourcePort = binTOdec(pktd, payloadStart, payloadStart + 1);
    printf("\nSource Port: %d", tcpSourcePort);

    // destination port
    int tcpDestinationPort = binTOdec(pktd, payloadStart + 2, payloadStart + 3);
    printf("\nDestination Port: %d", tcpDestinationPort);
                
    // sequence number
    uint32_t tcpSequenceNumber = binTOdec(pktd, payloadStart + 4, payloadStart + 7);
    printf("\nSequence Number: %" PRIu32, tcpSequenceNumber);

    // acknowledgment number
    uint32_t tcpAckNumber = binTOdec(pktd, payloadStart + 8, payloadStart + 11);
    printf("\nAchnowledgment Number: %" PRIu32, tcpAckNumber);    
        
    // data offset, reserved and ns flag
    int tcpDataOffset = (pktd[payloadStart + 12] >> 4) & 0x0F;
    printf("\nData Offset: %d", tcpDataOffset);
    if (tcpDataOffset < 5) { printf("\nInvalid TCP Header Length."); return; }

    int tcpReserved = (pktd[payloadStart + 12] >> 1) & 0x07;
    printf("\nReserved: %d", tcpReserved);
    
    int tcpNSFlag = pktd[payloadStart + 12] & 0x01;
    printf("\nNS Flag: %d", tcpNSFlag);
    
    // remaining flags
    u_char tcpFlags = pktd[payloadStart + 13];
    printf("\nCWR: %u", (tcpFlags >> 7) & 0x01);
    printf("\nECE: %u", (tcpFlags >> 6) & 0x01);
    printf("\nURG: %u", (tcpFlags >> 5) & 0x01);
    printf("\nACK: %u", (tcpFlags >> 4) & 0x01);
    printf("\nPSH: %u", (tcpFlags >> 3) & 0x01);
    printf("\nRST: %u", (tcpFlags >> 2) & 0x01);
    printf("\nSYN: %u", (tcpFlags >> 1) & 0x01);
    printf("\nFIN: %u", tcpFlags & 0x01);

    // window size
    int tcpWindowSize = binTOdec(pktd, payloadStart + 14, payloadStart + 15);
    printf("\nWindow Size: %d", tcpWindowSize);

    // checksum
    int tcpChecksum = binTOdec(pktd, payloadStart + 16, payloadStart + 17);
    printf("\nChecksum: 0x%04X", tcpChecksum);

    // urgent pointer
    int tcpUrgentPointer = binTOdec(pktd, payloadStart + 18, payloadStart + 19);
    printf("\nUrgent Pointer: 0x%04X", tcpUrgentPointer);

    // determinig start of tcp payload
    int tcpHeaderLength = tcpDataOffset * 4;
    int tcpPayloadStart = payloadStart + tcpHeaderLength;

    // actual header bounds check
    if (caplength < payloadStart + tcpHeaderLength) { printf("\nTruncated TCP Header."); return; } 
    
    // TCP header cant be larger than available IP payload
    if (tcpHeaderLength > payloadLength) { printf("\nInvalid TCP Header Length."); return; }
        
    // options
    printf("\n=- TCP Options...");

    int tcpOptionsLength = tcpHeaderLength - 20;
    printf("\nOptions Length: %d bytes", tcpOptionsLength);
        
    if (tcpOptionsLength > 0) {
        printf("\nOptions: ");
        for (int i = payloadStart + 20; i < tcpPayloadStart; i++) {
            printf("%02x", pktd[i]);
        }
    }
                    
    // tcp payload
    printf("\n=- TCP Payload...");

    int tcpPayloadLength = payloadLength - tcpHeaderLength;
    printf("\nPayload Length: %d bytes", tcpPayloadLength);

    // payload bounds check
    if (caplength < tcpPayloadStart + tcpPayloadLength) { printf("\nTruncated TCP Payload."); return; }

    printf("\nPayload: ");
    for (int i = tcpPayloadStart; i < tcpPayloadStart + tcpPayloadLength; i++) {
        printf("%02x ", pktd[i]);
    }

}

void parseUDP(const u_char *pktd, int payloadStart, int payloadLength, bpf_u_int32 caplen)
{

    printf("\n");
    // Parse UDP starting at payloadStart
    printf("\n=- UDP Header...");

    int caplength = (int)caplen;

    // minimim header bounds ckeck
    if (caplength < payloadStart + 8) { printf("\nTruncated UDP Header."); return; }

    // source port
    int udpSourcePort = binTOdec(pktd, payloadStart, payloadStart + 1);
    printf("\nSource Port: %d", udpSourcePort);

    // destination port
    int udpDestinationPort = binTOdec(pktd, payloadStart + 2, payloadStart + 3);
    printf("\nDestination Port: %d", udpDestinationPort);

    // length
    int udpLength = binTOdec(pktd, payloadStart + 4, payloadStart + 5);
    printf("\nLength: %d bytes", udpLength);
    if ((udpLength < 8) || (udpLength > payloadLength)) { printf("\nInvalid UDP Length."); return; }

    // checksum
    int udpChecksum = binTOdec(pktd, payloadStart + 6, payloadStart + 7);
    printf("\nChecksum: 0x%04X", udpChecksum);

    printf("\n=- UDP Payload...");

    // determinig start of tcp payload
    int udpHeaderLength = 8;
    int udpPayloadLength = udpLength - udpHeaderLength;
    int udpPayloadStart = payloadStart + udpHeaderLength;
    printf("\nPayload Length: %d bytes", udpPayloadLength);

    // payload bounds check
    if (caplength < udpPayloadStart + udpPayloadLength) { printf("\nTruncated UDP Payload."); return; }

    printf("\nPayload: ");
    for (int i = udpPayloadStart; i < udpPayloadStart + udpPayloadLength; i++){
        printf("%02x ", pktd[i]);
    }

    return;
}

void parseICMP(const u_char *pktd, int payloadStart, int totalLength, int ipHeaderLength, bpf_u_int32 caplen) 
{

    printf("\n");
    // parse ICMP starting at payloadStart
    printf("\n=- ICMP Header...");

    int caplength = (int)caplen;

    // minimum header bounds check
    if (caplength < payloadStart + 8) { printf("\nTruncated ICMP Header."); return; }

    // type
    int icmpType = binTOdec(pktd, payloadStart, payloadStart);
    printf("\nType: %d", icmpType);

    // code
    int icmpCode = binTOdec(pktd, payloadStart + 1, payloadStart + 1);
    printf("\nCode: %d", icmpCode);

    // checksum
    int icmpChecksum = binTOdec(pktd, payloadStart + 2, payloadStart + 3);
    printf("\nChecksum: 0x%04X", icmpChecksum);

    // parsing message types
    if (icmpType == 0 || icmpType == 8) 
    {

        printf("\n\n-Echo Request/Reply");

        // identifier
        int icmpIdentifier = binTOdec(pktd, payloadStart + 4, payloadStart + 5);
        printf("\nIdentifier: %d", icmpIdentifier);

        // sequence number
        int icmpSequenceNumber = binTOdec(pktd, payloadStart + 6, payloadStart + 7);
        printf("\nSequence Number: %d", icmpSequenceNumber);

        // determinig start of icmp payload
        int icmpHeaderLength = 8;
        int icmpLength = totalLength - ipHeaderLength;
        int icmpPayloadLength = icmpLength - icmpHeaderLength;
        int icmpPayloadStart = payloadStart + icmpHeaderLength;

        printf("\n=- ICMP Payload...");
        printf("\nPayload Length: %d bytes", icmpPayloadLength);
        
        // payload bounds check
        if (caplength < icmpPayloadStart + icmpPayloadLength) { printf("\nTruncated ICMP Payload"); return; }

        printf("\nPayload: ");
        for (int i = icmpPayloadStart; i < icmpPayloadStart + icmpPayloadLength; i++){
            printf("%02x ", pktd[i]);
        }

    }
    else if (icmpType == 3) 
    {

        printf("\n\n-Destination Unreachable");

        // determine reason from Code
        if (icmpCode == 0) { printf("\nReason: Network Unreachable"); } 
        else if (icmpCode == 1) { printf("\nReason: Host Unreachable"); }
        else if (icmpCode == 2) { printf("\nReason: Protocol Unreachable"); }
        else if (icmpCode == 3) { printf("\nReason: Port Unreachable"); }
        else if (icmpCode == 4) { printf("\nReason: Fragmentation Needed"); }
        else if (icmpCode == 5) { printf("\nReason: Source Route Failed"); }
        else { printf("\nReason: Unknown"); }

        // the original IPv4 packet starts after the 8-byte ICMP header
        int originalIPStart = payloadStart + 8;

        // original IPv4 packet existance check
        if (caplength < originalIPStart + 20) { printf("\nTruncated Original IPv4 Header."); return; }

        printf("\n\n- Original IPv4 Packet...");

        // original source IP
        printf("\nSource IP: %u.%u.%u.%u", pktd[originalIPStart + 12], pktd[originalIPStart + 13], pktd[originalIPStart + 14], pktd[originalIPStart + 15]);

        // original destination IP
        printf("\nDestination IP: %u.%u.%u.%u", pktd[originalIPStart + 16], pktd[originalIPStart + 17], pktd[originalIPStart + 18], pktd[originalIPStart + 19]);

        // original protocol
        int originalProtocol = pktd[originalIPStart + 9];

        printf("\nProtocol: %d", originalProtocol);

        if (originalProtocol == 6) { printf(" TCP"); }
        else if (originalProtocol == 17) { printf(" UDP"); }
        else if (originalProtocol == 1) { printf(" ICMP"); }

    }
    else if (icmpType == 11)
    {

        printf("\n\n-Time Exceeded");

        if (icmpCode == 0) { printf("\nTime To Live exceeded in transit."); }
        else if (icmpCode == 1) { printf("\nFragment Reassembly Time exceeded."); }
        else { printf("\nUnknown Time Exceeded code."); }

        // the original IPv4 packet starts after the 8-byte ICMP header
        int originalIPStart = payloadStart + 8;

        // original IPv4 packet existance check
        if (caplength < originalIPStart + 20) { printf("\nTruncated Original IPv4 Header."); return; }

        printf("\n\n- Original IPv4 Packet...");

        // original source IP
        printf("\nSource IP: %u.%u.%u.%u", pktd[originalIPStart + 12], pktd[originalIPStart + 13], pktd[originalIPStart + 14], pktd[originalIPStart + 15]);

        // original destination IP
        printf("\nDestination IP: %u.%u.%u.%u", pktd[originalIPStart + 16], pktd[originalIPStart + 17], pktd[originalIPStart + 18], pktd[originalIPStart + 19]);

        // original protocol
        int originalProtocol = pktd[originalIPStart + 9];

        printf("\nProtocol: %d", originalProtocol);

        if (originalProtocol == 6) { printf(" TCP"); }
        else if (originalProtocol == 17) { printf(" UDP"); }
        else if (originalProtocol == 1) { printf(" ICMP"); }
    
    }
    else 
    {
        printf("\nUnknown Message Type.");
    }

    return;
}


void parseICMPv6(const u_char *pktd, int payloadStart, int payloadLength, bpf_u_int32 caplen) 
{

    printf("\n");
    // parse ICMPv6 starting at payloadStart
    printf("\n=- ICMPv6 Header...");

    int caplength = (int)caplen;

    // minimum header bounds check
    if (caplength < payloadStart + 8) { printf("\nTruncated ICMPv6 Header."); return; }

    // type
    int type = pktd[payloadStart];
    printf("\nType: %d", type);

    // code
    int code = pktd[payloadStart + 1];
    printf("\nCode: %d", code);

    // checksum
    int checksum = binTOdec(pktd, payloadStart + 2, payloadStart + 3);
    printf("\nChecksum: 0x%04X", checksum);

    if (type == 128 || type == 129) 
    {

        printf("\n-Echo Request/Reply");

        // identifier
        int identifier = binTOdec(pktd, payloadStart + 4, payloadStart + 5);
        printf("\nIdentifier: %d", identifier);

        // sequence number
        int sequenceNumber = binTOdec(pktd, payloadStart + 6, payloadStart + 7);
        printf("\nSequence Number: %d", sequenceNumber);

        // determining start of icmpv6 payload
        int icmpv6HeaderLength = 8;
        int icmpv6PayloadStart = payloadStart + icmpv6HeaderLength;
        int icmpv6PayloadLength = payloadLength - icmpv6HeaderLength;

        printf("\n=- ICMP Payload...");
        printf("\nPayload Length: %d bytes", icmpv6PayloadLength);
        
        // payload existence check
        if (icmpv6PayloadLength == 0) { printf("\nNo Payload/Data Found."); return; }
        else if (icmpv6PayloadLength < 0) { printf("\nInvalid ICMPv6 Payload Length."); return; }

        // payload bounds check
        if (caplength < icmpv6PayloadStart + icmpv6PayloadLength) { printf("\nTruncated ICMPv6 Payload"); return; }

        printf("\nPayload: ");
        for (int i = icmpv6PayloadStart; i < icmpv6PayloadStart + icmpv6PayloadLength; i++){
            printf("%02x ", pktd[i]);
        }

    }
    else if (type == 135)
    {

        printf("\n-Neighbour Solicitation");

        // reserved
        int reserved = binTOdec(pktd, payloadStart + 4, payloadStart + 7);
        printf("\nReserved: %d", reserved);

        // target IPv6 address
        printf("\nTarget IPv6 Address: ");
        printIPv6Address(pktd, payloadStart + 8);

        // determining start of icmpv6 payload
        int icmpv6HeaderLength = 8;
        int icmpv6PayloadStart = payloadStart + icmpv6HeaderLength;
        int icmpv6PayloadLength = payloadLength - icmpv6HeaderLength;

        printf("\n=- ICMP Payload...");
        printf("\nPayload Length: %d bytes", icmpv6PayloadLength);
        
        // payload existence check
        if (icmpv6PayloadLength == 0) { printf("\nNo Payload/Data Found."); return; }
        else if (icmpv6PayloadLength < 0) { printf("\nInvalid ICMPv6 Payload Length."); return; }

        // payload bounds check
        if (caplength < icmpv6PayloadStart + icmpv6PayloadLength) { printf("\nTruncated ICMPv6 Payload"); return; }

        printf("\nPayload: ");
        for (int i = icmpv6PayloadStart; i < icmpv6PayloadStart + icmpv6PayloadLength; i++){
            printf("%02x ", pktd[i]);
        }

    }

}
