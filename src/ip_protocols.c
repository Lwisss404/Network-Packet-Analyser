#include <stdio.h>

#include "ip_protocols.h"

void parseTCP(const u_char *pktd, int payloadStart, int payloadLength, bpf_u_int32 caplen) 
{

    printf("\n");
    // Parse TCP starting at payloadStart
    printf("\n=-TCP Header...");

    int capLength = (int)caplen;

    // minimum header bounds check
    if (capLength < payloadStart + 20) { printf("\nTruncated TCP Header."); return; }

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
    if (capLength < payloadStart + tcpHeaderLength) { printf("\nTruncated TCP Header."); return; } 
    
    // TCP header cant be larger than available IP payload
    if (tcpHeaderLength > payloadLength) { printf("\nInvalid TCP Header Length."); return; }
        
    // options
    printf("\n=-TCP Options...");

    int tcpOptionsLength = tcpHeaderLength - 20;
    printf("\nOptions Length: %d bytes", tcpOptionsLength);
        
    if (tcpOptionsLength > 0) {
        printf("\nOptions: ");
        for (int i = payloadStart + 20; i < tcpPayloadStart; i++) {
            printf("%02x", pktd[i]);
        }
    }
                    
    // tcp payload
    printf("\n=-TCP Payload...");

    int tcpPayloadLength = payloadLength - tcpHeaderLength;
    printf("\nPayload Length: %d bytes", tcpPayloadLength);

    // payload bounds check
    if (capLength < tcpPayloadStart + tcpPayloadLength) { printf("\nTruncated TCP Payload."); return; }

    printf("\nPayload: ");
    if (tcpPayloadLength > 0)
    {
        for (int i = tcpPayloadStart; i < tcpPayloadStart + tcpPayloadLength; i++) {
            printf("%02x ", pktd[i]);
        }
    }
    else { printf(" [EMPTY]"); }

    return;

}

void parseUDP(const u_char *pktd, int payloadStart, int payloadLength, bpf_u_int32 caplen)
{

    printf("\n");
    // Parse UDP starting at payloadStart
    printf("\n=-UDP Header...");

    int capLength = (int)caplen;

    // minimim header bounds ckeck
    if (capLength < payloadStart + 8) { printf("\nTruncated UDP Header."); return; }

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

    printf("\n=-UDP Payload...");

    // determinig start of tcp payload
    int udpHeaderLength = 8;
    int udpPayloadLength = udpLength - udpHeaderLength;
    int udpPayloadStart = payloadStart + udpHeaderLength;
    printf("\nPayload Length: %d bytes", udpPayloadLength);

    // payload bounds check
    if (capLength < udpPayloadStart + udpPayloadLength) { printf("\nTruncated UDP Payload."); return; }

    printf("\nPayload: ");
    if (udpPayloadLength != 0)
    {
        for (int i = udpPayloadStart; i < udpPayloadStart + udpPayloadLength; i++){
            printf("%02x ", pktd[i]);
        }
    } 
    else { printf(" [EMPTY]"); }

    return;

}

void parseICMP(const u_char *pktd, int payloadStart, int totalLength, int ipHeaderLength, bpf_u_int32 caplen) 
{

    printf("\n");
    // parse ICMP starting at payloadStart
    printf("\n=-ICMP Header...");

    int capLength = (int)caplen;
    
    // minimum header bounds check
    if (capLength < payloadStart + 8) { printf("\nTruncated ICMP Header."); return; }

    int icmpLength = totalLength - ipHeaderLength;
    if (icmpLength < 8) { printf("\nTruncated ICMP Header."); return; }

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
        int icmpPayloadLength = icmpLength - icmpHeaderLength;
        int icmpPayloadStart = payloadStart + icmpHeaderLength;

        printf("\n=-Echo Payload...");
        printf("\nPayload Length: %d bytes", icmpPayloadLength);
        
        // payload bounds check
        if (capLength < icmpPayloadStart + icmpPayloadLength) { printf("\nTruncated Echo Payload"); return; }

        printf("\nPayload: ");
        if (icmpPayloadLength > 0)
        {
            for (int i = icmpPayloadStart; i < icmpPayloadStart + icmpPayloadLength; i++){
                printf("%02x ", pktd[i]);
            }
        }
        else { printf(" [EMPTY]"); }
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
        if (capLength < originalIPStart + 20) { printf("\nTruncated Original IPv4 Header."); return; }

        printf("\n\n-Original IPv4 Packet...");

        // original source IP
        printf("\nSource IP: %u.%u.%u.%u", pktd[originalIPStart + 12], pktd[originalIPStart + 13], pktd[originalIPStart + 14], pktd[originalIPStart + 15]);

        // original destination IP
        printf("\nDestination IP: %u.%u.%u.%u", pktd[originalIPStart + 16], pktd[originalIPStart + 17], pktd[originalIPStart + 18], pktd[originalIPStart + 19]);

        // original protocol
        int originalProtocol = pktd[originalIPStart + 9];

        printf("\nProtocol: %d", originalProtocol);

        if (originalProtocol == 6) { printf(" (TCP)"); }
        else if (originalProtocol == 17) { printf(" (UDP)"); }
        else if (originalProtocol == 1) { printf(" (ICMP)"); }

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
        if (capLength < originalIPStart + 20) { printf("\nTruncated Original IPv4 Header."); return; }

        printf("\n\n-Original IPv4 Packet...");

        // original source IP
        printf("\nSource IP: %u.%u.%u.%u", pktd[originalIPStart + 12], pktd[originalIPStart + 13], pktd[originalIPStart + 14], pktd[originalIPStart + 15]);

        // original destination IP
        printf("\nDestination IP: %u.%u.%u.%u", pktd[originalIPStart + 16], pktd[originalIPStart + 17], pktd[originalIPStart + 18], pktd[originalIPStart + 19]);

        // original protocol
        int originalProtocol = pktd[originalIPStart + 9];

        printf("\nProtocol: %d", originalProtocol);

        if (originalProtocol == 6) { printf(" (TCP)"); }
        else if (originalProtocol == 17) { printf(" (UDP)"); }
        else if (originalProtocol == 1) { printf(" (ICMP)"); }
    
    }
    else 
    {
        printf("\nUnsupported Message Type.");
    }

    return;
}


void parseICMPv6(const u_char *pktd, int payloadStart, int payloadLength, bpf_u_int32 caplen) 
{

    printf("\n");
    // parse ICMPv6 starting at payloadStart
    printf("\n=-ICMPv6 Header...");

    int capLength = (int)caplen;

    // minimum header bounds check
    if (capLength < payloadStart + 4) { printf("\nTruncated ICMPv6 Header."); return; }
    if (payloadLength < 4) { printf("\nTruncated ICMPv6 Header."); return; }

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

        printf("\n=-Echo Payload...");
        printf("\nPayload Length: %d bytes", icmpv6PayloadLength);
        
        printf("\nPayload: ");

        // payload existence check
        if (icmpv6PayloadLength == 0) { printf("[EMPTY]"); return; }
        else if (icmpv6PayloadLength < 0) { printf("[Invalid Echo Payload Length]"); return; }

        // payload bounds check
        if (capLength < icmpv6PayloadStart + icmpv6PayloadLength) { printf("[Truncated]"); return; }

        for (int i = icmpv6PayloadStart; i < icmpv6PayloadStart + icmpv6PayloadLength; i++){
            printf("%02x ", pktd[i]);
        }

    }
    else if (type == 135)
    {

        printf("\n-Neighbour Solicitation");

        if (payloadLength < 24) { printf("\nTruncated Neighbour-Solicitation Payload."); return; }
        if (capLength < payloadStart + 24) { printf("\nTruncated Neighbour-Solicitation Payload."); return; }

        // reserved
        int reserved = binTOdec(pktd, payloadStart + 4, payloadStart + 7);
        printf("\nReserved: %d", reserved);

        // target IPv6 address
        printf("\nTarget IPv6 Address: ");
        printIPv6Address(pktd, payloadStart + 8);

        // determining start of options
        int optionsStart = payloadStart + 24;
        int optionsLength = payloadLength - 24;
        if (parseICMPv6Options(pktd, optionsStart, optionsLength, capLength) == ICMPV6_OPTIONS_ERROR) { return; }

    }
    else if (type == 136)
    {

        printf("\n-Neighbour Advertisement");

        // bounds check
        if (payloadLength < 24) { printf("\nTruncated Neighbour-Advertisement Payload."); return; }
        if (capLength < payloadStart + 24) { printf("\nTruncated Neighbour-Advertisement Payload."); return; }

        // flags
        int R = (pktd[payloadStart + 4] >> 7) & 0x01;
        int S = (pktd[payloadStart + 4] >> 6) & 0x01;
        int O = (pktd[payloadStart + 4] >> 5) & 0x01;
        printf("\nFlags: \nR: %d \nS: %d \nO: %d", R, S, O);

        // target address
        printf("\nTarget Address: ");
        printIPv6Address(pktd, payloadStart + 8);

        // determining start of options
        int optionsStart = payloadStart + 24;
        int optionsLength = payloadLength - 24;
        if (parseICMPv6Options(pktd, optionsStart, optionsLength, capLength) == ICMPV6_OPTIONS_ERROR) { return; }

    }
    else if (type == 133) 
    {

        printf("\n-Router Solicitation");

        // bounds check
        if (payloadLength < 8) { printf("\nTruncated Router-Solicitation Payload."); return; }
        if (capLength < payloadStart + 8) { printf("\nTruncated Router-Solicitation Payload."); return; }

        // reserved
        int reserved = binTOdec(pktd, payloadStart + 4, payloadStart + 7);
        printf("\nReserved: %d", reserved);

        // determining start of options
        int optionsStart = payloadStart + 8;
        int optionsLength = payloadLength - 8;
        if (parseICMPv6Options(pktd, optionsStart, optionsLength, capLength) == ICMPV6_OPTIONS_ERROR) { return; }

    }
    else if (type == 134)
    {

        printf("\n-Router Advertisement");

        // bounds check
        if (payloadLength < 16) { printf("\nTruncated Router-Advertisement Payload."); return; }
        if (capLength < payloadStart + 16) { printf("\nTruncated Router-Advertisement Payload."); return; }

        // hop limit
        int hopLimit = pktd[payloadStart + 4];
        printf("\nHop Limit: %d", hopLimit);

        // flags
        int M = (pktd[payloadStart + 5] >> 7) & 0x01;
        int O = (pktd[payloadStart + 5] >> 6) & 0x01;
        printf("\nFlags: \nM: %d \nO: %d", M, O);

        // router lifetime
        int routerLifetime = binTOdec(pktd, payloadStart + 6, payloadStart + 7);
        printf("\nRouter Lifetime: %d", routerLifetime);

        // reachable time
        int reachableTime = binTOdec(pktd, payloadStart + 8, payloadStart + 11);
        printf("\nReachable Time: %d", reachableTime);

        // retransmission timer
        int retransTimer = binTOdec(pktd, payloadStart + 12, payloadStart + 15);
        printf("\nRetransmission Timer: %d", retransTimer);

        // determining start of options
        int optionsStart = payloadStart + 16;
        int optionsLength = payloadLength - 16;
        if (parseICMPv6Options(pktd, optionsStart, optionsLength, capLength) == ICMPV6_OPTIONS_ERROR) { return; }

    }
    else if (type == 1)
    {

        printf("\n-Destination Unreachable");

        if (payloadLength < 8) { printf("\nTruncated Destination-Unreachable Payload."); return; }
        if (capLength < payloadStart + 8) { printf("\nTruncated Destination-Unreachable Payload."); return; }
        
        // code
        printf("\nCode %d: ", code);
        switch (code)
        {
            case 0: printf("No route to destination"); break;
            case 1: printf("Communication with destination administratively prohibited"); break;
            case 2: printf("Beyond scope of source address"); break;
            case 3: printf("Address unreachable"); break;
            case 4: printf("Port unreachable"); break;
            case 5: printf("Source address failed ingress/egress policy"); break;
            case 6: printf("Reject route to destination"); break;
            case 7: printf("Error in Source Routing Header"); break;
            default: break;
        }
        
        // unused
        int unused = binTOdec(pktd, payloadStart + 4, payloadStart + 7);
        printf("\nUnused: %d", unused);

        // original packet
        int originalPacketStart = payloadStart + 8;
        int originalPacketLength = payloadLength - 8;

        if (originalPacketLength < 1) { printf("\nTruncated Original Packet Header."); return; }
        if (capLength < originalPacketStart + 1) { printf("\nTruncated Original Packet Header."); return; }

        // version
        int version = (pktd[originalPacketStart] >> 4) & 0x0F;
        if (version == 4)
        {
            
            printf("\n-Original Packet: IPv4");

            if (originalPacketLength < 20) { printf("\nTruncated Original IPv4 Header."); return; }
            if (capLength < originalPacketStart + 20) { printf("\nTruncated Original IPv4 Header."); return; }

            // ihl
            int ihl = pktd[originalPacketStart] & 0x0F;
            if (ihl < 5) { printf("\nInvalid IPv4 Header Length."); return; }
            int ipHeaderLength = ihl * 4;

            // actual header bounds check
            if (capLength < originalPacketStart + ipHeaderLength) { printf("\nTruncated Original IPv4 Header."); return; }
            printf("\nIHL: %d", ihl);

            // tos
            int tos = pktd[originalPacketStart + 1];
            printf("\nType Of Service: %d", tos);

            // total length
            int totalLength = binTOdec(pktd, originalPacketStart + 2, originalPacketStart + 3);
            printf("\nTotal Length: %d bytes", totalLength);
            if (totalLength < ipHeaderLength) { printf("\nInvalid IPv4 Total Length."); return; }

            // embedded packet bounds check
            if (originalPacketLength < totalLength) { printf("\nTruncated Original IPv4 Packet."); return; }

            // captured packet bounds check
            if (capLength < originalPacketStart + totalLength) { printf("\nTruncated Original IPv4 Packet."); return; }

            // Protocol
            int originalProtocol = pktd[originalPacketStart + 9];
            printf("\nProtocol: %d", originalProtocol);

            if (originalProtocol == 6) { printf(" (TCP)"); }
            else if (originalProtocol == 17) { printf(" (UDP)"); }
            else if (originalProtocol == 1) { printf(" (ICMP)"); }

            // source and destination IPs
            printf("\nSource IP: %u.%u.%u.%u", pktd[originalPacketStart + 12], pktd[originalPacketStart + 13], pktd[originalPacketStart + 14], pktd[originalPacketStart + 15]);
            printf("\nDestination IP: %u.%u.%u.%u", pktd[originalPacketStart + 16], pktd[originalPacketStart + 17], pktd[originalPacketStart + 18], pktd[originalPacketStart + 19]);

        }
        else if (version == 6)
        {

            printf("\n-Original Packet: IPv6");

            if (originalPacketLength < 40) { printf("\nTruncated Original IPv6 Header."); return; }
            if (capLength < originalPacketStart + 40) { printf("\nTruncated Original IPv6 Header."); return; }

            // Traffic Class
            int trafficClass = ((pktd[originalPacketStart] & 0x0F) << 4) | ((pktd[originalPacketStart + 1] >> 4) & 0x0F);
            printf("\nTraffic Class: %d", trafficClass);

            // Flow Label
            uint32_t flowLabel = ((uint32_t)(pktd[originalPacketStart] & 0x0F) << 16) | ((uint32_t)pktd[originalPacketStart + 1] << 8) | pktd[originalPacketStart + 2];
            printf("\nFlow Label: %" PRIu32, flowLabel);

            // Payload Length
            int payloadLength = binTOdec(pktd, originalPacketStart + 4, originalPacketStart + 5 );
            printf("\nPayload Length: %d bytes", payloadLength);
            
            // Next Header
            int nextHeader = pktd[originalPacketStart + 6];
            printf("\nNext Header: %d", nextHeader);
            
            if (nextHeader == 6) { printf(" (TCP)"); }
            else if (nextHeader == 17) { printf(" (UDP)"); }
            else if (nextHeader == 58) { printf(" (ICMPv6)"); }
            else if (nextHeader == 59) { printf(" (No Next Header)"); }
        
            // Hop Limit
            int hopLimit = pktd[originalPacketStart + 7];    
            printf("\nHop Limit: %d", hopLimit);

            // Source Address
            printf("\nSource Address: ");
            printIPv6Address(pktd, originalPacketStart + 8);

            // Destination Address
            printf("\nDestination Address: ");
            printIPv6Address(pktd, originalPacketStart + 24);

        }
        else { printf("\nInvalid Original Packet Version"); }

    }

}
