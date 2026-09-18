#include <stdio.h>

#include "parser.h"


void parsePacket(struct pcap_pkthdr *pkth, const u_char *pktd, int packetCount)  
{

    printf("\n\n\n==>Packet Number: %d", packetCount);
    printf("\nCaptured Length(Bytes): %u", pkth->caplen);
    printf("\nPacket Length(Bytes): %u", pkth->len);

    char buf[5];
    if (pkth->caplen >= 14) {
        char buffer[18];

        snprintf(buffer, sizeof(buffer), "%02X:%02X:%02X:%02X:%02X:%02X", pktd[0], pktd[1], pktd[2], pktd[3], pktd[4], pktd[5] );
        printf("\nDestination MAC: %s", buffer);

        snprintf(buffer, sizeof(buffer), "%02X:%02X:%02X:%02X:%02X:%02X", pktd[6], pktd[7], pktd[8], pktd[9], pktd[10], pktd[11] );
        printf("\nSource MAC: %s", buffer);

        binTOhex(buf, pktd, 12, 13);
        printf("\nEtherType: 0x%s", buf);
        if (strcmp(buf, "0806") == 0) { printf(" ARP "); parseARP(pktd, pkth->caplen); }
        else if (strcmp(buf, "0800") == 0) { printf(" IPv4 "); parseIPv4(pktd, pkth->caplen); }
        else if ((strcmp(buf, "86DD") == 0) || (strcmp(buf, "86dd") == 0)) { printf(" IPv6 "); parseIPv6(pktd, pkth->caplen); }
    }

}


void parseARP(const u_char *pktd, bpf_u_int32 caplen) 
{

    printf("\n");
    printf("\n=== ARP Header ===\n");

    int capLength = (int)caplen;

    // packet bounds check
    if (capLength < 42) { printf("\nTruncated ARP Packet."); return; }

    // determining start of arp packet
    int arpStart = 14;

    // hardware type
    int hardwareType = binTOdec(pktd, arpStart, arpStart + 1);
    printf("\nHardware Type: %d", hardwareType);
    if (hardwareType != 1) { printf("\nUnsupported Hardware Type."); return; }

    // protocol type
    int protocolType = binTOdec(pktd, arpStart + 2, arpStart + 3);
    printf("\nProtocol Type: %d", protocolType);
    if (protocolType != 0x0800) { printf("\nUnsupported Protocol Type."); return; }

    // hardware address length
    int hardwareLength = binTOdec(pktd, arpStart + 4, arpStart + 4);
    printf("\nHardware Length: %d", hardwareLength);
    if (hardwareLength != 6) { printf("\nUnsupported Hardware Length."); return; }

    // protocol address length
    int protocolLength = binTOdec(pktd, arpStart + 5, arpStart + 5);
    printf("\nProtocol Length: %d", protocolLength);
    if (protocolLength != 4) { printf("\nUnsupported Protocol Length."); return; }


    // operation
    int operation = binTOdec(pktd, arpStart + 6, arpStart + 7);
    printf("\nOperation: %d", operation);

    if (operation == 1) { printf(" ARP Request]\n"); }
    else if (operation == 2) { printf(" [ARP Reply]\n"); }
    else { printf(" [Unknown Operation]\n"); return; }

    // sender MAC
    printf("\nSender MAC: %02X:%02X:%02X:%02X:%02X:%02X", pktd[arpStart + 8], pktd[arpStart + 9], pktd[arpStart + 10], pktd[arpStart + 11], pktd[arpStart + 12], pktd[arpStart + 13]);

    // sender IP
    printf("\nSender IP: %u.%u.%u.%u", pktd[arpStart + 14], pktd[arpStart + 15], pktd[arpStart + 16], pktd[arpStart + 17]);

    // target MAC
    printf("\nTarget MAC: %02X:%02X:%02X:%02X:%02X:%02X", pktd[arpStart + 18], pktd[arpStart + 19], pktd[arpStart + 20], pktd[arpStart + 21], pktd[arpStart + 22], pktd[arpStart + 23]);

    // target IP
    printf("\nTarget IP: %u.%u.%u.%u", pktd[arpStart + 24], pktd[arpStart + 25], pktd[arpStart + 26], pktd[arpStart + 27]);

}


void parseIPv4(const u_char *pktd, bpf_u_int32 caplen) 
{

    printf("\n");
    printf("\n=== IPv4 Header ===\n");

    int capLength = (int)caplen;

    // determining start of ipv4 packet
    int ipv4Start = 14;

    // minimum header bounds check
    if (capLength < 34) { printf("\nTruncated IPv4 Header."); return; }

    // version check
    int version = (pktd[ipv4Start] >> 4) & 0x0F;
    if (version != 4) { printf("\nUnsupported IP Version."); return; }

    // determining start of the payload
    int ihl = pktd[ipv4Start] & 0x0F;
    if (ihl < 5) { printf("\nInvalid IPv4 Header Length."); return; }
    int ipHeaderLength = ihl * 4;

    // actual header bounds check
    if (capLength < ipv4Start + ipHeaderLength) { printf("\nTruncated IPv4 Header."); return; }

    int payloadStart = ipv4Start + ipHeaderLength;
    printf("\nPayload Start: %d", payloadStart);

    printf("\nVersion: %d", version);
    printf("\nIHL: %d", ihl);

    // tos
    int tos = pktd[ipv4Start + 1];
    printf("\nType Of Service: %d", tos);

    // total length
    int totalLength = binTOdec(pktd, ipv4Start + 2, ipv4Start + 3);
    printf("\nTotal Length: %d bytes", totalLength);
    if (totalLength < ipHeaderLength) { printf("\nInvalid IPv4 Total Length."); return; }

    // packet bounds check
    if (capLength < ipv4Start + totalLength) { printf("\nTruncated IPv4 Packet."); return; }

    // identification
    int identification = binTOdec(pktd, ipv4Start + 4, ipv4Start + 5);
    printf("\nIdentification: %d", identification);

    // flags & fragment offset
    int flags = (pktd[ipv4Start + 6] & 0xE0) >> 5;
    int R = (pktd[ipv4Start + 6] >> 7) & 0x01;
    int MF = (pktd[ipv4Start + 6] >> 5) & 0x01;
    int DF = (pktd[ipv4Start + 6] >> 6) & 0x01;
    int fragOffset = ((pktd[ipv4Start + 6] & 0x1F) << 8) | pktd[ipv4Start + 7];
    printf("\nFlags: %d", flags);
    printf("\nR: %d\nDF: %d\nMF: %d", R, DF, MF);
    printf("\nFrag Offset: %d", fragOffset);
    
    // TTL
    int ttl = pktd[ipv4Start + 8];
    printf("\nTTL: %d", ttl);
    
    // protocol
    int protocol = pktd[ipv4Start + 9];
    printf("\nProtocol: %d", protocol);
    if (protocol == 6) { printf(" (TCP)"); }
    else if (protocol == 17) { printf(" (UDP)"); }
    else if (protocol == 1) { printf(" (ICMP)"); }
    
    //header checksum
    int checksum = binTOdec(pktd, ipv4Start + 10, ipv4Start + 11);
    printf("\nHeader Checksum: 0x%04X", checksum);
    
    // source and destination IPs
    printf("\nSource IP: %u.%u.%u.%u", pktd[ipv4Start + 12], pktd[ipv4Start + 13], pktd[ipv4Start + 14], pktd[ipv4Start + 15]);
    printf("\nDestination IP: %u.%u.%u.%u", pktd[ipv4Start + 16], pktd[ipv4Start + 17], pktd[ipv4Start + 18], pktd[ipv4Start + 19]);
    
    // check transport header
    if (fragOffset != 0) { printf("\nNon-First IPv4 Fragment. Transport Header Not Parsed."); return; }
    
    if (protocol == 6) 
    {
        // parse TCP starting at payloadStart
        parseTCP(pktd, payloadStart, totalLength - ipHeaderLength, caplen);
    }
    else if (protocol == 17) 
    {
        // parse UDP starting at payloadStart
        parseUDP(pktd, payloadStart, totalLength - ipHeaderLength, caplen);
    }
    else if (protocol == 1) 
    {
        // parse ICMP starting at payloadStart
        parseICMP(pktd, payloadStart, totalLength, ipHeaderLength, caplen);
    }
    return;
    
}


void parseIPv6(const u_char *pktd, bpf_u_int32 caplen)
{

    printf("\n");
    printf("\n=== IPv6 Header ===\n");

    int capLength = (int)caplen;

    // determining start of ipv6 packet and payload
    int ipv6Start = 14;
    int payloadStart = ipv6Start + 40;

    // minimum header bounds check
    if (capLength < ipv6Start + 40) { printf("\nTruncated IPv6 Header."); return; }

    // version check
    int version = (pktd[ipv6Start] >> 4) & 0x0F;
    if (version != 6) { printf("\nUnsupported IP Version."); return; }

    // traffic class
    int trafficClass = ((pktd[ipv6Start] << 4) & 0xF0) | ((pktd[ipv6Start + 1] >> 4) & 0x0F);
    printf("\nTraffic Class: %d", trafficClass);

    // flow label
    uint32_t flowLabel = ((uint32_t)(pktd[ipv6Start] & 0x0F) << 16) | ((uint32_t)pktd[ipv6Start + 1] << 8) | pktd[ipv6Start + 2];
    printf("\nFlow Label: %" PRIu32, flowLabel);

    // payload length
    int payloadLength = binTOdec(pktd, ipv6Start + 4, ipv6Start + 5);
    printf("\nPayload length: %d", payloadLength);
    if (capLength < payloadStart + payloadLength) { printf("\nTruncated IPv6 Packet."); return; }

    // next header
    int nextHeader = pktd[ipv6Start + 6];
    printf("\nNext Header: %d", nextHeader);
    switch (nextHeader)
    {
        case 6: printf(" (TCP)"); break;
        case 17: printf(" (UDP)"); break; 
        case 58: printf(" (ICMPv6)"); break;
        case 59: printf(" (NONE)"); break;
        default: break;
    }

    // hop limit
    int hopLimit = pktd[ipv6Start + 7];
    printf("\nHop Limit: %d", hopLimit);

    // source and destination IPs
    printf("\nSource IP: ");
    printIPv6Address(pktd, ipv6Start + 8);
    
    printf("\nDestination IP: ");
    printIPv6Address(pktd, ipv6Start + 24);

    if (nextHeader == 6) 
    {
        parseTCP(pktd, payloadStart, payloadLength, caplen);
    }
    else if (nextHeader == 17) 
    {
        parseUDP(pktd, payloadStart, payloadLength, caplen);
    }
    else if (nextHeader == 58) 
    {
        parseICMPv6(pktd, payloadStart, payloadLength, caplen);
    }
    else if (nextHeader == 59) 
    {
        printf("\nNo Payload/Data Found."); return;
    }
    else 
    {
        printf("\n\n=-Extension Header...");
        if (parseIPv6ExtensionHeaders(pktd, payloadStart, payloadLength, nextHeader, caplen) == IPV6_EH_ERROR) { return; }
    }


}
