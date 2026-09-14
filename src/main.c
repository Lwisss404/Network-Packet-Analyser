#include <stdio.h>

#include "utils.h"
#include "interface.h"
#include "capture.h"









int main(void) 
{
    printf("===== Network Packet Analyser =====\n");
    

    EthernetProtocol ethProtocol;
    IPProtocol ipProtocol;
    char device[64];
    int running = 1;
    while (running)
    {
        printf("\n1. Start Capture");
        printf("\n2. Exit");
        
        // input handle
        printf("\nSelect Service: ");
        int choiceMain = readChoice(1, 2);
        switch (choiceMain) 
        {
            case 1: 
                printf("\n\nInitialising Capture Settings...\n");
                while (1)
                {
                    printf("\n-Device Menu: ");
                    DeviceStatus resultChooseDevice = chooseDevice(device, sizeof(device));
                    if (resultChooseDevice != DEVICE_SUCCESS) { break; }
                    else if (resultChooseDevice == DEVICE_SUCCESS) 
                    {
                        while (1) 
                        {
                            ethProtocol = chooseEthernetProtocol();
                            if (ethProtocol == EXIT_SIG_EP) { break; }
                            else if (ethProtocol == ETHERNET_ARP) 
                            {
                                running = 0; break; // arp has no ip protocol 
                            }
                            else 
                            {
                                while (1)
                                {

                                    printf("\n-IP Protocol Menu: ");
                                    ipProtocol = chooseIPProtocol(ethProtocol);
                                    if (ipProtocol == EXIT_SIG_IPP) { break; }
                                    else { running = 0; break; }
                                }
                            }
                            break;
                        }
                    }
                    break;
                }
                break;

            case 2: printf("\nExit Selected...Farewell!"); return 0;

            default: printf("\nInvalid Selection...Try Again!\n"); break;
        }
    }

    printf("\n");

    // build BPF
    printf("\nBuilding BPF...");
    
    char filter[128];
    buildBPF(ethProtocol, ipProtocol, filter, sizeof(filter));
    printf("\nSuccess Building BPF!");

    printf("\n");

    //apply libpcap capture handle 
    printf("\nConfiguring Capture Session...\n");
    CaptureStatus capStatus = startCapture(device, filter);
    errorcheckCaptureStatus(capStatus);

    return 0;
}































/*
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp;
    
    int result = pcap_findalldevs(&alldevsp, errbuf);

    if (result == PCAP_ERROR) { printf("%s", errbuf); pcap_freealldevs(alldevsp); return 1; }
    else if (result == 0) {
        if (alldevsp == NULL) { printf("\nNo Devices Were Found!"); pcap_freealldevs(alldevsp); return 0; }
        else 
        {
            pcap_if_t *tempdevp = alldevsp;
            while(tempdevp != NULL) 
            {
                printf("\nDevice Name: %s", tempdevp->name);
                tempdevp = tempdevp->next;
            }
        }
    }

    printf("\n");

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *devh = pcap_create("en0", errbuf);
    if (devh == NULL) { printf("%s", errbuf); pcap_freealldevs(alldevsp); return 1;}
    else { printf("\nCreation Success"); }

    int resultAct = pcap_activate(devh);
    if (resultAct > 0) { printf("\nWarning %d : %s", resultAct, pcap_statustostr(resultAct)); pcap_close(devh); pcap_freealldevs(alldevsp); return 1; }
    else if (resultAct < 0) { printf("\nError %d : %s", resultAct, pcap_statustostr(resultAct)); pcap_close(devh); pcap_freealldevs(alldevsp); return 1; }
    else { printf("\nActivation Success"); }

    printf("\n");

    struct pcap_pkthdr *pkth;
    const u_char *pktd;
    int resultNext;
    int packetsCaptured = 0;
    while ((resultNext = pcap_next_ex(devh, &pkth, &pktd)) == 1 && packetsCaptured < 20) 
    {
        packetsCaptured++;

        usleep(500000);

        printf("\nPacket Number: %d", packetsCaptured);
        printf("\nCaptured Length(Bytes): %u", pkth->caplen);
        printf("\nPacket Length(Bytes): %u", pkth->len);

        // printf("\n");
        // for (bpf_u_int32 i = 0; i < pkth->caplen; i++) {
        //     printf("%02x ", pktd[i]);
        // }

        char buf[5];
        if (pkth->caplen >= 14) {
            char buffer[18];

            snprintf(buffer, sizeof(buffer), "%02X:%02X:%02X:%02X:%02X:%02X", pktd[0], pktd[1], pktd[2], pktd[3], pktd[4], pktd[5] );
            printf("\nDestination MAC: %s", buffer);

            snprintf(buffer, sizeof(buffer), "%02X:%02X:%02X:%02X:%02X:%02X", pktd[6], pktd[7], pktd[8], pktd[9], pktd[10], pktd[11] );
            printf("\nSource MAC: %s", buffer);

            binTOhex(buf, pktd, 12, 13);
            printf("\nEtherType: 0x%s", buf);
            if (strcmp(buf, "0806") == 0) { printf(" ARP "); }
            else if ((strcmp(buf, "86DD") == 0) || (strcmp(buf, "86dd") == 0)) { printf(" IPv6 "); }
            else if (strcmp(buf, "0800") == 0) 
            { 
                printf(" IPv4 ");

                // determining start of the payload
                int ihl = pktd[14] & 0x0F;
                int  ipHeaderLength = ihl * 4;
                int payloadStart = 14 + ipHeaderLength;
                printf("\nPayload Start: %d", payloadStart);

                // total length
                int totalLength = binTOdec(pktd, 16, 17);
                printf("\nTotal Length: %d bytes", totalLength);

                // identification
                int identification = binTOdec(pktd, 18, 19);
                printf("\nIdentification: %d", identification);

                // flags & fragment offset
                int flags = (pktd[20] & 0xE0) >> 5;
                int fragOffset = ((pktd[20] & 0x1F) << 8) | pktd[21];
                printf("\nFlags: %d", flags);
                printf("\nFrag Offset: %d", fragOffset);

                // TTL
                int ttl = pktd[22];
                printf("\nTTL: %d", ttl);

                // protocol
                int protocol = pktd[23];
                printf("\nProtocol: %d", protocol);
                if (protocol == 6) { printf(" TCP"); }
                else if (protocol == 17) { printf(" UDP"); }
                else if (protocol == 1) { printf(" ICMP"); }
            
                //header checksum
                int checksum = binTOdec(pktd, 24, 25);
                printf("\nHeader Checksum: 0x%04X", checksum);

                // source and destination IPs
                printf("\nSource IP: %u.%u.%u.%u", pktd[26], pktd[27], pktd[28], pktd[29]);
                printf("\nDestination IP: %u.%u.%u.%u", pktd[30], pktd[31], pktd[32], pktd[33]);

                if (protocol == 6) 
                {
                    // Parse TCP starting at payloadStart
                    printf("\n=- TCP Header...");

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
                    printf("\nChechsum: 0x%04X", tcpChecksum);

                    // urgent pointer
                    int tcpUrgentPointer = binTOdec(pktd, payloadStart + 18, payloadStart + 19);
                    printf("\nUrgent Pointer: 0x%04X", tcpUrgentPointer);


                    // determinig start of tcp payload
                    int tcpHeaderLength = tcpDataOffset * 4;
                    int tcpPayloadStart = payloadStart + tcpHeaderLength;
                    
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

                    int tcpPayloadLength = totalLength - ipHeaderLength - tcpHeaderLength;
                    printf("\nTCP Payload Length: %d bytes", tcpPayloadLength);

                    printf("\nTCP Payload: ");
                    for (int i = tcpPayloadStart; i < 14 + totalLength; i++) {
                        printf("%02x", pktd[i]);
                    }

                }
                else if (protocol == 17) 
                {
                    // Parse UDP starting at payloadStart
                }
                else if (protocol == 1) 
                {
                    // Parse ICMP starting at payloadStart
                }
            }
            
            printf("\n");
        }
    }

    pcap_close(devh);
    pcap_freealldevs(alldevsp);
    */

