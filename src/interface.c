#include <stdio.h>

#include "interface.h"
#include "utils.h"

DeviceStatus chooseDevice(char *device, size_t deviceSize) 
{

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp;

    int result = pcap_findalldevs(&alldevsp, errbuf);

    if (result == PCAP_ERROR) { printf("%s", errbuf); pcap_freealldevs(alldevsp); device = NULL;; return DEVICE_ERROR; }
    else if (result == 0) {
        if (alldevsp == NULL) { printf("\nNo Devices Were Found!"); pcap_freealldevs(alldevsp); *device = '\0'; return NO_DEVICE; }
        else 
        {
            int deviceCounter = 0;
            pcap_if_t *tempdevp = alldevsp;
            while (tempdevp != NULL) 
            {
                printf("\n%d. %s",++deviceCounter, tempdevp->name);
                tempdevp = tempdevp->next;
            }
            printf("\n%d. Back\n", ++deviceCounter);
            
            // input handle
            while (1) {
                printf("\n==- Select Device: ");
                int choiceMenu = readChoice(1, deviceCounter);

                if (choiceMenu == deviceCounter) { printf("\nReturning To Previous Menu...\n"); pcap_freealldevs(alldevsp); device = NULL; return EXIT_SIG_DEV; }
                else if (!(choiceMenu < deviceCounter && choiceMenu > 0)) { printf("\nInvalid Selection... Try Again!\n"); }
                else
                {
                    tempdevp = alldevsp;
                    while (choiceMenu > 1) 
                    {
                        tempdevp = tempdevp->next;
                        choiceMenu--;
                    }
                }
                snprintf(device, deviceSize, "%s", tempdevp->name);
                break;
            }
        }
    }
    pcap_freealldevs(alldevsp);
    return DEVICE_SUCCESS;
}


EthernetProtocol chooseEthernetProtocol()
{

    while (1)
    {
        printf("\n-Ethernet Protocol Menu:");
        printf("\n1. ARP");
        printf("\n2. IPv4");
        printf("\n3. IPv6");
        printf("\n4. Back\n");
        
        printf("\n==- Select Ethernet Protocol: ");
        int choiceMenu = readChoice(1, 4);
        switch (choiceMenu) 
        {
            case 1: return ETHERNET_ARP;
            case 2: return ETHERNET_IPV4;
            case 3: return ETHERNET_IPV6;
            case 4: printf("\nReturning To Previous Menu...\n"); return EXIT_SIG_EP;
            default: printf("\nInvalid Selection...Try Again!\n"); break;
        }
    }

}


IPProtocol chooseIPProtocol(EthernetProtocol ethProtocol) 
{

    IPProtocol selected = EXIT_SIG_IPP;

    while (1)
    {
        printf("\n1. TCP     [%c]", (selected & IP_TCP) ? 'X' : ' ');
        printf("\n2. UDP     [%c]", (selected & IP_UDP) ? 'X' : ' ');
        
        if (ethProtocol == ETHERNET_IPV4)
        printf("\n3. ICMP    [%c]", (selected & IP_ICMP) ? 'X' : ' ');
        else
        printf("\n3. ICMPv6  [%c]", (selected & IP_ICMPV6) ? 'X' : ' ');
        
        printf("\n4. Confirm");
        printf("\n5. Back\n");
        
        printf("\n==- Select IP Protocol: ");
        int choiceMenu = readChoice(1, 5);
        switch (choiceMenu)
        {
            case 1: selected ^= IP_TCP; break;
            
            case 2: selected ^= IP_UDP; break;
            
            case 3:
                if (ethProtocol == ETHERNET_IPV4) { selected ^= IP_ICMP; }
                else { selected ^= IP_ICMPV6; }
                break;
            
            case 4:
                if (selected != EXIT_SIG_IPP) { return selected; }
                printf("\nNo Protocol Selected!\n"); break;

            case 5:
                return EXIT_SIG_IPP;

            default:
                printf("\nInvalid Selection...Try Again!\n");
                break;
        }
    }
}

void buildBPF(EthernetProtocol ethProtocol, IPProtocol ipProtocol, char *filter, size_t filterSize) 
{

    if (ethProtocol == ETHERNET_ARP) { snprintf(filter, filterSize, "arp"); }
    else if (ethProtocol == ETHERNET_IPV4) 
    {
        if (ipProtocol == (IP_TCP | IP_UDP | IP_ICMP)) { snprintf(filter, filterSize, "ip"); }
        else if (ipProtocol == (IP_UDP | IP_ICMP)) { snprintf(filter, filterSize, "ip and (udp or icmp)"); }
        else if (ipProtocol == (IP_TCP | IP_ICMP)) { snprintf(filter, filterSize, "ip and (tcp or icmp)"); }
        else if (ipProtocol == (IP_TCP | IP_UDP)) { snprintf(filter, filterSize, "ip and (tcp or udp)"); }
        else if (ipProtocol == IP_ICMP) { snprintf(filter, filterSize, "ip and icmp"); }
        else if (ipProtocol == IP_UDP) { snprintf(filter, filterSize, "ip and udp"); }
        else if (ipProtocol == IP_TCP) { snprintf(filter, filterSize, "ip and tcp"); }
    }
    else if (ethProtocol == ETHERNET_IPV6) 
    {
         if (ipProtocol == (IP_TCP | IP_UDP | IP_ICMPV6)) { snprintf(filter, filterSize, "ip6"); }
        else if (ipProtocol == (IP_UDP | IP_ICMPV6)) { snprintf(filter, filterSize, "ip6 and (udp or icmp6)"); }
        else if (ipProtocol == (IP_TCP | IP_ICMPV6)) { snprintf(filter, filterSize, "ip6 and (tcp or icmp6)"); }
        else if (ipProtocol == (IP_TCP | IP_UDP)) { snprintf(filter, filterSize, "ip6 and (tcp or udp)"); }
        else if (ipProtocol == IP_ICMPV6) { snprintf(filter, filterSize, "ip6 and icmp6"); }
        else if (ipProtocol == IP_UDP) { snprintf(filter, filterSize, "ip6 and udp"); }
        else if (ipProtocol == IP_TCP) { snprintf(filter, filterSize, "ip6 and tcp"); }
    }

}

int choosePacketLimit() 
{
    while (1) 
    {
        printf("\nPacket Limit Menu:"); 
        printf("\n1. Capture 20 Packets");
        printf("\n2. Capture 50 Packets");
        printf("\n3. Capture 100 Packets");
        printf("\n4. Capture 500 Packets");
        printf("\n5. Capture Indefinitely");
        printf("\n6. Exit The Program");
        
        printf("\nSelect packet Limit: ");
        int choiceMenu = readChoice(1, 6);
        switch (choiceMenu)
        {
            case 1: return 20;
            case 2: return 50;
            case 3: return 100;
            case 4: return 500;
            case 5: return 0;
            case 6: return -1;
            default: printf("\n Invalid Selection...Try Again!\n"); break;
        }
    }
}
