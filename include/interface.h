#ifndef INTERFACE_H
#define INTERFACE_H

#include <pcap.h>

typedef enum {
    DEVICE_SUCCESS,
    DEVICE_ERROR,
    NO_DEVICE,
    EXIT_SIG_DEV
} DeviceStatus;

typedef enum {
    ETHERNET_IPV4,
    ETHERNET_IPV6,
    ETHERNET_ARP,
    EXIT_SIG_EP
} EthernetProtocol;

typedef enum {
    EXIT_SIG_IPP = 0,
    IP_TCP = 1 << 0,
    IP_UDP = 1 << 1,
    IP_ICMP = 1 << 2,
    IP_ICMPV6 = 1 << 3
} IPProtocol;


DeviceStatus chooseDevice(char *device, size_t deviceSize);
EthernetProtocol chooseEthernetProtocol(void);
IPProtocol chooseIPProtocol(EthernetProtocol ethProtocol);
void buildBPF(EthernetProtocol ethProtocol, IPProtocol ipProtocol, char *filter, size_t filterSize);
int choosePacketLimit(void);


#endif
