#ifndef PARSER_H
#define PARSER_H

#include <stdint.h>
#include <inttypes.h>

#include "utils.h"
#include "ip_protocols.h"


void parsePacket(struct pcap_pkthdr *pkth, const u_char *pktd, int packetCount);
void parseARP(const u_char *pktd, bpf_u_int32 capLen);
void parseIPv4(const u_char *pktd, bpf_u_int32 caplen);
void parseIPv6(const u_char *pktd, bpf_u_int32 caplen);


#endif