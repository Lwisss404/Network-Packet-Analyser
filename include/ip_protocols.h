#ifndef IP_PROTOCOLS_H
#define IP_PROTOCOLS_H

#include "utils.h"

void parseTCP(const u_char *pktd, int payloadStart, int payloadLength, bpf_u_int32 caplen);
void parseUDP(const u_char *pktd, int payloadStart, int payloadLength, bpf_u_int32 caplen);
void parseICMP(const u_char *pktd, int payloadStart, int totalLength, int ipHeaderLength, bpf_u_int32 caplen);
void parseICMPv6(const u_char *pktd, int payloadStart, int payloadLength, bpf_u_int32 caplen);

#endif