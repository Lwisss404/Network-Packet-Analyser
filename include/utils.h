#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "capture.h"
#include "ip_protocols.h"


typedef enum {
    INPUT_OK,
    INPUT_ERROR,
    INPUT_EOF,
    INPUT_TOO_LONG
} inputResult;

typedef enum {
    ICMPV6_OPTIONS_SUCCESS,
    ICMPV6_OPTIONS_ERROR
} ICMPv6OptionsStatus;

typedef enum {
    IPV6_EH_SUCCESS,
    IPV6_EH_ERROR
} IPv6ExtensionHeaderStatus;


inputResult readLine(char* buffer, size_t size);
int readChoice(int min, int max);
void binTOhex(char* hex, const u_char* bin, int seqStart, int seqEnd);
uint32_t binTOdec(const u_char* bin, int seqStart, int seqEnd);
void errorcheckCaptureStatus(CaptureStatus status);
void printIPv6Address(const u_char *pktd, int start);
ICMPv6OptionsStatus parseICMPv6Options(const u_char *pktd, int optionsStart, int optionsLength, int capLength);
IPv6ExtensionHeaderStatus parseIPv6ExtensionHeaders(const u_char *pktd, int payloadStart, int payloadLength, int nextHeader, bpf_u_int32 caplen);


#endif
