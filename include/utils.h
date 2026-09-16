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


typedef enum {
    INPUT_OK,
    INPUT_ERROR,
    INPUT_TOO_LONG
} inputResult;

inputResult readLine(char* buffer, size_t size);
int readChoice(int min, int max);
void binTOhex(char* hex, const u_char* bin, int seqStart, int seqEnd);
uint32_t binTOdec(const u_char* bin, int seqStart, int seqEnd);
void errorcheckCaptureStatus(CaptureStatus status);
void printIPv6Address(const u_char *pktd, int start);


#endif
