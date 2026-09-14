#ifndef CAPTURE_H
#define CAPTURE_H

#include <stddef.h>
#include <unistd.h>
#include <pcap.h>

typedef enum {
    CAPTURE_SUCCESS,
    CREATE_ERROR,
    COMPILE_ERROR,
    SETTING_ERROR,
    ACTIVATE_ERROR,
    PKT_LIMIT_ERROR
} CaptureStatus;

CaptureStatus startCapture(const char *device, const char *filter);

#endif
