#include <stdio.h>

#include "capture.h"
#include "interface.h"


CaptureStatus startCapture(const char *device, const char *filter) 
{

    char errorBuffer[PCAP_ERRBUF_SIZE];

    printf("\n"); // first a device capture handle must be created

    printf("Creating Capture Handle...");
    pcap_t *devHandle = pcap_create(device, errorBuffer);
    if (devHandle == NULL) { printf("Error: %s", errorBuffer); return CREATE_ERROR;}
    else { printf("\nCreation Successful!"); }

    printf("\n"); // next the device capture handle can be activated

    printf("\nActivating Capture Handle...");
    int resultActivation = pcap_activate(devHandle);
    if (resultActivation < 0) { printf("\nError %d : %s", resultActivation, pcap_statustostr(resultActivation)); pcap_close(devHandle); return ACTIVATE_ERROR; }
    else if (resultActivation > 0) { printf("\nWarning %d : %s", resultActivation, pcap_statustostr(resultActivation)); }
    else { printf("\nActivation Success"); }

    printf("\n"); // then the built BPF must be compiled

    printf("\nCompiling BPF Handle...");
    struct bpf_program filterProgram;
    int resultCompile = pcap_compile(devHandle, &filterProgram, filter, 0, PCAP_NETMASK_UNKNOWN);
    if (resultCompile == PCAP_ERROR) { printf("\nError: %s", pcap_geterr(devHandle)); pcap_close(devHandle); return COMPILE_ERROR; }
    else { printf("\nCompilation Successful!"); }

    printf("\n"); // and the compiled BPF must be set up

    printf("\nSetting Filter...");
    int resultSetting = pcap_setfilter(devHandle, &filterProgram);
    if (resultSetting == PCAP_ERROR_NOT_ACTIVATED) { printf("\nError: Device Handle Not Activated!"); pcap_close(devHandle); pcap_freecode(&filterProgram); return SETTING_ERROR; }
    else if (resultSetting == PCAP_ERROR) { printf("Error: %s", pcap_geterr(devHandle)); pcap_close(devHandle); pcap_freecode(&filterProgram); return SETTING_ERROR; }
    else { printf("\nSetting Successful!"); }

    printf("\n"); // here is the start of capturing packets

    struct pcap_pkthdr *pkth;
    const u_char *pktd;
    int resultNext;
    int packetCount = 0;
    int packetLimit = choosePacketLimit();
    if (packetLimit == -1) { pcap_close(devHandle); pcap_freecode(&filterProgram); return PKT_LIMIT_ERROR; }
    while (packetLimit == 0 || (packetCount < packetLimit)) 
    {
        if ((resultNext = pcap_next_ex(devHandle, &pkth, &pktd)) != 1) { break; }

        packetCount++;

        usleep(500000);

        printf("\nPacket Number: %d", packetCount);
        printf("\nCaptured Length(Bytes): %u", pkth->caplen);
        printf("\nPacket Length(Bytes): %u", pkth->len);
    }
    pcap_close(devHandle);
    pcap_freecode(&filterProgram);
    return CAPTURE_SUCCESS;

}
