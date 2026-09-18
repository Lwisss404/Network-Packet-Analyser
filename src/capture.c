#include <stdio.h>

#include "capture.h"
#include "interface.h"
#include "parser.h"


CaptureStatus startCapture(const char *device, const char *filter) 
{

    char errorBuffer[PCAP_ERRBUF_SIZE];

    printf("\n"); // first a device capture handle must be created

    printf("Creating Capture Handle...");
    pcap_t *devHandle = pcap_create(device, errorBuffer);
    if (devHandle == NULL) { printf("Error: %s", errorBuffer); return CREATE_ERROR;}
    else { printf("\nCreation Successful!"); }

    // fix BSD-derived BPF devices timeout issue
    pcap_set_snaplen(devHandle, 65535);
    pcap_set_promisc(devHandle, 1);
    pcap_set_timeout(devHandle, 1000);        // ms — bounds the wait
    pcap_set_immediate_mode(devHandle, 1);    // deliver packets as they arrive, don't wait for buffer fill

    printf("\n"); // next the device capture handle can be activated

    printf("\nActivating Capture Handle...");
    int resultActivation = pcap_activate(devHandle);
    if (resultActivation < 0) { printf("\nError %d : %s", resultActivation, pcap_statustostr(resultActivation)); pcap_close(devHandle); return ACTIVATE_ERROR; }
    else if (resultActivation > 0) { printf("\nWarning %d : %s", resultActivation, pcap_statustostr(resultActivation)); }
    else { printf("\nActivation Successful!"); }

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

    // here is the start of capturing packets

    struct pcap_pkthdr *pkth;
    const u_char *pktd;
    int resultNext;
    int packetCount = 0;
    int packetLimit = choosePacketLimit();
    if (packetLimit == -1) { pcap_close(devHandle); pcap_freecode(&filterProgram); return PKT_LIMIT_ERROR; }
    while (packetLimit == 0 || (packetCount < packetLimit)) 
    {

        resultNext = pcap_next_ex(devHandle, &pkth, &pktd);
        
        if (resultNext == 0) { printf("\n\nThe packet buffer timeout expired"); continue; }
        if (resultNext == PCAP_ERROR) { printf("\nError: %s", pcap_geterr(devHandle)); break; }
        if (resultNext == PCAP_ERROR_BREAK) { printf("\nReading from a savefile finished because there are no more packets."); break; }

        packetCount++;

        usleep(100000);

        parsePacket(pkth, pktd, packetCount);
    }
    pcap_close(devHandle);
    pcap_freecode(&filterProgram);
    return CAPTURE_SUCCESS;

}
