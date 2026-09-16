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
