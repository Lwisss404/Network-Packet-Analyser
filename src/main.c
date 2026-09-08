#include <stdio.h>
#include <pcap.h>
#include <unistd.h>


int main(void) 
{


    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp;

    int result = pcap_findalldevs(&alldevsp, errbuf);

    if (result == PCAP_ERROR) { printf("%s", errbuf); pcap_freealldevs(alldevsp); return 1; }
    else if (result == 0) {
        if (alldevsp == NULL) { printf("\nNo Devices Were Found!"); pcap_freealldevs(alldevsp); return 0; }
        else 
        {
            pcap_if_t *tempdevp = alldevsp;
            while(tempdevp != NULL) 
            {
                printf("\nDevice Name: %s", tempdevp->name);
                tempdevp = tempdevp->next;
            }
        }
    }

    printf("\n");

    pcap_t *devh = pcap_create("en0", errbuf);
    if (devh == NULL) { printf("%s", errbuf); pcap_freealldevs(alldevsp); return 1;}
    else { printf("\nCreation Success"); }

    int resultAct = pcap_activate(devh);
    if (resultAct > 0) { printf("\nWarning %d : %s", resultAct, pcap_statustostr(resultAct)); pcap_close(devh); pcap_freealldevs(alldevsp); return 1; }
    else if (resultAct < 0) { printf("\nError %d : %s", resultAct, pcap_statustostr(resultAct)); pcap_close(devh); pcap_freealldevs(alldevsp); return 1; }
    else { printf("\nActivation Success"); }

    printf("\n");

    struct pcap_pkthdr *pkth;
    const u_char *pktd;
    int resultNext;
    int packetsCaptured = 0;
    while ((resultNext = pcap_next_ex(devh, &pkth, &pktd)) == 1 && packetsCaptured < 10) 
    {
        packetsCaptured++;

        usleep(1000000);

        printf("\nPacket Number: %d", packetsCaptured);
        printf("\nCaptured Length(Bytes): %u", pkth->caplen);
        printf("\nPacket Length(Bytes): %u\n", pkth->len);

        for (bpf_u_int32 i = 0; i < pkth->caplen; i++) {
            printf("%02x ", pktd[i]);
        }

        if (pkth->caplen >= 14) {
            char buffer[18];

            snprintf(buffer, sizeof(buffer), "%02X:%02X:%02X:%02X:%02X:%02X", pktd[0], pktd[1], pktd[2], pktd[3], pktd[4], pktd[5] );
            printf("\nDestination MAC: %s", buffer);

            snprintf(buffer, sizeof(buffer), "%02X:%02X:%02X:%02X:%02X:%02X", pktd[6], pktd[7], pktd[8], pktd[9], pktd[10], pktd[11] );
            printf("\nSource MAC: %s", buffer);

            printf("\nEtherType: 0x%02X%02X", pktd[12], pktd[13]);
            printf("\n");
        }
    }

    pcap_close(devh);
    pcap_freealldevs(alldevsp);
    return 0;

}