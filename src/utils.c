#include <stdio.h>

#include "utils.h"


inputResult readLine(char* buffer, size_t size) {
    // checks if error/failure occurred when fgetting input (EOF, input error...)
    if (fgets(buffer, size, stdin) == NULL) { return feof(stdin) ? INPUT_EOF : INPUT_ERROR; }
    
    // check buffer overflow and flush overflow characters
    size_t length = strlen(buffer);

    if (length > 0 && buffer[length-1] != '\n')
    {
        int character;
        while ((character = getchar()) != '\n' && character != EOF)
        {
            // discard remaining chars
        }
        return INPUT_TOO_LONG;
    }

    if (length > 0 && buffer[length - 1] == '\n') { buffer[length - 1] = '\0'; }

    return INPUT_OK;
}


int readChoice(int min, int max)
{
    char buffer[12];
    inputResult result = readLine(buffer, sizeof(buffer));
    if (result != INPUT_OK) { return -1; }

    char *endptr;
    errno = 0;
    long choice = strtol(buffer, &endptr, 10);

    if (endptr == buffer || *endptr != '\0' || errno == ERANGE) { return -1; }

    if (choice < min || choice > max) { return -1; }

    return (int)choice;
}


uint32_t binTOdec(const u_char* bin, int seqStart, int seqEnd)
{
    int result = 0;
    for (int i = seqStart; i <= seqEnd; i++) {
        result = (result << 8) | bin[i];
    }
    return result;
}


void binTOhex(char* hex, const u_char* bin, int seqStart, int seqEnd) 
{
    for (int i = seqStart; i <= seqEnd; i++) {
        snprintf(hex + ((i - seqStart) * 2), 3, "%02x", bin[i]);
    }
    hex[(seqEnd - seqStart + 1) * 2] = '\0';
    return;
}


void errorcheckCaptureStatus(CaptureStatus status) 
{
    printf("\n");
    switch(status)
    {
        case CREATE_ERROR: printf("\nError Creating Handle!"); break;
        case COMPILE_ERROR: printf("\nError Compiling Filter!"); break;
        case SETTING_ERROR: printf("\nError Setting Filter!"); break;
        case ACTIVATE_ERROR: printf("\nError Activating Handle!"); break;
        case PKT_LIMIT_ERROR: printf("\nPacket Limit Exit!"); break;
        default: printf("\nSuccess!"); break;
    }
}


void printIPv6Address(const u_char *pktd, int start) 
{

    for (int i = start; i < start + 16; i+=2) {
        printf("%02x%02x", pktd[i], pktd[i + 1]);
        if (i < (start + 16) - 2) { printf(":"); }
    }

}


ICMPv6OptionsStatus parseICMPv6Options(const u_char *pktd, int optionsStart, int optionsLength, int capLength)
{

        printf("\n=-Options...");
        printf("\nOptions Length: %d bytes", optionsLength);
        
        // options existence check
        if (optionsLength == 0) { printf("\nNo Payload/Data Found."); return ICMPV6_OPTIONS_ERROR; }
        else if (optionsLength < 0) { printf("\nInvalid Options Length."); return ICMPV6_OPTIONS_ERROR; }

        // options bounds check
        if (capLength < optionsStart + optionsLength) { printf("\nTruncated Options."); return ICMPV6_OPTIONS_ERROR; }

        int currentOption = optionsStart;
        int optionNumber = 0;

        while (currentOption < optionsStart + optionsLength) 
        {

            printf("\n-Option %d..", ++optionNumber);

            if (optionsStart + optionsLength - currentOption < 2) { printf("\nTruncated Option Header."); return ICMPV6_OPTIONS_ERROR; }

            // option type
            int optionType = pktd[currentOption];
            printf("\nOption Type: %d", optionType);

            //option length
            int optionLength = pktd[currentOption + 1];
            printf("\nOption Length: %d Bytes", optionLength * 8);
            if (optionLength == 0) { printf("\nInvalid Option Length."); return ICMPV6_OPTIONS_ERROR; }
            
            if (currentOption + optionLength * 8 > optionsStart + optionsLength) { printf("\nTruncated Option Field."); return ICMPV6_OPTIONS_ERROR; }
            
            if (optionType == 1)
            {
                if (optionLength != 1) { printf("\nInvalid Source Link-Layer Address Option Length."); return ICMPV6_OPTIONS_ERROR; }
            
                printf("\nSource Link-Layer Address: ");
                for (int i = currentOption + 2; i < currentOption + 8; i++) { 
                    printf("%02x", pktd[i]); 
                    if (i < currentOption + 7) { printf(":"); }
                }
            }
            else if (optionType == 2)
            {
                if (optionLength != 1 ) { printf("\nInvalid Target Link-Layer Address Option Length."); return ICMPV6_OPTIONS_ERROR; }

                printf("\nTarget Link-Layer Address:");
                for (int i = currentOption + 2; i < currentOption + 8; i++) {
                    printf("%02x", pktd[i]);
                    if (i < currentOption + 7) { printf(":"); }
                }
            }
            
            currentOption += optionLength * 8;

        }
    return ICMPV6_OPTIONS_SUCCESS;
    
}


IPv6ExtensionHeaderStatus parseIPv6ExtensionHeaders(const u_char *pktd, int payloadStart, int payloadLength, int nextHeader, bpf_u_int32 caplen) 
{

    int currentHeader = nextHeader;
    int currentStart = payloadStart;
    int remainingLength = payloadLength;
    int capLength = (int)caplen;

    while (1) 
    {

        // check for non special next headers
        if (currentHeader == 6 || currentHeader == 17 || currentHeader == 58 || currentHeader == 59) { break; }

        // hop-by-hop, routing, destination
        if (currentHeader == 0 || currentHeader == 43 || currentHeader == 60) 
        {
            switch (currentHeader) 
            {
                case 0: printf("\n-Hop-By-Hop Extension Header..."); break;
                case 43: printf("\n-Routing Extension Header..."); break;
                case 60: printf("\n-Destination Extension Header..."); break;
                default: break;
            }
            
            // check minimim header length bounds
            if (remainingLength < 2) { printf("\nTruncated IPv6 Extension Header."); return IPV6_EH_ERROR; }

            // check bounds relative to captured length
            if (capLength < currentStart + 2) { printf("\nTruncated IPv6 Extension Header."); return IPV6_EH_ERROR; }

            int next = pktd[currentStart];
            int hdrExtLength = pktd[currentStart + 1];
            int headerLength = (hdrExtLength + 1) * 8;

            // check bounds that remaining length isnt out of bounds of header length
            if (remainingLength < headerLength) { printf("\nTruncated IPv6 Extension Header."); return IPV6_EH_ERROR; }

            // same relative to caplen
            if (capLength < currentStart + headerLength) { printf("\nTruncated IPv6 Extension Header."); return IPV6_EH_ERROR; }

            printf("\nExtension Header Length: %d bytes", headerLength);

            currentStart += headerLength;
            remainingLength -= headerLength;
            currentHeader = next;
        } 
        // fragment header
        else if (currentHeader == 44) 
        {
            printf("\n-Fragment Header...");

            // check minimim header length bounds
            if (remainingLength < 8) { printf("\nTruncated IPv6 Fragment Header."); return IPV6_EH_ERROR; }

            // check bounds relative to captured length
            if (capLength < currentStart + 8) { printf("\nTruncated IPv6 Fragment Header."); return IPV6_EH_ERROR; }

            int next = pktd[currentStart];
            
            // fragment offset
            int fragmentOffset = ((pktd[currentStart + 2] << 8) | pktd[currentStart + 3]) >> 3;
            printf("\nFragment Offset: %d", fragmentOffset);
            if (fragmentOffset != 0) { printf("\nNon-First IPv6 Fragment. Transport Header Not Parsed."); return IPV6_EH_ERROR; }

            // fragments
            int moreFragments = pktd[currentStart + 3] & 0x01;
            printf("\nMore Fragments: %d", moreFragments);

            // identification
            uint32_t identification = ((uint32_t)pktd[currentStart + 4] << 24) | ((uint32_t)pktd[currentStart + 5] << 16) | ((uint32_t)pktd[currentStart + 6] << 8) | pktd[currentStart + 7];
            printf("\nIdentification: %" PRIu32, identification);

            currentStart += 8;
            remainingLength -= 8;
            currentHeader = next;
        }
        else 
        {
            printf("\nUnsupported IPv6 Extention Header: %d", currentHeader);
            return IPV6_EH_ERROR;
        }

    }

    // parse extension chain
    switch (currentHeader) 
    {
        case 6: printf("\nNext Header: 6 (TCP)"); parseTCP(pktd, currentStart, remainingLength, caplen); break;
        case 17: printf("\nNext Header: 17 (UDP)"); parseUDP(pktd, currentStart, remainingLength, caplen); break;
        case 58: printf("\nNext Header: 58 (ICMPv6)"); parseICMPv6(pktd, currentStart, remainingLength, caplen); break;
        case 59: printf("\nNo Next Header."); break;
        default: break;
    }

    return IPV6_EH_SUCCESS;

}
