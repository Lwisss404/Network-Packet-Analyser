#include <stdio.h>

#include "utils.h"


inputResult readLine(char* buffer, size_t size) {
    // checks if error/failure occurred when fgetting input (EOF, input error...)
    if (fgets(buffer, size, stdin) == NULL) { return INPUT_ERROR; }
    
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
