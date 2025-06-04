#include "clogfile.h"
#include <stdio.h>
#include <stdarg.h>

#ifdef LOG_FILE
extern "C" void LOG(char* fmt, ...)
{
    va_list marker;	
    FILE* f = fopen(LOG_FILE,"a");
    if (f != NULL)
    {
        va_start(marker, fmt);
        vfprintf(f, fmt, marker);
        va_end(marker);
        fprintf(f, "\n");
        fclose(f);
    }
}
#endif