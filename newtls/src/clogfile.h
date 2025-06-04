#ifndef __CLOGFILE_H__
#define __CLOGFILE_H__

#ifdef ENABLE_LOG

#ifndef LOG_FILE
#define LOG_FILE "C:\\ssl.log"
#endif
extern "C" void LOG(char* fmt, ...);
#else
#define LOG(arg...)	

#endif // ENABLE_LOG
#endif // __CLOGFILE_H__
