// Copyright (c) 1997-2009 Nokia Corporation and/or its subsidiary(-ies).
// All rights reserved.
// This component and the accompanying materials are made available
// under the terms of "Eclipse Public License v1.0"
// which accompanies this distribution, and is available
// at the URL "http://www.eclipse.org/legal/epl-v10.html".
//
// Initial Contributors:
// Nokia Corporation - initial contribution.
//
// Contributors:
//
// Description:
// Comms Debug Utility (File and Serial logger) Client side header
// 
//

/**
@file
@publishedAll
@deprecated Migrate to Open System Trace Instrumentation API instead
*/

#ifndef __COMMSDEBUGUTILITY_H__
#define __COMMSDEBUGUTILITY_H__

#ifndef __FLOG_NO_UDEB
	#ifdef _DEBUG
		#ifndef __FLOG_ACTIVE
			#define __FLOG_ACTIVE
		#endif
	#endif // _DEBUG
#endif //__FLOG_NO_UDEB

#ifdef __FLOG_UREL
	#ifndef _DEBUG
		#ifndef __FLOG_ACTIVE
			#define __FLOG_ACTIVE
		#endif //__FLOG_ACTIVE
	#endif //_DEBUG
#endif //__FLOG_UREL


#define __FLOG_DECLARATION_MEMBER_SIZE   TInt32


// constants available to clients in either build so they can be used in classes
#include <e32base.h>

const TInt KLogBufferSize=200;		///< Any attempt to write logs longer than KLogBufferSize and the client string will be truncated.
const TInt KMaxHexDumpWidth = 150;	///< If the client asks to hexdump a string longer than this, the string will be truncated
const TInt KMaxTagLength = 16;		///< Maximum length of the client tag strings. Exceeding this causes the tag to be truncated.


#if defined __FLOG_ACTIVE

// make sure clients using this in release mode get a warning.
#if (!defined __FLOG_SUPPRESS_REL_WARNING) && (!defined _DEBUG)
#pragma message ("WARNING: Use of comms-infras/CommsDebugUtility.h in active mode in a release build")
#endif


const TInt KMaxMediaSettingLength = 0x20; ///< Maximum expected length for media setting tag


_LIT(KFloggerPanic, "Comsdbgutil.dll");		///< The text which defines any flogger panic. Sent to User::Panic.

/**
 * Panic codes
 *
 * @publishedAll
 * @deprecated Migrate to Open System Trace Instrumentation API instead
 * @note The order of the panic numbers should not be changed.
 *       New panic codes must be added at the end of this enum.
 *       All panic codes are assigned to values to ease debugging.
 */
enum TFloggerPanics
	{
	ESetLogTagsNotCalled = 0,   ///< Attempt by client to write without first setting the ID tags
	EInternalConsistencyFault = 1   ///< A situation has arisen which indicates a programming fault in flogger since the situation should not be caused by any external inputs
	};

/**
 * Logging Mode codes
 *
 * @publishedAll
 * @deprecated As of version 8.0 the logging modes are deprecated due to the introduction
 *             of a single log file. Appent mode is the default for all write operations,
 *             while Overwrite can be achieved using new __FLOG_CLEAR macro, or ClearLog API.
 */
enum TFileLoggingMode 
	{
	EFileLoggingModeUnknown =0,  ///< Deprecated - has no effect
	EFileLoggingModeAppend,      ///< Deprecated - has no effect
	EFileLoggingModeOverwrite,    ///< Deprecated - has no effect
	EFileLoggingModeAppendRaw,	 ///< Deprecated - has no effect
	EFileLoggingModeOverwriteRaw ///< Deprecated - has no effect	
	};

class RFileLoggerBody;


/**
 * Flogger - File and Serial Logger client interface 
 *
 * @publishedAll
 * @deprecated Migrate to Open System Trace Instrumentation API instead
 * 
 * This class is responsible for providing all functions
 * clients require of the flogger system. It is preferred, though,
 * that clients use the provided macros which refer to these API's
 * so that all logging code is governed by the global __FLOG_ACTIVE
 * macro setting. The macro's are not currently documented using
 * doxygen - you will need to consult the flogger user guide instead.
 * RFileLogger is the only exported interface for the flogger component.
 */
class RFileLogger
	{
public:
	IMPORT_C RFileLogger();
	IMPORT_C ~RFileLogger();
	IMPORT_C TVersion Version() const;
	IMPORT_C TInt Connect();
	IMPORT_C void SetDateAndTime(TBool aUseDate,TBool aUseTime);	//Deprecated. Does nothing.
	IMPORT_C void CreateLog(const TDesC& aSubsystem, const TDesC& aComponent, TFileLoggingMode /*aMode*/);	//Deprecated. Use SetLogTags instead.
	IMPORT_C void CloseLog();	//Deprecated.
	
	IMPORT_C static void Write(const TDesC& aSubsystem, const TDesC& aComponent, TFileLoggingMode /*aMode*/, const TDesC16& aText);   // Removed
	IMPORT_C static void WriteFormat(const TDesC& aSubsystem, const TDesC& aComponent, TFileLoggingMode aMode, TRefByValue<const TDesC16> aFmt,...); // Removed
	IMPORT_C static void WriteFormat(const TDesC& aSubsystem, const TDesC& aComponent, TFileLoggingMode /*aMode*/, TRefByValue<const TDesC16> aFmt, VA_LIST& aList);  // Removed
	IMPORT_C static void Write(const TDesC& aSubsystem, const TDesC& aComponent, TFileLoggingMode /*aMode*/, const TDesC8& aText);  // Removed
	IMPORT_C static void WriteFormat(const TDesC& aSubsystem, const TDesC& aComponent, TFileLoggingMode aMode, TRefByValue<const TDesC8> aFmt,...);  // Removed
	IMPORT_C static void WriteFormat(const TDesC& aSubsystem, const TDesC& aComponent, TFileLoggingMode /*aMode*/, TRefByValue<const TDesC8> aFmt, VA_LIST& aList);  // Removed
	IMPORT_C static void HexDump(const TDesC& aSubsystem, const TDesC& aComponent, TFileLoggingMode /*aMode*/, const TText* aHeader, const TText* aMargin, const TUint8* aPtr, TInt aLen);  // Removed

	IMPORT_C static void Write(const TDesC8& aSubsystem, const TDesC8& aComponent, const TDesC16& aText);
	IMPORT_C static void WriteFormat(const TDesC8& aSubsystem, const TDesC8& aComponent, const TRefByValue<const TDesC16> aFmt,...);
	IMPORT_C static void WriteFormat(const TDesC8& aSubsystem, const TDesC8& aComponent, const TRefByValue<const TDesC16> aFmt, VA_LIST& aList);
	IMPORT_C static void Write(const TDesC8& aSubsystem, const TDesC8& aComponent, const TDesC8& aText);
	IMPORT_C static void WriteFormat(const TDesC8& aSubsystem, const TDesC8& aComponent, const TRefByValue<const TDesC8> aFmt,...);
	IMPORT_C static void WriteFormat(const TDesC8& aSubsystem, const TDesC8& aComponent, const TRefByValue<const TDesC8> aFmt, VA_LIST& aList);
	IMPORT_C static void HexDump(const TDesC8& aSubsystem, const TDesC8& aComponent, const TDesC8& aData, const TDesC8& aHeader = TPtrC8(NULL,0));
	
	IMPORT_C void Write(const TDesC16& aText);
	IMPORT_C void WriteFormat(TRefByValue<const TDesC16> aFmt,...);
	IMPORT_C void WriteFormat(TRefByValue<const TDesC16> aFmt, VA_LIST& aList);
	IMPORT_C void Write(const TDesC8& aText);
	IMPORT_C void WriteFormat(TRefByValue<const TDesC8> aFmt,...);
	IMPORT_C void WriteFormat(TRefByValue<const TDesC8> aFmt, VA_LIST& aList);
	IMPORT_C void WriteBinary(const TDesC8& aData);
	IMPORT_C void HexDump(const TText* aHeader, const TText* aMargin, const TUint8* aPtr, TInt aLen);
	IMPORT_C void HexDump(const TDesC8& aData, const TDesC8& aHeader = TPtrC8(NULL,0));
	
	IMPORT_C TInt LastError() const;	//Deprecated.
	IMPORT_C TBool LogValid() const;	//Deprecated.
	IMPORT_C void Close();
	IMPORT_C TInt ClearLog();
	IMPORT_C TInt SetLogTags(const TDesC8& aSubsystem, const TDesC8& aComponent);
	IMPORT_C TInt Handle() const;
	IMPORT_C TInt Share();
	IMPORT_C void __DbgShutDownServer();	//For testing purposes only
	IMPORT_C void __DbgSetHeapFailure(TInt aFailAfter);
private:
	TInt DoConnect();
	TInt DoSetLogTags(const TDesC8& aSubsystem, const TDesC8& aComponent);
	void DoWrite(const TDesC8& aBuf);
	void DoWriteFormat(TRefByValue<const TDesC16> aFmt, VA_LIST& aList);
	void DoWriteFormat(TRefByValue<const TDesC8> aFmt, VA_LIST& aList);
	void DoSendStaticWrite(const TDesC8& aDir, const TDesC8& aName, const TDesC8& aBuf);
	static void DoStaticWrite(const TDesC8& aDir, const TDesC8& aName, const TDesC8& aBuf);
	static void DoStaticWriteFormat(const TDesC8& aDir, const TDesC8& aName, const TRefByValue<const TDesC16> aFmt, VA_LIST& aList);
	static void DoStaticWriteFormat(const TDesC8& aDir, const TDesC8& aName, const TRefByValue<const TDesC8> aFmt, VA_LIST& aList);
	void DoHexDump(const TText* aHeader, const TText* aMargin, const TUint8* aPtr, TInt aLen);
	void DoHexDump(const TDesC8& aData, const TDesC8& aHeader, const TDesC8& aMargin);
	TBool IsLogging();
	RFileLogger& operator=(const RFileLogger& aLogger);	//Outlaw copying RFileLogger objects.
	RFileLogger(const RFileLogger& aLogger); //Outlaw copy constructor
private:
	RFileLoggerBody* iLoggerBody;   ///< Reference to all the data the client interface requires. This keeps the class size small and less likely to change in size.
	};


// Consult the How-to/User Guide for how to use these macros

// Sundry Logging Macros

#define __FLOG_DECLARATION_MEMBER_MUTABLE  mutable RFileLogger __logger__

#define __FLOG_DECLARATION_MEMBER		   RFileLogger __logger__

#define __FLOG_DECLARATION_VARIABLE		   RFileLogger __logger__

#define __FLOG_OPEN(subsys,compnt)		__logger__.Connect();\
										__logger__.SetLogTags(subsys,compnt)

#define __FLOG_OPENC(subsys,compnt)		__logger__.Connect();\
										__logger__.SetLogTags(subsys,compnt);\
										CleanupClosePushL(__logger__)

#define __FLOG_CLOSE					__logger__.Close()

#define __FLOG_CLOSE_CLEANUP			CleanupStack::PopAndDestroy(&__logger__)

#define __FLOG_CLEAR					__logger__.ClearLog()

#define __FLOG_SET_TAGS(subsys,compnt)	__logger__.SetLogTags(subsys,compnt)

#define __FLOG_STMT(text) text

// Connected Output Logging Macros

#define __FLOG_0(text)					__logger__.Write(text)

#define __FLOG_1(text,a)				__logger__.WriteFormat(text,a)

#define __FLOG_2(text,a,b)				__logger__.WriteFormat(text,a,b)

#define __FLOG_3(text,a,b,c)			__logger__.WriteFormat(text,a,b,c)

#define __FLOG_4(text,a,b,c,d)			__logger__.WriteFormat(text,a,b,c,d)

#define __FLOG_5(text,a,b,c,d,e)		__logger__.WriteFormat(text,a,b,c,d,e)

#define __FLOG_6(text,a,b,c,d,e,f)		__logger__.WriteFormat(text,a,b,c,d,e,f)

#define __FLOG_7(text,a,b,c,d,e,f,g)	__logger__.WriteFormat(text,a,b,c,d,e,f,g)

#define __FLOG_8(text,a,b,c,d,e,f,g,h)	__logger__.WriteFormat(text,a,b,c,d,e,f,g,h)

#define __FLOG_9(text,a,b,c,d,e,f,g,h,i)	__logger__.WriteFormat(text,a,b,c,d,e,f,g,h,i)

#define __FLOG(text)						__logger__.Write(text)

#define __FLOG_VA(args)						__logger__.WriteFormat args

#define __FLOG_HEXDUMP(args)				__logger__.HexDump args

#define __FLOG_BINARY(data)					__logger__.WriteBinary(data)

// Static Output Logging Macros
#define __FLOG_STATIC0(subsys,compnt,text)						RFileLogger::Write(subsys,compnt, text)

#define __FLOG_STATIC1(subsys,compnt,text,a)					RFileLogger::WriteFormat(subsys,compnt, text,a)

#define __FLOG_STATIC2(subsys,compnt,text,a,b)					RFileLogger::WriteFormat(subsys,compnt, text,a,b)

#define __FLOG_STATIC3(subsys,compnt,text,a,b,c)				RFileLogger::WriteFormat(subsys,compnt, text,a,b,c)

#define __FLOG_STATIC4(subsys,compnt,text,a,b,c,d)				RFileLogger::WriteFormat(subsys,compnt, text,a,b,c,d)

#define __FLOG_STATIC5(subsys,compnt,text,a,b,c,d,e)			RFileLogger::WriteFormat(subsys,compnt, text,a,b,c,d,e)

#define __FLOG_STATIC6(subsys,compnt,text,a,b,c,d,e,f)			RFileLogger::WriteFormat(subsys,compnt, text,a,b,c,d,e,f)

#define __FLOG_STATIC7(subsys,compnt,text,a,b,c,d,e,f,g)		RFileLogger::WriteFormat(subsys,compnt, text,a,b,c,d,e,f,g)

#define __FLOG_STATIC8(subsys,compnt,text,a,b,c,d,e,f,g,h)		RFileLogger::WriteFormat(subsys,compnt, text,a,b,c,d,e,f,g,h)

#define __FLOG_STATIC9(subsys,compnt,text,a,b,c,d,e,f,g,h,i)	RFileLogger::WriteFormat(subsys,compnt, text,a,b,c,d,e,f,g,h,i)

#define __FLOG_STATIC(subsys,compnt,text)						RFileLogger::WriteFormat(subsys,compnt, text)

#define __FLOG_STATIC_VA(args)									RFileLogger::WriteFormat args

#define __FLOG_STATIC_HEXDUMP(args)								RFileLogger::HexDump args



// Line below is used to check that RFileLogger stays the same size as
// __FLOG_DECLARATION_MEMBER_SIZE. If the RFileLogger object ever changes size,
// the line below will cause the compiler to throw an error. __FLOG_DECLARATION_MEMBER_SIZE
// should then be changed accordingly.
const TInt KCheckRFileLoggerIsCorrectSize = 1/(sizeof(RFileLogger)==sizeof(__FLOG_DECLARATION_MEMBER_SIZE));



#else
// Begin declarations for when Flogger is NOT to be used.
// This declares all macros to be void and the class to be replaced with a stub.
// This will result in Flogger only requiring 32 bits for each component which uses it.

// Consult the How-to/User Guide for how to use these macros

// Sundry Logging Macros

#define __FLOG_DECLARATION_MEMBER_MUTABLE	__FLOG_DECLARATION_MEMBER_SIZE __noLogger__; \
											inline void useNoLogger() { __noLogger__ = 0; }

#define __FLOG_DECLARATION_MEMBER			__FLOG_DECLARATION_MEMBER_SIZE __noLogger__; \
											inline void useNoLogger() { __noLogger__ = 0; }

#define __FLOG_DECLARATION_VARIABLE

#define __FLOG_OPEN(subsys,compnt)

#define __FLOG_OPENC(subsys,compnt)

#define __FLOG_CLOSE

#define __FLOG_CLOSE_CLEANUP

#define __FLOG_HEXDUMP(args)

#define __FLOG_CLEAR					

#define __FLOG_SET_TAGS(subsys,compnt)		


#define __FLOG_STMT(text)


// Connected Output Logging Macros

#define __FLOG_0(text)

#define __FLOG_1(text,a)

#define __FLOG_2(text,a,b)

#define __FLOG_3(text,a,b,c)

#define __FLOG_4(text,a,b,c,d)

#define __FLOG_5(text,a,b,c,d,e)

#define __FLOG_6(text,a,b,c,d,e,f)

#define __FLOG_7(text,a,b,c,d,e,f,g)

#define __FLOG_8(text,a,b,c,d,e,f,g,h)

#define __FLOG_9(text,a,b,c,d,e,f,g,h,i)

#define __FLOG(text)

#define __FLOG_VA(args)

#define __FLOG_BINARY(data)	

// Static Output Logging Macros
#define __FLOG_STATIC0(subsys,compnt,text)		

#define __FLOG_STATIC1(subsys,compnt,text,a)		

#define __FLOG_STATIC2(subsys,compnt,text,a,b)		

#define __FLOG_STATIC3(subsys,compnt,text,a,b,c)	

#define __FLOG_STATIC4(subsys,compnt,text,a,b,c,d)		

#define __FLOG_STATIC5(subsys,compnt,text,a,b,c,d,e)	

#define __FLOG_STATIC6(subsys,compnt,text,a,b,c,d,e,f)		

#define __FLOG_STATIC7(subsys,compnt,text,a,b,c,d,e,f,g)	

#define __FLOG_STATIC8(subsys,compnt,text,a,b,c,d,e,f,g,h)	

#define __FLOG_STATIC9(subsys,compnt,text,a,b,c,d,e,f,g,h,i)	

#define __FLOG_STATIC(subsys,compnt,text)

#define __FLOG_STATIC_VA(args)

#define __FLOG_STATIC_HEXDUMP(args)		


#endif






#endif // __COMMSDEBUGUTILITY_H__
