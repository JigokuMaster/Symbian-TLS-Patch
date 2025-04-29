// Copyright (c) 2009 Nokia Corporation and/or its subsidiary(-ies).
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
// SSL exported functions. 
// 
//

/** 
 * @file ssl_internal.h
 * SSL internal constants and classes. 
 */

#ifndef __TCPSSL_INTERNAL_H__
#define __TCPSSL_INTERNAL_H__

#include <e32base.h>
#include <es_sock.h>

//TDNInfo & TCertInfo moved to a header file owned by HTTP
//included their file here to reduce impact of this move
// next 3 lines xfer from ssldata.h
/*
Code using this const has been commented out.
Be careful 0x406 could have been defined in the in_sock.h in the mean time...
const TUint KSoCurrentConnectStatus =0x406;
*/
/** 
 * The SSL connection status. 
 *
 * @internalComponent
 * 
 * @since v6.0 *
 * @deprecated No longer used by networking
 */
enum TSSLConnectStatus 
	{
	/** Connected. */
	ESSLConnected, 
	/** Waiting for user to answer. */
	ESSLWaitingUserAnswer, 
	/** Connection failed. */
	ESSLConnectFailed
	};
	
/** 
 * No dialogs. 
 *
 * @internalComponent
 */
const TUint KSSLUserDialogMode = 0x02;   // no dialogs

/** 
 * SSL Protocol Module's UID. 
 *
 * @internalComponent
 */
const TInt KUidSSLProtocolModule = 0x100011b2;

/** 
 * Unicode SSL Protocol Module's UID. 
 *
 * @internalComponent
 */
const TInt KUidUnicodeSSLProtocolModule = 0x1000183d;

/** 
 * SSL v3 Protocol Module's UID. 
 *
 * @internalComponent
 */
const TInt KUidSSLv3ProtocolModule = 0x10001699;

/** 
 * Socket reads from SSL. 
 *
 * @internalComponent
 */
const TUint KSockReadFromSSL = 0x10040000;

/** 
 * Socket writes to SSL. 
 *
 * @internalComponent
 */
const TUint KSockWriteFromSSL = 0x10044000;

// SSL/TLS connection Option taken from previous releases. This information has been
// removed from in_sock.h. All adaptor options have been removed.
const TUint KSolInetSSL = 0x205;				//< SSL setopts/ioctls

const TUint KSoCurrentCipherSuite  = 0x402;		//< Get current cipher suites
const TUint KSoSSLServerCert = 0x403;			//< Get server certificate
const TUint KSoDialogMode = 0x404;				//< Get/Set current dialog mode
const TUint KSoAvailableCipherSuites = 0x405;	//< Get available cipher suites
												// 0x406 skipped - See KSoCurrentConnectStatus
const TUint KSoKeyingMaterial = 0x407;			//< Get Keying Material for EAP


/**
 * Interface to the client code which decides which PSK identity and value should be used to secure the connection. 
*/
class MSoPskKeyHandler
	{
public:
	/**
		Called during the TLS PSK handshake to get the PSK identity and value to be used to secure the connection.

		@param aPskIdentityHint	A ptr to an HBufC8 containing the "PSK identity hint", or NULL if the server did not send one.
		@param aPskIdentity		NULL passed in, must be set to an HBufC8 containing the PSK Identity to be used.
		@param aPskKey			NULL passed in, must be set to an HBufC8 containing the PSK key value to be used.

		Note that the meaning of the PSK identity hint is NOT defined by the TLS standard, therefore any application
		using PSK must previously agree the source of the PSK to be used and the interpretion of the (optional) PSK identity 
		hint.
	*/
	virtual void GetPskL(const HBufC8 * aPskIdentityHint, HBufC8 *& aPskIdentity, HBufC8 *& aPskKey) = 0;
	};

/**
 *
 * @internalComponent
 */
const TUint KSoSSLDomainName = 0x505;			//< Set Domain name

// Adaptor layer specific options
// all SSL related options are supposed to be here
// rather then in insock/inc/in_sock.h
/** 
 * Use SSL v2 handschake. 
 * 
 * @internalAll
 * @deprecated the option is no longer supported
 */
const TUint KSoUseSSLv2Handshake = 0x500;  

// For KSoDialogMode
const TUint KSSLDialogUnattendedMode= 0x01;	//< No dialogs
const TUint KSSLDialogAttendedMode  = 0x00;	//< dialogs


// A version must be specified when creating an SSL factory
/** 
 * SSL module major version number. 
 * 
 * @internalComponent 
 */
const TUint KSSLMajorVersionNumber=1;
/** 
 * SSL module minor version number. 
 * 
 * @internalComponent 
 */
const TUint KSSLMinorVersionNumber=0;
/** 
 * SSL module build version number. 
 * 
 * @internalComponent 
 */
const TUint KSSLBuildVersionNumber=500;

class RMBufChain;
class CSSLSessionStore;
class CSSLSessionState;
class CNifFactory;
class CSSLProviderBase;
class CSymmetricCipher;
class CCryptoFactory;
class CCertFactory;
class CSSLTimers;
class MSSLSocketNotify 				
   /**
	* Abstract base class used to notify the SSL socket server that various events 
	* have occurred. The class provides several up-call member functions. 
	*
	* @internalComponent
	* 
	* @since v5.0 
	*
	* @deprecated No longer used by networking
	*/
	{
public:
// NOTE: THESE ARE A SUBSET OF MSocketNotify
	/** Called with unencrypted data to be given to the client application.
	* 
	* @param aDesc			Descriptor holding the unencrypted data. 
    * @param aRestingData	
	*/
	virtual void SSLDeliver(const TDesC8 &aDesc, TUint aRestingData)=0;

	virtual TUint SSLWrite(const TDesC8 &aDesc,TUint options, TSockAddr* aAddr=NULL)=0;
	
	/** Indicates that new buffer space is available. */
	virtual void SSLCanSend()=0;
	
	/** Indicates that a connection attempt has completed successfully. */
	virtual void SSLConnectComplete()=0;
	
	/** Indicates that the SAP has finished closing down. */
	virtual void SSLCanClose()=0;
	
	/** Tells the socket server that an error state has arisen within the protocol.
	* 
	* It should not be used to report programmatic errors, either in the protocol 
	* itself or the socket server (a panic should be used in these cases).
	* 
	* @param anError	Error that has arisen. */
	virtual void SSLError(TInt anError)=0;
	
	/** Called when the connection is closed due to an error. */
	virtual void SSLDisconnectIndication(void)=0;
	
	/** Called when the connection is closed due to an error.
	* 
	* @param aDisconnectData	Descriptor holding the disconnect data. */
	virtual void SSLDisconnectIndication(TDesC8& aDisconnectData)=0;
	
	/** Called when the connection is closed due to an error.
	* 
	* @param aError	The disconnect error. */
	virtual void SSLDisconnectIndication(TInt aError)=0;
	
	virtual void SSLIoctlComplete(TDesC8 *aBuf)=0;
	};

class CSSLTimers : public CBase
   /**
	* Base class for SSL timers. 
	*
	* @internalComponent
	* 
	* @since v5.0 
	*
	* @deprecated No longer used by networking
	*/
	{
public:
	/** Stops the SSLTimer, if it is running and destructs the object. */
	virtual ~CSSLTimers();
	
	/** Creates a new SSL Timer.
	* 
	* @return	KErrNone if successful; otherwise, a system-wide error code. */
	static CSSLTimers *NewL();

	/** Starts the SSL timer.
	* 
	* @param aCallBack	Call back function.
	* @param aTimeout	Time. */
	void StartSSLTimer(TCallBack aCallBack,TInt aTimeout);

	/** Stops the timer. */
	void StopSSLTimer();

	/** Stops and cancels the time recorded by the timer. */
	void DoSSLTimerExpired();
private:
	CSSLTimers();
private:
	TDeltaTimerEntry iSSLTimer;
	TDeltaTimerEntry *iSSLTimerH;
	};

class SSLGlobals
   /** 
	* @internalComponent
	*
	* @deprecated No longer used by networking
	*/
	{
public:
	CObjectConIx *iContainer;
	CObjectCon *iSSLFactories;
	TInt iSSLUnloadTimeout;
	TInt iSecureSocketCount;
	};

class RSSLDialogServer;
class CSSLFactory : public CObject
   /** 
	* Factory base for creating a concrete instance of a CSSLBase.
	*
	* @internalComponent
	* 
	* @since v5.0 
	* @deprecated No longer used by networking
	*/
	{	
public:	
	CSSLFactory();
	virtual ~CSSLFactory();
	virtual CSSLProviderBase* NewSecureSocketL(MSSLSocketNotify* aParent);
	virtual TInt Open();
	virtual void Close();
	virtual void InitL(RLibrary& aLib, CObjectCon& aCon);
	virtual TVersion Version() const;
//	static void Cleanup(TAny* aObject);
//	static TInt ControlledDelete(TAny* aSSLFactory);
	void SecureSocketShutdown(CSSLProviderBase *aSecureSocket);
	// other public members
	void SetSessionStateL(CSSLSessionState* aState,const TDesC8&);//const TDesC8& aSessionID,const TDesC8& aMasterSecret);
	TPtrC8 GetSession(const TDesC8&,CSSLSessionState*);
	void ConstructL();
private:
	void InitCryptoL();
public:
	RLibrary iLib;	
private:
//	RLibrary iCryptLibrary;
//	RLibrary iCertLibrary;
	TDblQue<CSSLProviderBase> iSecureSocketsList;
	TUint iSecureSocketsCount;	
	CSSLSessionStore *iSessStore;
	};

class CSSLProviderBase : public CBase
   /**
	* Abstract base class for all SSL protocol implementations. 
	*
	* @internalComponent
	*
	* @since v5.0
	* 
	* @deprecated No longer used by networking
	*/
	{
public:
	friend class CSSLFactory;
/** Connection closing type. */
	enum TCloseType 
	{
	/** Normal. */
	ENormal,
	/** Stop input. */
	EStopInput,
	/** Stop output. */
	EStopOutput,
	/** Close immediately. */
	EImmediate
	};
	
	CSSLProviderBase(CSSLFactory& aFactory);
	virtual ~CSSLProviderBase();

	/** Set the notification parent,
	* 
	* @param aNotify	Parent to be notified. */
	inline void SetNotify(MSSLSocketNotify* aNotify);
public:
// NOTE I'VE COPIED THESE DIRECTLY FROM CServProviderBase
	virtual const TInt GetOption(TUint level,TUint name,TDes8& anOption) =0;
	virtual void Ioctl(TUint level,TUint name,TDes8* anOption)=0;
	virtual void CancelIoctl(TUint aLevel,TUint aName)=0;
	
	/** Sets an option.
	* 
	* @param level		Integer constant identifying the option.
	* @param name		Option name.
	* @param anOption	Option value packaged in a descriptor.
	* @return			KErrNone if successful; otherwise, a system-wide error code. */
	virtual TInt SetOption(TUint level,TUint name,const TDesC8 &anOption)=0;
	
	virtual TUint Write(const TDesC8& aDesc,TUint options,TSockAddr* anAddr=NULL)=0;
	
	/** Process the event in the buffer.
	* 
	* @param aBuf	Chain with events to process. */
	virtual void Process(RMBufChain& aBuf)=0;
	
	virtual void ProcessL(const TDesC8 &aDesc)=0;
	
	/** Initiates a connection operation.
	*
	* This means that it tells the protocol to 
	* attempt to connect to a peer. It is called by the socket server in response 
	* to a connect request from a client. ActiveOpen() is only ever called on connection-oriented 
	* sockets. Such a socket should always have both the local address and the remote 
	* address specified before ActiveOpen() is called. If this is not the case, 
	* then the protocol should panic. When a connection has completed, the protocol 
	* should call ConnectComplete() on its TNotify.
	*
	* If an error occurs during connection the protocol should not call ConnectComplete() 
	* at all; instead it should call Error(). 
	*
	* @return	KErrNone if successful; otherwise, a system-wide error code. */
	virtual TInt ActiveOpen()=0;
	
	/** Same as ActiveOpen(), but with user data in the connection frame.
	*
	* @param aConnectionData	User specified connection data.
	* @return					KErrNone if successful; otherwise, a system-wide error code. */
	virtual TInt ActiveOpen(const TDesC8& aConnectionData)=0;
	
	/** Tells the protocol to start waiting for an incoming connection request on this 
	* socket (i.e. port). 
	*
	* It is called by the socket server in response to a listen request from a client.
	*
	* PassiveOpen() is only ever called on connection-oriented sockets. Such a socket 
	* should always have both the local address and the remote address specified 
	* before PassiveOpen() is called. If this is not the case, then the protocol 
	* should panic.
	*
	* The protocol should keep a count of sockets in Start state - incrementing 
	* a variable in ConnectComplete(), and decrementing it in Start(). 
	*
	* When a connection has completed, the protocol should call ConnectComplete() 
	* on its TNotify. 
	* 
	* If an error occurs during connection the protocol should not call ConnectComplete() 
	* at all; instead it should call Error(). 
	* 
	* @param aQueSize	The number of sockets which can be waiting for an outstanding 
	* 					Start() after calling ConnectComplete().
	* @return			KErrNone if successful; otherwise, a system-wide error code. */
	virtual TInt PassiveOpen(TUint aQueSize)=0;
	
	/** Same as PassiveOpen(), but with user data in the connection frame.
	*
	* @param aQueSize			The number of sockets which can be waiting for an outstanding 
	* 							Start() after calling ConnectComplete().
	* @param aConnectionData	User specified connection data
	* @return					KErrNone if successful, a system-wide error code if not. */
	virtual TInt PassiveOpen(TUint aQueSize,const TDesC8& aConnectionData)=0;
	
	/** Terminates a connection (or closes a non connection-oriented socket down).
	*
	* Normally, when the socket server has called Shutdown() for a socket, it will 
	* wait for the socket to call CanClose() before destroying the CServProviderBase 
	* object. */
	virtual void Shutdown()=0;
	
	/** Closes the connection. */
	virtual void Close()=0;
	/** Second phase contructor.
	*
	* @param aParent	Parent to be notified. */
	virtual void ConstructL(MSSLSocketNotify *aParent)=0;
	/** Indicates that the connection has been completed. */
	virtual void ConnectCompleted()=0;

public:
	TDblQueLink iLink;
protected:
	CSSLFactory* iFactory;
private:
	MSSLSocketNotify* iSocket;
	};

#endif
