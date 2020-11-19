#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Simple SMB Server example.
#
# Author:
#  Alberto Solino (@agsolino)
#

import sys
import argparse
import logging

from impacket.examples import logger
from impacket import smbserver, version
from impacket.smbserver import *

from impacket.ntlm import compute_lmhash, compute_nthash

#imports que he tenido que anadir
#---------------------------------
import random
import string
from impacket import smb3structs as smb2
from impacket import smb

from six.moves import configparser, socketserver


TRAZAS=True
class SimpleSMBServer2:
    """
    SimpleSMBServer class - Implements a simple, customizable SMB Server

    :param string listenAddress: the address you want the server to listen on
    :param integer listenPort: the port number you want the server to listen on
    :param string configFile: a file with all the servers' configuration. If no file specified, this class will create the basic parameters needed to run. You will need to add your shares manually tho. See addShare() method
    """
    def __init__(self, listenAddress = '0.0.0.0', listenPort=445, configFile=''):
        if configFile != '':
            print (" >>> SimpleSMBServer2: creando un SMBSERVER2...")
           #self.server = smbserver.SMBSERVER2((listenAddress,listenPort))
            self.server = SMBSERVER2((listenAddress,listenPort))
            self.server.processConfigFile(configFile)
            self.__smbConfig = None
        else:
            # Here we write a mini config for the server
            self.__smbConfig = smbserver.configparser.ConfigParser()
            self.__smbConfig.add_section('global')
            self.__smbConfig.set('global','server_name',''.join([random.choice(string.ascii_letters) for _ in range(8)]))
            self.__smbConfig.set('global','server_os',''.join([random.choice(string.ascii_letters) for _ in range(8)])
)
            self.__smbConfig.set('global','server_domain',''.join([random.choice(string.ascii_letters) for _ in range(8)])
)
            self.__smbConfig.set('global','log_file','None')
            self.__smbConfig.set('global','rpc_apis','yes')
            self.__smbConfig.set('global','credentials_file','')
            self.__smbConfig.set('global', 'challenge', "A"*8)

            # IPC always needed
            self.__smbConfig.add_section('IPC$')
            self.__smbConfig.set('IPC$','comment','')
            self.__smbConfig.set('IPC$','read only','yes')
            self.__smbConfig.set('IPC$','share type','3')
            self.__smbConfig.set('IPC$','path','')
            #self.server = smbserver.SMBSERVER((listenAddress,listenPort), config_parser = self.__smbConfig)
            self.server = SMBSERVER2((listenAddress,listenPort), config_parser = self.__smbConfig)
            
            self.server.processConfigFile()

        # Now we have to register the MS-SRVS server. This specially important for 
        # Windows 7+ and Mavericks clients since they WON'T (specially OSX) 
        # ask for shares using MS-RAP.

        self.__srvsServer = smbserver.SRVSServer()
        self.__srvsServer.daemon = True
        self.__wkstServer = smbserver.WKSTServer()
        self.__wkstServer.daemon = True
        self.server.registerNamedPipe('srvsvc',('127.0.0.1',self.__srvsServer.getListenPort()))
        self.server.registerNamedPipe('wkssvc',('127.0.0.1',self.__wkstServer.getListenPort()))

        self.origRead= None
        self.origWrite= None
        self.origCreate=None


    def start(self):
        self.__srvsServer.start()
        self.__wkstServer.start()
        self.server.serve_forever()

    def registerNamedPipe(self, pipeName, address):
        return self.server.registerNamedPipe(pipeName, address)

    def unregisterNamedPipe(self, pipeName):
        return self.server.unregisterNamedPipe(pipeName)

    def getRegisteredNamedPipes(self):
        return self.server.getRegisteredNamedPipes()

    def addShare(self, shareName, sharePath, shareComment='', shareType = '0', readOnly = 'no'):
        share = shareName.upper()
        self.__smbConfig.add_section(share)
        self.__smbConfig.set(share, 'comment', shareComment)
        self.__smbConfig.set(share, 'read only', readOnly)
        self.__smbConfig.set(share, 'share type', shareType)
        self.__smbConfig.set(share, 'path', sharePath)
        self.server.setServerConfig(self.__smbConfig)
        self.__srvsServer.setServerConfig(self.__smbConfig)
        self.server.processConfigFile()
        self.__srvsServer.processConfigFile()

    def removeShare(self, shareName):
        self.__smbConfig.remove_section(shareName.upper())
        self.__server.setServerConfig(self.__smbConfig)
        self.__srvsServer.setServerConfig(self.__smbConfig)
        self.server.processConfigFile()
        self.__srvsServer.processConfigFile()

    def setSMBChallenge(self, challenge):
        if challenge != '':
            self.__smbConfig.set('global', 'challenge', unhexlify(challenge))
            self.server.setServerConfig(self.__smbConfig)
            self.server.processConfigFile()
        
    def setLogFile(self, logFile):
        self.__smbConfig.set('global','log_file',logFile)
        self.server.setServerConfig(self.__smbConfig)
        self.server.processConfigFile()

    def setCredentialsFile(self, logFile):
        self.__smbConfig.set('global','credentials_file',logFile)
        self.server.setServerConfig(self.__smbConfig)
        self.server.processConfigFile()

    def addCredential(self, name, uid, lmhash, nthash):
        self.server.addCredential(name, uid, lmhash, nthash)

    def setSMB2Support(self, value):
        if value is True:
            self.__smbConfig.set("global", "SMB2Support", "True")
        else:
            self.__smbConfig.set("global", "SMB2Support", "False")
        self.server.setServerConfig(self.__smbConfig)
        self.server.processConfigFile()

    # AQUI VOY A PONER LAS FUNCIONES CALLBACK
    ##############################################################
    def sethooks(self):
        print ("creando HOOKs")
        print ("hooking comando ", smb2.SMB2_READ)
        self.origRead=self.server.hookSmb2Command(smb2.SMB2_READ,callback_READ) 
        print ("hooking comando ", smb2.SMB2_WRITE)
        self.origWrite=self.server.hookSmb2Command(smb2.SMB2_WRITE,callback_WRITE) 
        print ("hooking comando ", smb2.SMB2_CREATE)


        #self.origCreate=self.server.hookSmb2Command(smb2.SMB2_CREATE,callback_CREATE) # on hace nada

        #self.origRead=self.server.hookSmbCommand(smb.SMB.SMB_COM_READ,self.callback_READ) # on hace nada
        #self.origWrite=self.server.hookSmbCommand(smb.SMB.SMB_COM_WRITE,self.callback_WRITE) # on hace nada

        #self.orig_tr2=self.server.hookTransaction2(smb.SMB.TRANS2_QUERY_FILE_INFORMATION,self.callback_TR) # on hace nada

        #self.origSmbComNegotiate = self.server.hookSmbCommand(smb.SMB.SMB_COM_NEGOTIATE, self.SmbComNegotiate)


def callback_READ(connId, smbServer,  recvPacket):
    if TRAZAS:
        print (" >>>> hola esto es un callback READ")
        print ("======================================================")
        print ("conn: ",connId)
        #estas dos lineas son solo con proposito debug
        #readRequest   = smb2.SMB2Read(recvPacket['Data'])
        #print ("req:", readRequest.dump())# objeto de clase SMB2Read

    try:
        print ("lanzando comando...")
        read_response, cosa, error= SMB2Commands2.smb2Read(connId, smbServer, recvPacket)
    except:
        print ("ha habido una EXCEPCION")
        return  [], None, STATUS_INVALID_HANDLE
    if TRAZAS:
        print ("error:", error)
    if (error!=STATUS_SUCCESS):
        return read_response, cosa, error
    if TRAZAS:    
        print ("offset:",read_response[0]['DataOffset'])
        offset=read_response[0]['DataOffset']
        print ("len:",read_response[0]['DataLength'])
        print ("remain:",read_response[0]['DataRemaining'])
        print (" >>> lectura original realizada ok")
        print (read_response[0]['Buffer'])
        print ("mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm")
        print ("read buffer:",read_response[0]['Buffer'])
    payload= bytearray(read_response[0]['Buffer'])
    if (len(payload)>0):
        ind=0
        pay2=bytearray() 
        for i in payload:
            n=i
            if (n==ord('a')):
                n=ord('e')
            elif (n==ord('e')):
                n=ord('a') 
            pay2.append(n)
            ind+=1
        #print ("payload2:",pay2)
        nuevopay=bytes (pay2)
        read_response[0]['Buffer']=nuevopay
        if TRAZAS: 
            print ("-----------------------")
            print ("DECO buffer:",nuevopay)
            print ("-----------------------")
        
    return read_response,cosa,error
    


def callback_WRITE(connId, smbServer,  recvPacket):
    if TRAZAS:
        print (">>> hola esto es un callback WRITE")
        print ("======================================================")
    misbytes= bytearray(recvPacket['Data'])
    header=misbytes[0:47] #misbytes[0:47]
    payload=misbytes[47:] #misbytes[48:]
    ind=0
    pay2=bytearray() 
    if (len(payload)>0):
        for i in payload:
            n=  i  #^ 68
            if (n==ord('a')):
                n=ord('e')
            elif (n==ord('e')):
                n=ord('a')  
            #print ("ind:",ind,"->  ", i," --> n:", chr(n))
            pay2.append(n)
            ind+=1
        #print ("payload2:",pay2)
        cosa=bytes (header+pay2)
        #print ("cosa:",cosa)
        recvPacket['Data']=cosa
    #print ("--------------------------")
    return SMB2Commands2.smb2Write(connId, smbServer, recvPacket)

    #@staticmethod
def callback_CREATE(connId, smbServer, recvPacket):
    if TRAZAS:
        print (" >>> hola esto es un callback CREATE")
        print ("======================================================")
    #self.__SMB.log("Incoming connection (%s,%d)" % (self.__ip, self.__port))
    #self.__SMB.log("hola amigos (%s,%d)" % (self.__ip, self.__port))
    #self.origSmbComREAD = self.server.hookSmbCommand(SMB.SMB_COM_READ, self.SmbComRead)
    #def smb2Create(connId, smbServer, recvPacket):
    #return smbServer.origCreate(connId, smbServer, recvPacket)
    #return smbServer.__smb2CommandsHandler.smb2Create(connId, smbServer, recvPacket)
    return SMB2Commands2.smb2Create(connId, smbServer, recvPacket)
  



############################################################################################################################################

class SMBSERVERHandler2(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server, select_poll = False):
        if TRAZAS:
            print (" >>>  SMBSERVERHandler: init")
        #self.__SMB.log(">>>  SMBSERVERHandler: init")
        self.__SMB = server
        # In case of AF_INET6 the client_address contains 4 items, ignore the last 2
        self.__ip, self.__port = client_address[:2]
        self.__request = request
        self.__connId = threading.currentThread().getName()
        self.__timeOut = 60*5
        self.__select_poll = select_poll
        #self.__connId = os.getpid()
        socketserver.BaseRequestHandler.__init__(self, request, client_address, server)

    def handle(self):
        if TRAZAS:
            print (" >>>  SMBSERVERHandler: handle")
        #self.__SMB.log(">>>  SMBSERVERHandler: handle")

        self.__SMB.log("Incoming connection (%s,%d)" % (self.__ip, self.__port))
        self.__SMB.addConnection(self.__connId, self.__ip, self.__port)
        while True:
            try:
                # First of all let's get the NETBIOS packet
                session = nmb.NetBIOSTCPSession(self.__SMB.getServerName(), 'HOST', self.__ip, sess_port=self.__port,
                                                sock=self.__request, select_poll=self.__select_poll)
                try:
                    p = session.recv_packet(self.__timeOut)
                except nmb.NetBIOSTimeout:
                    raise
                except nmb.NetBIOSError:
                    break                 


                if p.get_type() == nmb.NETBIOS_SESSION_REQUEST:
                   # Someone is requesting a session, we're gonna accept them all :)
                   _, rn, my = p.get_trailer().split(' ')
                   remote_name = nmb.decode_name(b'\x20'+rn)
                   myname = nmb.decode_name(b'\x20'+my)
                   self.__SMB.log("NetBIOS Session request (%s,%s,%s)" % (self.__ip, remote_name[1].strip(), myname[1])) 
                   r = nmb.NetBIOSSessionPacket()
                   r.set_type(nmb.NETBIOS_SESSION_POSITIVE_RESPONSE)
                   r.set_trailer(p.get_trailer())
                   self.__request.send(r.rawData())
                else:
                   resp = self.__SMB.processRequest(self.__connId, p.get_trailer())
                   # Send all the packets received. Except for big transactions this should be
                   # a single packet
                   for i in resp:
                       if hasattr(i, 'getData'):
                           session.send_packet(i.getData())
                       else:
                           session.send_packet(i)
            except Exception as e:
                self.__SMB.log("Handle: %s" % e)
                #import traceback
                #traceback.print_exc()
                break

    def finish(self):
        # Thread/process is dying, we should tell the main SMB thread to remove all this thread data
        self.__SMB.log("Closing down connection (%s,%d)" % (self.__ip, self.__port))
        self.__SMB.removeConnection(self.__connId)
        return socketserver.BaseRequestHandler.finish(self)

class SMBSERVER2(socketserver.ThreadingMixIn, socketserver.TCPServer):
#class SMBSERVER(socketserver.ForkingMixIn, socketserver.TCPServer):
    def __init__(self, server_address, handler_class=SMBSERVERHandler2, config_parser = None):
        #self.log(' >>> SMBSERVER2: init')
        if TRAZAS:
            print (' >>> SMBSERVER2: init')
        socketserver.TCPServer.allow_reuse_address = True
        socketserver.TCPServer.__init__(self, server_address, handler_class)

        # Server name and OS to be presented whenever is necessary
        self.__serverName   = ''
        self.__serverOS     = ''
        self.__serverDomain = ''
        self.__challenge    = ''
        self.__log          = None

        # Our ConfigParser data
        self.__serverConfig = config_parser

        # Our credentials to be used during the server's lifetime
        self.__credentials = {}

        # Our log file
        self.__logFile = ''

        # Registered Named Pipes, format is PipeName,Socket
        self.__registeredNamedPipes = {}

        # JTR dump path
        self.__jtr_dump_path = ''

        # SMB2 Support flag = default not active
        self.__SMB2Support = False
 
        # Our list of commands we will answer, by default the NOT IMPLEMENTED one
        self.__smbCommandsHandler = SMBCommands()
        #self.__smbCommandsHandler = smbserver.SMBCommands()
        self.__smbTrans2Handler   = TRANS2Commands()
        #self.__smbTrans2Handler   = smbserver.TRANS2Commands()
        self.__smbTransHandler    = TRANSCommands()
        #self.__smbTransHandler    = smbserver.TRANSCommands()
        self.__smbNTTransHandler  = NTTRANSCommands()
        #self.__smbNTTransHandler  = smbserver.NTTRANSCommands()
        
        self.__smb2CommandsHandler = SMB2Commands2()
        #self.__smb2CommandsHandler = smbserver.SMB2Commands()
        
        self.__IoctlHandler       = Ioctls()
        #self.__IoctlHandler       = smbserver.Ioctls()

        self.__smbNTTransCommands = {
        # NT IOCTL, can't find doc for this
        0xff                               :self.__smbNTTransHandler.default
        }

        self.__smbTransCommands  = {
'\\PIPE\\LANMAN'                       :self.__smbTransHandler.lanMan,
smb.SMB.TRANS_TRANSACT_NMPIPE          :self.__smbTransHandler.transactNamedPipe,
        }
        self.__smbTrans2Commands = {
 smb.SMB.TRANS2_FIND_FIRST2            :self.__smbTrans2Handler.findFirst2,
 smb.SMB.TRANS2_FIND_NEXT2             :self.__smbTrans2Handler.findNext2,
 smb.SMB.TRANS2_QUERY_FS_INFORMATION   :self.__smbTrans2Handler.queryFsInformation,
 smb.SMB.TRANS2_QUERY_PATH_INFORMATION :self.__smbTrans2Handler.queryPathInformation,
 smb.SMB.TRANS2_QUERY_FILE_INFORMATION :self.__smbTrans2Handler.queryFileInformation,
 smb.SMB.TRANS2_SET_FILE_INFORMATION   :self.__smbTrans2Handler.setFileInformation,
 smb.SMB.TRANS2_SET_PATH_INFORMATION   :self.__smbTrans2Handler.setPathInformation
        }

        self.__smbCommands = { 
 #smb.SMB.SMB_COM_FLUSH:              self.__smbCommandsHandler.smbComFlush, 
 smb.SMB.SMB_COM_CREATE_DIRECTORY:   self.__smbCommandsHandler.smbComCreateDirectory, 
 smb.SMB.SMB_COM_DELETE_DIRECTORY:   self.__smbCommandsHandler.smbComDeleteDirectory, 
 smb.SMB.SMB_COM_RENAME:             self.__smbCommandsHandler.smbComRename, 
 smb.SMB.SMB_COM_DELETE:             self.__smbCommandsHandler.smbComDelete, 
 smb.SMB.SMB_COM_NEGOTIATE:          self.__smbCommandsHandler.smbComNegotiate, 
 smb.SMB.SMB_COM_SESSION_SETUP_ANDX: self.__smbCommandsHandler.smbComSessionSetupAndX,
 smb.SMB.SMB_COM_LOGOFF_ANDX:        self.__smbCommandsHandler.smbComLogOffAndX,
 smb.SMB.SMB_COM_TREE_CONNECT_ANDX:  self.__smbCommandsHandler.smbComTreeConnectAndX,
 smb.SMB.SMB_COM_TREE_DISCONNECT:    self.__smbCommandsHandler.smbComTreeDisconnect,
 smb.SMB.SMB_COM_ECHO:               self.__smbCommandsHandler.smbComEcho,
 smb.SMB.SMB_COM_QUERY_INFORMATION:  self.__smbCommandsHandler.smbQueryInformation,
 smb.SMB.SMB_COM_TRANSACTION2:       self.__smbCommandsHandler.smbTransaction2,
 smb.SMB.SMB_COM_TRANSACTION:        self.__smbCommandsHandler.smbTransaction,
 # Not needed for now
 smb.SMB.SMB_COM_NT_TRANSACT:        self.__smbCommandsHandler.smbNTTransact,
 smb.SMB.SMB_COM_QUERY_INFORMATION_DISK: self.__smbCommandsHandler.smbQueryInformationDisk,
 smb.SMB.SMB_COM_OPEN_ANDX:          self.__smbCommandsHandler.smbComOpenAndX,
 smb.SMB.SMB_COM_QUERY_INFORMATION2: self.__smbCommandsHandler.smbComQueryInformation2,
 smb.SMB.SMB_COM_READ_ANDX:          self.__smbCommandsHandler.smbComReadAndX,
 smb.SMB.SMB_COM_READ:               self.__smbCommandsHandler.smbComRead,
 smb.SMB.SMB_COM_WRITE_ANDX:         self.__smbCommandsHandler.smbComWriteAndX,
 smb.SMB.SMB_COM_WRITE:              self.__smbCommandsHandler.smbComWrite,
 smb.SMB.SMB_COM_CLOSE:              self.__smbCommandsHandler.smbComClose,
 smb.SMB.SMB_COM_LOCKING_ANDX:       self.__smbCommandsHandler.smbComLockingAndX,
 smb.SMB.SMB_COM_NT_CREATE_ANDX:     self.__smbCommandsHandler.smbComNtCreateAndX,
 0xFF:                               self.__smbCommandsHandler.default
}

        self.__smb2Ioctls = { 
 smb2.FSCTL_DFS_GET_REFERRALS:            self.__IoctlHandler.fsctlDfsGetReferrals, 
# smb2.FSCTL_PIPE_PEEK:                    self.__IoctlHandler.fsctlPipePeek, 
# smb2.FSCTL_PIPE_WAIT:                    self.__IoctlHandler.fsctlPipeWait, 
 smb2.FSCTL_PIPE_TRANSCEIVE:              self.__IoctlHandler.fsctlPipeTransceive, 
# smb2.FSCTL_SRV_COPYCHUNK:                self.__IoctlHandler.fsctlSrvCopyChunk, 
# smb2.FSCTL_SRV_ENUMERATE_SNAPSHOTS:      self.__IoctlHandler.fsctlSrvEnumerateSnapshots, 
# smb2.FSCTL_SRV_REQUEST_RESUME_KEY:       self.__IoctlHandler.fsctlSrvRequestResumeKey, 
# smb2.FSCTL_SRV_READ_HASH:                self.__IoctlHandler.fsctlSrvReadHash, 
# smb2.FSCTL_SRV_COPYCHUNK_WRITE:          self.__IoctlHandler.fsctlSrvCopyChunkWrite, 
# smb2.FSCTL_LMR_REQUEST_RESILIENCY:       self.__IoctlHandler.fsctlLmrRequestResiliency, 
# smb2.FSCTL_QUERY_NETWORK_INTERFACE_INFO: self.__IoctlHandler.fsctlQueryNetworkInterfaceInfo, 
# smb2.FSCTL_SET_REPARSE_POINT:            self.__IoctlHandler.fsctlSetReparsePoint, 
# smb2.FSCTL_DFS_GET_REFERRALS_EX:         self.__IoctlHandler.fsctlDfsGetReferralsEx, 
# smb2.FSCTL_FILE_LEVEL_TRIM:              self.__IoctlHandler.fsctlFileLevelTrim, 
 smb2.FSCTL_VALIDATE_NEGOTIATE_INFO:      self.__IoctlHandler.fsctlValidateNegotiateInfo, 
}

        self.__smb2Commands = { 
 smb2.SMB2_NEGOTIATE:       self.__smb2CommandsHandler.smb2Negotiate, 
 smb2.SMB2_SESSION_SETUP:   self.__smb2CommandsHandler.smb2SessionSetup, 
 smb2.SMB2_LOGOFF:          self.__smb2CommandsHandler.smb2Logoff, 
 smb2.SMB2_TREE_CONNECT:    self.__smb2CommandsHandler.smb2TreeConnect, 
 smb2.SMB2_TREE_DISCONNECT: self.__smb2CommandsHandler.smb2TreeDisconnect, 
 smb2.SMB2_CREATE:          self.__smb2CommandsHandler.smb2Create, 
 smb2.SMB2_CLOSE:           self.__smb2CommandsHandler.smb2Close, 
 smb2.SMB2_FLUSH:           self.__smb2CommandsHandler.smb2Flush, 
 smb2.SMB2_READ:            self.__smb2CommandsHandler.smb2Read, 
 smb2.SMB2_WRITE:           self.__smb2CommandsHandler.smb2Write, 
 smb2.SMB2_LOCK:            self.__smb2CommandsHandler.smb2Lock, 
 smb2.SMB2_IOCTL:           self.__smb2CommandsHandler.smb2Ioctl, 
 smb2.SMB2_CANCEL:          self.__smb2CommandsHandler.smb2Cancel, 
 smb2.SMB2_ECHO:            self.__smb2CommandsHandler.smb2Echo, 
 smb2.SMB2_QUERY_DIRECTORY: self.__smb2CommandsHandler.smb2QueryDirectory, 
 smb2.SMB2_CHANGE_NOTIFY:   self.__smb2CommandsHandler.smb2ChangeNotify, 
 smb2.SMB2_QUERY_INFO:      self.__smb2CommandsHandler.smb2QueryInfo, 
 smb2.SMB2_SET_INFO:        self.__smb2CommandsHandler.smb2SetInfo, 
# smb2.SMB2_OPLOCK_BREAK:    self.__smb2CommandsHandler.smb2SessionSetup, 
 0xFF:                      self.__smb2CommandsHandler.default
}

        # List of active connections
        self.__activeConnections = {}
  
    def getIoctls(self):
        return self.__smb2Ioctls

    def getCredentials(self):
        return self.__credentials

    def removeConnection(self, name):
        try:
           del(self.__activeConnections[name])
        except:
           pass
        self.log("Remaining connections %s" % list(self.__activeConnections.keys()))

    def addConnection(self, name, ip, port):
        self.__activeConnections[name] = {}
        # Let's init with some know stuff we will need to have
        # TODO: Document what's in there
        #print "Current Connections", self.__activeConnections.keys()
        self.__activeConnections[name]['PacketNum']       = 0
        self.__activeConnections[name]['ClientIP']        = ip
        self.__activeConnections[name]['ClientPort']      = port
        self.__activeConnections[name]['Uid']             = 0
        self.__activeConnections[name]['ConnectedShares'] = {}
        self.__activeConnections[name]['OpenedFiles']     = {}
        # SID results for findfirst2
        self.__activeConnections[name]['SIDs']            = {}
        self.__activeConnections[name]['LastRequest']     = {}
        self.__activeConnections[name]['SignatureEnabled']= False
        self.__activeConnections[name]['SigningChallengeResponse']= ''
        self.__activeConnections[name]['SigningSessionKey']= b''
        self.__activeConnections[name]['Authenticated']= False

    def getActiveConnections(self):
        return self.__activeConnections

    def setConnectionData(self, connId, data):
        self.__activeConnections[connId] = data
        #print "setConnectionData" 
        #print self.__activeConnections

    def getConnectionData(self, connId, checkStatus = True):
        conn = self.__activeConnections[connId]
        if checkStatus is True:
            if ('Authenticated' in conn) is not True:
                # Can't keep going further
                raise Exception("User not Authenticated!")
        return conn

    def getRegisteredNamedPipes(self):
        return self.__registeredNamedPipes

    def registerNamedPipe(self, pipeName, address):
        self.__registeredNamedPipes[str(pipeName)] = address
        return True

    def unregisterNamedPipe(self, pipeName):
        if pipeName in self.__registeredNamedPipes:
            del(self.__registeredNamedPipes[str(pipeName)])
            return True
        return False

    def unregisterTransaction(self, transCommand):
        if transCommand in self.__smbTransCommands:
           del(self.__smbTransCommands[transCommand])

    def hookTransaction(self, transCommand, callback):
        # If you call this function, callback will replace 
        # the current Transaction sub command.
        # (don't get confused with the Transaction smbCommand)
        # If the transaction sub command doesn't not exist, it is added
        # If the transaction sub command exists, it returns the original function         # replaced
        #
        # callback MUST be declared as:
        # callback(connId, smbServer, recvPacket, parameters, data, maxDataCount=0)
        #
        # WHERE:
        #
        # connId      : the connection Id, used to grab/update information about 
        #               the current connection
        # smbServer   : the SMBServer instance available for you to ask 
        #               configuration data
        # recvPacket  : the full SMBPacket that triggered this command
        # parameters  : the transaction parameters
        # data        : the transaction data
        # maxDataCount: the max amount of data that can be transferred agreed 
        #               with the client
        #
        # and MUST return:
        # respSetup, respParameters, respData, errorCode
        #
        # WHERE:
        #
        # respSetup: the setup response of the transaction
        # respParameters: the parameters response of the transaction
        # respData: the data response of the transaction
        # errorCode: the NT error code 

        if transCommand in self.__smbTransCommands:
           originalCommand = self.__smbTransCommands[transCommand]
        else:
           originalCommand = None 

        self.__smbTransCommands[transCommand] = callback
        return originalCommand

    def unregisterTransaction2(self, transCommand):
        if transCommand in self.__smbTrans2Commands:
           del(self.__smbTrans2Commands[transCommand])

    def hookTransaction2(self, transCommand, callback):
        # Here we should add to __smbTrans2Commands
        # Same description as Transaction
        if transCommand in self.__smbTrans2Commands:
           originalCommand = self.__smbTrans2Commands[transCommand]
        else:
           originalCommand = None 

        self.__smbTrans2Commands[transCommand] = callback
        return originalCommand

    def unregisterNTTransaction(self, transCommand):
        if transCommand in self.__smbNTTransCommands:
           del(self.__smbNTTransCommands[transCommand])

    def hookNTTransaction(self, transCommand, callback):
        # Here we should add to __smbNTTransCommands
        # Same description as Transaction
        if transCommand in self.__smbNTTransCommands:
           originalCommand = self.__smbNTTransCommands[transCommand]
        else:
           originalCommand = None 

        self.__smbNTTransCommands[transCommand] = callback
        return originalCommand

    def unregisterSmbCommand(self, smbCommand):
        if smbCommand in self.__smbCommands:
           del(self.__smbCommands[smbCommand])

    def hookSmbCommand(self, smbCommand, callback):
        # Here we should add to self.__smbCommands
        # If you call this function, callback will replace 
        # the current smbCommand.
        # If smbCommand doesn't not exist, it is added
        # If SMB command exists, it returns the original function replaced
        #
        # callback MUST be declared as:
        # callback(connId, smbServer, SMBCommand, recvPacket)
        #
        # WHERE:
        #
        # connId    : the connection Id, used to grab/update information about 
        #             the current connection
        # smbServer : the SMBServer instance available for you to ask 
        #             configuration data
        # SMBCommand: the SMBCommand itself, with its data and parameters. 
        #             Check smb.py:SMBCommand() for a reference
        # recvPacket: the full SMBPacket that triggered this command
        #
        # and MUST return:
        # <list of respSMBCommands>, <list of packets>, errorCode
        # <list of packets> has higher preference over commands, in case you 
        # want to change the whole packet 
        # errorCode: the NT error code 
        #
        # For SMB_COM_TRANSACTION2, SMB_COM_TRANSACTION and SMB_COM_NT_TRANSACT
        # the callback function is slightly different:
        #
        # callback(connId, smbServer, SMBCommand, recvPacket, transCommands)
        #
        # WHERE:
        # 
        # transCommands: a list of transaction subcommands already registered
        #

        if smbCommand in self.__smbCommands:
           originalCommand = self.__smbCommands[smbCommand]
        else:
           originalCommand = None 

        self.__smbCommands[smbCommand] = callback
        return originalCommand
  
    def unregisterSmb2Command(self, smb2Command):
        if smb2Command in self.__smb2Commands:
           del(self.__smb2Commands[smb2Command])

    def hookSmb2Command(self, smb2Command, callback):
        if smb2Command in self.__smb2Commands:
           originalCommand = self.__smb2Commands[smb2Command]
        else:
           originalCommand = None 

        self.__smb2Commands[smb2Command] = callback
        return originalCommand

    def log(self, msg, level=logging.INFO):
        self.__log.log(level,msg)

    def getServerName(self):
        return self.__serverName

    def getServerOS(self):
        return self.__serverOS
  
    def getServerDomain(self):
        return self.__serverDomain

    def getSMBChallenge(self):
        return self.__challenge
  
    def getServerConfig(self):
        return self.__serverConfig

    def setServerConfig(self, config):
        self.__serverConfig = config

    def getJTRdumpPath(self):
        return self.__jtr_dump_path

    def verify_request(self, request, client_address):
        # TODO: Control here the max amount of processes we want to launch
        # returning False, closes the connection
        return True

    def signSMBv1(self, connData, packet, signingSessionKey, signingChallengeResponse):
        # This logic MUST be applied for messages sent in response to any of the higher-layer actions and in
        # compliance with the message sequencing rules.
        #  * The client or server that sends the message MUST provide the 32-bit sequence number for this
        #    message, as specified in sections 3.2.4.1 and 3.3.4.1.
        #  * The SMB_FLAGS2_SMB_SECURITY_SIGNATURE flag in the header MUST be set.
        #  * To generate the signature, a 32-bit sequence number is copied into the
        #    least significant 32 bits of the SecuritySignature field and the remaining
        #    4 bytes are set to 0x00.
        #  * The MD5 algorithm, as specified in [RFC1321], MUST be used to generate a hash of the SMB
        #    message from the start of the SMB Header, which is defined as follows.
        #    CALL MD5Init( md5context )
        #    CALL MD5Update( md5context, Connection.SigningSessionKey )
        #    CALL MD5Update( md5context, Connection.SigningChallengeResponse )
        #    CALL MD5Update( md5context, SMB message )
        #    CALL MD5Final( digest, md5context )
        #    SET signature TO the first 8 bytes of the digest
        # The resulting 8-byte signature MUST be copied into the SecuritySignature field of the SMB Header,
        # after which the message can be transmitted.

        #print "seq(%d) signingSessionKey %r, signingChallengeResponse %r" % (connData['SignSequenceNumber'], signingSessionKey, signingChallengeResponse)
        packet['SecurityFeatures'] = struct.pack('<q',connData['SignSequenceNumber'])
        # Sign with the sequence
        m = hashlib.md5()
        m.update( signingSessionKey )
        m.update( signingChallengeResponse )
        if hasattr(packet, 'getData'):
            m.update( packet.getData() )
        else:
            m.update( packet )
        # Replace sequence with acual hash
        packet['SecurityFeatures'] = m.digest()[:8]
        connData['SignSequenceNumber'] +=2

    def signSMBv2(self, packet, signingSessionKey):
        packet['Signature'] = b'\x00'*16
        packet['Flags'] |= smb2.SMB2_FLAGS_SIGNED
        signature = hmac.new(signingSessionKey, packet.getData(), hashlib.sha256).digest()
        packet['Signature'] = signature[:16]
        #print "%s" % packet['Signature'].encode('hex')

    def processRequest(self, connId, data):
        #if TRAZAS:
        #    print (" >>> SMBSERVER2: processrequest")
        #self.log(">>>  SMBSERVER2: processrequest")
        
        # TODO: Process batched commands.
        isSMB2      = False
        SMBCommand  = None
        #if TRAZAS:
        #    print (" >>> SMBSERVER2: processrequest: trying")
        try:
            packet = smb.NewSMBPacket(data = data)
            SMBCommand  = smb.SMBCommand(packet['Data'][0])
            #if TRAZAS:
            #    print (" >>> SMBSERVER2: processrequest: el comando SMB1 es", SMBCommand)
        except:
            # Maybe a SMB2 packet?
            packet = smb2.SMB2Packet(data = data)
            connData = self.getConnectionData(connId, False)
            self.signSMBv2(packet, connData['SigningSessionKey'])
            isSMB2 = True
            #if TRAZAS:
            #   print (" >>> SMBSERVER2: processrequest: paquete SMB2")

        connData    = self.getConnectionData(connId, False)

        # We might have compound requests
        compoundedPacketsResponse = []
        compoundedPackets         = []
        try:
            # Search out list of implemented commands
            # We provide them with:
            # connId      : representing the data for this specific connection
            # self        : the SMBSERVER if they want to ask data to it
            # SMBCommand  : the SMBCommand they are expecting to process
            # packet      : the received packet itself, in case they need more data than the actual command
            # Only for Transactions
            # transCommand: a list of transaction subcommands
            # We expect to get:
            # respCommands: a list of answers for the commands processed
            # respPacket  : if the commands chose to directly craft packet/s, we use this and not the previous
            #               this MUST be a list
            # errorCode   : self explanatory
            if isSMB2 is False:
                # Is the client authenticated already?
                if connData['Authenticated'] is False and packet['Command'] not in (smb.SMB.SMB_COM_NEGOTIATE, smb.SMB.SMB_COM_SESSION_SETUP_ANDX):
                    # Nope.. in that case he should only ask for a few commands, if not throw him out.
                    errorCode = STATUS_ACCESS_DENIED
                    respPackets = None
                    respCommands = [smb.SMBCommand(packet['Command'])]
                else:
                    if TRAZAS:
                        print (" >>> SMBSERVER2: processrequest: paquete SMB: ", packet['Command'])
                    if packet['Command'] == smb.SMB.SMB_COM_TRANSACTION2:
                        respCommands, respPackets, errorCode = self.__smbCommands[packet['Command']](
                                      connId,
                                      self,
                                      SMBCommand,
                                      packet,
                                      self.__smbTrans2Commands)
                    elif packet['Command'] == smb.SMB.SMB_COM_NT_TRANSACT:
                        respCommands, respPackets, errorCode = self.__smbCommands[packet['Command']](
                                      connId,
                                      self,
                                      SMBCommand,
                                      packet,
                                      self.__smbNTTransCommands)
                    elif packet['Command'] == smb.SMB.SMB_COM_TRANSACTION:
                        respCommands, respPackets, errorCode = self.__smbCommands[packet['Command']](
                                      connId,
                                      self,
                                      SMBCommand,
                                      packet,
                                      self.__smbTransCommands)
                    else:
                        if packet['Command'] in self.__smbCommands:
                           if self.__SMB2Support is True:
                               if packet['Command'] == smb.SMB.SMB_COM_NEGOTIATE:
                                   try:
                                       respCommands, respPackets, errorCode = self.__smb2Commands[smb2.SMB2_NEGOTIATE](connId, self, packet, True)
                                       isSMB2 = True
                                   except Exception as e:
                                       import traceback
                                       traceback.print_exc()
                                       self.log('SMB2_NEGOTIATE: %s' % e, logging.ERROR)
                                       # If something went wrong, let's fallback to SMB1
                                       respCommands, respPackets, errorCode = self.__smbCommands[packet['Command']](
                                           connId,
                                           self,
                                           SMBCommand,
                                           packet)
                                       #self.__SMB2Support = False
                                       pass
                               else:
                                   respCommands, respPackets, errorCode = self.__smbCommands[packet['Command']](
                                           connId,
                                           self,
                                           SMBCommand,
                                           packet)
                           else:
                               respCommands, respPackets, errorCode = self.__smbCommands[packet['Command']](
                                           connId,
                                           self,
                                           SMBCommand,
                                           packet)
                        else:
                           respCommands, respPackets, errorCode = self.__smbCommands[255](connId, self, SMBCommand, packet)

                compoundedPacketsResponse.append((respCommands, respPackets, errorCode))
                compoundedPackets.append(packet)

            else:
                # Is the client authenticated already?
                if connData['Authenticated'] is False and packet['Command'] not in (smb2.SMB2_NEGOTIATE, smb2.SMB2_SESSION_SETUP):
                    # Nope.. in that case he should only ask for a few commands, if not throw him out.
                    errorCode = STATUS_ACCESS_DENIED
                    respPackets = None
                    respCommands = ['']
                    compoundedPacketsResponse.append((respCommands, respPackets, errorCode))
                    compoundedPackets.append(packet)
                else:
                    done = False
                    while not done:
                        if packet['Command'] in self.__smb2Commands:
                           if TRAZAS:
                                print (" >>> SMBSERVER2: processrequest: el comando SMB2 es ",packet['Command'])
                                print ("el paquete es:", packet) # objeto de clase smb3structs.SMB2Packet
                                print ("sesion:",packet['SessionID'])
                                print ("data:",packet['Data'])
                                print ("TID:",packet['TreeID'])
                                
                                
                           if self.__SMB2Support is True:
                            respCommands, respPackets, errorCode = self.__smb2Commands[packet['Command']](
                                       connId,
                                       self,
                                       packet)
                           else:
                               respCommands, respPackets, errorCode = self.__smb2Commands[255](connId, self, packet)
                        else:
                           respCommands, respPackets, errorCode = self.__smb2Commands[255](connId, self, packet)
                        # Let's store the result for this compounded packet
                        compoundedPacketsResponse.append((respCommands, respPackets, errorCode))
                        compoundedPackets.append(packet)
                        if packet['NextCommand'] != 0:
                            data = data[packet['NextCommand']:]
                            packet = smb2.SMB2Packet(data = data)
                        else:
                            done = True

        except Exception as e:
            #import traceback
            #traceback.print_exc()
            # Something wen't wrong, defaulting to Bad user ID
            self.log('processRequest (0x%x,%s)' % (packet['Command'],e), logging.ERROR)
            raise

        # We prepare the response packet to commands don't need to bother about that.
        connData    = self.getConnectionData(connId, False)

        # Force reconnection loop.. This is just a test.. client will send me back credentials :)
        #connData['PacketNum'] += 1
        #if connData['PacketNum'] == 15:
        #    connData['PacketNum'] = 0
        #    # Something wen't wrong, defaulting to Bad user ID
        #    self.log('Sending BAD USER ID!', logging.ERROR)
        #    #raise
        #    packet['Flags1'] |= smb.SMB.FLAGS1_REPLY
        #    packet['Flags2'] = 0
        #    errorCode = STATUS_SMB_BAD_UID
        #    packet['ErrorCode']   = errorCode >> 16
        #    packet['ErrorClass']  = errorCode & 0xff
        #    return [packet]

        self.setConnectionData(connId, connData)    

        packetsToSend = []
        for packetNum in range(len(compoundedPacketsResponse)):
            respCommands, respPackets, errorCode = compoundedPacketsResponse[packetNum]
            packet = compoundedPackets[packetNum]
            if respPackets is None:
                for respCommand in respCommands:
                    if isSMB2 is False:
                        respPacket           = smb.NewSMBPacket()
                        respPacket['Flags1'] = smb.SMB.FLAGS1_REPLY

                        # TODO this should come from a per session configuration
                        respPacket['Flags2'] = smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_LONG_NAMES | packet['Flags2'] & smb.SMB.FLAGS2_UNICODE
                        #respPacket['Flags2'] = smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_LONG_NAMES 
                        #respPacket['Flags1'] = 0x98
                        #respPacket['Flags2'] = 0xc807
                

                        respPacket['Tid']    = packet['Tid']
                        respPacket['Mid']    = packet['Mid']
                        respPacket['Pid']    = packet['Pid']  # el pid existe pero no en smb2

                        
                        respPacket['Uid']    = connData['Uid']
        
                        respPacket['ErrorCode']   = errorCode >> 16
                        respPacket['_reserved']   = errorCode >> 8 & 0xff
                        respPacket['ErrorClass']  = errorCode & 0xff
                        respPacket.addCommand(respCommand)

                        if connData['SignatureEnabled']:
                            respPacket['Flags2'] |= smb.SMB.FLAGS2_SMB_SECURITY_SIGNATURE
                            self.signSMBv1(connData, respPacket, connData['SigningSessionKey'], connData['SigningChallengeResponse'])
            
                        packetsToSend.append(respPacket)
                    else:
                        respPacket = smb2.SMB2Packet()
                        respPacket['Flags']     = smb2.SMB2_FLAGS_SERVER_TO_REDIR
                        if packetNum > 0:
                            respPacket['Flags'] |= smb2.SMB2_FLAGS_RELATED_OPERATIONS
                        respPacket['Status']    = errorCode
                        respPacket['CreditRequestResponse'] = packet['CreditRequestResponse']
                        respPacket['Command']   = packet['Command']
                        respPacket['CreditCharge'] = packet['CreditCharge']
                        #respPacket['CreditCharge'] = 0
                        respPacket['Reserved']  = packet['Reserved']
                        respPacket['SessionID'] = connData['Uid']
                        respPacket['MessageID'] = packet['MessageID']
                        respPacket['TreeID']    = packet['TreeID']
                        if hasattr(respCommand, 'getData'):
                            respPacket['Data']      = respCommand.getData()
                        else:
                            respPacket['Data']      = str(respCommand)

                        if connData['SignatureEnabled']:
                            self.signSMBv2(respPacket, connData['SigningSessionKey'])

                        packetsToSend.append(respPacket)
            else:
                # The SMBCommand took care of building the packet
                packetsToSend = respPackets

        if isSMB2 is True:
            # Let's build a compound answer
            finalData = b''
            i = 0
            for i in range(len(packetsToSend)-1):
                packet = packetsToSend[i]
                # Align to 8-bytes
                padLen = (8 - (len(packet) % 8) ) % 8
                packet['NextCommand'] = len(packet) + padLen
                if hasattr(packet, 'getData'):
                    finalData += packet.getData() + padLen*b'\x00'
                else:
                    finalData += packet + padLen*b'\x00'

            # Last one
            if hasattr(packetsToSend[len(packetsToSend)-1], 'getData'):
                finalData += packetsToSend[len(packetsToSend)-1].getData()
            else:
                finalData += packetsToSend[len(packetsToSend)-1]
            packetsToSend = [finalData]

        # We clear the compound requests
        connData['LastRequest'] = {}

        return packetsToSend

    def processConfigFile(self, configFile = None):
        # TODO: Do a real config parser
        if self.__serverConfig is None:
            if configFile is None:
                configFile = 'smb.conf'
            self.__serverConfig = configparser.ConfigParser()
            self.__serverConfig.read(configFile)

        self.__serverName   = self.__serverConfig.get('global','server_name')
        self.__serverOS     = self.__serverConfig.get('global','server_os')
        self.__serverDomain = self.__serverConfig.get('global','server_domain')
        self.__logFile      = self.__serverConfig.get('global','log_file')
        if self.__serverConfig.has_option('global', 'challenge'):
            self.__challenge    = b(self.__serverConfig.get('global', 'challenge'))
        else:
            self.__challenge    = b'A'*8

        if self.__serverConfig.has_option("global", "jtr_dump_path"):
            self.__jtr_dump_path = self.__serverConfig.get("global", "jtr_dump_path")

        if self.__serverConfig.has_option("global", "SMB2Support"):
            self.__SMB2Support = self.__serverConfig.getboolean("global","SMB2Support")
        else:
            self.__SMB2Support = False

        if self.__logFile != 'None':
            logging.basicConfig(filename = self.__logFile, 
                             level = logging.DEBUG, 
                             format="%(asctime)s: %(levelname)s: %(message)s", 
                             datefmt = '%m/%d/%Y %I:%M:%S %p')
        self.__log        = LOG

        # Process the credentials
        credentials_fname = self.__serverConfig.get('global','credentials_file')
        if credentials_fname is not "":
            cred = open(credentials_fname)
            line = cred.readline()
            while line:
                name, uid, lmhash, nthash = line.split(':')
                self.__credentials[name] = (uid, lmhash, nthash.strip('\r\n'))
                line = cred.readline()
            cred.close()
        self.log('Config file parsed')

    def addCredential(self, name, uid, lmhash, nthash):
        # If we have hashes, normalize them
        if lmhash != '' or nthash != '':
            if len(lmhash) % 2:
                lmhash = '0%s' % lmhash
            if len(nthash) % 2:
                nthash = '0%s' % nthash
            try: # just in case they were converted already
                lmhash = a2b_hex(lmhash)
                nthash = a2b_hex(nthash)
            except:
                pass
        self.__credentials[name] = (uid, lmhash, nthash)


########################################################################################################################################
class SMB2Commands2:
    @staticmethod
    def smb2Negotiate(connId, smbServer, recvPacket, isSMB1 = False):
        connData = smbServer.getConnectionData(connId, checkStatus = False)

        respPacket = smb2.SMB2Packet()
        respPacket['Flags']     = smb2.SMB2_FLAGS_SERVER_TO_REDIR
        respPacket['Status']    = STATUS_SUCCESS
        respPacket['CreditRequestResponse'] = 1
        respPacket['Command']   = smb2.SMB2_NEGOTIATE
        respPacket['SessionID'] = 0
        if isSMB1 is False:
            respPacket['MessageID'] = recvPacket['MessageID']
        else:
            respPacket['MessageID'] = 0
        respPacket['TreeID']    = 0


        respSMBCommand = smb2.SMB2Negotiate_Response()

        respSMBCommand['SecurityMode'] = 1
        if isSMB1 is True:
            # Let's first parse the packet to see if the client supports SMB2
            SMBCommand = smb.SMBCommand(recvPacket['Data'][0])
        
            dialects = SMBCommand['Data'].split(b'\x02')
            if b'SMB 2.002\x00' in dialects or b'SMB 2.???\x00' in dialects:
                respSMBCommand['DialectRevision'] = smb2.SMB2_DIALECT_002
            else:
                # Client does not support SMB2 fallbacking
                raise Exception('SMB2 not supported, fallbacking')
        else:
            respSMBCommand['DialectRevision'] = smb2.SMB2_DIALECT_002
        respSMBCommand['ServerGuid'] = b'A'*16
        respSMBCommand['Capabilities'] = 0
        respSMBCommand['MaxTransactSize'] = 65536
        respSMBCommand['MaxReadSize'] = 65536
        respSMBCommand['MaxWriteSize'] = 65536
        respSMBCommand['SystemTime'] = getFileTime(calendar.timegm(time.gmtime()))
        respSMBCommand['ServerStartTime'] = getFileTime(calendar.timegm(time.gmtime()))
        respSMBCommand['SecurityBufferOffset'] = 0x80

        blob = SPNEGO_NegTokenInit()
        blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]

        respSMBCommand['Buffer'] = blob.getData()
        respSMBCommand['SecurityBufferLength'] = len(respSMBCommand['Buffer'])

        respPacket['Data']      = respSMBCommand

        smbServer.setConnectionData(connId, connData)

        return None, [respPacket], STATUS_SUCCESS

    @staticmethod
    def smb2SessionSetup(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId, checkStatus = False)

        respSMBCommand = smb2.SMB2SessionSetup_Response()

        sessionSetupData = smb2.SMB2SessionSetup(recvPacket['Data'])

        connData['Capabilities'] = sessionSetupData['Capabilities']

        securityBlob = sessionSetupData['Buffer']

        rawNTLM = False
        if struct.unpack('B',securityBlob[0:1])[0] == ASN1_AID:
           # NEGOTIATE packet
           blob =  SPNEGO_NegTokenInit(securityBlob)
           token = blob['MechToken']
           if len(blob['MechTypes'][0]) > 0:
               # Is this GSSAPI NTLM or something else we don't support?
               mechType = blob['MechTypes'][0]
               if mechType != TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']:
                   # Nope, do we know it?
                   if mechType in MechTypes:
                       mechStr = MechTypes[mechType]
                   else:
                       mechStr = hexlify(mechType)
                   smbServer.log("Unsupported MechType '%s'" % mechStr, logging.CRITICAL)
                   # We don't know the token, we answer back again saying 
                   # we just support NTLM.
                   # ToDo: Build this into a SPNEGO_NegTokenResp()
                   respToken = b'\xa1\x15\x30\x13\xa0\x03\x0a\x01\x03\xa1\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a'
                   respSMBCommand['SecurityBufferOffset'] = 0x48
                   respSMBCommand['SecurityBufferLength'] = len(respToken)
                   respSMBCommand['Buffer'] = respToken

                   return [respSMBCommand], None, STATUS_MORE_PROCESSING_REQUIRED
        elif struct.unpack('B',securityBlob[0:1])[0] == ASN1_SUPPORTED_MECH:
           # AUTH packet
           blob = SPNEGO_NegTokenResp(securityBlob)
           token = blob['ResponseToken']
        else:
           # No GSSAPI stuff, raw NTLMSSP
           rawNTLM = True
           token = securityBlob

        # Here we only handle NTLMSSP, depending on what stage of the 
        # authentication we are, we act on it
        messageType = struct.unpack('<L',token[len('NTLMSSP\x00'):len('NTLMSSP\x00')+4])[0]

        if messageType == 0x01:
            # NEGOTIATE_MESSAGE
            negotiateMessage = ntlm.NTLMAuthNegotiate()
            negotiateMessage.fromString(token)
            # Let's store it in the connection data
            connData['NEGOTIATE_MESSAGE'] = negotiateMessage
            # Let's build the answer flags
            # TODO: Parse all the flags. With this we're leaving some clients out 

            ansFlags = 0

            if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_56:
               ansFlags |= ntlm.NTLMSSP_NEGOTIATE_56
            if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_128:
               ansFlags |= ntlm.NTLMSSP_NEGOTIATE_128
            if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH:
               ansFlags |= ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH
            if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
               ansFlags |= ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
            if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
               ansFlags |= ntlm.NTLMSSP_NEGOTIATE_UNICODE
            if negotiateMessage['flags'] & ntlm.NTLM_NEGOTIATE_OEM:
               ansFlags |= ntlm.NTLM_NEGOTIATE_OEM

            ansFlags |= ntlm.NTLMSSP_NEGOTIATE_VERSION | ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO | ntlm.NTLMSSP_TARGET_TYPE_SERVER | ntlm.NTLMSSP_NEGOTIATE_NTLM | ntlm.NTLMSSP_REQUEST_TARGET

            # Generate the AV_PAIRS
            av_pairs = ntlm.AV_PAIRS()
            # TODO: Put the proper data from SMBSERVER config
            av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] = av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME] = smbServer.getServerName().encode('utf-16le')
            av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] = av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] = smbServer.getServerDomain().encode('utf-16le')
            av_pairs[ntlm.NTLMSSP_AV_TIME] = struct.pack('<q', (116444736000000000 + calendar.timegm(time.gmtime()) * 10000000) )

            challengeMessage = ntlm.NTLMAuthChallenge()
            challengeMessage['flags']            = ansFlags
            challengeMessage['domain_len']       = len(smbServer.getServerDomain().encode('utf-16le'))
            challengeMessage['domain_max_len']   = challengeMessage['domain_len']
            challengeMessage['domain_offset']    = 40 + 16
            challengeMessage['challenge']        = smbServer.getSMBChallenge()
            challengeMessage['domain_name']      = smbServer.getServerDomain().encode('utf-16le')
            challengeMessage['TargetInfoFields_len']     = len(av_pairs)
            challengeMessage['TargetInfoFields_max_len'] = len(av_pairs)
            challengeMessage['TargetInfoFields'] = av_pairs
            challengeMessage['TargetInfoFields_offset']  = 40 + 16 + len(challengeMessage['domain_name'])
            challengeMessage['Version']          = b'\xff'*8
            challengeMessage['VersionLen']       = 8

            if rawNTLM is False:
                respToken = SPNEGO_NegTokenResp()
                # accept-incomplete. We want more data
                respToken['NegResult'] = b'\x01'
                respToken['SupportedMech'] = TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']

                respToken['ResponseToken'] = challengeMessage.getData()
            else:
                respToken = challengeMessage

            # Setting the packet to STATUS_MORE_PROCESSING
            errorCode = STATUS_MORE_PROCESSING_REQUIRED
            # Let's set up an UID for this connection and store it 
            # in the connection's data
            # Picking a fixed value
            # TODO: Manage more UIDs for the same session
            connData['Uid'] = random.randint(1,0xffffffff)
            # Let's store it in the connection data
            connData['CHALLENGE_MESSAGE'] = challengeMessage

        elif messageType == 0x02:
            # CHALLENGE_MESSAGE
            raise Exception('Challenge Message raise, not implemented!')
        elif messageType == 0x03:
            # AUTHENTICATE_MESSAGE, here we deal with authentication
            authenticateMessage = ntlm.NTLMAuthChallengeResponse()
            authenticateMessage.fromString(token)
            smbServer.log("AUTHENTICATE_MESSAGE (%s\\%s,%s)" % (
            authenticateMessage['domain_name'].decode('utf-16le'), authenticateMessage['user_name'].decode('utf-16le'),
            authenticateMessage['host_name'].decode('utf-16le')))
            # TODO: Check the credentials! Now granting permissions
            # Do we have credentials to check?
            if len(smbServer.getCredentials()) > 0:
                isGuest = False
                identity = authenticateMessage['user_name'].decode('utf-16le')
                # Do we have this user's credentials?
                if identity in smbServer.getCredentials():
                    # Process data:
                    # Let's parse some data and keep it to ourselves in case it is asked
                    uid, lmhash, nthash = smbServer.getCredentials()[identity]

                    errorCode, sessionKey = computeNTLMv2(identity, lmhash, nthash, smbServer.getSMBChallenge(),
                                                          authenticateMessage, connData['CHALLENGE_MESSAGE'],
                                                          connData['NEGOTIATE_MESSAGE'])

                    if sessionKey is not None:
                        connData['SignatureEnabled'] = True
                        connData['SigningSessionKey'] = sessionKey
                        connData['SignSequenceNumber'] = 1
                else:
                    errorCode = STATUS_LOGON_FAILURE
            else:
                # No credentials provided, let's grant access
                isGuest = True
                errorCode = STATUS_SUCCESS

            if errorCode == STATUS_SUCCESS:
                connData['Authenticated'] = True
                respToken = SPNEGO_NegTokenResp()
                # accept-completed
                respToken['NegResult'] = b'\x00'
                smbServer.log('User %s\\%s authenticated successfully' % (
                authenticateMessage['host_name'].decode('utf-16le'), authenticateMessage['user_name'].decode('utf-16le')))
                # Let's store it in the connection data
                connData['AUTHENTICATE_MESSAGE'] = authenticateMessage
                try:
                    jtr_dump_path = smbServer.getJTRdumpPath()
                    ntlm_hash_data = outputToJohnFormat(connData['CHALLENGE_MESSAGE']['challenge'],
                                                        authenticateMessage['user_name'],
                                                        authenticateMessage['domain_name'],
                                                        authenticateMessage['lanman'], authenticateMessage['ntlm'])
                    smbServer.log(ntlm_hash_data['hash_string'])
                    if jtr_dump_path is not '':
                        writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'],
                                              jtr_dump_path)
                except:
                    smbServer.log("Could not write NTLM Hashes to the specified JTR_Dump_Path %s" % jtr_dump_path)

                if isGuest:
                    respSMBCommand['SessionFlags'] = 1

            else:
                respToken = SPNEGO_NegTokenResp()
                respToken['NegResult'] = b'\x02'
                smbServer.log("Could not authenticate user!")
        else:
            raise Exception("Unknown NTLMSSP MessageType %d" % messageType)

        respSMBCommand['SecurityBufferOffset'] = 0x48
        respSMBCommand['SecurityBufferLength'] = len(respToken)
        respSMBCommand['Buffer'] = respToken.getData()

        # From now on, the client can ask for other commands
        connData['Authenticated'] = True
        # For now, just switching to nobody
        #os.setregid(65534,65534)
        #os.setreuid(65534,65534)
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2TreeConnect(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respPacket = smb2.SMB2Packet()
        respPacket['Flags']     = smb2.SMB2_FLAGS_SERVER_TO_REDIR
        respPacket['Status']    = STATUS_SUCCESS
        respPacket['CreditRequestResponse'] = 1
        respPacket['Command']   = recvPacket['Command']
        respPacket['SessionID'] = connData['Uid']
        respPacket['Reserved']  = recvPacket['Reserved']
        respPacket['MessageID'] = recvPacket['MessageID']
        respPacket['TreeID']    = recvPacket['TreeID']

        respSMBCommand        = smb2.SMB2TreeConnect_Response()

        treeConnectRequest = smb2.SMB2TreeConnect(recvPacket['Data'])

        errorCode = STATUS_SUCCESS

        ## Process here the request, does the share exist?
        path = recvPacket.getData()[treeConnectRequest['PathOffset']:][:treeConnectRequest['PathLength']]
        UNCOrShare = path.decode('utf-16le')

        # Is this a UNC?
        if ntpath.ismount(UNCOrShare):
            path = UNCOrShare.split('\\')[3]
        else:
            path = ntpath.basename(UNCOrShare)

        share = searchShare(connId, path.upper(), smbServer)
        if share is not None:
            # Simple way to generate a Tid
            if len(connData['ConnectedShares']) == 0:
               tid = 1
            else:
               tid = list(connData['ConnectedShares'].keys())[-1] + 1
            connData['ConnectedShares'][tid] = share
            connData['ConnectedShares'][tid]['shareName'] = path
            respPacket['TreeID']    = tid
            smbServer.log("Connecting Share(%d:%s)" % (tid,path))
        else:
            smbServer.log("SMB2_TREE_CONNECT not found %s" % path, logging.ERROR)
            errorCode = STATUS_OBJECT_PATH_NOT_FOUND
            respPacket['Status'] = errorCode
        ##

        if path.upper() == 'IPC$':
            respSMBCommand['ShareType'] = smb2.SMB2_SHARE_TYPE_PIPE
            respSMBCommand['ShareFlags'] = 0x30
        else:
            respSMBCommand['ShareType'] = smb2.SMB2_SHARE_TYPE_DISK
            respSMBCommand['ShareFlags'] = 0x0

        respSMBCommand['Capabilities'] = 0
        respSMBCommand['MaximalAccess'] = 0x000f01ff

        respPacket['Data'] = respSMBCommand

        # Sign the packet if needed
        if connData['SignatureEnabled']:
            smbServer.signSMBv2(respPacket, connData['SigningSessionKey'])
        smbServer.setConnectionData(connId, connData)

        return None, [respPacket], errorCode

    @staticmethod
    def smb2Create(connId, smbServer, recvPacket):
        #print (">>> SMB2Commands2 : smb2Create: hemos llegado al create original")
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb2.SMB2Create_Response()

        ntCreateRequest       = smb2.SMB2Create(recvPacket['Data'])

        respSMBCommand['Buffer'] = b'\x00'
        # Get the Tid associated
        if recvPacket['TreeID'] in connData['ConnectedShares']:
             # If we have a rootFid, the path is relative to that fid
             errorCode = STATUS_SUCCESS
             if 'path' in connData['ConnectedShares'][recvPacket['TreeID']]:
                 path = connData['ConnectedShares'][recvPacket['TreeID']]['path']
             else:
                 path = 'NONE'
                 errorCode = STATUS_ACCESS_DENIED

             deleteOnClose = False

             fileName = os.path.normpath(ntCreateRequest['Buffer'][:ntCreateRequest['NameLength']].decode('utf-16le').replace('\\','/'))
             if len(fileName) > 0 and (fileName[0] == '/' or fileName[0] == '\\'):
                # strip leading '/'
                fileName = fileName[1:]
             pathName = os.path.join(path,fileName)
             createDisposition = ntCreateRequest['CreateDisposition']
             mode = 0

             if createDisposition == smb2.FILE_SUPERSEDE:
                 mode |= os.O_TRUNC | os.O_CREAT
             elif createDisposition & smb2.FILE_OVERWRITE_IF == smb2.FILE_OVERWRITE_IF:
                 mode |= os.O_TRUNC | os.O_CREAT
             elif createDisposition & smb2.FILE_OVERWRITE == smb2.FILE_OVERWRITE:
                 if os.path.exists(pathName) is True:
                     mode |= os.O_TRUNC 
                 else:
                     errorCode = STATUS_NO_SUCH_FILE
             elif createDisposition & smb2.FILE_OPEN_IF == smb2.FILE_OPEN_IF:
                 if os.path.exists(pathName) is True:
                     mode |= os.O_TRUNC 
                 else:
                     mode |= os.O_TRUNC | os.O_CREAT
             elif createDisposition & smb2.FILE_CREATE == smb2.FILE_CREATE:
                 if os.path.exists(pathName) is True:
                     errorCode = STATUS_OBJECT_NAME_COLLISION
                 else:
                     mode |= os.O_CREAT
             elif createDisposition & smb2.FILE_OPEN == smb2.FILE_OPEN:
                 if os.path.exists(pathName) is not True and (str(pathName) in smbServer.getRegisteredNamedPipes()) is not True:
                     errorCode = STATUS_NO_SUCH_FILE

             if errorCode == STATUS_SUCCESS:
                 desiredAccess = ntCreateRequest['DesiredAccess']
                 if (desiredAccess & smb2.FILE_READ_DATA) or (desiredAccess & smb2.GENERIC_READ):
                     mode |= os.O_RDONLY
                 if (desiredAccess & smb2.FILE_WRITE_DATA) or (desiredAccess & smb2.GENERIC_WRITE):
                     if (desiredAccess & smb2.FILE_READ_DATA) or (desiredAccess & smb2.GENERIC_READ):
                         mode |= os.O_RDWR #| os.O_APPEND
                     else: 
                         mode |= os.O_WRONLY #| os.O_APPEND
                 if desiredAccess & smb2.GENERIC_ALL:
                     mode |= os.O_RDWR #| os.O_APPEND

                 createOptions =  ntCreateRequest['CreateOptions']
                 if mode & os.O_CREAT == os.O_CREAT:
                     if createOptions & smb2.FILE_DIRECTORY_FILE == smb2.FILE_DIRECTORY_FILE: 
                         try:
                             # Let's create the directory
                             os.mkdir(pathName)
                             mode = os.O_RDONLY
                         except Exception as e:
                             smbServer.log("SMB2_CREATE: %s,%s,%s" % (pathName,mode,e),logging.ERROR)
                             errorCode = STATUS_ACCESS_DENIED
                 if createOptions & smb2.FILE_NON_DIRECTORY_FILE == smb2.FILE_NON_DIRECTORY_FILE:
                     # If the file being opened is a directory, the server MUST fail the request with
                     # STATUS_FILE_IS_A_DIRECTORY in the Status field of the SMB Header in the server
                     # response.
                     if os.path.isdir(pathName) is True:
                        errorCode = STATUS_FILE_IS_A_DIRECTORY

                 if createOptions & smb2.FILE_DELETE_ON_CLOSE == smb2.FILE_DELETE_ON_CLOSE:
                     deleteOnClose = True
                 
                 if errorCode == STATUS_SUCCESS:
                     try:
                         if os.path.isdir(pathName) and sys.platform == 'win32':
                            fid = VOID_FILE_DESCRIPTOR
                         else:
                            if sys.platform == 'win32':
                               mode |= os.O_BINARY
                            if str(pathName) in smbServer.getRegisteredNamedPipes():
                                fid = PIPE_FILE_DESCRIPTOR
                                sock = socket.socket()
                                sock.connect(smbServer.getRegisteredNamedPipes()[str(pathName)])
                            else:
                                fid = os.open(pathName, mode)
                     except Exception as e:
                         smbServer.log("SMB2_CREATE: %s,%s,%s" % (pathName,mode,e),logging.ERROR)
                         #print e
                         fid = 0
                         errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_SMB_BAD_TID

        if errorCode == STATUS_SUCCESS:
            # Simple way to generate a fid
            fakefid = uuid.generate()

            respSMBCommand['FileID'] = fakefid
            respSMBCommand['CreateAction'] = createDisposition

            if fid == PIPE_FILE_DESCRIPTOR:
                respSMBCommand['CreationTime']   = 0
                respSMBCommand['LastAccessTime'] = 0
                respSMBCommand['LastWriteTime']  = 0
                respSMBCommand['ChangeTime']     = 0
                respSMBCommand['AllocationSize'] = 4096
                respSMBCommand['EndOfFile']      = 0
                respSMBCommand['FileAttributes'] = 0x80

            else:
                if os.path.isdir(pathName):
                    respSMBCommand['FileAttributes'] = smb.SMB_FILE_ATTRIBUTE_DIRECTORY
                else:
                    respSMBCommand['FileAttributes'] = ntCreateRequest['FileAttributes']
                # Let's get this file's information
                respInfo, errorCode = queryPathInformation('',pathName,level= smb.SMB_QUERY_FILE_ALL_INFO)
                if errorCode == STATUS_SUCCESS:
                    respSMBCommand['CreationTime']   = respInfo['CreationTime']
                    respSMBCommand['LastAccessTime'] = respInfo['LastAccessTime']
                    respSMBCommand['LastWriteTime']  = respInfo['LastWriteTime']
                    respSMBCommand['LastChangeTime'] = respInfo['LastChangeTime']
                    respSMBCommand['FileAttributes'] = respInfo['ExtFileAttributes']
                    respSMBCommand['AllocationSize'] = respInfo['AllocationSize']
                    respSMBCommand['EndOfFile']      = respInfo['EndOfFile']

            if errorCode == STATUS_SUCCESS:
                # Let's store the fid for the connection
                # smbServer.log('Create file %s, mode:0x%x' % (pathName, mode))
                connData['OpenedFiles'][fakefid] = {}
                connData['OpenedFiles'][fakefid]['FileHandle'] = fid
                connData['OpenedFiles'][fakefid]['FileName'] = pathName
                connData['OpenedFiles'][fakefid]['DeleteOnClose']  = deleteOnClose
                connData['OpenedFiles'][fakefid]['Open']  = {}
                connData['OpenedFiles'][fakefid]['Open']['EnumerationLocation'] = 0
                connData['OpenedFiles'][fakefid]['Open']['EnumerationSearchPattern'] = ''
                if fid == PIPE_FILE_DESCRIPTOR:
                    connData['OpenedFiles'][fakefid]['Socket'] = sock
        else:
            respSMBCommand = smb2.SMB2Error()
        
        if errorCode == STATUS_SUCCESS:
            connData['LastRequest']['SMB2_CREATE'] = respSMBCommand
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2Close(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb2.SMB2Close_Response()

        closeRequest = smb2.SMB2Close(recvPacket['Data'])

        if closeRequest['FileID'].getData() == b'\xff'*16:
            # Let's take the data from the lastRequest
            if  'SMB2_CREATE' in connData['LastRequest']:
                fileID = connData['LastRequest']['SMB2_CREATE']['FileID']
            else:
                fileID = closeRequest['FileID'].getData()
        else:
            fileID = closeRequest['FileID'].getData()

        if fileID in connData['OpenedFiles']:
             errorCode = STATUS_SUCCESS
             fileHandle = connData['OpenedFiles'][fileID]['FileHandle']
             pathName = connData['OpenedFiles'][fileID]['FileName']
             infoRecord = None
             try:
                 if fileHandle == PIPE_FILE_DESCRIPTOR:
                     connData['OpenedFiles'][fileID]['Socket'].close()
                 elif fileHandle != VOID_FILE_DESCRIPTOR:
                     os.close(fileHandle)
                     infoRecord, errorCode = queryFileInformation(os.path.dirname(pathName), os.path.basename(pathName), smb2.SMB2_FILE_NETWORK_OPEN_INFO)
             except Exception as e:
                 smbServer.log("SMB2_CLOSE %s" % e, logging.ERROR)
                 errorCode = STATUS_INVALID_HANDLE
             else:
                 # Check if the file was marked for removal
                 if connData['OpenedFiles'][fileID]['DeleteOnClose'] is True:
                     try:
                         if os.path.isdir(pathName):
                             shutil.rmtree(connData['OpenedFiles'][fileID]['FileName'])
                         else:
                             os.remove(connData['OpenedFiles'][fileID]['FileName'])
                     except Exception as e:
                         smbServer.log("SMB2_CLOSE %s" % e, logging.ERROR)
                         errorCode = STATUS_ACCESS_DENIED
    
                 # Now fill out the response
                 if infoRecord is not None:
                     respSMBCommand['CreationTime']   = infoRecord['CreationTime']
                     respSMBCommand['LastAccessTime'] = infoRecord['LastAccessTime']
                     respSMBCommand['LastWriteTime']  = infoRecord['LastWriteTime']
                     respSMBCommand['ChangeTime']     = infoRecord['ChangeTime']
                     respSMBCommand['AllocationSize'] = infoRecord['AllocationSize']
                     respSMBCommand['EndofFile']      = infoRecord['EndOfFile']
                     respSMBCommand['FileAttributes'] = infoRecord['FileAttributes']
                 if errorCode == STATUS_SUCCESS:
                     del(connData['OpenedFiles'][fileID])
        else:
            errorCode = STATUS_INVALID_HANDLE

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2QueryInfo(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb2.SMB2QueryInfo_Response()

        queryInfo = smb2.SMB2QueryInfo(recvPacket['Data'])
       
        errorCode = STATUS_SUCCESS 

        respSMBCommand['OutputBufferOffset'] = 0x48
        respSMBCommand['Buffer'] = b'\x00'

        if queryInfo['FileID'].getData() == b'\xff'*16:
            # Let's take the data from the lastRequest
            if  'SMB2_CREATE' in connData['LastRequest']:
                fileID = connData['LastRequest']['SMB2_CREATE']['FileID']
            else:
                fileID = queryInfo['FileID'].getData()
        else:
            fileID = queryInfo['FileID'].getData()

        if recvPacket['TreeID'] in connData['ConnectedShares']:
            if fileID in connData['OpenedFiles']:
                fileName = connData['OpenedFiles'][fileID]['FileName']

                if queryInfo['InfoType'] == smb2.SMB2_0_INFO_FILE:
                    if queryInfo['FileInfoClass'] == smb2.SMB2_FILE_INTERNAL_INFO:
                        # No need to call queryFileInformation, we have the data here
                        infoRecord = smb2.FileInternalInformation()
                        infoRecord['IndexNumber'] = fileID
                    else:
                        infoRecord, errorCode = queryFileInformation(os.path.dirname(fileName),
                                                                     os.path.basename(fileName),
                                                                     queryInfo['FileInfoClass'])
                elif queryInfo['InfoType'] == smb2.SMB2_0_INFO_FILESYSTEM:
                    if queryInfo['FileInfoClass'] == smb2.SMB2_FILE_EA_INFO:
                        infoRecord = b'\x00'*4
                    else:
                        infoRecord = queryFsInformation(os.path.dirname(fileName), os.path.basename(fileName), queryInfo['FileInfoClass'])
                elif queryInfo['InfoType'] == smb2.SMB2_0_INFO_SECURITY:
                    # Failing for now, until we support it
                    infoRecord = None
                    errorCode = STATUS_ACCESS_DENIED
                else:
                    smbServer.log("queryInfo not supported (%x)" %  queryInfo['InfoType'], logging.ERROR)

                if infoRecord is not None:
                    respSMBCommand['OutputBufferLength'] = len(infoRecord)
                    respSMBCommand['Buffer'] = infoRecord
            else:
                errorCode = STATUS_INVALID_HANDLE
        else:
            errorCode = STATUS_SMB_BAD_TID


        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2SetInfo(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb2.SMB2SetInfo_Response()

        setInfo = smb2.SMB2SetInfo(recvPacket['Data'])
       
        errorCode = STATUS_SUCCESS 

        if setInfo['FileID'].getData() == b'\xff'*16:
            # Let's take the data from the lastRequest
            if  'SMB2_CREATE' in connData['LastRequest']:
                fileID = connData['LastRequest']['SMB2_CREATE']['FileID']
            else:
                fileID = setInfo['FileID'].getData()
        else:
            fileID = setInfo['FileID'].getData()

        if recvPacket['TreeID'] in connData['ConnectedShares']:
            path     = connData['ConnectedShares'][recvPacket['TreeID']]['path']
            if fileID in connData['OpenedFiles']:
                pathName = connData['OpenedFiles'][fileID]['FileName']

                if setInfo['InfoType'] == smb2.SMB2_0_INFO_FILE:
                    # The file information is being set
                    informationLevel = setInfo['FileInfoClass']
                    if informationLevel == smb2.SMB2_FILE_DISPOSITION_INFO:
                        infoRecord = smb.SMBSetFileDispositionInfo(setInfo['Buffer'])
                        if infoRecord['DeletePending'] > 0:
                           # Mark this file for removal after closed
                           connData['OpenedFiles'][fileID]['DeleteOnClose'] = True
                    elif informationLevel == smb2.SMB2_FILE_BASIC_INFO:
                        infoRecord = smb.SMBSetFileBasicInfo(setInfo['Buffer'])
                        # Creation time won't be set,  the other ones we play with.
                        atime = infoRecord['LastWriteTime']
                        if atime == 0:
                            atime = -1
                        else:
                            atime = getUnixTime(atime)
                        mtime = infoRecord['ChangeTime']
                        if mtime == 0:
                            mtime = -1
                        else:
                            mtime = getUnixTime(mtime)
                        if atime > 0 and mtime > 0:
                            os.utime(pathName,(atime,mtime))
                    elif informationLevel == smb2.SMB2_FILE_END_OF_FILE_INFO:
                        fileHandle = connData['OpenedFiles'][fileID]['FileHandle']
                        infoRecord = smb.SMBSetFileEndOfFileInfo(setInfo['Buffer'])
                        if infoRecord['EndOfFile'] > 0:
                            os.lseek(fileHandle, infoRecord['EndOfFile']-1, 0)
                            os.write(fileHandle, b'\x00')
                    elif informationLevel == smb2.SMB2_FILE_RENAME_INFO:
                        renameInfo = smb2.FILE_RENAME_INFORMATION_TYPE_2(setInfo['Buffer'])
                        newPathName = os.path.join(path,renameInfo['FileName'].decode('utf-16le').replace('\\', '/')) 
                        if renameInfo['ReplaceIfExists'] == 0 and os.path.exists(newPathName):
                            return [smb2.SMB2Error()], None, STATUS_OBJECT_NAME_COLLISION
                        try:
                             os.rename(pathName,newPathName)
                             connData['OpenedFiles'][fileID]['FileName'] = newPathName
                        except Exception as e:
                             smbServer.log("smb2SetInfo: %s" % e, logging.ERROR)
                             errorCode = STATUS_ACCESS_DENIED
                    else:
                        smbServer.log('Unknown level for set file info! 0x%x' % informationLevel, logging.ERROR)
                        # UNSUPPORTED
                        errorCode =  STATUS_NOT_SUPPORTED
                #elif setInfo['InfoType'] == smb2.SMB2_0_INFO_FILESYSTEM:
                #    # The underlying object store information is being set.
                #    setInfo = queryFsInformation('/', fileName, queryInfo['FileInfoClass'])
                #elif setInfo['InfoType'] == smb2.SMB2_0_INFO_SECURITY:
                #    # The security information is being set.
                #    # Failing for now, until we support it
                #    infoRecord = None
                #    errorCode = STATUS_ACCESS_DENIED
                #elif setInfo['InfoType'] == smb2.SMB2_0_INFO_QUOTA:
                #    # The underlying object store quota information is being set.
                #    setInfo = queryFsInformation('/', fileName, queryInfo['FileInfoClass'])
                else:
                    smbServer.log("setInfo not supported (%x)" %  setInfo['InfoType'], logging.ERROR)

            else:
                errorCode = STATUS_INVALID_HANDLE
        else:
            errorCode = STATUS_SMB_BAD_TID


        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2Write(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb2.SMB2Write_Response()
        writeRequest   = smb2.SMB2Write(recvPacket['Data'])

        respSMBCommand['Buffer'] = b'\x00'

        if writeRequest['FileID'].getData() == b'\xff'*16:
            # Let's take the data from the lastRequest
            if  'SMB2_CREATE' in connData['LastRequest']:
                fileID = connData['LastRequest']['SMB2_CREATE']['FileID']
            else:
                fileID = writeRequest['FileID'].getData()
        else:
            fileID = writeRequest['FileID'].getData()

        if fileID in connData['OpenedFiles']:
             fileHandle = connData['OpenedFiles'][fileID]['FileHandle']
             errorCode = STATUS_SUCCESS
             try:
                 if fileHandle != PIPE_FILE_DESCRIPTOR:
                     offset = writeRequest['Offset']
                     # If we're trying to write past the file end we just skip the write call (Vista does this)
                     if os.lseek(fileHandle, 0, 2) >= offset:
                         os.lseek(fileHandle,offset,0)
                         os.write(fileHandle,writeRequest['Buffer'])
                 else:
                     sock = connData['OpenedFiles'][fileID]['Socket']
                     sock.send(writeRequest['Buffer'])

                 respSMBCommand['Count']    = writeRequest['Length']
                 respSMBCommand['Remaining']= 0xff
             except Exception as e:
                 smbServer.log('SMB2_WRITE: %s' % e, logging.ERROR)
                 errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_INVALID_HANDLE

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2Read(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb2.SMB2Read_Response()
        readRequest   = smb2.SMB2Read(recvPacket['Data'])

        respSMBCommand['Buffer'] = b'\x00'

        if readRequest['FileID'].getData() == b'\xff'*16:
            # Let's take the data from the lastRequest
            if  'SMB2_CREATE' in connData['LastRequest']:
                fileID = connData['LastRequest']['SMB2_CREATE']['FileID']
            else:
                fileID = readRequest['FileID'].getData()
        else:
            fileID = readRequest['FileID'].getData()

        if fileID in connData['OpenedFiles']:
             fileHandle = connData['OpenedFiles'][fileID]['FileHandle']
             errorCode = 0
             try:
                 if fileHandle != PIPE_FILE_DESCRIPTOR:
                     offset = readRequest['Offset']
                     os.lseek(fileHandle,offset,0)
                     content = os.read(fileHandle,readRequest['Length'])
                 else:
                     sock = connData['OpenedFiles'][fileID]['Socket']
                     content = sock.recv(readRequest['Length'])

                 respSMBCommand['DataOffset']   = 0x50
                 respSMBCommand['DataLength']   = len(content)
                 respSMBCommand['DataRemaining']= 0
                 respSMBCommand['Buffer']       = content
             except Exception as e:
                 smbServer.log('SMB2_READ: %s ' % e, logging.ERROR)
                 errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_INVALID_HANDLE

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2Flush(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb2.SMB2Flush_Response()
        flushRequest   = smb2.SMB2Flush(recvPacket['Data'])

        if flushRequest['FileID'].getData() in connData['OpenedFiles']:
             fileHandle = connData['OpenedFiles'][flushRequest['FileID'].getData()]['FileHandle']
             errorCode = STATUS_SUCCESS
             try:
                 os.fsync(fileHandle)
             except Exception as e:
                 smbServer.log("SMB2_FLUSH %s" % e, logging.ERROR)
                 errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_INVALID_HANDLE

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode


    @staticmethod
    def smb2QueryDirectory(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)
        respSMBCommand = smb2.SMB2QueryDirectory_Response()
        queryDirectoryRequest   = smb2.SMB2QueryDirectory(recvPacket['Data'])

        respSMBCommand['Buffer'] = b'\x00'

        # The server MUST locate the tree connection, as specified in section 3.3.5.2.11.
        if (recvPacket['TreeID'] in connData['ConnectedShares']) is False:
            return [smb2.SMB2Error()], None, STATUS_NETWORK_NAME_DELETED
       
        # Next, the server MUST locate the open for the directory to be queried 
        # If no open is found, the server MUST fail the request with STATUS_FILE_CLOSED
        if queryDirectoryRequest['FileID'].getData() == b'\xff'*16:
            # Let's take the data from the lastRequest
            if  'SMB2_CREATE' in connData['LastRequest']:
                fileID = connData['LastRequest']['SMB2_CREATE']['FileID']
            else:
                fileID = queryDirectoryRequest['FileID'].getData()
        else:
            fileID = queryDirectoryRequest['FileID'].getData()

        if (fileID in connData['OpenedFiles']) is False:
            return [smb2.SMB2Error()], None, STATUS_FILE_CLOSED

        # If the open is not an open to a directory, the request MUST be failed 
        # with STATUS_INVALID_PARAMETER.
        if os.path.isdir(connData['OpenedFiles'][fileID]['FileName']) is False:
            return [smb2.SMB2Error()], None, STATUS_INVALID_PARAMETER

        # If any other information class is specified in the FileInformationClass 
        # field of the SMB2 QUERY_DIRECTORY Request, the server MUST fail the 
        # operation with STATUS_INVALID_INFO_CLASS. 
        if queryDirectoryRequest['FileInformationClass'] not in (
        smb2.FILE_DIRECTORY_INFORMATION, smb2.FILE_FULL_DIRECTORY_INFORMATION, smb2.FILEID_FULL_DIRECTORY_INFORMATION,
        smb2.FILE_BOTH_DIRECTORY_INFORMATION, smb2.FILEID_BOTH_DIRECTORY_INFORMATION, smb2.FILENAMES_INFORMATION):
            return [smb2.SMB2Error()], None, STATUS_INVALID_INFO_CLASS

        # If SMB2_REOPEN is set in the Flags field of the SMB2 QUERY_DIRECTORY 
        # Request, the server SHOULD<326> set Open.EnumerationLocation to 0 
        # and Open.EnumerationSearchPattern to an empty string.
        if queryDirectoryRequest['Flags'] & smb2.SMB2_REOPEN:
            connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'] = 0
            connData['OpenedFiles'][fileID]['Open']['EnumerationSearchPattern'] = ''
        
        # If SMB2_RESTART_SCANS is set in the Flags field of the SMB2 
        # QUERY_DIRECTORY Request, the server MUST set 
        # Open.EnumerationLocation to 0.
        if queryDirectoryRequest['Flags'] & smb2.SMB2_RESTART_SCANS:
            connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'] = 0

        # If Open.EnumerationLocation is 0 and Open.EnumerationSearchPattern 
        # is an empty string, then Open.EnumerationSearchPattern MUST be set 
        # to the search pattern specified in the SMB2 QUERY_DIRECTORY by 
        # FileNameOffset and FileNameLength. If FileNameLength is 0, the server 
        # SHOULD<327> set Open.EnumerationSearchPattern as "*" to search all entries.

        pattern = queryDirectoryRequest['Buffer'].decode('utf-16le')
        if  connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'] == 0 and \
            connData['OpenedFiles'][fileID]['Open']['EnumerationSearchPattern'] == '':
            if pattern == '':
                pattern = '*'
            connData['OpenedFiles'][fileID]['Open']['EnumerationSearchPattern'] = pattern

        # If SMB2_INDEX_SPECIFIED is set and FileNameLength is not zero, 
        # the server MUST set Open.EnumerationSearchPattern to the search pattern 
        # specified in the request by FileNameOffset and FileNameLength.
        if queryDirectoryRequest['Flags'] & smb2.SMB2_INDEX_SPECIFIED and \
           queryDirectoryRequest['FileNameLength'] > 0:
            connData['OpenedFiles'][fileID]['Open']['EnumerationSearchPattern'] = pattern

        pathName = os.path.join(os.path.normpath(connData['OpenedFiles'][fileID]['FileName']),pattern)
        searchResult, searchCount, errorCode = findFirst2(os.path.dirname(pathName),
                  os.path.basename(pathName),
                  queryDirectoryRequest['FileInformationClass'], 
                  smb.ATTR_DIRECTORY, isSMB2 = True )

        if errorCode != STATUS_SUCCESS:
            return [smb2.SMB2Error()], None, errorCode

        if searchCount > 2 and pattern == '*':
            # strip . and ..
            searchCount -= 2
            searchResult = searchResult[2:]

        if searchCount == 0 and connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'] == 0:
            return [smb2.SMB2Error()], None, STATUS_NO_SUCH_FILE

        if  connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'] < 0:
            return [smb2.SMB2Error()], None, STATUS_NO_MORE_FILES

        totalData = 0
        respData = b''
        for nItem in range(connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'], searchCount):
            connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'] += 1
            if queryDirectoryRequest['Flags'] & smb2.SL_RETURN_SINGLE_ENTRY:
                # If single entry is requested we must clear the NextEntryOffset
                searchResult[nItem]['NextEntryOffset'] = 0
            data = searchResult[nItem].getData()
            lenData = len(data)
            padLen = (8-(lenData % 8)) %8
 
            if (totalData+lenData) >= queryDirectoryRequest['OutputBufferLength']:
                connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'] -= 1
                break
            else:
                respData += data + b'\x00'*padLen
                totalData += lenData + padLen

            if queryDirectoryRequest['Flags'] & smb2.SL_RETURN_SINGLE_ENTRY:
                break

        if connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'] >= searchCount:
             connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'] = -1

        respSMBCommand['OutputBufferOffset'] = 0x48
        respSMBCommand['OutputBufferLength'] = totalData
        respSMBCommand['Buffer'] = respData

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2ChangeNotify(connId, smbServer, recvPacket):

        return [smb2.SMB2Error()], None, STATUS_NOT_SUPPORTED

    @staticmethod
    def smb2Echo(connId, smbServer, recvPacket):

        respSMBCommand = smb2.SMB2Echo_Response()

        return [respSMBCommand], None, STATUS_SUCCESS

    @staticmethod
    def smb2TreeDisconnect(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb2.SMB2TreeDisconnect_Response()

        if recvPacket['TreeID'] in connData['ConnectedShares']:
            smbServer.log("Disconnecting Share(%d:%s)" % (
            recvPacket['TreeID'], connData['ConnectedShares'][recvPacket['TreeID']]['shareName']))
            del(connData['ConnectedShares'][recvPacket['TreeID']])
            errorCode = STATUS_SUCCESS
        else:
            # STATUS_SMB_BAD_TID
            errorCode = STATUS_SMB_BAD_TID


        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2Logoff(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb2.SMB2Logoff_Response()

        if recvPacket['SessionID'] != connData['Uid']:
            # STATUS_SMB_BAD_UID
            errorCode = STATUS_SMB_BAD_UID
        else:
            errorCode = STATUS_SUCCESS

        connData['Uid'] = 0
        connData['Authenticated'] = False

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2Ioctl(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb2.SMB2Ioctl_Response()
        ioctlRequest   = smb2.SMB2Ioctl(recvPacket['Data'])

        ioctls = smbServer.getIoctls()
        if ioctlRequest['CtlCode'] in ioctls:
            outputData, errorCode = ioctls[ioctlRequest['CtlCode']](connId, smbServer, ioctlRequest)
            if errorCode == STATUS_SUCCESS:
                respSMBCommand['CtlCode']      = ioctlRequest['CtlCode']
                respSMBCommand['FileID']       = ioctlRequest['FileID']
                respSMBCommand['InputOffset']  = 0
                respSMBCommand['InputCount']   = 0
                respSMBCommand['OutputOffset'] = 0x70
                respSMBCommand['OutputCount']  = len(outputData)
                respSMBCommand['Flags']        = 0
                respSMBCommand['Buffer']       = outputData
            else:
                respSMBCommand = outputData
        else:
            smbServer.log("Ioctl not implemented command: 0x%x" % ioctlRequest['CtlCode'],logging.DEBUG)
            errorCode = STATUS_INVALID_DEVICE_REQUEST
            respSMBCommand = smb2.SMB2Error()

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2Lock(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb2.SMB2Lock_Response()

        # I'm actually doing nothing.. just make MacOS happy ;)
        errorCode = STATUS_SUCCESS

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2Cancel(connId, smbServer, recvPacket):
        # I'm actually doing nothing
        return [smb2.SMB2Error()], None, STATUS_CANCELLED

    @staticmethod
    def default(connId, smbServer, recvPacket):
        # By default we return an SMB Packet with error not implemented
        smbServer.log("Not implemented command: 0x%x" % recvPacket['Command'],logging.DEBUG)
        return [smb2.SMB2Error()], None, STATUS_NOT_SUPPORTED
########################################################################################################################################
if __name__ == '__main__':
    print ("bienvenido al SMB server SECUREWORLD 1.0 ")
    print ("---------------------------------------- ")
    print("usage example:")
    print ('  py smbserver.py -smb2support -port 5000 "miculo" -username "joseja" -password "caca" C:\\proyectos\\proyectos09\\SECUREWORLD\\SW1\smb\\prueba\culo')
    print("")
    # Init the example's logger theme
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "This script will launch a SMB Server and add a "
                                     "share specified as an argument. You need to be root in order to bind to port 445. "
                                     "For optional authentication, it is possible to specify username and password or the NTLM hash. "
                                     "Example: smbserver.py -comment 'My share' TMP /tmp")

    parser.add_argument('shareName', action='store', help='name of the share to add')
    parser.add_argument('sharePath', action='store', help='path of the share to add')
    parser.add_argument('-comment', action='store', help='share\'s comment to display when asked for shares')
    parser.add_argument('-username', action="store", help='Username to authenticate clients')
    parser.add_argument('-password', action="store", help='Password for the Username')
    parser.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes for the Username, format is LMHASH:NTHASH')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ip', '--interface-address', action='store', default='0.0.0.0', help='ip address of listening interface')
    parser.add_argument('-port', action='store', default='445', help='TCP port for listening incoming connections (default 445)')
    parser.add_argument('-smb2support', action='store_true', default=False, help='SMB2 Support (experimental!)')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    try:
       options = parser.parse_args()
    except Exception as e:
       logging.critical(str(e))
       sys.exit(1)

    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    if options.comment is None:
        comment = ''
    else:
        comment = options.comment

    #server = smbserver.SimpleSMBServer(listenAddress=options.interface_address, listenPort=int(options.port))
    server = SimpleSMBServer2(listenAddress=options.interface_address, listenPort=int(options.port))

    server.addShare(options.shareName.upper(), options.sharePath, comment)
    server.setSMB2Support(options.smb2support)

    # If a user was specified, let's add it to the credentials for the SMBServer. If no user is specified, anonymous
    # connections will be allowed
    if options.username is not None:
        # we either need a password or hashes, if not, ask
        if options.password is None and options.hashes is None:
            from getpass import getpass
            password = getpass("Password:")
            # Let's convert to hashes
            lmhash = compute_lmhash(password)
            nthash = compute_nthash(password)
        elif options.password is not None:
            lmhash = compute_lmhash(options.password)
            nthash = compute_nthash(options.password)
        else:
            lmhash, nthash = options.hashes.split(':')

        server.addCredential(options.username, 0, lmhash, nthash)

    # Here you can set a custom SMB challenge in hex format
    # If empty defaults to '4141414141414141'
    # (remember: must be 16 hex bytes long)
    # e.g. server.setSMBChallenge('12345678abcdef00')
    server.setSMBChallenge('')

    # If you don't want log to stdout, comment the following line
    # If you want log dumped to a file, enter the filename
    server.setLogFile('')


    # vamos a instalar hooks antes de lanzarlo
    #----------------------------------------------------
    server.sethooks()
    
    # Rock and roll
    server.start()

#============================================================================



