#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description: Mini shell using some of the SMB funcionality of the library
#
# Author:
#  Alberto Solino (@agsolino)
#
#
# Reference for:
#  SMB DCE/RPC
#
from __future__ import division
from __future__ import print_function
import sys
import logging
import argparse
from impacket.examples import logger
from impacket.examples.smbclient import MiniImpacketShell
from impacket import version
from impacket.smbconnection import SMBConnection


# Cosas anadidas
from impacket import smb, smb3, nmb, nt_errors, LOG
from impacket.ntlm import compute_lmhash, compute_nthash
from impacket.smb3structs import SMB2Packet, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30, GENERIC_ALL, FILE_SHARE_READ, \
    FILE_SHARE_WRITE, FILE_SHARE_DELETE, FILE_NON_DIRECTORY_FILE, FILE_OVERWRITE_IF, FILE_ATTRIBUTE_NORMAL, \
    SMB2_IL_IMPERSONATION, SMB2_OPLOCK_LEVEL_NONE, FILE_READ_DATA , FILE_WRITE_DATA, FILE_OPEN, GENERIC_READ, GENERIC_WRITE, \
    FILE_OPEN_REPARSE_POINT, MOUNT_POINT_REPARSE_DATA_STRUCTURE, FSCTL_SET_REPARSE_POINT, SMB2_0_IOCTL_IS_FSCTL, \
    MOUNT_POINT_REPARSE_GUID_DATA_STRUCTURE, FSCTL_DELETE_REPARSE_POINT, FSCTL_SRV_ENUMERATE_SNAPSHOTS, SRV_SNAPSHOT_ARRAY, \
    FILE_SYNCHRONOUS_IO_NONALERT, FILE_READ_EA, FILE_READ_ATTRIBUTES, READ_CONTROL, SYNCHRONIZE, SMB2_DIALECT_311


def main():
    # Init the example's logger theme
    logger.init()
    print(version.BANNER)
    parser = argparse.ArgumentParser(add_help = True, description = "SMB client implementation.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-file', type=argparse.FileType('r'), help='input file with commands to execute in the mini shell')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    #group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
    #                   help='Destination port to connect to SMB Server')
    group.add_argument('-port', choices=['139', '445','4000'], nargs='?', default='5000', metavar="destination port",
                       help='Destination port to connect to SMB Server')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    import re
    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        options.target).groups('')

    #In case the password contains '@'
    if '@' in address:
        password = password + '@' + address.rpartition('@')[0]
        address = address.rpartition('@')[2]

    if options.target_ip is None:
        options.target_ip = address

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    try:
        smbClient = SMBConnection(address, options.target_ip, sess_port=int(options.port))
        #smbClient = SMBConnection(address, options.target_ip, sess_port=int(options.port), preferredDialect=0x02FF)
        print ("mi dialecto es ",smbClient._SMBConnection.getDialect())
        print ("hola aqui estamos")
        if options.k is True:
            smbClient.kerberosLogin(username, password, domain, lmhash, nthash, options.aesKey, options.dc_ip )
        else:
            smbClient.login(username, password, domain, lmhash, nthash)

        shell = MiniImpacketShell(smbClient)

        #micreateMountPoint(smbClient,'C:\\proyectos\\proyectos09\\SECUREWORLD\\SW1\\smb\\prueba\\culo','micosa')
        if options.file is not None:
            logging.info("Executing commands from %s" % options.file.name)
            for line in options.file.readlines():
                if line[0] != '#':
                    print("# %s" % line, end=' ')
                    shell.onecmd(line)
                else:
                    print(line, end=' ')
        else:
            shell.cmdloop()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))


def micreateMountPoint(client, path, target):
        """
        creates a mount point at an existing directory

        :param int tid: tree id of current connection
        :param string path: directory at which to create mount point (must already exist)
        :param string target: target address of mount point
        """

        # Verify we're under SMB2+ session
        #if client.getDialect() not in [SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30]:
        #    raise SessionError(error = nt_errors.STATUS_NOT_SUPPORTED)
       
        # esto del tid es el tree ID
        tid=client._SMBConnection.connect_tree(target)
        print ("tid:", tid)
        fid = client.openFile(tid, path, GENERIC_READ | GENERIC_WRITE,
                            creationOption=FILE_OPEN_REPARSE_POINT)

        print("fichero ",path ," abierto")
        if target.startswith("\\"):
            fixed_name  = target.encode('utf-16le')
        else:
            fixed_name  = ("\\??\\" + target).encode('utf-16le')

        name        = target.encode('utf-16le')

        reparseData = MOUNT_POINT_REPARSE_DATA_STRUCTURE()

        reparseData['PathBuffer']           = fixed_name + b"\x00\x00" + name + b"\x00\x00"
        reparseData['SubstituteNameLength'] = len(fixed_name)
        reparseData['PrintNameOffset']      = len(fixed_name) + 2
        reparseData['PrintNameLength']      = len(name)

        client._SMBConnection.ioctl(tid, fid, FSCTL_SET_REPARSE_POINT, flags=SMB2_0_IOCTL_IS_FSCTL,
                                  inputBlob=reparseData)

        client.closeFile(tid, fid)


if __name__ == "__main__":
    main()



