# !/usr/bin/python
# -*- coding: utf-8 -*-

#

"""
    DNS Text Record Reader

    Aims of this project:

    - Use the Windows built in ctypes to request DNS TXT records
    - Parse the values out as required
"""

from sys import exit, platform, argv
from ctypes import *
from ctypes.wintypes import DWORD, LPSTR, WORD
from getopt import getopt
from datetime import datetime

__author__ = 'Chris John Riley'
__credits__ = 'est <http://blog.est.im/>'
__link__ = 'http://pastebin.com/f39d8b997'
__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'Chris John Riley'
__email__ = 'contact@c22.cc'
__status__ = 'Prototype'

kernel32 = windll.kernel32
wininet = windll.wininet
dnsapi = windll.dnsapi

CHAR = c_char
LPTSTR = LPSTR

logo =\
'''\n
\t\t\t ____  _  _  ___    ____  _  _  ____     ___  ____  ____
\t\t\t(  _ \( \( )/ __)  (_  _)( \/ )(_  _)   / __)( ___)(_  _)
\t\t\t )(_) ))  ( \__ \    )(   )  (   )(    ( (_-. )__)   )(
\t\t\t(____/(_)\_)(___/   (__) (_/\_) (__)    \___/(____) (__)

\t\t\t\t\t\t\t-------------------------
\t\t\t\t\t\t\t| The DNS TXT retriever |
\t\t\t\t\t\t\t-------------------------
\t\t\t\t\t\t\t        Chris John Riley
\t\t\t\t\t\t\t             blog.c22.cc
'''

usage = \
'''
\tusage:\n

\t\t -d <domain> / --domain=<domain> - Specify target domain
\t\t -t / --tcponly - [Opt] Use TCP ONLY
\t\t -u / --udponly - [Opt] Use UDP ONLY

\texample:\n
\t ./dnstxt.py -d c22.cc
'''

def main():

    dns, proto = setup()
    checks()
    txtvalues = dnsworker(dns, proto)
    display(txtvalues, dns)


def setup():

    # setup variables

    print logo
    dns = ''
    proto = {"tcp" : False, "udp": False}

    if len(argv) > 1:
        SHORTOPTS = "hd:tu"
        LONGOPTS = ("help", "domain=", "tcponly", "udponly")
        try:
            (opts, args) = getopt(argv[1:], SHORTOPTS, LONGOPTS)
        except:
            print usage
            exit(0)

        for (opt, arg) in opts:
            if opt in ('-h', '--help'):
                print usage
                exit(0)
            elif opt in ('-d', '--domain'):
                dns = arg
            elif opt in ('-t', '--tcponly'):
                proto['tcp'] = True
                proto['udp'] = False
            elif opt in ('-u', '--udponly'):
                proto['tcp'] = False
                proto['udp'] = True

        if not dns:
            print '\t[!] Domain value required'
            print usage
            exit(0)

        if not proto['tcp'] and not proto['udp']:
            # set both
            proto['tcp'] = True
            proto['udp'] = True

    else:
        print usage
        exit(0)

    print '\t[ ] DNS: %s' % dns

    return dns, proto


def checks():

    # check platform and connection

    check_platform()
    check_network()


def check_platform():

    # check target is 'winXX'

    if not platform.startswith('win'):
        print '\t[!] Not a Windows system!, exiting'
        exit(1)


def check_network():

    # check network connection

    flags = DWORD()
    print '\n\t[>] Checking connection'
    connected = wininet.InternetGetConnectedState(
                byref(flags),
                None,
                )

    if not connected:
        print '\t[!] No internet connection, cannot retrieve data'
        exit(1)
    else:
        print '\t[<] Connection check confirmed'


def dnsworker(dns, proto):

    # handle tcp and udp request types

    tcpres = []
    udpres = []
    result = []

    if proto['udp']:
        udpres.append(dnsrequest(dns, reqtype='udp'))
    if proto['tcp']:
        tcpres.append(dnsrequest(dns, reqtype='tcp'))

    if proto['tcp'] and proto['udp']:
        result = set(tcpres[0] + udpres[0])
    elif proto['tcp']:
        result = set(tcpres[0])
    elif proto['udp']:
        result = set(udpres[0])

    return result


def dnsrequest(dns, reqtype):

    # attempt to retrieve remote DNS record (TXT)

    try:

        class _DnsRecordFlags(Structure):
            _fields_ = [
                ('Section', DWORD, 2),
                ('Delete', DWORD, 1),
                ('CharSet', DWORD, 2),
                ('Unused', DWORD, 3),
                ('Reserved', DWORD, 24),
        ]

        DNS_RECORD_FLAGS = _DnsRecordFlags

        class DNS_TXT_DATA(Structure):
            _fields_ = [
                ('dwStringCount', DWORD),
                ('pStringArray', LPTSTR * 1),
        ]

        class DnsRecord_FLAG_DATA(Union):
            _fields_ = [
                ('DW', DWORD),
                ('S', DNS_RECORD_FLAGS),
        ]

        class DnsRecord_TXT_DATA(Union):
            _fields_ = [
                ('TXT', DNS_TXT_DATA),
                ('Txt', DNS_TXT_DATA),
                ('HINFO', DNS_TXT_DATA),
                ('Hinfo', DNS_TXT_DATA),
        ]

        class _DnsRecord(Structure):
            pass

        _DnsRecord._fields_ = [
                ('pNext', POINTER(_DnsRecord)),
                ('pName', LPTSTR),
                ('wType', WORD),
                ('wDataLength', WORD),
                ('Flags', DnsRecord_FLAG_DATA),
                ('dwTtl', DWORD),
                ('dwReserved', DWORD),
                ('Data', DnsRecord_TXT_DATA),
            ]

        DNS_RECORD = _DnsRecord

        precord = pointer(pointer(DNS_RECORD()))

        DNS_TYPE_TEXT = 0x0010
        DNS_QUERY_STANDARD = 0x00000001
        DNS_QUERY_BYPASS_CACHE = 0x00000008
        DNS_QUERY_NO_HOSTS_FILE = 0x00000040
        DNS_QUERY_NO_NETBT = 0x00000080
        DNS_QUERY_NO_MULTICAST = 0x00000800
        DNS_QUERY_TREAT_AS_FQDN = 0x00001000
        DNS_QUERY_ACCEPT_TRUNCATED_RESPONSE  = 0x00000001
        DNS_QUERY_WIRE_ONLY = 0x100
        DNS_QUERY_USE_TCP_ONLY = 0x00000002

        if reqtype == 'udp':
            print '\t[>] Checking DNS using %s' % reqtype.upper()
            Options = \
                    DNS_QUERY_STANDARD | DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE | \
                    DNS_QUERY_NO_NETBT | DNS_QUERY_NO_MULTICAST | DNS_QUERY_TREAT_AS_FQDN | \
                    DNS_QUERY_WIRE_ONLY
        elif reqtype == 'tcp':
            print '\t[>] Checking DNS using %s' % reqtype.upper()
            Options = \
                    DNS_QUERY_STANDARD | DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE | \
                    DNS_QUERY_NO_NETBT | DNS_QUERY_NO_MULTICAST | DNS_QUERY_TREAT_AS_FQDN | \
                    DNS_QUERY_WIRE_ONLY | DNS_QUERY_ACCEPT_TRUNCATED_RESPONSE | \
                    DNS_QUERY_USE_TCP_ONLY
        else:
            print '\t[!] Unable to select protocol type'
            return

        # Loop through the provided DNS names and gather TXT records to check

        dnsquery = dnsapi.DnsQuery_A(
                dns,
                DNS_TYPE_TEXT,
                Options,
                False,
                precord,
                False,
                )

        if not dnsquery == 0:
            print '\t[!] Unable to get TXT record from %s (%s)' % (dns, reqtype.upper())
            return[]

        dnsvalue = precord.contents
        txtvalues = []

        while True:
            try:
                records = dnsvalue.contents.Data.TXT.dwStringCount
                i = 0
                while i < records:
                    txtvalues.append(dnsvalue.contents.Data.TXT.pStringArray[i])
                    i = i +1
                dnsvalue = dnsvalue.contents.pNext
            except:
                # No more records
                break

        return txtvalues

    except Exception, error:
        print '\t[!] Error ::: %s' % error
        exit(1)


def display(txtvalues, dns):

    if txtvalues:
        print '\t[<] %d TXT records retrieved from %s\n' % (len(txtvalues), dns)
        for entry in txtvalues:
            print '\t[ ] %s' % entry
    else:
        print '\t[!] No TXT records recieved from %s' % dns

    print '\n [ ] Exiting...'

if __name__ == '__main__':
    main()