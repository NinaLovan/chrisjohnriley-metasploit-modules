# !/usr/bin/python
# -*- coding: utf-8 -*-

#

"""
    Simple ICMP packet sender

    Aims of this project:

    - Use the Windows built in ctypes to send ICMP packets
    - Build on this basis to create a data exfiltration script
"""

from ctypes import windll, Structure, c_ulong, c_ushort, c_void_p, c_ubyte, byref, sizeof, POINTER
from socket import inet_ntoa, inet_aton, error
from struct import pack, unpack
from sys import argv, exit, platform
from getopt import getopt

__author__ = 'Chris John Riley'
__credits__ = 'Greg Hazel'
__link__ = 'http://svn.tribler.org/software_general/web_2.0_browser/torrent/btl/win32icmp.py'
__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'Chris John Riley'
__email__ = 'contact@c22.cc'
__status__ = 'Prototype'

icmp = windll.icmp

IcmpCreateFile = icmp.IcmpCreateFile
IcmpCloseHandle = icmp.IcmpCloseHandle

logo =\
'''

\t\t\t\t\t\t\t\t  _   _   _   _   _   _
\t\t\t\t\t\t\t\t / \ / \ / \ / \ / \ / \
\t\t\t\t\t\t\t\t( S | _ | i | c | m | p )
\t\t\t\t\t\t\t\t \_/ \_/ \_/ \_/ \_/ \_/

\t\t\t\t\t\t\t---------------------------------
\t\t\t\t\t\t\t| Simple icmp traffic generator |
\t\t\t\t\t\t\t---------------------------------
\t\t\t\t\t\t\t\t\t Chris John Riley
\t\t\t\t\t\t\t\t\t      blog.c22.cc
'''

usage = \
'''
\tusage:\n
\t ./simpleicmp.py -i <ip> -d <data> -t <timeout> -s <packet size>

\t\t -i <ip> / --ip=<ip> - Should be a valid IP address
\t\t -d <data> / --data=<data> - [Optional:] Data to include in the icmp packet,
\t\t\t\t  Note: enclose data in double quotes if it contains spaces
\t\t -t <timeout> / --timeout=<timeout> - [Optional:] Timeout (default: 1000)
\t\t -s <size> / --size=<size> - [Optional:] Packet Size to use (default: 1450)

\texample:\n
\t ./simpleicmp.py -i 8.8.8.8 -d "test icmp packet" -t 1000 -s 1450
'''

def main():
    ''' Send ping to target containing the requests data '''
    check_platform()
    target, data, timeout, size, options = setup()
    run(target, data, timeout, size, options)

def check_platform():

    # check target is 'winXX'

    if not platform.startswith('win'):
        print '\t[!] Not a Windows system!, exiting'
        exit(1)

def setup():
    ''' setup vars '''

    print logo

    if len(argv) > 1:
        SHORTOPTS = "h:i:d:t:s:"
        LONGOPTS = ("help", "ip=", "data=", "timeout=", "size=")
        try:
            (opts, args) = getopt(argv[1:], SHORTOPTS, LONGOPTS)
        except:
            print usage
            exit(0)

        # set defaults
        data='abcdefghijklmnopqrstuvwxyz0123456789'
        timeout=1000
        size=1450
        options = False

        for (opt, arg) in opts:
            if opt in ('-h', '--help'):
                print usage
                exit(0)
            elif opt in ('-i', '--ip'):
                target = arg
            elif opt in ('-d', '--data'):
                data = arg
            elif opt in ('-t', '--timeout'):
                if arg.isdigit():
                    timeout = arg
                else:
                    timeout = 1000
            elif opt in ('-s', '--size'):
                if arg.isdigit():
                    size = arg
                else:
                    size = 1450

    return target, data, timeout, size, options

def run(target, data, timeout, size, options):
    ''' send packets '''

    print "\n\t[ ] Pinging %s with %d bytes of data" % (target, len(data))

    dpos = data
    window = int(size)
    packets = div_ceil(len(data),window)

    print "\t[ ] Sending %d packet(s) with a window size of %s" % (packets, window)

    while dpos != '':
        tosend = dpos[:window]

        icmpFile = IcmpCreateFile()
        o = Options()

        raddr, status, rtt = IcmpSendEcho(icmpFile, target, tosend, options, timeout)

        IcmpCloseHandle(icmpFile)

        if status == 0:
            statustext = "(0) Successful"
        else:
            statustext = "(%s) Error" % str(status)

        if raddr == "0.0.0.0":
            print "\n\t[!] No response from remote server"

        print "\n\t[ ] Target (IP) ::: %s" % raddr
        print "\t[ ] Data Sent   ::: \"%s\"" % dpos[:window]
        print "\t[ ] Status Code ::: %s" % statustext
        print "\t[ ] Round-Trip  ::: %d" % rtt
        print "        ______ ______ ______ ______ ______ ______  ______ "

        dpos = dpos[window:]

    print "\n\t[ ] Finished sending! \n"
    exit(0)

def div_ceil(a, b):
    if a%b:
        packets = ((a/b)+1)
    else:
        packets = (a/b)
    return int(packets)

class IPAddr(Structure):
    _fields_ = [ ("S_addr", c_ulong),]

    def __str__(self):
        return inet_ntoa(pack("L", self.S_addr))

def inet_addr(ip):
        try:
            return IPAddr(unpack("L", inet_aton(ip))[0])
        except error, msg:
            print "\n\t[!] An error has occured ::: %s" % msg
            exit(1)

class IP_OPTION_INFORMATION(Structure):
    _fields_ = [ ("Ttl", c_ubyte),
                ("Tos", c_ubyte),
                ("Flags", c_ubyte),
                ("OptionsSize", c_ubyte),
                ("OptionsData", POINTER(c_ubyte)),
            ]

Options = IP_OPTION_INFORMATION

class ICMP_ECHO_REPLY(Structure):
    _fields_ = [ ("Address", IPAddr),
                ("Status", c_ulong),
                ("RoundTripTime", c_ulong),
                ("DataSize", c_ushort),
                ("Reserved", c_ushort),
                ("Data", c_void_p),
                ("Options", IP_OPTION_INFORMATION),
            ]

def IcmpSendEcho(handle, addr, data, options, timeout):
    reply = ICMP_ECHO_REPLY()
    data = data or ''
    if options:
        options = byref(options)
    r = icmp.IcmpSendEcho(handle, inet_addr(addr),
                            data,
                            len(data),
                            options,
                            byref(reply),
                            sizeof(ICMP_ECHO_REPLY) + len(data),
                            timeout)
    return str(reply.Address), reply.Status, reply.RoundTripTime

class Options(object):
    pass

if __name__ == '__main__':
    main()
