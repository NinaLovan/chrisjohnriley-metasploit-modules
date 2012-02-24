# !/usr/bin/python
# -*- coding: utf-8 -*-

#

"""
    Example script to retrieve contents of a URL using Windows Functions

    This script uses SSPI to reuse the current users credentials to make
    the request (bypassing issues with restrictive Proxy servers (NTLM auth)
"""

from sys import exit, platform, argv
from urlparse import urlparse
from ctypes import *
from ctypes.wintypes import DWORD
from getopt import getopt
from os import path
from string import split

__author__ = 'Chris John Riley'
__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'Chris John Riley'
__email__ = 'contact@c22.cc'
__status__ = 'Prototype'

kernel32 = windll.kernel32
wininet = windll.wininet

logo =\
'''\n
\t\t\t\t\t\t          .   ..--. .
\t\t\t\t\t\t          |   ||   )|
\t\t\t\t\t\t   .--.   |   ||--' |
\t\t\t\t\t\t   `--.   :   ;|  \ |
\t\t\t\t\t\t   `--'____`-' '   `'---'

\t\t\t\t\t\t   ------------------------
\t\t\t\t\t\t   | Simple url retriever |
\t\t\t\t\t\t   ------------------------
\t\t\t\t\t\t           Chris John Riley
\t\t\t\t\t\t               blog.c22.cc
'''

usage = \
'''
\tusage:\n
\t ./simpleurl.py -u <url> -o <outfile> -b <int> -d

\t\t -u <url> / --url=<url> - Specific URL to access
\t\t -o <file> / --outfile=<file> - [opt:] Output file
\t\t -b <int> / --buffer=<int> - [opt:] Buffer length
\t\t -d / --display - [opt:] Display retrieved URL

\texample:\n
\t ./simpleicmp.py -u http://c22.cc -b 16000 -d
'''

def main():

    url, outfile, display, bufflen = setup()
    checks()
    contents = urlrequest(url, bufflen)
    if display:
        displayurl(contents, url)
    if outfile:
        saveurl(contents, outfile, url)

def setup():

    # setup variables

    print logo

    if len(argv) > 1:
        SHORTOPTS = "hu:o:b:d"
        LONGOPTS = ("help", "url=", "outfile=", "buffer=", "display")
        try:
            (opts, args) = getopt(argv[1:], SHORTOPTS, LONGOPTS)
        except:
            print usage
            exit(0)

        # set defaults
        outfile =''
        display = False
        bufflen = 0x16000

        for (opt, arg) in opts:
            if opt in ('-h', '--help'):
                print usage
                exit(0)
            elif opt in ('-u', '--url'):
                if arg.startswith('http'):
                    url = arg
                else:
                    url = 'http://' + arg
            elif opt in ('-o', '--outfile'):
                outfile = arg
            elif opt in ('-b', '--buffer'):
                if arg.isdigit():
                    bufflen = int(arg)
            elif opt in ('-d', '--display'):
                display = True

        print ' [ ] Target: %s' % url
        print ' [ ] Buffer: %#x (%d)' % (bufflen, bufflen)

        if outfile:
            if path.exists(outfile):
                print ' [!] Output file "%s" already exists!' % outfile
                exit(0)
            else:
                print ' [ ] File Output: %s' % outfile
        else:
            print ' [ ] File Output: Off'

        if display:
            print ' [ ] Display: On'
        else:
            print ' [ ] Display: Off'

        if not outfile and not display:
            print ' [!] Display and file output disabled... running silent'

        return url, outfile, display, bufflen

    else:
        print usage
        exit(0)


def checks():

    # check platform and connection

    check_platform()
    check_network()


def check_platform():

    # check target is 'winXX'

    if not platform.startswith('win'):
        print ' [!] Not a Windows system!, exiting'
        exit(1)


def check_network():

    # check network connection

    flags = DWORD()
    print '\n [>] Checking connection'
    connected = wininet.InternetGetConnectedState(
                byref(flags),
                None,
                )

    if not connected:
        print ' [!] No internet connection, cannot retrieve data'
        exit(1)
    else:
        print ' [<] Connection check confirmed'


def urlrequest(url, bufflen):

    # attempt to use Internet Explorer (urlmon) to retrieve shellcode from a remote URL

    INTERNET_OPEN_TYPE_PRECONFIG = 0
    INTERNET_SERVICE_HTTP = 3
    INTERNET_FLAG_RELOAD = 0x80000000
    INTERNET_FLAG_CACHE_IF_NET_FAIL = 0x00010000
    INTERNET_FLAG_NO_CACHE_WRITE = 0x04000000
    INTERNET_FLAG_PRAGMA_NOCACHE = 0x00000100
    INTERNET_FLAG_SECURE = 0x00800000
    HTTP_QUERY_FLAG_NUMBER = 0x20000000
    HTTP_QUERY_STATUS_CODE = 19
    SECURITY_FLAG_IGNORE_REVOCATION = 0x00000080
    SECURITY_FLAG_IGNORE_UNKNOWN_CA = 0x00000100
    SECURITY_FLAG_IGNORE_WRONG_USAGE = 0x00000200
    INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP = 0x00008000
    INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS = 0x00004000
    INTERNET_FLAG_IGNORE_CERT_DATE_INVALID = 0x00002000
    INTERNET_FLAG_IGNORE_CERT_CN_INVALID = 0x00001000
    INTERNET_OPTION_SECURITY_FLAGS = 31

    dwStatus = DWORD()
    dwBufLen = DWORD(4)
    dwFlags = DWORD()
    buff = c_buffer(bufflen)
    bytesRead = DWORD()
    useragent = 'Mozilla/5.0'
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

    print '\n [>] Checking URL'

    try:
        hInternet = wininet.InternetOpenA(
                    useragent,
                    INTERNET_OPEN_TYPE_PRECONFIG,
                    False,
                    False,
                    0,
                    )

        if not hInternet:
            print ' [!] Unable to build connection to %s' % p_url.geturl()
            raise Exception(('InternetOpenA Failed (Windows error %d)') % GetLastError())

        hConnect = wininet.InternetConnectA(
                    hInternet,
                    netloc[0],
                    conn_port,
                    conn_user,
                    conn_pass,
                    INTERNET_SERVICE_HTTP,
                    0,
                    0,
                    )

        if not hConnect:
            print ' [!] Unable to make connection to %s' % p_url.geturl()
            raise Exception(('InternetConnectA Failed (Windows error %d)') % GetLastError())

        dwFlags = \
            INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | \
            INTERNET_FLAG_CACHE_IF_NET_FAIL | INTERNET_FLAG_PRAGMA_NOCACHE

        if p_url.scheme == 'https':
            dwFlags |= INTERNET_FLAG_SECURE

        hRequest = wininet.HttpOpenRequestA(
                    hConnect,
                    method,
                    path,
                    False,
                    False,
                    False,
                    dwFlags,
                    0,
                    )

        # ignore CA errors and redirects

        dwFlags = \
            'SECURITY_FLAG_IGNORE_REVOCATION | SECURITY_FLAG_IGNORE?_UNKNOWN_CA | \
            SECURITY_FLAG_IGNORE_WRONG_USAGE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | \
            INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS | \
            INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP'

        sOptions = wininet.InternetSetOptionA(hRequest,
                    INTERNET_OPTION_SECURITY_FLAGS,
                    dwFlags,
                    sizeof(DWORD)
                    )

        if not sOptions:
            print ' [!] Unable to set internet options'
            raise Exception(('InternetSetOptionA Failed (Windows error %d)') % GetLastError())

        if not hRequest:
            print ' [!] Unable to open request to %s' % p_url.geturl()
            raise Exception(('HttpOpenRequestA Failed (Windows error %d)') % GetLastError())

        hSendRequest = wininet.HttpSendRequestA(
                        hRequest,
                        False,
                        0,
                        False,
                        0,
                        )

        if not hSendRequest:
            print ' [!] Unable to send request to %s' % p_url.geturl()
            raise Exception(('HttpSendRequestA Failed (Windows error %d)') % GetLastError())

        hQuery = wininet.HttpQueryInfoA(
                    hRequest,
                    HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                    byref(dwStatus),
                    byref(dwBufLen),
                    False,
                    )

        if not hQuery:
            print ' [!] Unable to complete query to %s' % p_url.geturl()
            raise Exception(('HttpQueryInfoA Failed (Windows error %d)') % GetLastError())

        if dwStatus.value != 200:
            print ' [!] Incorrect server response from %s' % p_url.geturl()
            raise Exception(('Non 200 OK response (Windows error %d)') % GetLastError())
        else:
            print ' [<] Server response %s received' % dwStatus.value

        # conntection ok, read data (limited to buffer size)

        hRead = wininet.InternetReadFile(
                hRequest,
                buff,
                len(buff),
                byref(bytesRead),
                )

        if not hRead:
            print ' [!] Unable to read response from %s' % p_url.geturl()
            raise Exception(('InternetReadFile Failed (Windows error %d)') % GetLastError())
        else:
            data = data + buff.raw[:bytesRead.value]
            print ' [<] Reading in response from %s' % p_url.geturl()
            print ' [ ] Read %d bytes from %s' % (len(data), p_url.geturl())
            if len(buff) == len(data):
                print ' [!] The website appears too large for the buffer %#x (%d)' % (len(buff), len(buff))

        # teardown connections

        wininet.InternetCloseHandle(hRequest)
        wininet.InternetCloseHandle(hConnect)
        wininet.InternetCloseHandle(hInternet)
 
        return data

    except Exception, error:
        print ' [!] Unable to retrieve URL (%s)' % p_url.geturl()
        print ' [!] Error ::: %s' % error
        exit(1)


def displayurl(contents, url):

    print '\n [>] Beginning output of %d bytes of data from %s\n' % (len(contents), url)
    lines = split(contents, '\n')
    for each in lines:
        print '\t' + each
    print '\n [<] Output complete'


def saveurl(contents, outfile, url):

    print '\n [>] Saving %d bytes of data from %s to %s' % (len(contents), url, outfile)
    handle = open(outfile, 'w')
    handle.write(contents)
    handle.close()
    print ' [<] Output saved successfully'


if __name__ == '__main__':
    main()
