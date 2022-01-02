from scapy.all import *
from scapy.layers.inet import TCP, IP
import sys
header = """
SYNOPSIS

    c:/python/py port_scanner.py 192.168.1.1 0

DESCRIPTION

    c:/python/py port_scanner.py 192.168.1.1 0
    at command prompt enter an IP to scan or range, modifier at end is verbose [on/off] [1/0]
    
EXAMPLES

    
    Usage -     /port_scanner.py [Target-IP] [verbose -v ON]
    Example -   /port_scanner.py 192.168.1.1  
    Example -   Scans 192.168.1.1 with verbose off!

AUTHOR

    James Thompson jthompson@tmc.org

LICENSE

    This script is the exclusive and proprietary property of
    TiO2 Minerals Consultants Pty Ltd. It is only for use and
    distribution within the stated organisation and its
    undertakings.

VERSION
    Beta
    0.5
"""
if '-v' in sys.argv:
    verbose = 1
else:
    verbose = 0

#command line args instructions ---------------- refine menu
if len(sys.argv) ==  or '-h' in sys.argv:
    print(header)
    sys.exit()


#command line args
else:
    destIP = sys.argv[1]



#define port list and random source port
destPorts = [21, 22, 23, 25, 53, 80, 110, 135, 137, 138, 139, 443, 1433, 1434, 8080]
srcPort = RandShort()

#main loop for packet send receive
for port in destPorts:
    pac = IP(dst=destIP) /TCP(dport=port)
    re = sr1(pac, timeout=2.0, retry=2, verbose=verbose)
    if re == None:
        print("\nNo response on port {} - filtered".format(
            pac.dport))
        #print(re.summary())
    else:
        print("\nComplicating the matrix ---", re.summary())
        if re.getlayer(TCP).flags == 'SA':
            reset = sr(IP(dst=destIP) / TCP(sport=srcPort, dport=port, flags='R'), timeout=2, verbose=0,)
            print("{} on port {}  is open for business".format(pac.dst, pac.dport))

        elif re.getlayer(TCP).flags == 'RA':
            print("{}:{} is closed".format(pac.dst, pac.dport))

sys.exit()



