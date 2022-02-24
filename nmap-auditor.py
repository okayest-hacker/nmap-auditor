#!/usr/bin/python -tt
# -*- coding: utf-8 -*-
#must pip3 install python-libnmap
import re
import os, sys
import colorama
from colorama import Fore
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException


def do_scan(targets, options):
    parsed = None
    nmproc = NmapProcess(targets,options)
    rc = nmproc.run()
    if rc != 0:
        print("nmap scan failed: {0}".format(nmproc.stderr))
    try:
        parsed = NmapParser.parse(nmproc.stdout)
    except NmapParserException as e:
        print("Exception raised while parsing scan: {0}".format(e.msg))

    return parsed


# print scan results from a nmap report
def print_scan(nmap_report):
    print("----------------------------------------------------------")
    print(key, '-', command2)
    f.write("--------------------------------------------------------------------------" +"\n")
    f.write(str(key) + "\n")
    f.write("--------------------------------------------------------------------------" +"\n")
    for host in nmap_report.hosts:
        if len(host.hostnames):
            tmp_host = host.hostnames.pop()
        else:
            tmp_host = host.address
        print("----------------------------------------------------------")
        f.write("----------------------------------------------------------" + "\n")
        print("  PORT     STATE         SERVICE")
        f.write("  PORT     STATE         SERVICE" + "\n")
        print("----------------------------------------------------------")
        f.write("----------------------------------------------------------" + "\n")

        for serv in host.services:
            pserv = "{0:>5s}/{1:3s}  {2:12s}  {3}".format(
                    str(serv.port),
                    serv.protocol,
                    serv.state,
                    serv.service)
            if len(serv.banner):
                pserv += " ({0})".format(serv.banner)   
            print(pserv)
            f.write(pserv + "\n")
if __name__ == "__main__":
    if not os.geteuid()==0:
        sys.exit(Fore.RED + 'This script must be run as root!')
    scantarget = input('what ip address do you want to scan(use the -6 option before an ivp6 address): ')
    portz = input('what ports do you want to scan(example:1-100, 500 or - for all ports): ')
    f = open('%s.txt' % scantarget,'w')
    #just add scan variables here like 'MAIMON':'-sM','PROTOCOL':'-sO'
    scantypes = {'MAIMON':'-sM','PROTOCOL':'-sO'}
    valuez = scantypes.values()
    keyz = scantypes.keys()
    for key, value in scantypes.items():
        if value == '-sO':
            portz = '1-255'
        command = (scantarget,value,'-p'+ portz)
        commandz = ''.join(str(command))
        command1 = re.sub(r"[^a-zA-Z0-9-. ]", "", commandz)
        command2 = str(command1)
        report = do_scan(" ", command2)
        if report:
            print_scan(report) 
        else:
            print("No results returned")
            f.close()
