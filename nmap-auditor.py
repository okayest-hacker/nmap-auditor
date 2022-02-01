#!/usr/bin/env python
# -*- coding: utf-8 -*-
#must pip3 install python-libnmap
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException

def do_scan(targets, options):
    parsed = None
    nmproc = NmapProcess(targets, options)
    rc = nmproc.run()
    if rc != 0:
        print("nmap scan failed: {0}".format(nmproc.stderr))
    print(type(nmproc.stdout))

    try:
        parsed = NmapParser.parse(nmproc.stdout)
    except NmapParserException as e:
        print("Exception raised while parsing scan: {0}".format(e.msg))

    return parsed


# print scan results from a nmap report
def print_scan(nmap_report):
    print("Starting Nmap {0} ( http://nmap.org ) at {1}".format(
        nmap_report.version,
        nmap_report.started))

    for host in nmap_report.hosts:
        if len(host.hostnames):
            tmp_host = host.hostnames.pop()
        else:
            tmp_host = host.address
        print("Nmap scan report for {0} ({1})".format(
            tmp_host,
            host.address))
        print(Type)
        f.write(str(Type) + "\n")
        print("Host is {0}.".format(host.status))
        f.write("Host is {0}.".format(host.status) + "\n")
        print("  PORT     STATE         SERVICE")
        f.write("  PORT     STATE         SERVICE" + "\n")

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
    print(nmap_report.summary)
if __name__ == "__main__":
        scantarget = input('what ip do you want to scan: ')
        f = open('%s.txt' % scantarget,'w')
        #just add scan variables here like "-sF" or "-sS"
        scantypes = ['-sF', '-sW']
        for line in scantypes:
                Type = line.split(",")
                report = do_scan(scantarget, 'Type')
                if report:
                        print_scan(report)
                else:
                        print("No results returned")
f.close()

