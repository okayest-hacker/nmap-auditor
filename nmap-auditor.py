import ctypes
import os, sys
import questionary
from colorama import Fore, Back, Style, init
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException


def do_scan(targets, options):
    parsed = None
    nmproc = NmapProcess(targets, options)
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
    print(Fore.GREEN, target, options + Fore.RESET)
    f.write("----------------------------------------------------------" + "\n")
    f.write("{} {}\n".format(target, options))
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

def isAdmin():
    try:
        is_admin = (os.getuid() == 0)
    except AttributeError:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    return is_admin

if __name__ == "__main__":
    if not isAdmin():
        sys.exit(Fore.RED + 'This script must be run as root!')
    IPv4 = "IPv4"
    IPv6 = "Ipv6"
    test1 = questionary.select("do you want to scan IPv4 or IPV6", choices=[IPv4, IPv6], ).ask()
    if test1 == IPv6:
        test1 = '-6'
    elif test1 == IPv4:
        test1 = ""
    scantarget = input('Please enter hosts to scan separated by a space: ')
    scantypez = questionary.checkbox('Select scan type or types;',
                                     choices=['-sS', '-sT', '-sF', '-sX', '-sU', '-sW', '-sM', '-sO']).ask()
    print(scantypez)
    portz = input('what ports do you want to scan(example:1-100, 500 or - for all ports): ')
    active_hosts = scantarget.split(' ')

    for i in active_hosts:
        target = i
        f = open('%s.txt' % target, 'w')
        for x in scantypez:
            if x == '-sO':
                portz = '1-255'
            options = (test1+" "+x+" "+"-p"+" "+ portz)
            report = do_scan(target, options)
            if report:
                print_scan(report)
            else:
                print("No results returned")
                f.close()
