
import csv
import shutil
import pathlib
import ctypes
import os, sys
import questionary
import multiprocessing
from colorama import Fore, Back, Style, init
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
from functools import partial

def looper(hosts, test1, scantypez, portz, test2):
        for x in scantypez:
            if x == '-sO':
                portz = '1-254'
            options = (test1+" "+test2+" "+"-PN"+" "+"-n"+" "+"-p"+" "+portz+" "+"-oG "+"%s.gnmap" % hosts+" "+x)
            report = do_scan(hosts, options)
            if report:
                print_scan(report, hosts, options)
            else:
                print("No results returned")

def do_scan(hosts, options):
    parsed = None
    nmproc = NmapProcess(hosts,options, safe_mode=False)
    rc = nmproc.run()
    if rc != 0:
        print("nmap scan failed: {0}".format(nmproc.stderr))
    try:
        parsed = NmapParser.parse(nmproc.stdout)
    except NmapParserException as e:
        print("Exception raised while parsing scan: {0}".format(e.msg))

    return parsed

# print scan results from a nmap report
def print_scan(nmap_report, hosts, options):
    if os.path.exists(hosts):
        # Delete the directory and its contents
       shutil.rmtree(hosts)
    
    # Create the directory
    os.makedirs(hosts)
    file_name = os.path.join(hosts, f"{hosts}.txt")
    file2_name = os.path.join(hosts, f"{hosts}.csv")
    f = open(file_name, 'w')
    z = open(file2_name, 'w',newline='')
    write = csv.writer(z)
    fields = ['Port','State','service']
    headerz = [hosts, options]
    write.writerow(headerz)
    write.writerow(fields)
    k=' '
    print("----------------------------------------------------------")
    print(Fore.GREEN, k*8, hosts, options + Fore.RESET)
    f.write("----------------------------------------------------------" + "\n")
    f.write("        {0} {1}\n".format(hosts, options))
    for host in nmap_report.hosts:
        if len(host.hostnames):
            tmp_host = host.hostnames.pop()
        else:
            tmp_host = host.address
        print("----------------------------------------------------------")
        f.write("----------------------------------------------------------" + "\n")
        print("    PORT     STATE        SERVICE")
        f.write("    PORT     STATE        SERVICE" + "\n")
        print("----------------------------------------------------------")
        f.write("----------------------------------------------------------" + "\n")
        for serv in host.services:
            pserv = "{0:>5s}/{1:3s}  {2:12s}  {3}".format(
                str(serv.port),
                serv.protocol,
                serv.state,
                serv.service)
            pserved = pserv.split(' ')
            pserved2 = new_list = [elem for elem in pserved if elem.strip()]
            rows = pserved2
            write.writerows([rows])
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
    yes = "yes"
    no = "no"
    test1 = questionary.select("do you want to scan IPv4 or IPV6", choices=[IPv4, IPv6], ).ask()
    if test1 == IPv6:
        test1 = '-6'
    elif test1 == IPv4:
        test1 = ""
    choice = input('Are you using a Target.txt or Manually entering targets(txt or man): ')
    if choice == 'txt':
        file_path = input("Enter the full path and file name to the text file containing targets (example:/root/test/file.txt): ")
        with open(file_path, 'r') as file:
            targets = file.read().splitlines()
            print(targets)
    elif choice == 'man':
        scantarget = input('Please enter hosts to scan separated by a space: ')
        targets = scantarget.split(' ')
    else:
        print("Invalid choice. Please choose y or n.")
        sys.exit()
    scantypez = questionary.checkbox('Select scan type or types;', choices=['-sA','-sS', '-sT', '-sF', '-sX', '-sU', '-sW', '-sM', '-sI', '-sO',]).ask()
    portz = input('what ports do you want to scan(example:1-100, 500 or - for all ports): ')
    staticport = portz
    test2 = questionary.select("do you want to scan for only open ports", choices=[yes, no], ).ask()
    if test2 == yes:
        test2 = '--open'
    elif test2 == no:
        test2 = ""
    active_hosts = targets
    hosts = active_hosts # Add the IP addresses you want to scan
    num_processes = 8  # Number of parallel processes
    partial_looper = partial(looper, test1=test1, scantypez=scantypez, portz=portz, test2=test2)
    pool = multiprocessing.Pool(processes=num_processes)
    pool.map(partial_looper, hosts)
    pool.close()
    pool.join()



