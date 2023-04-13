import socket
import termcolor


def scan(target, ports):
    print('\n' + " Starting Scan for {}".format(target))
    opens = 0
    for port in range(1, ports):
        opens += scan_port(target, port)
    return opens


def scan_port(ipaddress, port):
    try:
        sock = socket.socket()
        sock.connect((ipaddress, port))
        print("[+] Port {} is Open".format(port))
        sock.close()
        return 1
    except:
        return 0
        # print("[-] Port {} is Closed".format(port))


targets = input("[*] Enter target ip addresses to scan (split by comma)")
ports = int(input("[*] Enter how many ports you want to scan"))
targets = targets.split(',')
print(termcolor.colored("[*] Scanning target", 'green'))
opens = 0
for ip_addr in targets:
    opens += scan(ip_addr.strip(' '), ports)
print(termcolor.colored("{} ports are open".format(opens), 'green'))
print(termcolor.colored("{} ports are closed".format(ports - opens), 'red'))
