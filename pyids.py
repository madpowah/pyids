import psutil
import sys
import time
import os
import re

class PYIDS:
    def __init__(self) -> None:
        print(">> Python IDS starting ...")
        self.alert = ''


    def get_open_ports(self):
        """
        get_open_ports: return the list of open ports in IPv4 and IPv6

        :return: list of IPv4 open ports and list of IPv6 open ports 
        """
        # We check all tcp connections
        list_open_ports = psutil.net_connections(kind="tcp")

        list_open_ports_ipv4 = []
        list_open_ports_ipv6 = []
        # We all only keep status LISTEN
        for l in list_open_ports:
            if l[5] == 'LISTEN':
                # For IPv4
                if str(l[1]) == 'AddressFamily.AF_INET':
                    list_open_ports_ipv4.append(l)
                    # We sort by open port
                    list_open_ports_ipv4.sort(key=lambda x: x[3][1])
                # For IPv6
                elif str(l[1]) == 'AddressFamily.AF_INET6':
                    list_open_ports_ipv6.append(l)
                     # We sort by open port
                    list_open_ports_ipv6.sort(key=lambda x: x[3][1])
        
        return list_open_ports_ipv4, list_open_ports_ipv6


    def check_new_port(self, list_ipv4, list_ipv6)->int:
        """
        check_new_port gets the open ports and compare the list with the list given in argument.

        :param list_ipv4: initial list of IPv4 open ports
        :param list_ipv6: initial list of IPv6 open ports
        :return: 0 if the lists are similar or if there is less open ports, 1 if there is new port open
        """
        # We list open ports
        new_list_ipv4, new_list_ipv6 = self.get_open_ports()
        # if new list is different than initial list, we create an alert, only if wa have an add
        if list_ipv4 != new_list_ipv4 or list_ipv6 != new_list_ipv6:
            if len(new_list_ipv4) > len(list_ipv4):
                # We check the difference
                list_port = set(new_list_ipv4).difference(set(list_ipv4))
                
                ports = ''
                for l in list_port:
                    if str(l[3][1]) != ' ':
                        ports = ports + ' ' + str(l[3][1])
                
                
                self.alert = '/!\ New port open : ' + ports
                return 1

        return 0


    def get_default_gateway(self)->str:
        """
        get_default_gateway returns the ip and the mac address of the gateway

        return: ip and the mac address of the gateway
        """
        with os.popen('arp -a') as f:
            data = f.read()
        line = re.findall('([-.0-9]+)\s+([-0-9a-f]{17})\s+(\w+)',data)
        ip_gateway = line[0][0]
        mac_gateway = line[0][1]

        return ip_gateway, mac_gateway
    

    def check_mac_change(self, ip, mac)->int:
        """
        check_mac_change compare 2 mac address

        param ip: IP of the gateway
        param mac: MAC address of the gateway

        return: 0 if MAC address are equals else 1
        """
        ret = 0
        ip_gw, mac_gw = self.get_default_gateway()
        if mac_gw != mac:
            ret = 1
            self.alert = "/!\ Gateway ARP Spoofing detected !"

        return ret


    def print_alert(self)->str:
        print(self.alert)


def main():
    ids = PYIDS()
    sys.stdout.write("Initializing TCP Open Ports ....")
    list_ipv4, list_ipv6 = ids.get_open_ports()
    sys.stdout.flush()
    print("Done")
    ip_gw, mac_gw = ids.get_default_gateway()
    print("Default Gateway detected : " + str(ip_gw))
    print("Protection Activated.")
    while True:
        # Open port detection
        newport = ids.check_new_port(list_ipv4, list_ipv6)
        if newport == 1:
            ids.print_alert()
            list_ipv4, list_ipv6 = ids.get_open_ports()

        # ARP spoofing detection
        arpspoof = ids.check_mac_change(ip_gw, mac_gw)
        if arpspoof == 1:
            ids.print_alert()
            ip_gw, mac_gw = ids.get_default_gateway()
        time.sleep(1)


if __name__ == '__main__':
    main()