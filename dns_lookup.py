# DNS lookup tool written in python3

import socket 
import os
import sys
from datetime import datetime

def get_args() -> list:
    """
    This function validate number of arguments and their count
    """
    # get all positional arguments discarding name of the program
    args = sys.argv[1:]
    # for now we have a single argument, which is a domain name
    if len(args) != 2:
        print(f"[!] Invalid number of arguments. Expected: 1 got: {len(args)}")
        print("[+] Usage: python3 ./dns_lookup.py <target domain name> <target port>")
        sys.exit(-1)
    return args

def dns_query(domain_name : str, port : int) -> list:
    """
    This function sends a DNS query to the nameserver specified in /etc/hosts and return a formatted dictionary
    """
    result = {
        "cname": domain_name,
        "a": ""
    }
    sock_info = {
        "timestamp": "",
        "sock_family": "",
        "sock_type": "",
        "sock_proto": "",
        "query_info": []
    }
    all_fields = []
    info = []
    try:
        info = socket.getaddrinfo(domain_name, port)
    except socket.gaierror:
        # catching Name or service is not known
        print("[!] Name or service is not known!")
        sys.exit(-1)

    for line in info:
        sock_info = {}
        sock_info["query_info"] = []
        sock_info["timestamp"] = str(datetime.now())
        # defining is target socket is ipv4 or ipv6
        if line[0] is socket.AddressFamily.AF_INET:
            sock_info["sock_family"] = "IPv4"
        elif line[0] is socket.AddressFamily.AF_INET6:
            sock_info["sock_family"] = "IPv6"
        
        # if target socket TCP, UDP or Raw socket
        if line[1] is socket.SocketKind.SOCK_STREAM:
            sock_info["sock_type"] = "TCP"
        elif line[1] is socket.SocketKind.SOCK_DGRAM:
            sock_info["sock_type"] = "UDP"
        elif line[1] is socket.SocketKind.SOCK_RAW:
            sock_info["sock_type"] = "RAW"

        # getting socket proto
        sock_info["sock_proto"] = line[2]

        # getting A record
        a_rec = line[4]
        result["a"] = a_rec[0] # get only IP
        sock_info["query_info"].append(result)
        all_fields.append(sock_info)
    return all_fields

def main() -> None:
    domain_name, port = get_args()
    results = dns_query(domain_name, int(port))
    print("-"*38)
    for i in results:
        print(f"Time:\t{i['timestamp']}")
        print(f"{i['sock_family']}:\t{i['sock_type']}\t{i['sock_proto']}")
        for j in i["query_info"]:
            print(f"CNAME:\t{domain_name}")
            print(f"A:\t{j['a']}")
        print("-"*38)

if __name__ == "__main__":
    main()
