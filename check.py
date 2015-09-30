#! /usr/bin/env python
"""
Read a data file from a tinydns server and make a query for every line to
check if a given DNS server responds correct
"""
from dns import resolver, reversename
import sys

resolver = resolver.Resolver()


def a_record(name, ip):
    """
    Query an A record and check the result
    """
    query = make_query(name, "A")
    if query:
        result = [str(x) for x in query]
        if ip not in result:
            print("A: '{}' should be '{}' but is '{}'".format(name,
                                                              ip,
                                                              result))
    else:
        print("A check for {} failed.".format(name))



def ptr_record(name, ip):
    """
    Query a PTR record and check the result
    """
    a_record(name, ip)
    reverse_addr = reversename.from_address(ip)
    query = make_query(reverse_addr, "PTR")
    if query:
        result = [str(x).strip(".") for x in query]
        if name not in result:
            print("PTR: '{}' should be '{}' but is '{}'".format(ip,
                                                                name,
                                                                result))
    else:
        print("PTR check for {} failed.".format(name))


def cname_record(cname, name):
    """
    Query a CNAME record and check the result
    """
    query = make_query(cname, "CNAME")
    if query:
        result = [str(x).strip(".") for x in query]
        if name not in result:
            print("CNAME: '{}' should be '{}' but is '{}'".format(cname,
                                                                  name,
                                                                  result))
    else:
        print("CNAME check for {} failed.".format(cname))


def mx_record(name, hostname, ttl):
    """
    Query a MX record and check the result
    """
    query = make_query(name, "MX")
    if query:
        result = [str(x) for x in query]
        entry = "{} {}.".format(ttl, hostname)
        if entry not in result:
            print("MX: '{}' should be '{}' but is '{}'".format(name,
                                                               entry,
                                                               result))
    else:
        print("MX check for {} failed.".format(name))

def make_query(address, type):
    try:
        return resolver.query(address, type)
    except:
        return None


def soa_record(domain, nameserver, email):
    """
    Query a SOA record and check the result
    """
    query = make_query(domain, "SOA")
    if query:
        result = str(query[0])
        entry = "{} {}".format(nameserver, email)
        if not result.startswith(entry):
            print("SOA: '{}' should be '{}' but is '{}'".format(domain,
                                                                entry,
                                                                result))
    else:
        print("SOA check for {} failed.".format(domain))


def handle_line(line):
    """
    Parse a line from a tinydns data file and determine the record type
    """
    record_type = line[0]
    if record_type in ["&", "+", "@", "Z", "=", "C"]:
        if (record_type == "&"):
            pass
        if (record_type == "+"):
            record_name, record_ip, *_ = line[1:].split(":")
            a_record(record_name, record_ip)
        if (record_type == "@"):
            name, ip, hostname, ttl, *_ = line[1:].split(":")
            mx_record(name, hostname, ttl)
        if (record_type == "Z"):
            domain, nameserver, email, *_ = line[1:].split(":")
            soa_record(domain, nameserver, email)
        if (record_type == "="):
            record_name, record_ip, *_ = line[1:].split(":")
            ptr_record(record_name, record_ip)
        if (record_type == "C"):
            record_name, record_ip, *_ = line[1:].split(":")
            cname_record(record_name, record_ip)
    else:
        print("Unknown Type: {}".format(line))


def main(data, ip):
    """
    The main function
    """
    with open(data, "r") as f:
        resolver.nameservers = [ip]

        for line in f:
            line = line.strip()

            # no empty line and no comment
            if line != "" and not line.startswith("#"):
                handle_line(line)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage:\n./check.py <data> <dnsserver ip>")
    else:
        main(sys.argv[1], sys.argv[2])
