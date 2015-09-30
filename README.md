# djbdns-migration
Migrating from DJBDNS/TinyDNS to another Server. This script parses your old Zone file and makes a query for every entry to the new server.

### Requirements
  * Python 3
  * dnspython

### Usage
./check.py <data file> <new dnsserver ip>
