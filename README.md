# Dnscat-decoder
This is a small [DnscAt](https://github.com/iagox86/dnscat2) decoder written in python:
```python
from scapy.all import *
import argparse

def decode_full_message(full_message):
    decoded_message = bytes.fromhex(full_message).decode('utf-8', errors='ignore')  # We decode the hex message to plain text
    return decoded_message  # We return the decoded message

def parse_pcap(file_name, domain, src_ip, dst_ip):
    packets = rdpcap(file_name)  # Read the pcap file
    full_message = ""   #initialize the full hex message

    # Iterate through the packets
    for packet in packets:
        # We filter the packets that have DNS in them and have a DNSQR (DNS Query Record) and not a DNSRR (DNS Resource Record)
        if DNS in packet and packet[DNS].haslayer(DNSQR) and not packet[DNS].haslayer(DNSRR) and packet.haslayer(IP) and packet[IP].dst == f"{dst_ip}" and packet[IP].src == f"{src_ip}" :
            if f".{domain}." in  packet[DNS].qd.qname.decode('utf-8') : # We filter the packets that have the domain name in them
                queried_domain = packet[DNS].qd.qname.decode('utf-8')   # We get the queried domain name
                sub_domain = queried_domain.replace(f".{domain}.", "")  # We extract the subdomain
                valid_query = sub_domain[18:].replace(".", "").replace("\n", "")    # We remove control bytes, dots and newlines
                full_message +=  valid_query    # We add the valid query to the full message
    return full_message   # We return the full hex message

def main():
    parser = argparse.ArgumentParser(description='Parse pcap file for DNS queries')
    parser.add_argument('-f', '--file', required=True, help='Path to the pcap file')
    parser.add_argument('-d', '--domain', required=True, help='Domain to filter')
    parser.add_argument('-s', '--src_ip', required=True, help='Source IP address')
    parser.add_argument('-t', '--dst_ip', required=True, help='Destination IP address')
    parser.add_argument('-o', '--output', required=True, help='Output file')

    args = parser.parse_args()
    try:
        subdomain_parser = parse_pcap(args.file, args.domain, args.src_ip, args.dst_ip)
        plain_text = decode_full_message(subdomain_parser)

        with open(args.output, 'w') as f:
            f.write(plain_text)

        print("[*]Message extracted succesfully\n[*]Script by Disturbante")
    except:
        print("[*]There is an error with your file")
if __name__ == "__main__":
    main()
```

Usage:
```bash
usage: Dnscat_decoder.py [-h] -f FILE -d DOMAIN -s SRC_IP -t DST_IP -o OUTPUT
Dnscat_decoder.py: error: the following arguments are required: -f/--file, -d/--domain, -s/--src_ip, -t/--dst_ip, -o/--output
```
_Example:_
```bash
python3 Dnscat_decoder.py -f ./suspicious_traffic.pcap -d microsofto365.com -s 192.168.157.144 -t 192.168.157.145 -o decoded_traffic.txt
```

Once we have decoded the traffic we can do cat on the output file.
## Be Careful:
If you are running this in linux you will need to cat the file in order to see the plain-text content and text editor would probably see just hex.
In windows it should be just fine to open the created file.
