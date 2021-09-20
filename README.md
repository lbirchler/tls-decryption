# tls-decrypt
Decrypt TLS traffic from a pcap file

## Requirements
Wireshark (scripts will work if only tshark is installed)

Any Linux distribution 

Pcap/SSLKEYLOGFILE 

## Usage

```decrypt.py```

```
usage: decrypt.py [-h] -k  -p

optional arguments:
  -h, --help         show this help message and exit

required arguments:
  -k , --key_file    key log file
  -p , --pcap_file   input capture file
```
Example:

Generate new pcap with decrypted traffic
```
$ python decrypt.py -k Wireshark-tutorial-KeysLogFile.txt \
-p Wireshark-tutorial-on-decrypting-HTTPS-SSL-TLS-traffic.pcap

-- extracting client randoms --
pcap client random count: 8
keylog client random count: 8
client randoms removed from keylog file: 0

-- decrypting tls streams --
tls streams decrypted
decrypted pcap saved to: dsb-Wireshark-tutorial-on-decrypting-HTTPS-SSL-TLS-traffic.pcap
```

```pcap_diff.py```
```
usage: pcap_diff.py [-h] [-p] [-o] [-d]

optional arguments:
  -h, --help         show this help message and exit
  -p, --print_diff   print altered/changed packets from original and decrypted pcap files

required arguments:
  -o , --original    original pcap file
  -d , --decrypted   decrypted pcap file
```
Examples:

Display number of packets changed from original and decrypted pcap files 
```
$ python pcap_diff.py -o Wireshark-tutorial-on-decrypting-HTTPS-SSL-TLS-traffic.pcap \
-d dsb-Wireshark-tutorial-on-decrypting-HTTPS-SSL-TLS-traffic.pcap

diff: 91
```

Display original/decrypted packets
```
$ python pcap_diff.py -o Wireshark-tutorial-on-decrypting-HTTPS-SSL-TLS-traffic.pcap \
-d dsb-Wireshark-tutorial-on-decrypting-HTTPS-SSL-TLS-traffic.pcap -p

original:    163  29.461540 94.103.84.245 → 10.4.1.101   TLSv1.2 312 New Session Ticket, Change Cipher Spec, Encrypted Handshake Message
decrypted:   163  29.461540 94.103.84.245 → 10.4.1.101   TLSv1.2 312 New Session Ticket, Change Cipher Spec, Finished

original:    165  30.099384   10.4.1.101 → 94.103.84.245 TLSv1.2 251 Application Data
decrypted:   165  30.099384   10.4.1.101 → 94.103.84.245 HTTP 251 GET /invest_20.dll HTTP/1.1 

original:    168  30.849935 94.103.84.245 → 10.4.1.101   TLSv1.2 334 Application Data
decrypted:   168  30.849935 94.103.84.245 → 10.4.1.101   TLSv1.2 334 [TLS segment of a reassembled PDU]
...
```

### References

[pcap and key log files](https://github.com/pan-unit42/wireshark-tutorial-decrypting-HTTPS-traffic) used in example

[article](https://unit42.paloaltonetworks.com/wireshark-tutorial-decrypting-https-traffic/) explaining how this can be done in Wireshark 

