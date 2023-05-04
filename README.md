# tls-decryption
Decrypt TLS traffic from a pcap file

## Requirements
- Wireshark
- TLS 1.2 or 1.3 capture file 
- Key log file

## Usage

```
usage: decrypt.py [-h] PCAP KEYLOGFILE

positional arguments:
  PCAP        PCAP path
  KEYLOGFILE  KEYLOGFILE path

options:
  -h, --help  show this help message and exit
```

## Examples

**TLS 1.2**
```shell
$ ./decrypt.py data/tls2/dump.pcapng data/tls2/premaster.txt
dsb-pcap saved to: data/tls2/dsb-dump.pcapng
```
Files: [dump.pcapng](https://bugs.wireshark.org/bugzilla/attachment.cgi?id=11612), [premaster.txt](https://bugs.wireshark.org/bugzilla/attachment.cgi?id=11616)

**TLS 1.3**
```shell
$ ./decrypt.py data/tls3/tls3.cryptohack.org.pcapng data/tls3/keylogfile.txt
dsb-pcap saved to: data/tls3/dsb-tls3.cryptohack.org.pcapng
```
Files: [tls3.cryptohack.org.pcapng](https://cryptohack.org/static/challenges/tls3_871583423e02a66acd81eb34ed967489.cryptohack.org.pcapng), [keylogfile.txt](https://cryptohack.org/static/challenges/keylogfile_c86a7e105b820e0780e903b0d8388fa3.txt)

## Resources
[Wireshark: TLS Decryption](https://wiki.wireshark.org/TLS#tls-decryption)

[NSS Key Log Format](https://web.archive.org/web/20230425034128/https://firefox-source-docs.mozilla.org/security/nss/legacy/key_log_format/index.html)