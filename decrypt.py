#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import shlex
import subprocess
import tempfile
from pathlib import Path


# https://firefox-source-docs.mozilla.org/security/nss/legacy/key_log_format/index.html
LABELS = {
    # 48 bytes for the master secret, encoded as 96 hexadecimal characters
    # (for SSL 3.0, TLS 1.0, 1.1 and 1.2)
    'CLIENT_RANDOM',
    # the hex-encoded early traffic secret for the client side (for TLS 1.3)
    'CLIENT_EARLY_TRAFFIC_SECRET',
    # the hex-encoded handshake traffic secret for the client side (for TLS
    # 1.3)
    'CLIENT_HANDSHAKE_TRAFFIC_SECRET',
    # the hex-encoded handshake traffic secret for the server side (for TLS
    # 1.3)
    'SERVER_HANDSHAKE_TRAFFIC_SECRET',
    # the first hex-encoded application traffic secret for the client side
    # (for TLS 1.3)
    'CLIENT_TRAFFIC_SECRET_0',
    # the first hex-encoded application traffic secret for the server side
    # (for TLS 1.3)
    'SERVER_TRAFFIC_SECRET_0',
    # the hex-encoded early exporter secret (for TLS 1.3).
    'EARLY_EXPORTER_SECRET',
    # the hex-encoded exporter secret (for TLS 1.3)
    'EXPORTER_SECRET',
}

KEYLOG_RE = re.compile(
    fr'({"|".join(LABELS)}) '
    + '([0-9a-fA-F]{64}) '
    + '([0-9a-fA-F]{64}|[0-9a-fA-F]{96}|[0-9a-fA-F]{128})'
)


def extract_keylog_randoms(keylog: Path, pcap_randoms: list) -> list:
  randoms = []
  with open(keylog) as f:
    for line in f:
      match = KEYLOG_RE.match(line)
      if match and match.group(2) in pcap_randoms:
        randoms.append(line)
  return randoms


def extract_pcap_randoms(pcap: Path) -> list:
  randoms = []
  cmd = f'tshark -r {pcap} -Y tls.handshake.type==1 -T fields -e tls.handshake.random'
  out = subprocess.run(
      shlex.split(cmd),
      capture_output=True,
      text=True,
      check=True
  )
  for random in out.stdout.split():
    if random and len(random) == 64:
      randoms.append(random)
  return randoms


def decrypt_tls_stream(pcap: Path, keylog: Path) -> None:
  dsb_path = str(pcap.parent / f'dsb-{pcap.name}')

  pcap_randoms = extract_pcap_randoms(pcap)
  keylog_randoms = extract_keylog_randoms(keylog, pcap_randoms)

  with tempfile.NamedTemporaryFile(mode='w+') as tmp:
    for random in keylog_randoms:
      tmp.write(random)
    tmp.seek(0)

    cmd = f'editcap --discard-all-secrets --inject-secrets tls,{tmp.name} {str(pcap)} {str(dsb_path)}'
    out = subprocess.run(
        shlex.split(cmd),
        capture_output=True
    )
    if out.returncode == 0:
      print(f'tls streams decrypted, pcap saved to: {dsb_path}')


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('PCAP', type=Path, help='PCAP path')
  parser.add_argument('KEYLOGFILE', type=Path, help='KEYLOGFILE path')

  args = parser.parse_args()

  decrypt_tls_stream(args.PCAP, args.KEYLOGFILE)


if __name__ == '__main__':
  main()
