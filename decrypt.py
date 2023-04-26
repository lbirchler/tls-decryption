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
    # hex-encoded early traffic secret - client side - TLS 1.3
    'CLIENT_EARLY_TRAFFIC_SECRET',
    # hex-encoded handshake traffic secret - client side - TLS 1.3
    'CLIENT_HANDSHAKE_TRAFFIC_SECRET',
    # hex-encoded handshake traffic secret for - server side - TLS 1.3
    'SERVER_HANDSHAKE_TRAFFIC_SECRET',
    # first hex-encoded application traffic secret - client side - TLS 1.3
    'CLIENT_TRAFFIC_SECRET_0',
    # first hex-encoded application traffic secret - server side - TLS 1.3
    'SERVER_TRAFFIC_SECRET_0',
    # hex-encoded early exporter secret - TLS 1.3
    'EARLY_EXPORTER_SECRET',
    # hex-encoded exporter secret - TLS 1.3
    'EXPORTER_SECRET',
}

KEYLOG_RE = re.compile(
    # label
    fr'({"|".join(LABELS)}) '
    # client random
    + '([0-9a-fA-F]{64}) '
    # secret
    + '([0-9a-fA-F]{64}|[0-9a-fA-F]{96}|[0-9a-fA-F]{128})'
)


def extract_keylog_randoms(keylog: Path, pcap_randoms: list) -> list:
  randoms = []
  with open(keylog) as f:
    for line in f:
      match = KEYLOG_RE.fullmatch(line.rstrip())
      # ensure client random is in pcap
      if match and match.group(2) in pcap_randoms:
        randoms.append(line)
  return randoms


def extract_pcap_randoms(pcap: Path) -> list:
  randoms = []
  cmd = f'tshark -r {pcap} -Y tls.handshake.type==1 -T fields -e tls.handshake.random'
  try:
    proc = subprocess.run(
        shlex.split(cmd),
        capture_output=True,
        text=True,
        check=True
    )
    for random in proc.stdout.split():
      if random and len(random) == 64:
        randoms.append(random)
  except subprocess.CalledProcessError as e:
    print(f'cmd: {e.cmd}, err: {e.stderr}')
    raise
  return randoms


def inject_secrets(pcap: Path, keylog: Path) -> None:
  dsb_path = pcap.parent / f'dsb-{pcap.name}'

  pcap_randoms = extract_pcap_randoms(pcap)
  keylog_randoms = extract_keylog_randoms(keylog, pcap_randoms)

  with tempfile.NamedTemporaryFile(mode='w+') as tmp:
    tmp.write(''.join(keylog_randoms))
    tmp.seek(0)
    cmd = f'editcap --log-level info --discard-all-secrets --inject-secrets tls,{tmp.name} {pcap} {dsb_path}'
    try:
      subprocess.run(
          shlex.split(cmd),
          capture_output=True,
          text=True,
          check=True
      )
      print('dsb-pcap saved to: %s' % dsb_path)
    except subprocess.CalledProcessError as e:
      print(f'cmd: {e.cmd}, err: {e.stderr}')
      raise


def _valid_file(path: Path | str):
  if not isinstance(path, Path):
    path = Path(path)
  if not path.exists():
    raise argparse.ArgumentTypeError(f'Invalid file path: {path}')
  return path


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('PCAP', type=_valid_file, help='PCAP path')
  parser.add_argument('KEYLOGFILE', type=_valid_file, help='KEYLOGFILE path')

  args = parser.parse_args()

  inject_secrets(args.PCAP, args.KEYLOGFILE)


if __name__ == '__main__':
  main()
