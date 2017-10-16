#!/usr/bin/env python

# based on:
# https://stackoverflow.com/questions/27293924/change-tcp-payload-with-nfqueue-scapy?rq=1
# https://github.com/DanMcInerney/cookiejack/blob/master/cookiejack.py

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import nfqueue
from scapy.all import *
import os
import re

from os import path

# https://forum.z.cash/t/about-dev-fees-and-how-to-remove-them/9600/36
#os.system('iptables -A OUTPUT -p tcp --dport 4444 -j NFQUEUE --queue-num 0')
os.system('iptables -A OUTPUT -p tcp --dport 5555 -j NFQUEUE --queue-num 0') # hush
#os.system('iptables -A OUTPUT -p tcp --dport 9999 -d eth-us-west1.nanopool.org -j NFQUEUE --queue-num 0')
#os.system('iptables -A OUTPUT -p tcp --dport 5000 -j NFQUEUE --queue-num 0')
#os.system('iptables -A INPUT -p tcp --dport 5000 -j NFQUEUE --queue-num 0')

my_eth_address = 't1Qr9xvPfbrQ4wmKa6pco16TBKWucWzi8VU'

addresses_to_redirect = [re.compile(re.escape(x.lower()), re.IGNORECASE) for x in [
  # tcpdump -i enp4s0 host zech-us-west1.nanopool.org -X > log_mining_activity.txt
  # tcpdump -i eth0 host hushpool.cloud -X > log_mining_activity.txt
  't1dn3KXy6mBi5TR1ifRwYse6JMgR2w7zUbr',
  't1W9HL5Aep6WHsSqHiP9YrjTH2ZpfKR1d3t',
  't1N7NByjcXxJEDPeb1KBDT9Q8Wocb3urxnv',
  't1b9PsiekL4RbMoGzyLMFkMevbz7QfwepgP',



]]

logfile = open('nofees_log.txt', 'w', 0)

print "NoFee Hush starting..."

def callback(arg1, payload):
  data = payload.get_data()
  pkt = IP(data)

  payload_before = len(pkt[TCP].payload)

  payload_text = str(pkt[TCP].payload)
  for address_to_redirect in addresses_to_redirect:
    payload_text = address_to_redirect.sub(my_eth_address, payload_text)
  pkt[TCP].payload = payload_text

  payload_after = len(payload_text)

  payload_dif = payload_after - payload_before

  pkt[IP].len = pkt[IP].len + payload_dif

  pkt[IP].ttl = 40

  del pkt[IP].chksum
  del pkt[TCP].chksum
  payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
  logfile.write(payload_text)
  logfile.write('\n')
  logfile.flush()
def main():
  q = nfqueue.queue()
  q.open()
  q.bind(socket.AF_INET)
  q.set_callback(callback)
  q.create_queue(0)
  try:
    q.try_run() # Main loop
  except KeyboardInterrupt:
    q.unbind(socket.AF_INET)
    q.close()
    if path.exists('./restart_iptables'):
      os.system('./restart_iptables')

main()
