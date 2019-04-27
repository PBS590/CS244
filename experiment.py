from scapy.all import *
import sys
import random
from threading import Thread
from collections import defaultdict
import time

sport = random.randint(1025, 56000)
#sport = 12345
dport = 80 
init_seq = 1000
icws = {}
#dst = sys.argv[1]
websites = ["google.com",
    "youtube.com",
    "facebook.com",
    "amazon.com",
    "wikipedia.com",
    "reddit.com",
    "yahoo.com",
    "twitter.com",
    "linkedin.com",
    "instagram.com",
    "ebay.com",
    "netflix.com",
    "twitch.tv",
    "instructure.com",
    "pornhub.com",
    "imgur.com",
    "live.com",
    "espn.com",
    "craigslist.org",
    "chase.com",
    "paypal.com",
    "bing.com",
    "T.co",
    "cnn.com",
    "fandom.com",
    "imdb.com",
    "pinterest.com",
    "office.com",
    "nytimes.com",
    "github.com",
    "hulu.com",
    "microsoft.com",
    "salesforce.com",
    "zillow.com",
    "stackoverflow.com",
    "force.com",
    "intuit.com",
    "apple.com",
    "yelp.com",
    "walmart.com",
    "bankofamerica.com",
    "livejasmin.com",
    "dropbox.com",
    "quora.com",
    "tumblr.com",
    "wellsfargo.com",
    "weather.com",
    "quizlet.com",
    "xvideos.com",]

ips = {}
def get_ips(website, packet):
  ips[website] = str(packet[IP].src)

def count_packet(website, packet):
  ips[website] = packet[IP].src
  size = packet[IP].len - 20 - (packet[TCP].dataofs * 4)
  start_seqno = icws[website][0]
  diff = packet[TCP].seq + size - start_seqno
  if diff < 100000 and diff > icws[website][1]:
    icws[website][1] = diff
  if (Raw in packet):
      print(packet[Raw])
      print("-------------------------------------------------------------------")
  print(website + ": " + str(icws[website][1]))
  print(packet[IP].src)
  print(packet[TCP].flags)

for website in websites:
  ip = IP(dst=website)
  SYN=TCP(sport=sport, dport=dport, flags="S", seq=init_seq, options=[('MSS', 10)])
  SYNACK=sr1(ip/SYN, timeout=20)

  ACK=TCP(sport=sport, dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
  http ="GET / HTTP/1.0\r\n\r\n"
  icws[website] = [SYNACK.seq, 0]
  send_res = send(ip/ACK/http)
  sniff(timeout=1, filter="dst port " + str(sport), prn=lambda x: count_packet(website, x))
 
for web in icws.keys():
  print(web + ": " + icws[web])


