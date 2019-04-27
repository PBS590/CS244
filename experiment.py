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
icws = defaultdict(int)
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

def count_packet(website, packet):
  icws[website] += packet[IP].len
  print(website + ": " + str(icws[website]))

for website in websites:
  ip = IP(dst=website)
  SYN=TCP(sport=sport, dport=dport, flags="S", seq=init_seq, options=[('MSS', 10)])
  SYNACK=sr1(ip/SYN, timeout=20)

  ACK=TCP(sport=sport, dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
  http ="GET / HTTP/1.0\r\n\r\n"
  
  send_res = send(ip/ACK/http)
  sniff(timeout=3, filter="dst port " + str(sport), prn=lambda x: count_packet(website, x))

for web in icws.keys():
  print(web + ": " + icws[web])


