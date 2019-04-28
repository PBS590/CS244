from scapy.all import *
import sys
import random
from threading import Thread
from collections import defaultdict
import time
import threading

sport = random.randint(1025, 56000)
#sport = 12345
dport = 80 
icws = {}
if len(sys.argv) > 1:
  dst = sys.argv[1]
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
    "microsoftonline.com",
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

packet_seqnos = {}

def get_ips(website, packet):
  ips[website] = str(packet[IP].src)

def count_packet(website, packet):
  if (packet[TCP].seq not in packet_seqnos):
    icws[website][2] += 1
    packet_seqnos[packet[TCP].seq] = 1

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

def run_sniff(website, sport):
  sniff(timeout=3, filter="dst port " + str(sport) + " and src " + website, prn=lambda x: count_packet(website, x))
  
for website in websites:
  ip = IP(dst=website)
  SYN=TCP(sport=sport, dport=dport, flags="S", seq=init_seq, options=[('MSS', 10)])
  SYNACK=sr1(ip/SYN, timeout=5)
  if (SYNACK == None):
    continue
  ACK=TCP(sport=sport, dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
  http ="GET /dfadfdsafdsafjdsfkjhasdfjkasdflkjhasdflhdsaflkjhasdlkfjhadsklfjhasdflkjhasdlfkjhasdflkjasdhfkljdshflkjasdhflkjdsahflkjsdahflksadjhflasdkjhfladskjhfasdlkjfhasdlkjfhsdalkjfhasdlkjfhasdlkfjhasdlfkjhasdlfkjhsdaflkjhadflkjhasdlfkjadhsflkjdashflkdsjahflkasdjhflasdjfhasdlkjfhasdlkjfhasdlkjfhdaslkfjhasdlkjfhadslfkhasdflkjasdhfsadfljsdhfkljdsahfljashflkahflkasdjhflskdahjfaljfhlkajhfklasdjhfklasdhflkasdjhflaksdjhflakjfhdlskjfhsdalkjfhsdlkajhfldskjfhasdlkjfhasdlkjfhasdlkf HTTP/1.0\r\n\r\n"
  
  packet_seqnos[SYNACK.seq] = 1
  icws[website] = [SYNACK.seq, 0, 0]
  
  t1 = threading.Thread(target=run_sniff, args=(website, sport))
  t1.start()
  
  time.sleep(1)
  send_res = send(ip/ACK/http)
  t1.join()
  
  sport += 1
  packet_seqnos.clear()

for web in icws.keys():
  print(web + ": " + str(icws[web][1]) + ": " + str(icws[web][2]))


