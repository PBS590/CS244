# CS 244 (Spring 2019) Project 2 Script
# Peter Spradling, Jerry Zhilin Jiang
# Tested to work on MacOS only
# Requirements: Python 3.4+, pip, Homebrew

# Install Python dependencies
# Alternatively, run:
#     sudo pip install -r requirements.txt
sudo pip install --pre scapy[complete]

# Install Scapy MacOS dependencies
brew update
brew install libdnet
brew install https://raw.githubusercontent.com/secdev/scapy/master/.travis/pylibpcap.rb

# Temporarily block all RST packets so Scapy can handle the SYN-ACKs
echo "block drop proto tcp all flags R/R" | sudo tee -a /etc/pf.conf
sudo pfctl -f /etc/pf.conf
sudo pfctl -e

# Execute experiment
sudo python experiment.py

# Undo PF blocking of RST packets
sudo sed -i '' -e '$ d' /etc/pf.conf
sudo pfctl -f /etc/pf.conf
