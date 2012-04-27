#!/bin/bash

outfile_cnc_ip="./output/cnc_ip.txt"
outfile_cnc_url="./output/cnc_url.txt"

outfile_exploit_ip="./output/exploit_ip.txt"

outfile_rbn_ip="./output/rbn_ip.txt"

outfile_bad_ports="./output/bad_ports.txt"

# Cnc IP
wget -q -O- "https://spyeyetracker.abuse.ch/blocklist.php?download=ipblocklist" | 
sed '1,6d' >> outfile_cnc_ip
wget -q -O- "https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist" | 
sed '1d' >> outfile_cnc_ip
wget -q -O- "https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist" | 
sed '1,6d' >> outfile_cnc_ip

#CnC URL
wget -q -O- "https://spyeyetracker.abuse.ch/blocklist.php?download=domainblocklist" | 
sed '1,6d' >> outfile_cnc_url
wget -q -O- "https://palevotracker.abuse.ch/blocklists.php?download=domainblocklist" | 
sed '1d' >> outfile_cnc_url
wget -q -O- "https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist" | 
sed '1,6d' >> outfile_cnc_url

#Exploit IP
wget -q -O- "http://www.ciarmy.com/list/ci-badguys.txt" | 
cat >> outfile_exploit_ip
wget -q -O- "http://feeds.dshield.org/top10-2.txt" |
awk '{print $1}' >> outfile_exploit_ip
wget -q -O- "http://tcats.stop-spam.org/sibl/sibl.txt" |
awk '{print $1}' >> outfile_exploit_url
wget -q -O- "www.openbl.org/lists/base.txt" | 
sed '1,4d' >> outfile_exploit_ip

#RBN IP
wget -q -O- "http://doc.emergingthreats.net/pub/Main/RussianBusinessNetwork/RussianBusinessNetworkIPs.txt" | 
cat >> outfile_rbn_ip




#echo "First wget at: "`date()` 
#wget -i $infile_cnc_urls -O $outfile_cnc_urls
#echo "Second wget at: "`date()` 
