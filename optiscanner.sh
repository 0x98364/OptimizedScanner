#!/bin/bash

RED='\033[0;31m'
NC='\033[0m'

cat << "EOF"

  ___        _   _           _             _
 / _ \ _ __ | |_(_)_ __ ___ (_)_______  __| |
| | | | '_ \| __| | '_ ` _ \| |_  / _ \/ _` |
| |_| | |_) | |_| | | | | | | |/ /  __/ (_| |
 \___/| .__/ \__|_|_| |_| |_|_/___\___|\__,_|
      |_|
 ____
/ ___|  ___ __ _ _ __  _ __   ___ _ __
\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 ___) | (_| (_| | | | | | | |  __/ |
|____/ \___\__,_|_| |_|_| |_|\___|_|

By Matias Moreno (@mmorenodev)

EOF


if [ $# -lt 3 ]
then
  echo "Usage: $0 <networkrange> <top_ports_number> <rate>"
  exit 1
fi

range=$(echo $1 | cut -d "/" -f1)
port_range=$2
timestamp=$(date +%H:%M:%S)
folder_name=$range$timestamp

mkdir $folder_name

#First, discover alive hosts in networkrange
#printf "${RED}[*]${NC} Discovering alive hosts...\n"
#nmap=$(nmap -sP $1 -oG $folder_name/alive_hosts)

#Then, grep alive_hosts and create hosts_list
#`cat $folder_name/alive_hosts | cut -d " " -f2 | sed '/^Nmap/ d' > $folder_name/hosts_list`

#nmap -sT --top-ports 2000 -v -oG -
#masscan for detect common open ports
printf "${RED}[*]${NC} Scanning $port_range common TCP ports in range $1\n"
printf "\n"

port_list=$(nmap -sT -oG - -v --top-ports $port_range 0.0.0.0 | awk -F'[);]' '/Ports/{print $2}')
#echo "masscan -iL $folder_name/hosts_list -p$port_list -oG $folder_name/mass_result"
#masscan=$(masscan -iL $folder_name/hosts_list -p$port_list -oG $folder_name/mass_result --rate $3)
masscan=$(masscan $1 -p$port_list -oG $folder_name/mass_result --rate $3)

#Split hosts for other tools
cat $folder_name/mass_result | cut -d " " -f2,4 | grep "^[0-99999]" | grep " 445/open" | cut -d " " -f1 > $folder_name/smb_hosts
cat $folder_name/mass_result | cut -d " " -f2,4 | grep "^[0-99999]" | grep " 3389/open" | cut -d " " -f1 > $folder_name/rdp_hosts
cat $folder_name/mass_result | cut -d " " -f2,4 | grep "^[0-99999]" | grep " 5900/open" | cut -d " " -f1 > $folder_name/vnc_hosts
cat $folder_name/mass_result | cut -d " " -f2,4 | grep "^[0-99999]" | grep " 21/open" | cut -d " " -f1 > $folder_name/ftp_hosts
cat $folder_name/mass_result | cut -d " " -f2,4 | grep "^[0-99999]" | grep " 22/open" | cut -d " " -f1 > $folder_name/ssh_hosts
cat $folder_name/mass_result | cut -d " " -f2,4 | grep "^[0-99999]" | grep " 1433/open" | cut -d " " -f1 > $folder_name/mssql_hosts
cat $folder_name/mass_result | cut -d " " -f2,4 | grep "^[0-99999]" | grep " 3306/open" | cut -d " " -f1 > $folder_name/mysql_hosts
cat $folder_name/mass_result | cut -d " " -f2,4 | grep "^[0-99999]" | grep " 5432/open" | cut -d " " -f1 > $folder_name/postgre_hosts
cat $folder_name/mass_result | cut -d " " -f2,4 | grep "^[0-99999]" | grep " 389/open" | cut -d " " -f1 > $folder_name/ldap_hosts
cat $folder_name/mass_result | cut -d " " -f2,4 | grep "^[0-99999]" | grep " 25/open" | cut -d " " -f1 > $folder_name/smtp_hosts
cat $folder_name/mass_result | cut -d " " -f2,4 | grep "^[0-99999]" | grep " 53/open" | cut -d " " -f1 > $folder_name/dns_hosts

#Create file for only common open ports
cat $folder_name/mass_result | cut -d " " -f4 | cut -d "/" -f1 | grep "^[0-99999]" | sort -u -n > $folder_name/open_ports

#Create file for alive hosts from responding hosts to port scanner
cat $folder_name/mass_result | cut -d " " -f2 | grep "^[0-99999]" | sort -u > $folder_name/hosts_list

#Format open ports file to nmap Format
open_ports=$(cat $folder_name/open_ports | tr "\n" ",")

#Scan with NMAP with Service Version
printf "${RED}[*]${NC} Scanning TCP services banners on range $1"
printf "\n"
nmap=$(nmap -sS -sV -O -iL $folder_name/hosts_list -p$open_ports -oA $folder_name/nmap_results -oG $folder_name/nmap_results_grepable -v -n -Pn)

printf "${RED}[*]${NC} Optimized TCP Scan COMPLETED on $1\n"
printf "${RED}[*]${NC} All the results saved to folder $folder_name\n"

printf "==================TCP RESULTS===================\n"
hosts_list_count=$(cat $folder_name/hosts_list | wc -l)
printf "Alive Hosts -> $hosts_list_count \n"
cat $folder_name/hosts_list

printf "\n"

open_ports_count=$(cat $folder_name/open_ports | wc -l)
printf "Total Open Ports -> $open_ports_count \n"
cat $folder_name/open_ports
#printf $cat_ports
printf "============================================\n"

echo -n "Do you want to scan UDP ports in this network? This may take a while (y/n)"
read answer
if echo "$answer" | grep -iq "^y" ;then

udp_port_list=$(nmap -sU -oG - -v --top-ports 1000 0.0.0.0 | awk -F'[);]' '/Ports/{print $4}' | sed -e 's/,/,U:/g')

masscan_udp=$(masscan -iL $folder_name/hosts_list -p$udp_port_list -oG $folder_name/mass_result_udp --rate $3)

cat $folder_name/mass_result_udp | cut -d " " -f4 | cut -d "/" -f1 | grep "^[0-99999]" | sort -u -n > $folder_name/open_udp_ports

#Format open ports file to nmap Format
open_udp_ports=$(cat $folder_name/open_udp_ports | tr "\n" ",")

printf "${RED}[*]${NC} Scanning common UDP services banners on range $1"
printf "\n"
nmap=$(nmap -sU -sV -iL $folder_name/hosts_list -p$open_udp_ports -oA $folder_name/nmap_udp_results -oG $folder_name/nmap_udp_results_grepable -v -n -Pn)

printf "${RED}[*]${NC} Optimized UDP Scan COMPLETED on $1\n"
printf "${RED}[*]${NC} All the results saved to folder $folder_name\n"

printf "==================UDP RESULTS===================\n"
hosts_list_count=$(cat $folder_name/hosts_list | wc -l)
printf "Alive Hosts -> $hosts_list_count \n"
cat $folder_name/hosts_list

printf "\n"

open_ports_count=$(cat $folder_name/open_udp_ports | wc -l)
printf "Total Open Ports -> $open_ports_count \n"
cat $folder_name/open_udp_ports
#printf $cat_ports
printf "============================================\n"
else
    exit;
fi
