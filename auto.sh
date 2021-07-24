#!/bin/bash

url=$1

if [ ! -d "$url" ];then
	mkdir $url
fi
if [ ! -d "$url/recon" ];then
	mkdir $url/recon
fi
#    if [ ! -d '$url/recon/eyewitness' ];then
#        mkdir $url/recon/eyewitness
#    fi
if [ ! -d "$url/recon/gowitness" ];then
	mkdir $url/recon/gowitness
fi
if [ ! -d "$url/recon/scans" ];then
	mkdir $url/recon/scans
fi
if [ ! -d "$url/recon/httprobe" ];then
	mkdir $url/recon/httprobe
fi
if [ ! -d "$url/recon/potential_takeovers" ];then
	mkdir $url/recon/potential_takeovers
fi
if [ ! -d "$url/recon/wayback" ];then
	mkdir $url/recon/wayback
fi
if [ ! -d "$url/recon/wayback/params" ];then
	mkdir $url/recon/wayback/params
fi
if [ ! -d "$url/recon/wayback/extensions" ];then
	mkdir $url/recon/wayback/extensions
fi
if [ ! -d "$url/recon/subdomain" ];then
	mkdir $url/recon/subdomain
fi
if [ ! -f "$url/recon/httprobe/alive.txt" ];then
	touch $url/recon/httprobe/alive.txt
fi
if [ ! -f "$url/recon/final.txt" ];then
	touch $url/recon/final.txt
fi
if [ ! -f "$url/recon/potential_takeovers/potential_takeovers.txt" ];then
	touch $url/recon/potential_takeovers/potential_takeovers.txt
fi

#echo "[+] Harvesting subdomains with assetfinder..."
#assetfinder $url >> $url/recon/assets.txt
#cat $url/recon/assets.txt | sort -u | grep $1 >> $url/recon/final.txt
#rm $url/recon/assets.txt

echo "[+] Probing for alive domains..."
cat $url/recon/final.txt | sort -u | httprobe -s -p https:443 | tr -d '443' | sed s/.$// >> $url/recon/httprobe/fgowitness.txt
cat $url/recon/httprobe/fgowitness.txt | sed 's/https\?:\/\///' >> $url/recon/httprobe/alive.txt

echo "[+] Checking for possible subdomain takeover..."
subjack -w $url/recon/final.txt -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 -o $url/recon/potential_takeovers/potential_takeovers.txt

echo "[+] Scanning for open ports..."
nmap -iL $url/recon/httprobe/alive.txt -T4 -oA $url/recon/scans/scanned.txt

echo "[+] Running gowitness against all compiled domains..."
gowitness file -s $url/recon/httprobe/fgowitness.txt -d $url/recon/gowitness
rm $url/recon/httprobe/fgowitness.txt

echo "[+] Scraping wayback data..."
cat $url/recon/final.txt | sort -u | waybackurls >> $url/recon/wayback/wayback_output.txt
sort -u $url/recon/wayback/wayback_output.txt

echo "[+] Pulling and compiling all possible params found in wayback data..."
cat $url/recon/wayback/wayback_output.txt | grep '?*=' | cut -d '=' -f 1 | sort -u >> $url/recon/wayback/params/wayback_params.txt
for line in $(cat $url/recon/wayback/params/wayback_params.txt);do echo $line'=';done

echo "[+] Pulling and compiling js/php/aspx/jsp/json files from wayback output..."
for line in $(cat $url/recon/wayback/wayback_output.txt);do
	ext="${line##*.}"
	if [[ "$ext" == "js" ]]; then
		echo $line >> $url/recon/wayback/extensions/js1.txt
		sort -u $url/recon/wayback/extensions/js1.txt >> $url/recon/wayback/extensions/js.txt
	fi
	if [[ "$ext" == "html" ]];then
		echo $line >> $url/recon/wayback/extensions/jsp1.txt
		sort -u $url/recon/wayback/extensions/jsp1.txt >> $url/recon/wayback/extensions/jsp.txt
	fi
	if [[ "$ext" == "json" ]];then
		echo $line >> $url/recon/wayback/extensions/json1.txt
		sort -u $url/recon/wayback/extensions/json1.txt >> $url/recon/wayback/extensions/json.txt
	fi
	if [[ "$ext" == "php" ]];then
		echo $line >> $url/recon/wayback/extensions/php1.txt
		sort -u $url/recon/wayback/extensions/php1.txt >> $url/recon/wayback/extensions/php.txt
	fi
	if [[ "$ext" == "aspx" ]];then
		echo $line >> $url/recon/wayback/extensions/aspx1.txt
		sort -u $url/recon/wayback/extensions/aspx1.txt >> $url/recon/wayback/extensions/aspx.txt
	fi
done

rm $url/recon/wayback/extensions/js1.txt
rm $url/recon/wayback/extensions/jsp1.txt
rm $url/recon/wayback/extensions/json1.txt
rm $url/recon/wayback/extensions/php1.txt
rm $url/recon/wayback/extensions/aspx1.txt


#echo "[+] Running eyewitness against all compiled domains..."
#python3 EyeWitness/EyeWitness.py --web -f $url/recon/httprobe/alive.txt -d $url/recon/eyewitness --resolve

#echo "[+] Double checking for subdomains with censys..."
#python censys_subdomain_finder.py $url >> $url/recon/subdomain/censys1.txt
#sort -u $url/recon/subdomain/censys1.txt >> $url/recon/subdomain/censys.txt
#rm $url/recon/subdomain/censys1.txt

#echo "[+] Double checking for subdomains with findomain..."
#./findomain-linux -t $url >> $url/recon/subdomain/findomain1.txt
#sort -u $url/recon/subdomain/findomain1.txt >> $url/recon/subdomain/findomain.txt
#rm $url/recon/subdomain/findomain1.txt

#echo "[+] Double checking for subdomains with amass..."
#amass enum -d $url >> $url/recon/subdomain/amass1.txt
#sort -u $url/recon/subdomain/amass1.txt >> $url/recon/subdomain/amass.txt
#rm $url/recon/subdomain/amass1.txt

#echo "[+] Double checking for subdomains with sublist3r..."
#python sublist3r.py -d $url >> $url/recon/subdomain/sublist3r1.txt
#sort -u $url/recon/subdomain/sublist3r1.txt >> $url/recon/subdomain/sublist3r.txt
#rm $url/recon/subdomain/sublist3r1.txt

#echo "[+] Double checking for subdomains with knockpy..."
#knockpy $url >> $url/recon/subdomain/knockpy1.txt
#sort -u $url/recon/subdomain/knockpy1.txt >> $url/recon/subdomain/knockpy.txt
#rm $url/recon/subdomain/knockpy1.txt

#echo "[+] Double checking for subdomains with subfinder..."
#subfinder -d $url >> $url/recon/subdomain/subfinder1.txt
#sort -u $url/recon/subdomain/subfinder1.txt >> $url/recon/subdomain/subfinder.txt
#rm $url/recon/subdomain/subfinder1.txt

#echo "[+] Double checking for subdomains with aquatone-discover..."
#aquatone-discover --domain $url >> $url/recon/subdomain/aquatone1.txt
#sort -u $url/recon/subdomain/aquatone1.txt >> $url/recon/subdomain/aquatone.txt
#rm $url/recon/subdomain/aquatone1.txt
