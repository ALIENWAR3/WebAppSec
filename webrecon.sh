#!/bin/bash	
url=$1
if [ ! -d "$url" ];then
	mkdir $url
fi
if [ ! -d "$url/recon" ];then
	mkdir $url/recon
fi
if [ ! -d "$url/recon/wayback" ];then
	mkdir $url/recon/wayback
fi
echo "[+] Harvesting subdomains with assetfinder..."
assetfinder $url >> $url/recon/assets.txt
cat $url/recon/assets.txt | grep $1 >> $url/recon/finalsub.txt
# rm $url/recon/assets.txt

echo "[+] Double checking for subdomains with dnsx..."
dnsx -silent -d $url -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt >> $url/recon/f.txt
sort -u $url/recon/f.txt >> $url/recon/finalsub.txt
rm $url/recon/f.txt

echo "[+] Probing for alive domains..."
cat $url/recon/finalsub.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' >> $url/recon/a.txt
sort -u $url/recon/a.txt > $url/recon/alive.txt
rm $url/recon/a.txt

# echo "[+] Doing directory FUZZING"

# ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u https://$url/FUZZ -r -recursion -recursion-depth 1 -o dirs.html -of html -s
# mv dirs.html $url/recon/

echo "[+] Checking for possible subdomain takeover..."

if [ ! -f "$url/recon/potential_takeovers.txt" ];then
	touch $url/recon/potential_takeovers.txt
fi
subjack -w $url/recon/finalsub.txt -t 100 -timeout 30 -ssl -c /usr/share/subjack/fingerprints.json -v 3 -o $url/recon/potential_takeovers.txt

echo "[+] Scanning for open ports..."
nmap -iL $url/recon/alive.txt -T4 -o $url/recon/openports.txt --noninteractive

echo "[+] Scraping wayback data..."
cat $url/recon/finalsub.txt | waybackurls >> $url/recon/wayback/wayback_output.txt
sort -u $url/recon/wayback/wayback_output.txt

echo "[+] Pulling and compiling all possible params found in wayback data..."
cat $url/recon/wayback/wayback_output.txt | grep '?*=' | cut -d '=' -f 1 | sort -u >> $url/recon/wayback/wayback_params.txt
for line in $(cat $url/recon/wayback/wayback_params.txt);do echo $line'=';done

echo "[+] Pulling and compiling js/php/aspx/jsp/json files from wayback output..."
for line in $(cat $url/recon/wayback/wayback_output.txt);do
	ext="${line##*.}"
	if [[ "$ext" == "js" ]]; then
		echo $line >> $url/recon/wayback/js1.txt
		sort -u $url/recon/wayback/js1.txt >> $url/recon/wayback/js.txt
	fi
	if [[ "$ext" == "html" ]];then
		echo $line >> $url/recon/wayback/jsp1.txt
		sort -u $url/recon/wayback/jsp1.txt >> $url/recon/wayback/jsp.txt
	fi
	if [[ "$ext" == "json" ]];then
		echo $line >> $url/recon/wayback/json1.txt
		sort -u $url/recon/wayback/json1.txt >> $url/recon/wayback/json.txt
	fi
	if [[ "$ext" == "php" ]];then
		echo $line >> $url/recon/wayback/php1.txt
		sort -u $url/recon/wayback/php1.txt >> $url/recon/wayback/php.txt
	fi
	if [[ "$ext" == "aspx" ]];then
		echo $line >> $url/recon/wayback/aspx1.txt
		sort -u $url/recon/wayback/aspx1.txt >> $url/recon/wayback/aspx.txt
	fi
done

rm $url/recon/wayback/js1.txt
rm $url/recon/wayback/jsp1.txt
rm $url/recon/wayback/json1.txt
rm $url/recon/wayback/php1.txt
rm $url/recon/wayback/aspx1.txt
echo "[+] Running eyewitness against all compiled domains..."
eyewitness --web -f $url/recon/httprobe/alive.txt -d $url/recon/eyewitness --resolve

# echo "[+] Fuzzing alive hosts for directories/files..."
# for i in `cat $url/recon/alive.txt`; do ffuf -u $i/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -mc 200,302,401 -se -of html -o dirs.html;done