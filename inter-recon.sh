#!/bin/bash
#Wrote by Mario Sala (A2SECURE) INTERNON
#example of comand inter-recon.sh -t {NET OR IP} -w {DICT PATH} -s {scan type}
#inter-recon.sh -h for usage information

function initvariables(){
	if [[ -z $INTERINITFOLDER ]]; then
		INTERINITFOLDER=$(pwd)/$(echo $INTERTARGET | sed 's/\//-/g')
	fi
	INTERDEBUGFOLDER=$INTERINITFOLDER/debug
	INTERNMAPFOLDER=$INTERINITFOLDER/nmap
	INTERDISCOVERHTTPFOLDER=$INTERINITFOLDER/http-discover
	INTERFUZZINGFOLDER=$INTERINITFOLDER/fuzzing
	INTERSCREENSHOTFOLDER=$INTERINITFOLDER/screenshots
	INTERCVEFOLDER=$INTERINITFOLDER/cve
	INTERAUXFOLDER=$INTERINITFOLDER/aux
	INTERSERVICESFOLDER=$INTERINITFOLDER/services
	INTERBYP4XXFOLDER=$INTERINITFOLDER/bypass
	INTERSMBFOLDER=$INTERINITFOLDER/smb
	INTERDNSFOLDER=$INTERINITFOLDER/dns
	INTERDOCUFOLDER=$INTERINITFOLDER/documentation
	INTERFUZZFILTER="not (c=BBB and l=BBB and w=BBB)"
}

function initfolders(){
	if [ ! -d "$INTERINITFOLDER" ]; then
		mkdir $INTERINITFOLDER
	else
		echo -e "\e[33m[WARNING] - Initial Scan folder $INTERINITFOLDER exist.\e[0m"
	fi
	if [ ! -d "$INTERDEBUGFOLDER" ]; then
		mkdir $INTERDEBUGFOLDER
	fi
	if [ ! -d "$INTERAUXFOLDER" ]; then
		mkdir $INTERAUXFOLDER
	fi
}
function displaytime {
	local T=$1
	local D=$((T/60/60/24))
	local H=$((T/60/60%24))
	local M=$((T/60%60))
	local S=$((T%60))
	timecalc=""
	(( $D > 0 )) && stringreturn="$timecalc $D days "
	(( $H > 0 )) && stringreturn="$timecalc $H hours "
	(( $M > 0 )) && timecalc="$timecalc $M minutes "
	timecalc="$timecalc $S seconds"
}
function scripthelp(){
	echo "Usage: $0 [OPTIONS]"
	echo "	Options:"
	echo "		-T {file with targets by line}"
	echo "		-t {IP or IP/CIDR}"
	echo "		-d {directory path for initfolder}"
	echo "		-w {DICT PATH}"
        echo "	 	-s {all/web/vuln}"
        echo "		-a superautomaticscan"
	echo "	Examples:"
	echo "		inter-recon -t 127.0.0.1 -w \$(pwd)/dict.txt -s all -a true"
	echo "		inter-recon -T targets.txt -d \$(pwd)/domains -w \$(pwd)/dict.txt -s all -a true"
	echo "[INFO] - '-w' (I recommend you that if you have a lot of web services and low time use the /dictionaries/common.txt at least to start)"
	echo "[INFO] - '-a' is for super automatic scan skipping all skipable and not asking anything, just executing all without configuration and neither re-execution of anything"
	echo "[INFO] - '-d' and '-w' must be a full static path ex: /tmp/recon"
}

function portscan() {
	echo -e "\e[32m--------- Starting port scan process\e[0m" 
	echo "This is to retrieve all TCP ports and top UDP ports with version (sudo required for nmap -sSV and -sUV scan)"
	startportscanprocess=`date +%s`
	#startallprocess=`date +%s`
	#Nmap
	if [[ ! -z $INTERTARGETFILE ]]; then
		cp $INTERTARGETFILE $INTERINITFOLDER/targets.txt
	else
		echo $INTERTARGET > $INTERINITFOLDER/targets.txt
	fi
	#startinterlaceprocess=`date +%s`
	sudo nmap -sSV -T4 --max-retries 3 --min-parallelism 100 --min-hostgroup 256 -PS22,53,80,135,443,445,993,995,1521,3306,3389,5985,5986,8080,8081,8090,9001,9002,10443 -oX $INTERNMAPFOLDER/nmap-tcp-target.xml -oG $INTERNMAPFOLDER/nmap-tcp-target.gnmap --open -p- -iL $INTERINITFOLDER/targets.txt &> $INTERDEBUGFOLDER/nmap-tcp-output.txt
	sudo nmap -sUV -F --min-parallelism 100 --host-timeout 5m --version-intensity 0 -oX $INTERNMAPFOLDER/nmap-udp-target.xml -oG $INTERNMAPFOLDER/nmap-udp-target.gnmap --open -iL $INTERINITFOLDER/targets.txt &> $INTERDEBUGFOLDER/nmap-udp-output.txt
	#sudo interlace -tL $INTERINITFOLDER/targets.txt -threads 100 -c "nmap -sSV -T4 -PS22,53,80,135,443,445,993,995,1521,3306,3389,5985,5986,8080,8081,8090,9001,9002 -oX - --open -p- _target_ > $INTERNMAPFOLDER/_target_.xml" &> $INTERDEBUGFOLDER/interlace-output.txt
	#endinterlaceprocess=`date +%s`
	echo -e "\e[32m--------- Ended port scan process\e[0m"
	endportscanprocess=`date +%s`
	displaytime `expr $endportscanprocess - $startportscanprocess`
	echo "Execution time of all port scan process was$timecalc."
	#Export all ports to file to postprocess (we might remove this because Adan have another script that can take open ports and we might reutilize this instead of metasploit output)
	#echo 'Starting msfconsole retrieve all-ports from nmap process'
	#startmsfconsoleprocess=`date +%s`
	#msfconsole -x "workspace -a auxiliary; db_import $INTERNMAPFOLDER/*.xml; services -o $INTERINITFOLDER/all-ports.txt; workspace -d auxiliary; exit" -q &> $INTERDEBUGFOLDER/msfconsole-output.txt
	#endmsfconsoleprocess=`date +%s`
	#echo 'Ended msfconsole process'
	#echo Execution time of msfconsole process was `expr $endmsfconsoleprocess - $startmsfconsoleprocess` seconds.
}

function initialhttpdiscoveryscan() {
	echo -e "\e[32m--------- Starting http discovery process\e[0m" 
	echo "This is to retrieve valid http URLs from nmap files"
	starthttpdiscoveryprocess=`date +%s`
	if [ -d "$INTERAUXFOLDER/nmap" ]; then
		echo -e "\e[33mFound previous not ended http discovery process execution\e[0m"
		echo -e "\e[96mDo you want to continue from previous execution? ([n]/[y] default):\e[0m"
		read continueprevioushttpdiscovery
		if [ "$continueprevioushttpdiscovery" == "n" ]; then
			echo "Restarting initial http discovery scan from start"
			cp -r $INTERNMAPFOLDER $INTERAUXFOLDER/nmap
			rm -f $INTERINITFOLDER/full-initial-files.txt
			rm -rf $INTERDISCOVERHTTPFOLDER
			mkdir $INTERDISCOVERHTTPFOLDER
		else
			echo "Continuing from previous initial http discovery scan execution"
		fi
	else
		cp -r $INTERNMAPFOLDER $INTERAUXFOLDER/nmap
		if [ -f "$INTERINITFOLDER/full-initial-files.txt" ]; then
			rm -f $INTERINITFOLDER/full-initial-files.txt
		fi
	fi
	for line in $(cat $INTERNMAPFOLDER/nmap-tcp-target.xml | grep "<address \|<hostname " | sed 's/.*addr="\|.*name="//g' | sed 's/" addrtype.*$/,/g' | tr -d '\n' | sed  's/" type[^>]*>\([0-9]\)/\n\1/g' | sed 's/" type[^>]*>/,/g' | sed 's/,$/\n/g'); do echo $line >> $INTERINITFOLDER/ips-with-domains.txt  ; for domain in $(echo $line | sed 's/^[^,]*,//g' | sed 's/,/\n/g'); do ip=$(echo $line | awk -F ',' '{print $1}') ; cat $INTERINITFOLDER/full-nmap-parsed-tcp.txt | grep $ip | sed "s/`echo $ip`/`echo $domain`/g" | awk -F',' {' print $1 ":" $2'} >> $INTERDISCOVERHTTPFOLDER/httpx_aux.txt ; done ; done
	cat $INTERINITFOLDER/full-nmap-parsed-tcp.txt | awk -F ',' '{print $1 ":" $2}' >> $INTERDISCOVERHTTPFOLDER/httpx_aux.txt
	cat $INTERDISCOVERHTTPFOLDER/httpx_aux.txt | sort -u > $INTERDISCOVERHTTPFOLDER/httpx_aux_cleaned.txt
	httpx -l $INTERDISCOVERHTTPFOLDER/httpx_aux_cleaned.txt -silent -threads 100 -x ALL --retries 5 -status-code | grep -v '.400.' | awk -F' ' '{print $1}' | sort -u > $INTERINITFOLDER/full-initial-files.txt
	rm -rf $INTERAUXFOLDER/nmap
	endhttpdiscoveryprocess=`date +%s`
	echo -e "\e[32m--------- Ended http discovery initial files process\e[0m"
	displaytime `expr $endhttpdiscoveryprocess - $starthttpdiscoveryprocess`
	echo "Execution time of httpdiscovery initial files process was$timecalc."
}

function fuzzingscan() {
	echo -e "\e[32m--------- Starting wfuzz process\e[0m"
	echo "This is to retrieve new paths from URLs found by nmap and http discovery httpx"
	startwfuzzprocess=`date +%s`
	if [ -f "$INTERAUXFOLDER/full-initial-files.txt" ]; then
		echo -e "\e[33mFound previous not ended fuzzing process execution\e[0m"
		echo -e "\e[96mDo you want to continue from previous execution? ([n]/[y] default):\e[0m"
		read continuepreviousfuzzing
		if [ "$continuepreviousfuzzing" == "n" ]; then
			echo "Restarting fuzzing execution from start"
			cp $INTERINITFOLDER/full-initial-files.txt $INTERAUXFOLDER/full-initial-files.txt
			rm -f $INTERAUXFOLDER/wfuzz-skipped-urls.txt
			rm -rf $INTERFUZZINGFOLDER
			mkdir $INTERFUZZINGFOLDER
		else
			echo "Continuing from previous fuzzing execution"
			if [ -f "$INTERAUXFOLDER/wfuzz-skipped-urls.txt" ]; then
				echo -e "\e[33mFound skipped URLs in previous fuzzing process execution due to errors\e[0m"
				echo -e "\e[96mDo you want to process skipped files from previous execution? ([n]/[y] default):\e[0m"
				read continuewithskippedfuzzing
				if [ "$continuewithskippedfuzzing" == "n" ]; then
					echo "Continuing without skipped files"
				else
					echo "Adding skipped files to process URLs"
					cat $INTERAUXFOLDER/wfuzz-skipped-urls.txt | sort -u >> $INTERAUXFOLDER/full-initial-files.txt
				fi
			fi
		fi
	else
		cp $INTERINITFOLDER/full-initial-files.txt $INTERAUXFOLDER/full-initial-files.txt

		if [ -d "$INTERFUZZINGFOLDER" ]; then
			rm -rf $INTERFUZZINGFOLDER
			mkdir $INTERFUZZINGFOLDER
		else
			mkdir $INTERFUZZINGFOLDER
		fi

	fi
	if [[ ! -z $INTERSUPERAUTOMATICSCAN ]]; then
		echo -e "\e[96mDo you want to skip all URLs with errors? ([n] default. You will be asked for skipping/[y] Automatic skip):\e[0m"

		read skippallURLs
		if [ "$skippallURLs" == "y" ]; then
			echo "Skipping all URLs with errors (Recommended when no network or VPN issues, or small dictionaries)"
			for i in $(cat $INTERAUXFOLDER/full-initial-files.txt); do wfuzz --conn-delay 10 --req-delay 10 --efield url -t 40 --filter "$INTERFUZZFILTER" -w $INTERDICT --zE urlencode -f $INTERFUZZINGFOLDER/$(echo $i | sed 's/\//-/g' | sed 's/:/-/g').txt -L $i/"FUZZ{asdfnottherexxxasdf}" &>> $INTERDEBUGFOLDER/wfuzz-output.txt ; totalreq=$(cat  $INTERFUZZINGFOLDER/$(echo $i | sed 's/\//-/g' | sed 's/:/-/g').txt| grep "Total requests:" | awk -F":" '{print $2}' | sed 's/^ //g'); processedreq=$(cat  $INTERFUZZINGFOLDER/$(echo $i | sed 's/\//-/g' | sed 's/:/-/g').txt| grep "Processed Requests:" | awk -F":" '{print $2}' | sed 's/^ //g');if [[ `expr $(expr $totalreq + 1) - $processedreq` -gt 0  ]]; then echo -e "\e[33m[WARNING] - Found an error in $i URL. Review debug folder to see the error\e[0m"; echo "[INFO] - Skipping $i"; echo $i >> $INTERAUXFOLDER/wfuzz-skipped-urls.txt; fi; sed -i "/$(echo $i| sed 's/https*:\/\///g' | sed 's/\/$//g')/d" $INTERAUXFOLDER/full-initial-files.txt ; sleep 10 ;done
			echo "Skipped URLs in $INTERAUXFOLDER/wfuzz-skipped-urls.txt"	
		else
			echo "You will be asked to skip an URL with error (Recommended when network or VPN issues (like time limit in VPN), and for big dictionaries)"
			for i in $(cat $INTERAUXFOLDER/full-initial-files.txt); do wfuzz --efield url -t 40 --filter "$INTERFUZZFILTER" -w $INTERDICT --zE urlencode -f $INTERFUZZINGFOLDER/$(echo $i | sed 's/\//-/g' | sed 's/:/-/g').txt -L $i/"FUZZ{asdfnottherexxxasdf}" &>> $INTERDEBUGFOLDER/wfuzz-output.txt ; totalreq=$(cat  $INTERFUZZINGFOLDER/$(echo $i | sed 's/\//-/g' | sed 's/:/-/g').txt| grep "Total requests:" | awk -F":" '{print $2}' | sed 's/^ //g'); processedreq=$(cat  $INTERFUZZINGFOLDER/$(echo $i | sed 's/\//-/g' | sed 's/:/-/g').txt| grep "Processed Requests:" | awk -F":" '{print $2}' | sed 's/^ //g');if [[ `expr $(expr $totalreq + 1) - $processedreq` -gt 0  ]]; then echo -e "\e[33m[WARNING] - Found an error in $i URL. Review debug folder to see the error\e[0m"; echo -e "\e[96mDo you want to skip this URL and continue? ([y] default/[n]):\e[0m"; read skipURL ; if [ "$skipURL" == "n" ]; then echo "We will stop the process here. To continue with the process, execute again the script, it will make fuzzing to the files not processed yet."; exit 1; else echo "[INFO] - Skipping $i"; echo $i >> $INTERAUXFOLDER/wfuzz-skipped-urls.txt;  fi ; fi; sed -i "/$(echo $i| sed 's/https*:\/\///g' | sed 's/\/$//g')/d" $INTERAUXFOLDER/full-initial-files.txt ; sleep 10 ;done
		fi
	else
		for i in $(cat $INTERAUXFOLDER/full-initial-files.txt); do wfuzz --conn-delay 10 --req-delay 10 --efield url -t 40 --filter "$INTERFUZZFILTER" -w $INTERDICT --zE urlencode -f $INTERFUZZINGFOLDER/$(echo $i | sed 's/\//-/g' | sed 's/:/-/g').txt -L $i/"FUZZ{asdfnottherexxxasdf}" &>> $INTERDEBUGFOLDER/wfuzz-output.txt ; totalreq=$(cat  $INTERFUZZINGFOLDER/$(echo $i | sed 's/\//-/g' | sed 's/:/-/g').txt| grep "Total requests:" | awk -F":" '{print $2}' | sed 's/^ //g'); processedreq=$(cat  $INTERFUZZINGFOLDER/$(echo $i | sed 's/\//-/g' | sed 's/:/-/g').txt| grep "Processed Requests:" | awk -F":" '{print $2}' | sed 's/^ //g');if [[ `expr $(expr $totalreq + 1) - $processedreq` -gt 0  ]]; then echo -e "\e[33m[WARNING] - Found an error in $i URL. Review debug folder to see the error\e[0m"; echo "[INFO] - Skipping $i"; echo $i >> $INTERAUXFOLDER/wfuzz-skipped-urls.txt; fi; sed -i "/$(echo $i| sed 's/https*:\/\///g' | sed 's/\/$//g')/d" $INTERAUXFOLDER/full-initial-files.txt ; done
		echo "Skipped URLs in $INTERAUXFOLDER/wfuzz-skipped-urls.txt"
	fi

	rm $INTERAUXFOLDER/full-initial-files.txt
	endwfuzzprocess=`date +%s`
	echo -e "\e[32m--------- Ended wfuzz process\e[0m"
	displaytime `expr $endwfuzzprocess - $startwfuzzprocess`
	echo "Execution time of wfuzz process was$timecalc."
}

function screenshotscan() {
	echo -e "\e[32m--------- Starting HTTP screenshot process\e[0m"
	echo "This is to make screenshots of all status 200 URLs found after fuzzing"
	startscreenshotprocess=`date +%s`
	cat $INTERFUZZINGFOLDER/*.txt | grep http | sed 's/.* C=//g' | sed 's/ .*|//g' | sed 's/"$//g' | grep -v "^Target: " | sort -u > $INTERINITFOLDER/all-urls-fuzzing-results.txt
	allstatus=$(cat $INTERINITFOLDER/all-urls-fuzzing-results.txt | awk -F " " '{print $1}' | sort -u)
	for status in $allstatus; do cat $INTERINITFOLDER/all-urls-fuzzing-results.txt | grep "^$status" | awk -F " " '{print $2}' | sort -u > $INTERINITFOLDER/urls-status-$status.txt ; done
	cat $INTERINITFOLDER/urls-status-200.txt | aquatone -screenshot-timeout 120000 -threads 50 -http-timeout 120000 --scan-timeout 120000 -out $INTERSCREENSHOTFOLDER &> $INTERDEBUGFOLDER/screenshot-output.txt
	endscreenshotprocess=`date +%s`
	echo -e "\e[32m--------- Ended HTTP screenshot process\e[0m"
	displaytime `expr $endscreenshotprocess - $startscreenshotprocess`
	echo "Execution time of HTTP screenshot process was$timecalc."
}

function bypass403() {
	echo -e "\e[32m--------- Starting bypass 403 status urls process\e[0m"
	echo "This is to try some known bypasses of 403 fuzzing with some bypasses"
	startbyp4xxprocess=`date +%s`
	for url in $(cat $INTERINITFOLDER/urls-status-403.txt); do byp4xx -c $url > $INTERBYP4XXFOLDER/byp4xx-$(echo $url | sed 's/\//-/g' | sed 's/:/-/g').txt ; done >& $INTERDEBUGFOLDER/byp4xx-output.txt
	endbyp4xxprocess=`date +%s`
	echo -e "\e[32m--------- Ended bypass 403 urls prcess \e[0m"
	displaytime `expr $endbyp4xxprocess - $startbyp4xxprocess`
	echo "Execution time of bypass process was$timecalc."
}

function servicesparsing() {
	echo -e "\e[32m--------- Starting services parsing process\e[0m"
	echo "This is to parse the services found by nmap and make readable output"
	startservicesparsingprocess=`date +%s`
	uniqueservicestcp=$(cat $INTERNMAPFOLDER/nmap-tcp-target.gnmap | grep Ports: | sed 's/, /\n/g' | sed 's/.*Ports: //g' | awk -F'/' '{print $5}' | sort -u)
	for host in $(cat $INTERNMAPFOLDER/nmap-tcp-target.gnmap | grep Ports: | awk -F' ' '{print $2}'); do cat $INTERNMAPFOLDER/nmap-tcp-target.gnmap | grep $host | grep Ports | sed -e 's/.*Ports: //g' -e 's/, /\n/g' | sed -e s/^/$host,/g -e 's/\/open\/tcp\/\//,/g' -e 's/\/\//,/g' -e 's/\/$//g' | sed -e "s/\/        Ignored State:.*//g" >> $INTERINITFOLDER/full-nmap-parsed-tcp.txt ; done
	uniqueservicesudp=$(cat $INTERNMAPFOLDER/nmap-udp-target.gnmap | grep Ports | sed 's/, /\n/g' | sed 's/.*Ports: //g' | awk -F'/' '{print $5}' | sed 's/|/-/g' | sort -u)
    for host in $(cat $INTERNMAPFOLDER/nmap-udp-target.gnmap | grep Ports: | awk -F' ' '{print $2}'); do cat $INTERNMAPFOLDER/nmap-udp-target.gnmap | grep $host | grep Ports | sed -e 's/.*Ports: //g' -e 's/, /\n/g' | sed -e s/^/$host,/g -e 's/\/[a-z]*\/udp\/\//,/g' -e 's/\/\//,/g' -e 's/\/$//g' | sed -e "s/\/        Ignored State:.*//g" >> $INTERINITFOLDER/full-nmap-parsed-udp.txt ; done
	#for i in $(ls $INTERNMAPFOLDER/); do portsandservices=$(cat $INTERNMAPFOLDER/$i | grep 'service name=\"' | sed 's/.*portid="//g' | sed 's/".*service name=\"/,/g' | sed 's/" product="/,/g' | sed 's/" version="/,version /g' | sed 's/" extrainfo="/ /g'  | sed 's/" method="/,method /g' | sed 's/" conf="/,conf /g' | sed 's/".*//g'); uniqueservices=$(echo "$portsandservices" | awk -F ',' '{print $2}' | awk -F' ' '{print $1}' | sort -u); for service in $(echo "$uniqueservices"); do echo "$portsandservices" | grep ",$service$\|,$service," | awk -F ',' -v ip=$(echo $i | sed 's/.xml//g') '{print ip","$1","$2","$3","$4","$5}' >> $INTERSERVICESFOLDER/$service-service.txt; done ;done
	for servicetcp in $(echo $uniqueservicestcp); do cat $INTERINITFOLDER/full-nmap-parsed-tcp.txt | grep ",$servicetcp," >> $INTERSERVICESFOLDER/tcp-$(echo $servicetcp | sed 's/|/-/g' | tr -d '?')-service.txt; done
	for serviceudp in $(echo $uniqueservicesudp); do cat $INTERINITFOLDER/full-nmap-parsed-udp.txt | grep ",$serviceudp," >> $INTERSERVICESFOLDER/udp-$(echo $serviceudp | sed 's/|/-/g' | tr -d '?')-service.txt; done
	echo "Review services output in $INTERSERVICESFOLDER folder"
	endservicesparsingprocess=`date +%s`
	echo -e "\e[32m--------- Ended services parsing process\e[0m"
	displaytime `expr $endservicesparsingprocess - $startservicesparsingprocess`
	echo "Execution time of service parsing proces was$timecalc."

}

function cvescan() {
        echo -e "\e[32m--------- Starting scancves process\e[0m"
	echo "This is to retrieve the possible CVEs that some services are vulnerable"
	#echo -e "\e[96mChoose min cvss to vulnerability scan: (Press enter = default 5.0)\e[0m"
	#read mincvss
	#mincvss=${mincvss:-5.0}
	startcveprocess=`date +%s`
	#sudo interlace -tL $INTERINITFOLDER/targets.txt -threads 20 -c " if [[ \"\$(grep \"_target_,\" $INTERSERVICESFOLDER/* -h | awk -F ',' '{print \$2}' | tr '\n' ',' | sed 's/,\$//g')\" != \"\" ]]; then nmap -sSV --script vulners --script-args=mincvss=$mincvss -T4 -Pn --open -p\$(grep \"_target_,\" $INTERSERVICESFOLDER/* -h | awk -F ',' '{print \$2}' | tr '\n' ',' | sed 's/,\$//g') _target_ -oN $INTERCVEFOLDER/_target_.txt ; fi" &> $INTERDEBUGFOLDER/interlace-cve-output.txt
	for host in $(cat $INTERNMAPFOLDER/nmap-tcp-target.gnmap | grep Ports: | awk -F' ' '{print $2}'); do if [[ "$(grep "$host," $INTERSERVICESFOLDER/tcp* -h | awk -F ',' '{print $2}' | tr '\n' ',' | sed 's/,$//g')" != "" ]]; then sudo nmap -sSV -A -T4 --max-retries 3 --min-parallelism 100 --min-hostgroup 256 -Pn --open -p$(grep "$host," $INTERSERVICESFOLDER/tcp* -h | awk -F ',' '{print $2}' | tr '\n' ',' | sed 's/,$//g') $host -oN $INTERCVEFOLDER/$host-tcp-scripts-nmap.txt; fi; done &> $INTERDEBUGFOLDER/nmap-tcp-cve-output.txt
	for host in $(cat $INTERNMAPFOLDER/nmap-udp-target.gnmap | grep Ports: | awk -F' ' '{print $2}'); do if [[ "$(grep "$host," $INTERSERVICESFOLDER/udp* -h | awk -F ',' '{print $2}' | tr '\n' ',' | sed 's/,$//g')" != "" ]]; then sudo nmap -sUV -A -F --min-parallelism 100 --host-timeout 5m --version-intensity 0 -Pn --open -p$(grep "$host," $INTERSERVICESFOLDER/udp* -h | awk -F ',' '{print $2}' | tr '\n' ',' | sed 's/,$//g') $host -oN $INTERCVEFOLDER/$host-udp-scripts-nmap.txt; fi; done &> $INTERDEBUGFOLDER/nmap-udp-cve-output.txt
	endcveprocess=`date +%s`
	echo -e "\e[32m--------- Ended cve scan process\e[0m"
	displaytime `expr $endcveprocess - $startcveprocess`
	echo "Execution time of cve recon process was$timecalc."
}
function smbversion() {
	rhost=$1
	sudo tcpdump -s0 -n -i tun0 src $rhost and port 139 -A -c 10 2>/dev/null | grep -i "samba\|s.a.m\|pipe" | sed 's/\.\.\./\-/g' | tr -d '.' | sed 's/\([0-9]\)\-/\1\./g' | sed 's/\([0-9]\)\.\([a-zA-Z]\)/\1\-\2/g' | sed 's/\-/ /g' | sed 's/  /\n/g' | sed 's/^[ ]*//g' | sort -u & echo -n "$rhost: " &
	echo "exit" | smbclient -L $rhost 1>/dev/null 2>/dev/null
	echo "" && sleep 2
}
function smbscan() {
	echo -e "\e[32m--------- Starting samba scan process\e[0m"
	echo "This is to retrieve samba related version and information (sudo needed for tcpdump)"
	startsmbprocess=`date +%s`
	smb139hosts=$(cat $INTERSERVICESFOLDER/tcp-*-service.txt | grep ",139," | awk -F',' '{print $1}' | sort -u)
	smb445hosts=$(cat $INTERSERVICESFOLDER/tcp-*-service.txt | grep ",445," | awk -F',' '{print $1}' | sort -u)
	if [[ "$smb139hosts" != "" ]]; then
		for smb139host in $(echo $smb139hosts); do smbversion $smb139host > $INTERSMBFOLDER/smbversion/$smb139host-smbversion.txt ; done &> $INTERDEBUGFOLDER/smb-139-output.txt
	fi
	if [[ "$smb445hosts" != "" ]]; then
		for smb445host in $(echo $smb445hosts); do smbmap -u '' -p '' -H $smb445host > $INTERSMBFOLDER/smbmap/$smb445host-smbmap.txt ; enum4linux -U -S -G -P -o -n -i -l $smb445host > $INTERSMBFOLDER/enum4linux/$smb445host-enum4linux.txt ; done &> $INTERDEBUGFOLDER/smb-445-output.txt
	fi
	endsmbprocess=`date +%s`
	echo -e "\e[32m--------- Ended smb scan process\e[0m"
	displaytime `expr $endsmbprocess - $startsmbprocess`
	echo "Execution time of smb recon process was$timecalc."
}

function dnsscan() {
	echo -e "\e[32m--------- Starting dns scan process\e[0m"
	echo "This is to retrieve dns related version and information"
	startdnsprocess=`date +%s`
	dnshosts=$(cat $INTERSERVICESFOLDER/*-service.txt | grep ",53," | awk -F',' '{print $1}' | sort -u)
	cd $INTERINITFOLDER 
	if [[ "$dnshosts" != "" ]]; then
		for dnshost in $(echo $dnshosts)
		do 
			smb445hosts=$(cat $INTERSERVICESFOLDER/tcp-*-service.txt | grep $dnshost | grep ",445," | awk -F',' '{print $1}' | sort -u)
			ldap389=$(cat $INTERSERVICESFOLDER/tcp-*-service.txt | grep $dnshost | grep ",389," | awk -F',' '{print $1}' | sort -u)
			dnsnames=$(echo $(dig -x $dnshost @$dnshost | grep PTR | awk -F 'PTR' '{print $2}' | tr -d '     ' | sed 's/\.$//g' | grep [a-zA-Z0-9])","$(host $dnshost | grep -v "not found" | awk -F ' ' '{print $5}' | sed 's/\.$//g' | grep [a-zA-Z0-9]))
			if [[ "$smb445hosts" != "" ]]; then 
				dnsnames=$(echo $(crackmapexec smb $dnshost | sed -e s/.*name://g -e s/\).*\(domain:/,/g -e s/\).*//g)","$(crackmapexec smb $dnshost | sed -e s/.*name://g -e s/\).*\(domain:/./g -e s/\).*//g)","$dnsname)
			fi
			if [[ "$ldap389" != "" ]]; then
                                dnsnames=$(echo $(crackmapexec smb $dnshost | sed -e s/.*name://g -e s/\).*\(domain:/,/g -e s/\).*//g)","$(crackmapexec smb $dnshost | sed -e s/.*name://g -e s/\).*\(domain:/./g -e s/\).*//g)","$dnsnames)
			fi
			dnsnames=$(echo $dnsnames | sed 's/,/\n/g' | grep [a-zA-Z0-9] | grep -v "NXDOMAIN" | sort -u)
			if [[ "$dnsnames" != "" ]]; then
				for dnsname in $dnsnames
				do
					dnsrecon -d $dnsname -t axfr -n $dnshost > $INTERDNSFOLDER/dnsrecon/$dnshost-$dnsname-dnsrecon.txt
				done &> $INTERDEBUGFOLDER/dnsrecon-output.txt
			fi
		done
	fi
	cd ..
	enddnsprocess=`date +%s`
	echo -e "\e[32m--------- Ended dns scan process\e[0m"
        displaytime `expr $enddnsprocess - $startdnsprocess`
	echo "Execution time of dns recon process was$timecalc."
}

function makedocu() {
	echo -e "\e[32m--------- Making documentation files\e[0m"
	if [[ ! -d $INTERDOCUFOLDER ]]; then
		mkdir $INTERDOCUFOLDER
	else
		echo "Documentation folder exist"
	fi
	hosts=$(cat $INTERNMAPFOLDER/nmap-*-target.gnmap | grep Ports: | awk -F' ' '{print $2}' | sort -u)
	if [[ $hosts == "" ]]; then
		echo '### Target\n
No open ports found' > $INTERDOCUFOLDER/Target.md
	fi
	if [[ ! -d $INTERDOCUFOLDER/evidences/ ]]; then
		mkdir $INTERDOCUFOLDER/evidences/
	else
		echo "Evidence folder exist"
	fi
	for host in $hosts; do
		if [[ ! -d $INTERDOCUFOLDER/evidences/$host ]]; then
	        	mkdir $INTERDOCUFOLDER/evidences/$host
		else
			echo "Evidence host folder exist"
		fi
		echo -e '### '$host'\n' >> $INTERDOCUFOLDER/$host.md
		echo -e '## Virtual Servers - Domains related\n' >> $INTERDOCUFOLDER/$host.md
		if [[ -f $INTERINITFOLDER/ips-with-domains.txt ]]; then
			cat $INTERINITFOLDER/ips-with-domains.txt | grep $host | sed 's/,/\n/g' | sort -u >> $INTERDOCUFOLDER/$host.md
			echo -e '\n' >> $INTERDOCUFOLDER/$host.md
		else
			echo -e 'No domains found for this IP\n' >> $INTERDOCUFOLDER/$host.md
		fi
		echo -e '## Script execution comprobation\n' >> $INTERDOCUFOLDER/$host.md
		if [[ -f $INTERINITFOLDER/aux/wfuzz-skipped-urls.txt ]]; then
			echo -e 'Seems that there were some connection errors on the fuzzing part, we will need to make a manual execution on:\n' >> $INTERDOCUFOLDER/$host.md
			cat $INTERINITFOLDER/aux/wfuzz-skipped-urls.txt >> $INTERDOCUFOLDER/$host.md
			echo -e '\nwfuzz --efield url -t 40 --filter "not (c=BBB and l=BBB and w=BBB)" -w {INSERT Dictionary path} --zE urlencode -f $(pwd)/domain-or-ip-name.txt -Z -L {INSERT URL}"FUZZ{asdfnottherexxxasdf}"\n' >> $INTERDOCUFOLDER/$host.md
		else
			echo -e 'Script execution seems correct\n' >> $INTERDOCUFOLDER/$host.md
		fi
		echo -e '## Credentials\n
## Ports open\n
> TCP\n' >> $INTERDOCUFOLDER/$host.md
		if [[ $INTERSCANTYPE == "vuln" || $INTERSCANTYPE == "all" ]]; then
			if [[ -f $INTERINITFOLDER/full-nmap-parsed-tcp.txt ]]; then

			        cat $INTERINITFOLDER/full-nmap-parsed-tcp.txt | grep $host >> $INTERDOCUFOLDER/$host.md
			else
				echo "No TCP ports found on host $host"
				echo -e "No TCP ports found on host $host"
			fi
		fi
		echo -e '\n
> UDP\n' >> $INTERDOCUFOLDER/$host.md
		if [[ $INTERSCANTYPE == "vuln" || $INTERSCANTYPE == "all" ]]; then
			if [[ -f $INTERINITFOLDER/full-nmap-parsed-udp.txt ]]; then
				cat $INTERINITFOLDER/full-nmap-parsed-udp.txt | grep $host >> $INTERDOCUFOLDER/$host.md
			else
				echo "No UDP ports found on host $host"
				echo -e "No UDP ports found on host $host"
			fi
		fi
		echo -e '\n
## Gaining access\n' >> $INTERDOCUFOLDER/$host.md
		if [[ $INTERSCANTYPE == "vuln" || $INTERSCANTYPE == "all" ]]; then
			cat $INTERSERVICESFOLDER/*-service.txt | grep $host | awk -F ',' '{print "> " $3 " service" }' | sort -u >> $INTERDOCUFOLDER/$host.md
		fi
		echo -e '\n
## Privesc\n
## Postexplotation\n
> Local Hashes\ncat /etc/shadow or cat /etc/passwd\nSAM dump + lsa\n
> Users folder\nls -lahR /home\n
> Netstat\nnetstat -anopl\nnetstat -anobl\n
> Network interfaces\nifconfig\nipconfig\n
> SSH keys\nfind / | grep "\.ssh/"\n
> Database information\n
> Browser information if GUI\n
> Credentials on files/proofs.txt\n
' >> $INTERDOCUFOLDER/$host.md
	done
}

function vulnscan() {
	echo -e "\e[35mStarting vulnerability scan and service parsing processes\e[0m"
	echo "We are going to parse the services and execute nmap vulners and openvas to those services to retrieve vulnerabilities"
	startvulnprocess=`date +%s`
	if [ ! -d "$INTERNMAPFOLDER" ]; then
		echo -e "\e[33m[WARNING] - NMAP folder $INTERNMAPFOLDER doesn't exist, we will execute first a portscan to get NMAP.\e[0m"
		mkdir $INTERNMAPFOLDER
		portscan
	fi
	if [ -d "$INTERSERVICESFOLDER" ]; then
		echo -e "\e[33m[WARNING] - SERVICES scan folder $INTERSERVICESFOLDER exist.\e[0m"
		echo -e "\e[96mDo you want to skip servicesparsing? ([y] default/[n]):\e[0m"
		read skipservicesparsing
		if [ "$skipservicesparsing" == "n" ]; then
			echo "Restarting from services parsing"
			rm -rf $INTERSERVICESFOLDER
			mkdir $INTERSERVICESFOLDER
			servicesparsing
			rm -rf $INTERCVEFOLDER
			mkdir $INTERCVEFOLDER
			cvescan
			endvulnprocess=`date +%s`
			echo -e "\e[35mEnded vulnscan processes\e[0m"
			displaytime `expr $endvulnprocess - $startvulnprocess`
			echo "Execution time of vulnscan recon processes was$timecalc."
			return
		else
			echo "Skipping services parsing"
		fi
	else
		mkdir $INTERSERVICESFOLDER
		servicesparsing
	fi
	if [[ "$(cat $INTERSERVICESFOLDER/tcp-*-service.txt | grep ",445,\|,139,")" != "" ]]; then
		if [ -d "$INTERSMBFOLDER" ]; then
                	echo -e "\e[33m[WARNING] - SMB scan folder $INTERSMBFOLDER exist.\e[0m"
                	echo -e "\e[96mDo you want to skip smbscan? ([y] default/[n]):\e[0m"
                	read skipsmbscan
                	if [ "$skipsmbscan" == "n" ]; then
                        	echo "Restarting from smb scan"
                        	rm -rf $INTERSMBFOLDER
				mkdir $INTERSMBFOLDER
				mkdir $INTERSMBFOLDER/smbmap
				mkdir $INTERSMBFOLDER/smbversion
				mkdir $INTERSMBFOLDER/enum4linux
				smbscan
			else
				echo "Skipping smb scan"
			fi
		else
			mkdir $INTERSMBFOLDER
			mkdir $INTERSMBFOLDER/smbmap
                	mkdir $INTERSMBFOLDER/smbversion
                	mkdir $INTERSMBFOLDER/enum4linux
			smbscan
		fi
	else 
		echo -e "\e[33m[WARNING] - No port 445,139 found in nmap scan process.\e[0m"
                echo "Skipping processes dependents of default SMB ports"
	fi
	if [[ "$(cat $INTERSERVICESFOLDER/tcp-*-service.txt | grep ",53,")" != "" ]]; then
		if [ -d "$INTERDNSFOLDER" ]; then
                        echo -e "\e[33m[WARNING] - DNS san folder $INTERDNSFOLDER exist.\e[0m"
                        echo -e "\e[96mDo you want to skip dnsscan? ([y] default/[n]):\e[0m"
                        read skipdnsscan
                        if [ "$skipdnsscan" == "n" ]; then
                                echo "Restarting from dns scan"
                                rm -rf $INTERDNSFOLDER
                                mkdir $INTERDNSFOLDER
				mkdir $INTERDNSFOLDER/dnsrecon
				dnsscan
			else
				echo "Skipping dns scan"
			fi
		else
			mkdir $INTERDNSFOLDER
                        mkdir $INTERDNSFOLDER/dnsrecon
			dnsscan
		fi		
	else
		echo -e "\e[33m[WARNING] - No port 53 found in nmap scan process.\e[0m"
		echo "Skipping processes dependents of default DNS ports"
	fi
	if [ -d "$INTERCVEFOLDER" ]; then
                echo -e "\e[33m[WARNING] - CVE scan folder $INTERCVEFOLDER exist.\e[0m"
                echo -e "\e[96mDo you want to skip cvescan? ([y] default/[n]):\e[0m"
                read skipcvescan
                if [ "$skipcvescan" == "n" ]; then
                        echo "Restarting from cve scan"
                        rm -rf $INTERCVEFOLDER
                        mkdir $INTERCVEFOLDER
                        cvescan
                else
                        echo "Skipping cve scan"
                fi
        else
                mkdir $INTERCVEFOLDER
                cvescan
        fi
	endvulnprocess=`date +%s`
	echo -e "\e[35mEnded vulnscan processes\e[0m"
	displaytime `expr $endvulnprocess - $startvulnprocess`
	echo "Execution time of vulnscan recon processes was$timecalc."
}

function webscan(){
	echo -e "\e[35mStarting webscan processes\e[0m"
	echo "We are going to execute nmap and parse them, make fuzzing and make screenshots to review"
	echo "All processes execution will be inserted to debug folder"
	startwebprocess=`date +%s`
	if [ ! -d "$INTERNMAPFOLDER" ]; then
		echo -e "\e[33m[WARNING] - NMAP folder $INTERSERVICESFOLDER doesn't exist, we will execute first a portscan to get NMAP.\e[0m"
		mkdir $INTERNMAPFOLDER
		portscan
	fi
	if [ -d "$INTERDISCOVERHTTPFOLDER" ]; then
		echo -e "\e[33m[WARNING] - Initial http discovery from nmap folder $INTERDISCOVERHTTPFOLDER exist.\e[0m"
		echo -e "\e[96mDo you want to skip initial http discovery? ([y] default/[n]):\e[0m"
		read skipinitialhttpdiscoveryscan
		if [ "$skipinitialhttpdiscoveryscan" == "n" ]; then
			echo "Restarting from initial http discovery scan process"
			initialhttpdiscoveryscan
			fuzzingscan
			screenshotscan
			endwebprocess=`date +%s`
			echo -e "\e[35mEnded web recon process\e[0m"
			displaytime `expr $endwebprocess - $startwebprocess`
			echo "Execution time of web recon process was$timecalc."
			return
		else
			echo "Skipping initial http discovery scan"
		fi
	else
		mkdir $INTERDISCOVERHTTPFOLDER
		initialhttpdiscoveryscan
	fi
	if [[ "$(cat $INTERINITFOLDER/full-initial-files.txt)" != "" ]]; then
		if [ -d "$INTERFUZZINGFOLDER" ]; then
			echo -e "\e[33m[WARNING] - Fuzzing scan folder $INTERFUZZINGFOLDER exist.\e[0m"
			echo -e "\e[96mDo you want to skip fuzzingscan? ([y] default/[n]):\e[0m"
			read skipfuzzingscan
			if [ "$skipfuzzingscan" == "n" ]; then
				echo "Restarting from fuzzing scan process"
				fuzzingscan
				screenshotscan
				endwebprocess=`date +%s`
				echo -e "\e[35mEnded web recon process\e[0m"
				displaytime `expr $endwebprocess - $startwebprocess`
				echo "Execution time of web recon process was$timecalc."
				return
			else
				echo "Skipping fuzzing scan"
			fi
		else
			fuzzingscan
		fi
		if [ -d "$INTERSCREENSHOTFOLDER" ]; then
			echo -e "\e[33m[WARNING] - Final screenshot scan folder $INTERSCREENSHOTFOLDER exist.\e[0m"
			echo -e "\e[96mDo you want to skip screenshotscan? ([y] default/[n]):\e[0m"
			read skipscreenshotscan
			if [ "$skipscreenshotscan" == "n" ]; then
				echo "Restarting final screenshot scan"
				screenshotscan
			else
				echo "Skipping screenshot scan"
			fi
		else
			screenshotscan
		fi
		if [ -d "$INTERBYP4XXFOLDER" ]; then
			echo -e "\e[33m[WARNING] - byp4xx output folder exist.\e[0m"
			echo -e "\e[96mDo you want to skip byp4xx process? ([y] default/[n]):\e[0m"
                	read skipbyp4xx
			if [ "$skipbyp4xx" == "n" ]; then
                        	echo "Restarting bypass scan"
				if [ -f "$INTERINITFOLDER/urls-status-403.txt" ]; then
					mkdir $INTERBYP4XXFOLDER
					bypass403
				fi
			else
				echo "Skipping bypass 403 urls scan"
			fi
		else
			if [ -f "$INTERINITFOLDER/urls-status-403.txt" ]; then
				mkdir $INTERBYP4XXFOLDER
                		bypass403
        		fi

		fi
	else
		echo -e "\e[33m[WARNING] - No HTTP/S URL found in initial http discovery process.\e[0m"
		echo "Skipping processes dependents of initial http discovery process"
	fi
	endwebprocess=`date +%s`
	echo -e "\e[35mEnded web recon process\e[0m"
	displaytime `expr $endwebprocess - $startwebprocess`
        echo "Execution time of web recon process was$timecalc."
}

function scanall() {
	echo -e "\e[35mStarting web and vulnerability recon process\e[0m"
	startallprocess=`date +%s`
	if [ -d "$INTERNMAPFOLDER" ]; then
		echo -e "\e[33m[WARNING] - Port Scan folder $INTERNMAPFOLDER exist.\e[0m"
		echo -e "\e[96mDo you want to restart all the processes? ([y] perform new nmap restarting all processes/[n] default, continue with old nmap):\e[0m"
		read skipportscan
		if [ "$skipportscan" == "y" ]; then
			echo "Restarting all processes with new nmap"
			rm -rf $INTERINITFOLDER
			mkdir $INTERINITFOLDER
			mkdir $INTERDEBUGFOLDER
			mkdir $INTERAUXFOLDER
			mkdir $INTERNMAPFOLDER
			portscan
		else
			echo "Continuing processes with old nmap"
		fi
	else
		mkdir $INTERNMAPFOLDER
		portscan
	fi
	vulnscan
	webscan
	endallprocess=`date +%s`
	echo -e "\e[35mEnded all processes\e[0m"
	displaytime `expr $endallprocess - $startallprocess`
	echo "Execution time of web and vulns recon process was$timecalc."
}

function followingsteps() {
	echo '[INFO EXTRA] - Remember to check the following things depending of your scan:'
	echo '   - (VULNSCAN) The services folder (Check vulnerable versions in searchsploit and google)'
	echo '   - (VULNSCAN) The cve folder (Check known exploits from nmap scripts)'
	echo '   - (VULNSCAN) The smb folder (Check smbmap guest execution file, smbversion execution file and enum4linux execution file)'
	echo '   - (VULNSCAN) Check services that you don"t know the version on nmap using netcat or other way (Sometimes the version can"t be retrieved with nmap)'
	echo '   - (VULNSCAN) If you have a known user, execute smbmap and enum4linux with -u {user} -p {password}'
	echo '   - (WEBSCAN) The screenshot folder (Check the different http services)'
        echo '   - (WEBSCAN) The files with name url-status-{200,401,403,etc}.txt (We only perform status 200 screenshot and on other status maybe there is something new)'
	echo '   - (WEBSCAN) Fuzz paths in url-status-*.txt files (You can see other services/files inside first path with information)'
	echo '   - (WEBSCAN) Try bruteforce credentials on some login pages (Check status 200, 401, 403)'
	echo '============================================================================'
}
while getopts "hd:T:t:w:s:a" OPTION
do
     case $OPTION in
         h)
             scripthelp
             exit 1
             ;;
         a)
             INTERSUPERAUTOMATICSCAN=$OPTARG
             ;;
         d)
	     INTERINITFOLDER=$OPTARG
	     ;;
         T) 
	     INTERTARGETFILE=$OPTARG
	     ;;
         t)
             INTERTARGET=$OPTARG
             ;;
         w)
             INTERDICT=$OPTARG
             ;;
         s)
             INTERSCANTYPE=$OPTARG
             ;;
     esac
done
if ([[ ! -z $INTERTARGET ]] && [[ !  -z $INTERDICT ]] && [[ !  -z $INTERSCANTYPE ]]) || ([[ ! -z $INTERTARGETFILE ]] && [[ ! -z $INTERDICT ]] && [[ ! -z $INTERSCANTYPE ]] && [[ ! -z $INTERINITFOLDER ]]); then
	re='^(0*(1?[0-9]{1,2}|2([0-4][0-9]|5[0-5]))\.){3}.[0-2]?[0-9]|'
	re+='0*(1?[0-9]{1,2}|2([0-4][0-9]|5[0-5]))$'
#	re2='^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6}$'
	#re2='^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$'
	re2='^[A-Za-z0-9\-\.]+'

	if [[ ! -z $INTERTARGET ]]; then
		if [[ ! "$INTERTARGET" =~ $re ]] && [[ ! "$INTERTARGET" =~ $re2 ]]; then
			echo -e "\e[91mERROR:    Parameter -t should be an IP or IP/CIDR\e[0m"
			scripthelp
			exit 1
		fi
	fi
	if [ ! -f $INTERDICT ]; then
		echo -e "\e[91mERROR:	Parameter -w, dictionary file not found\e[0m"
		scripthelp
		exit 1
	fi
	if [ "$INTERSCANTYPE" != "all" ] && [ "$INTERSCANTYPE" != "web" ] && [ "$INTERSCANTYPE" != "vuln" ]; then
		echo -e "\e[91mERROR:	Parameter -s, scan type must be all, web, vuln\e[0m"
		scripthelp
		exit 1
	fi
	if [[ ! -z $INTERTARGETFILE ]]; then
	       if [ ! -f $INTERTARGETFILE ]; then
		       echo -e "\e[91mERROR:   Parameter -T , target file not found\e[0m"
		       scripthelp
		       exit 1
	       fi
	fi
	initvariables
	initfolders
	case $INTERSCANTYPE in
		all)
			scanall
			makedocu
			followingsteps
			exit 1
			;;
		web)
			webscan
			makedocu
			followingsteps
			exit 1
			;;
		vuln)
			vulnscan
			makedocu
			followingsteps
			exit 1
			;;
	esac
	exit 1
else
	scripthelp
	exit 1
fi
