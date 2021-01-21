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
	INTEREYEWITNESSFOLDER=$INTERINITFOLDER/screenshots
	INTERCVEFOLDER=$INTERINITFOLDER/cve
	INTERAUXFOLDER=$INTERINITFOLDER/aux
	INTERSERVICESFOLDER=$INTERINITFOLDER/services
	INTERBYP4XXFOLDER=$INTERINITFOLDER/bypass
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
	echo "		inter-recon -t 127.0.0.1 -w \$(pwd)/dict.txt -s all -a"
	echo "		inter-recon -T targets.txt -d \$(pwd)/domains -w \$(pwd)/dict.txt -s all -a"
	echo "[INFO] - '-w' (I recommend you that if you have a lot of web services and low time use the /dictionaries/common.txt at least to start)"
	echo "[INFO] - '-a' is for super automatic scan skipping all skipable and not asking anything, just executing all without configuration and neither re-execution of anything"
	echo "[INFO] - '-d' and '-w' must be a full static path ex: /tmp/recon"
}

function portscan() {
	echo -e "\e[32m--------- Starting nmap interlace process\e[0m" 
	echo "This is to retrieve all ports with version (sudo required for nmap -sSV scan)"
	startallprocess=`date +%s`
	#Nmap
	if [[ ! -z $INTERTARGETFILE ]]; then
		cp $INTERTARGETFILE $INTERINITFOLDER/targets.txt
	else
		echo $INTERTARGET > $INTERINITFOLDER/targets.txt
	fi
	startinterlaceprocess=`date +%s`
	sudo interlace -tL $INTERINITFOLDER/targets.txt -threads 100 -c "nmap -sSV -T4 -PS22,53,80,135,443,445,993,995,1521,3306,3389,5985,5986,8080,8081,8090,9001,9002 -oX - --open -p- _target_ > $INTERNMAPFOLDER/_target_.xml" &> $INTERDEBUGFOLDER/interlace-output.txt
	endinterlaceprocess=`date +%s`
	echo -e "\e[32m--------- Ended nmaps using interlace process\e[0m"
	displaytime `expr $endinterlaceprocess - $startinterlaceprocess`
	echo "Execution time of all nmaps using interlace process was$timecalc."
	#Export all ports to file to postprocess (we might remove this because Adan have another script that can take open ports and we might reutilize this instead of metasploit output)
	#echo 'Starting msfconsole retrieve all-ports from nmap process'
	#startmsfconsoleprocess=`date +%s`
	#msfconsole -x "workspace -a auxiliary; db_import $INTERNMAPFOLDER/*.xml; services -o $INTERINITFOLDER/all-ports.txt; workspace -d auxiliary; exit" -q &> $INTERDEBUGFOLDER/msfconsole-output.txt
	#endmsfconsoleprocess=`date +%s`
	#echo 'Ended msfconsole process'
	#echo Execution time of msfconsole process was `expr $endmsfconsoleprocess - $startmsfconsoleprocess` seconds.
}

function initialaquatonescan() {
	echo -e "\e[32m--------- Starting aquatone process\e[0m" 
	echo "This is to retrieve valid http URLs from nmap files"
	startaquatoneprocess=`date +%s`
	if [ -d "$INTERAUXFOLDER/nmap" ]; then
		echo -e "\e[33mFound previous not ended aquatone process execution\e[0m"
		echo -e "\e[96mDo you want to continue from previous execution? ([n]/[y] default):\e[0m"
		read continuepreviousaquatone
		if [ "$continuepreviousaquatone" == "n" ]; then
			echo "Restarting initial aquatone scan from start"
			cp -r $INTERNMAPFOLDER $INTERAUXFOLDER/nmap
			rm -f $INTERINITFOLDER/aquatone-full-initial-files.txt
		else
			echo "Continuing from previous initial aquatone scan execution"
		fi
	else
		cp -r $INTERNMAPFOLDER $INTERAUXFOLDER/nmap
		if [ -f "$INTERINITFOLDER/aquatone-full-initial-files.txt" ]; then
			rm -f $INTERINITFOLDER/aquatone-full-initial-files.txt
		fi
	fi
	for i in $(ls $INTERAUXFOLDER/nmap); do cat $INTERAUXFOLDER/nmap/$i | aquatone -nmap -screenshot-timeout 120000 -threads 4 -http-timeout 120000 --scan-timeout 120000 -out $INTERDISCOVERHTTPFOLDER/$(echo $i | sed 's/.xml//g'); cat $INTERDISCOVERHTTPFOLDER/$(echo $i | sed 's/.xml//g')/aquatone_urls.txt >> $INTERINITFOLDER/aquatone-full-initial-files.txt ; rm $INTERAUXFOLDER/nmap/$i ;done &> $INTERDEBUGFOLDER/aquatone-initial-files-output.txt
	rm -rf $INTERAUXFOLDER/nmap
	endaquatoneprocess=`date +%s`
	echo -e "\e[32m--------- Ended aquatone initial files process\e[0m"
	displaytime `expr $endaquatoneprocess - $startaquatoneprocess`
	echo "Execution time of aquatone initial files process was$timecalc."
}

function fuzzingscan() {
	echo -e "\e[32m--------- Starting wfuzz process\e[0m"
	echo "This is to retrieve new paths from URLs found by nmap and aquatone"
	startwfuzzprocess=`date +%s`
	if [ -f "$INTERAUXFOLDER/aquatone-full-initial-files.txt" ]; then
		echo -e "\e[33mFound previous not ended fuzzing process execution\e[0m"
		echo -e "\e[96mDo you want to continue from previous execution? ([n]/[y] default):\e[0m"
		read continuepreviousfuzzing
		if [ "$continuepreviousfuzzing" == "n" ]; then
			echo "Restarting fuzzing execution from start"
			cp $INTERINITFOLDER/aquatone-full-initial-files.txt $INTERAUXFOLDER/aquatone-full-initial-files.txt
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
					cat $INTERAUXFOLDER/wfuzz-skipped-urls.txt | sort -u >> $INTERAUXFOLDER/aquatone-full-initial-files.txt
				fi
			fi
		fi
	else
		cp $INTERINITFOLDER/aquatone-full-initial-files.txt $INTERAUXFOLDER/aquatone-full-initial-files.txt

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
			for i in $(cat $INTERAUXFOLDER/aquatone-full-initial-files.txt); do wfuzz --conn-delay 10 --req-delay 10 --efield url -t 40 --filter "$INTERFUZZFILTER" -w $INTERDICT --zE urlencode -f $INTERFUZZINGFOLDER/$(echo $i | sed 's/\//-/g' | sed 's/:/-/g').txt -L $i"FUZZ{asdfnottherexxxasdf}" &>> $INTERDEBUGFOLDER/wfuzz-output.txt ; totalreq=$(cat  $INTERFUZZINGFOLDER/$(echo $i | sed 's/\//-/g' | sed 's/:/-/g').txt| grep "Total requests:" | awk -F":" '{print $2}' | sed 's/^ //g'); processedreq=$(cat  $INTERFUZZINGFOLDER/$(echo $i | sed 's/\//-/g' | sed 's/:/-/g').txt| grep "Processed Requests:" | awk -F":" '{print $2}' | sed 's/^ //g');if [[ `expr $(expr $totalreq + 1) - $processedreq` -gt 0  ]]; then echo -e "\e[33m[WARNING] - Found an error in $i URL. Review debug folder to see the error\e[0m"; echo "[INFO] - Skipping $i"; echo $i >> $INTERAUXFOLDER/wfuzz-skipped-urls.txt; fi; sed -i "/$(echo $i| sed 's/https*:\/\///g' | sed 's/\/$//g')/d" $INTERAUXFOLDER/aquatone-full-initial-files.txt ; sleep 10 ;done
			echo "Skipped URLs in $INTERAUXFOLDER/wfuzz-skipped-urls.txt"	
		else
			echo "You will be asked to skip an URL with error (Recommended when network or VPN issues (like time limit in VPN), and for big dictionaries)"
			for i in $(cat $INTERAUXFOLDER/aquatone-full-initial-files.txt); do wfuzz --efield url -t 40 --filter "$INTERFUZZFILTER" -w $INTERDICT --zE urlencode -f $INTERFUZZINGFOLDER/$(echo $i | sed 's/\//-/g' | sed 's/:/-/g').txt -L $i"FUZZ{asdfnottherexxxasdf}" &>> $INTERDEBUGFOLDER/wfuzz-output.txt ; totalreq=$(cat  $INTERFUZZINGFOLDER/$(echo $i | sed 's/\//-/g' | sed 's/:/-/g').txt| grep "Total requests:" | awk -F":" '{print $2}' | sed 's/^ //g'); processedreq=$(cat  $INTERFUZZINGFOLDER/$(echo $i | sed 's/\//-/g' | sed 's/:/-/g').txt| grep "Processed Requests:" | awk -F":" '{print $2}' | sed 's/^ //g');if [[ `expr $(expr $totalreq + 1) - $processedreq` -gt 0  ]]; then echo -e "\e[33m[WARNING] - Found an error in $i URL. Review debug folder to see the error\e[0m"; echo -e "\e[96mDo you want to skip this URL and continue? ([y] default/[n]):\e[0m"; read skipURL ; if [ "$skipURL" == "n" ]; then echo "We will stop the process here. To continue with the process, execute again the script, it will make fuzzing to the files not processed yet."; exit 1; else echo "[INFO] - Skipping $i"; echo $i >> $INTERAUXFOLDER/wfuzz-skipped-urls.txt;  fi ; fi; sed -i "/$(echo $i| sed 's/https*:\/\///g' | sed 's/\/$//g')/d" $INTERAUXFOLDER/aquatone-full-initial-files.txt ; sleep 10 ;done
		fi
	else
		for i in $(cat $INTERAUXFOLDER/aquatone-full-initial-files.txt); do wfuzz --conn-delay 10 --req-delay 10 --efield url -t 40 --filter "$INTERFUZZFILTER" -w $INTERDICT --zE urlencode -f $INTERFUZZINGFOLDER/$(echo $i | sed 's/\//-/g' | sed 's/:/-/g').txt -L $i"FUZZ{asdfnottherexxxasdf}" &>> $INTERDEBUGFOLDER/wfuzz-output.txt ; totalreq=$(cat  $INTERFUZZINGFOLDER/$(echo $i | sed 's/\//-/g' | sed 's/:/-/g').txt| grep "Total requests:" | awk -F":" '{print $2}' | sed 's/^ //g'); processedreq=$(cat  $INTERFUZZINGFOLDER/$(echo $i | sed 's/\//-/g' | sed 's/:/-/g').txt| grep "Processed Requests:" | awk -F":" '{print $2}' | sed 's/^ //g');if [[ `expr $(expr $totalreq + 1) - $processedreq` -gt 0  ]]; then echo -e "\e[33m[WARNING] - Found an error in $i URL. Review debug folder to see the error\e[0m"; echo "[INFO] - Skipping $i"; echo $i >> $INTERAUXFOLDER/wfuzz-skipped-urls.txt; fi; sed -i "/$(echo $i| sed 's/https*:\/\///g' | sed 's/\/$//g')/d" $INTERAUXFOLDER/aquatone-full-initial-files.txt ; sleep 10 ;done
		echo "Skipped URLs in $INTERAUXFOLDER/wfuzz-skipped-urls.txt"
	fi

	rm $INTERAUXFOLDER/aquatone-full-initial-files.txt
	endwfuzzprocess=`date +%s`
	echo -e "\e[32m--------- Ended wfuzz process\e[0m"
	displaytime `expr $endwfuzzprocess - $startwfuzzprocess`
	echo "Execution time of wfuzz process was$timecalc."
}

function screenshotscan() {
	echo -e "\e[32m--------- Starting eyewitness process\e[0m"
	echo "This is to make screenshots of all status 200 URLs found after fuzzing"
	starteyewitnessprocess=`date +%s`
	cat $INTERFUZZINGFOLDER/*.txt |grep "C=2" | grep http | awk -F "|" '{print $2}' | grep http | sed 's/^ //g' | sed 's/"//g' | sort -u > $INTERINITFOLDER/eyewitness-200-parsed-urls.txt
	cat $INTERFUZZINGFOLDER/*.txt | grep http | sed 's/.* C=//g' | sed 's/ .*|//g' | sed 's/"$//g' | grep -v "^Target: " | sort -u > $INTERINITFOLDER/all-urls-fuzzing-results.txt
	allstatus=$(cat $INTERINITFOLDER/all-urls-fuzzing-results.txt | awk -F " " '{print $1}' | sort -u)
	for status in $allstatus; do cat $INTERINITFOLDER/all-urls-fuzzing-results.txt | grep "^$status" | awk -F " " '{print $2}' | sort -u > $INTERINITFOLDER/urls-status-$status.txt ; done
	eyewitness -f $INTERINITFOLDER/eyewitness-200-parsed-urls.txt --jitter 1 -d $INTEREYEWITNESSFOLDER --timeout 60 --threads 10 --web --max-retries 1 --no-prompt >& $INTERDEBUGFOLDER/eyewitness-output.txt
	endeyewitnessprocess=`date +%s`
	echo -e "\e[32m--------- Ended eyewitness process\e[0m"
	displaytime `expr $endeyewitnessprocess - $starteyewitnessprocess`
	echo "Execution time of eyewitness process was$timecalc."
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
	for i in $(ls $INTERNMAPFOLDER/); do portsandservices=$(cat $INTERNMAPFOLDER/$i | grep 'service name=\"' | sed 's/.*portid="//g' | sed 's/".*service name=\"/,/g' | sed 's/" product="/,/g' | sed 's/" version="/,version /g' | sed 's/" extrainfo="/ /g'  | sed 's/" method="/,method /g' | sed 's/" conf="/,conf /g' | sed 's/".*//g'); uniqueservices=$(echo "$portsandservices" | awk -F ',' '{print $2}' | awk -F' ' '{print $1}' | sort -u); for service in $(echo "$uniqueservices"); do echo "$portsandservices" | grep ",$service$\|,$service," | awk -F ',' -v ip=$(echo $i | sed 's/.xml//g') '{print ip","$1","$2","$3","$4","$5}' >> $INTERSERVICESFOLDER/$service-service.txt; done ;done
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
	mincvss=${mincvss:-5.0}
	startcveprocess=`date +%s`
	sudo interlace -tL $INTERINITFOLDER/targets.txt -threads 20 -c " if [[ \"\$(grep \"_target_,\" $INTERSERVICESFOLDER/* -h | awk -F ',' '{print \$2}' | tr '\n' ',' | sed 's/,\$//g')\" != \"\" ]]; then nmap -sSV --script vulners --script-args=mincvss=$mincvss -T4 -Pn --open -p\$(grep \"_target_,\" $INTERSERVICESFOLDER/* -h | awk -F ',' '{print \$2}' | tr '\n' ',' | sed 's/,\$//g') _target_ -oN $INTERCVEFOLDER/_target_.txt ; fi" &> $INTERDEBUGFOLDER/interlace-cve-output.txt
	endcveprocess=`date +%s`
	echo -e "\e[32m--------- Ended cve scan process\e[0m"
	displaytime `expr $endcveprocess - $startcveprocess`
	echo "Execution time of cve recon process was$timecalc."
}

function vulnscan() {
	echo -e "\e[35mStarting vulnerability scan and service parsing processes\e[0m"
	echo "We are going to parse the services and execute nmap vulners and openvas to those services to retrieve vulnerabilities"
	startvulnprocess=`date +%s`
	if [ ! -d "$INTERNMAPFOLDER" ]; then
		echo -e "\e[33m[WARNING] - NMAP folder $INTERSERVICESFOLDER doesn't exist, we will execute first a portscan to get NMAP.\e[0m"
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
		echo -e "\e[33m[WARNING] - Initial Aquatone from nmap folder $INTERDISCOVERHTTPFOLDER exist.\e[0m"
		echo -e "\e[96mDo you want to skip initialaquatonescan? ([y] default/[n]):\e[0m"
		read skipinitialaquatonescan
		if [ "$skipinitialaquatonescan" == "n" ]; then
			echo "Restarting from initial aquatone scan process"
			initialaquatonescan
			fuzzingscan
			screenshotscan
			endwebprocess=`date +%s`
			echo -e "\e[35mEnded web recon process\e[0m"
			displaytime `expr $endwebprocess - $startwebprocess`
			echo "Execution time of web recon process was$timecalc."
			return
		else
			echo "Skipping initial aquatone scan"
		fi
	else
		initialaquatonescan
	fi
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
	if [ -d "$INTEREYEWITNESSFOLDER" ]; then
		echo -e "\e[33m[WARNING] - Final screenshot scan folder $INTEREYEWITNESSFOLDER exist.\e[0m"
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
	if [ -f "$INTERINITFOLDER/byp4xx-output.txt" ]; then
		echo -e "\e[33m[WARNING] - byp4xx output file exist.\e[0m"
		echo -e "\e[96mDo you want to skip byp4xx process? ([y] default/[n]):\e[0m"
                read skipbyp4xx
		if [ "$skipbyp4xx" == "n" ]; then
                        echo "Restarting bypass scan"
			if [ -f "$INTERINITFOLDER/urls-status-403.txt" ]; then
				bypass403
			fi
		else
			echo "skipping bypass 403 urls scan"
		fi
	else
		if [ -f "$INTERINITFOLDER/urls-status-403.txt" ]; then
                	bypass403
        	fi

	fi
	#Now you have some screenshots to review with eyewitness you can open the report and check it there directly that it makes some groups and is easier
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
	echo '[INFO EXTRA] - Remember to check the following things depending of your scan: \n   - (WEBSCAN) The screenshot folder \n   - (VULNSCAN) The cve folder \n   - (VULNSCAN) The services folder \n   - (WEBSCAN) The files with name eyewitness*, as with this script we only perform a 200 screenshot and not other Status responses. On other responses maybe there is something where you can exploit ;).'
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
			followingsteps
			exit 1
			;;
		web)
			webscan
			followingsteps
			exit 1
			;;
		vuln)
			vulnscan
			followingsteps
			exit 1
			;;
	esac
	exit 1
else
	scripthelp
	exit 1
fi
