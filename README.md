# inter-recon
Script to perform automatic initial web and vulnerability recon.

It has some checks in case of errors.

There is a possibility to skip some checks, to restart them and/or to continue with the last point you stopped. (This is because sometimes there are network issues like time limit on VPN).

Remember if you copy or link the inter-recon script to bin path (ex: /usr/bin/) you can execute the script from where you want. It will create the output where you are.

This script is correctly being executed with /bin/bash. I had some problems executing in dash, so if you are executing this on kali, unlink /bin/sh and link it to /bin/bash, as interlace per default executes /bin/sh

To use multiple known domain/IPs:
- Create file domains.txt
- Execute: for domain in $(cat domains.txt); do inter-recon -t $domain -w {DICTPATH} -s all -a; done

## How to use:
  inter-recon.sh -t {NET OR IP} -w {DICT PATH} -s {scan type} -a {optional is for superautomaticscan skipping all and not asking anything on wfuzz process at fisrt time execution}

## Structure:
  - First ports scan with version (nmap, requires sudo)
  - Web fuzzing recon scan (aquatone, wfuzz, eyewitness, byp4xx 403 files)
  - Vulnerability recon scan (command to parse ports into services files, nmap with nmap-vulners script)

## Applications used:
  - interlace (just for paralelization, it can be removed but i like the speed for nmap)
  - nmap (version normal and with nmap-vulners script, both of them requires sudo)
  - aquatone (To get http ports from nmap execution)
  - wfuzz (To make fuzzing to the http ports)
  - eyewitness (To make screenshots to all Status 200 URLs. This could be removed and changed with aquatone, but personally i like the structured report it makes)
  - byp4xx (To try bypass 403 urls by different methods)
  
## Output folder structure: (example)
  - 192.168.122.1-24/ -> initial folder
    - nmap/ -> folder with nmap on xml output with version
      - {IPs}.xml -> nmap output to import to some tools
    - aux/ -> folder with control the previous execution and skipped wfuzz URLs
      - nmap/ -> here we have all the nmaps to aquatone, we will remove the processed nmap files in aquatone process, for in case that there is an error, continue with that nmap file.
      - aquatone-full-initial-files.txt -> here we will remove the URLs that the execution was correct
      - wfuzz-skipped-urls.txt -> here we will add the URLs that we skipped because there was an error ((Total request + 1) - Processed request != 0)
    - debug/ -> folder with debug the executions
      - interlace-output.txt -> interlace with nmap (version only) output execution
      - interlace-cve-output.txt -> interlace with nmap (nmap-vulners) output execution
      - aquatone-initial-files-output.txt -> initial aquatone output execution
      - wfuzz-output.txt -> wfuzz output execution
      - eyewitness-output.txt -> eyewitness output execution      
    - fuzzing/ -> folder with wfuzz executions (Important to review Status 50* and 40*)
      - *.txt -> wfuzz output files
    - services/ -> folder with all services parsed from nmap
      - {SERVICE-NAME}-services.txt -> services execution with IP,PORT,Extra-service-info output
    - cve/ -> folder with vulnerabilities by host found by nmap-vulners script
      - {IPs}.txt -> nmap-vulners script output
    - http-discover/ -> folder with screenshot of initial URL files found by nmap
      - {IPs} -> folders with screenshots by IP of nmap
    - screenshots/ -> folder with screenshots of status 200 URLs found by wfuzz
      - screens -> folder with all screenshots
      - report.html -> report with structured information
      - {OTHER} -> other things to report.html
    - aquatone-full-initial-files.txt -> files with initial aquatone found URLs to make fuzzing with wfuzz
    - eyewitness-200-urls.txt -> final status 200 URLs found by wfuzz
    - eyewitness-100-urls.txt -> final status 100 URLs found by wfuzz
    - eyewitness-300-urls.txt -> final status 300 URLs found by wfuzz
    - eyewitness-400-urls.txt -> final status 400 URLs found by wfuzz
    - eyewitness-500-urls.txt -> final status 500 URLs found by wfuzz 
    - targets.txt -> IP or network that you added on -t parameter
    
## To-Do:
  - Remove files in nmap folder with not UP hosts (If we make this before aquatone execution, we will solve the following point)
  - Remove folders with not UP hosts in initial-files-found-http
  - Include on vulnerability scan the "OPENVAS scan"
  - Include on web scan the URL and domains catching from http URLs found by wfuzz
  - Include a new scan type that is OSINT, that can execute some get information from web or from diferent script executions.
  - Change folders and files name to make easier to read and understand.
  
## Instalation tools URLs:
  - Interlace: https://github.com/codingo/Interlace - 
    - Arch-Linux) sudo pacman -S interlace
  - Aquatone: https://github.com/michenriksen/aquatone
    - Arch-Linux) sudo pacman -S aquatone
  - Wfuzz: https://github.com/xmendez/wfuzz
    - Arch-Linux) sudo pacman -S wfuzz
  - Eyewitness: https://github.com/FortyNorthSecurity/EyeWitness
    - Arch-Linux) sudo pacman -S eyewitness
  - Nmap-vulners: https://github.com/vulnersCom/nmap-vulners
  - byp4xx: https://github.com/lobuhi/byp4xx/	
