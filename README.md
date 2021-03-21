# inter-recon
Script to perform automatic initial web and vulnerability recon.

It has some checks in case of errors.

There is a possibility to skip some checks, to restart them and/or to continue with the last point you stopped. (This is because sometimes there are network issues like time limit on VPN).

Remember if you copy or link the inter-recon script to bin path (ex: /usr/bin/) you can execute the script from where you want. It will create the output where you are.

To use multiple known domain/IPs:
- Create file domains.txt
- Execute: inter-recon -T {target file path to use} -d {Directory full path to work on} -w {dictionary full path} -s {scan type} -a; done

## How to use:
  inter-recon.sh [OPTIONS]
		-t {NET OR IP}
		-T {Target PATH}
		-d {Dictionary Path}
		-w {DICT PATH}
		-s {scan type}
		-a optional is for superautomaticscan skipping all and not asking anything on wfuzz process at fisrt time execution

## Structure:
  - First ports scan tcp and udp with version (nmap, requires sudo)
  - Vulnerability recon scan (command to parse ports into a file with fromat IP,port,service,version, parse it on services files, perform nmap with full port/version related scripts)
  - Web fuzzing recon scan if aquatone finds a HTTP port (aquatone, wfuzz, eyewitness, byp4xx 403 files)

## Applications used:
  - nmap (version normal and with nmap-vulners script, both of them requires sudo, using tcp (full ports if the host is UP using -PS with some ports) and udp (only top 100 ports))
  - aquatone (To get http ports from nmap execution)
  - wfuzz (To make fuzzing to the http ports)
  - eyewitness (To make screenshots to all Status 200 URLs. This could be removed and changed with aquatone, but personally i like the structured report it makes)
  - byp4xx (To try bypass 403 urls by different methods)
  
## Output folder structure: (example)
  - 192.168.122.1-24/ -> initial folder
    - nmap/ -> folder with tcp and udp nmap on xml and grepable output with version
      - nmap-tcp-target.xml -> nmap output to import to some tools
      - nmap-udp-target.xml -> nmap output to import to some tools
      - nmap-tcp-target.xml -> grepable nmap to parse and make information more readable
      - nmap-udp-target.xml -> grepable nmap to parse and make information more readable
    - aux/ -> folder with control the previous execution and skipped wfuzz URLs
      - nmap/ -> here we have all the nmaps to aquatone, we will remove the processed nmap files in aquatone process, for in case that there is an error, continue with that nmap file.
      - aquatone-full-initial-files.txt -> here we will remove the URLs that the execution was correct
      - wfuzz-skipped-urls.txt -> here we will add the URLs that we skipped because there was an error ((Total request + 1) - Processed request != 0)
    - debug/ -> folder with debug the executions
      - nmap-tcp-output.txt -> nmap (version only) output execution
      - nmap-tcp-cve-output.txt -> nmap with -A option to execute all scripts related
      - nmap-udp-output.txt -> nmap (version only) output execution
      - nmap-udp-output.txt -> nmap with -A option to execute all scripts related
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
    - eyewitness-200-parsed-urls.txt -> file to pass to eyewitness
    - urls-status-{200,401,403,etc}.txt -> final status URLs found by wfuzz it changes depending on variable $status that is the status of the URLs found
    - targets.txt -> file with IP or network that you added on -t parameter
    - bypass/ -> Folder with byp4xx lobuhi application (only if 403 url found)
      - byp4xx-{URL without : and /}.txt -> byp4xx output of each 403 URL
    - all-urls-fuzzing-results.txt -> File with all URL fuzzing scan with format "urlStatus URL"
    - full-nmap-parsed-tcp.txt -> Nmap parsed with format "IP,Port,Service,Version"
    
## To-Do:
  - Add enum4linux and smbmap
  - Include on vulnerability scan the "OPENVAS scan"
  - Include on web scan the URL and domains catching from http URLs found by wfuzz
  - Include a new scan type that is OSINT, that can execute some get information from web or from diferent script executions.
  
## Instalation tools URLs:
  - Aquatone: https://github.com/michenriksen/aquatone
    - Arch-Linux) sudo pacman -S aquatone
  - Wfuzz: https://github.com/xmendez/wfuzz
    - Arch-Linux) sudo pacman -S wfuzz
  - Eyewitness: https://github.com/FortyNorthSecurity/EyeWitness
    - Arch-Linux) sudo pacman -S eyewitness
  - Nmap-vulners: https://github.com/vulnersCom/nmap-vulners
  - byp4xx: https://github.com/lobuhi/byp4xx/

## Additional Informaiton
  - Deleted interlace dependency as nmap can perform paralelization and it is quicker when we are scanning only 1 IP (When scanning multiple, the difference is low)
  - The UDP nmap is only to 100 top ports, if you have time, perform an additional nmap with full UDP ports in background.
  - The TCP nmap is checking some ports to know if the host is UP and scan it if it is UP, if you have time, perform an additional nmap with full TCP ports with -Pn in background.
  - Aquatone can fail checking http/s ports on nmap (I'm not sure why, but recheck the services to check if there is any possible http port/service missing on the scan and scan it manually)
  - I saw few times that wfuzz blocks the script, i need to test it more but maybe we will change wfuzz to other path fuzzing. (I like wfuzz but fuff is good too)
  - We use eyewitness because on the http report, it groups the different screenshots by category.
