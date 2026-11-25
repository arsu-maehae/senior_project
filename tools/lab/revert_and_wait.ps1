<#
=====================================================================================
 revert_and_wait.ps1  -  COMBINED host loop (VirtualBox, Owners A + B)  [B-migrated]
=====================================================================================
 Each cycle: clear READY -> revert my VMs -> (DC owner boots DC FIRST + writes DC_READY;
 EP owner WAITS for a fresh DC_READY before booting) -> wait ready -> write READY ->
 wait GO -> collect guests over WinRM -> clear READY -> write COLLECTED -> loop.

 BOOT ORDER (v2.2 s10): DC-01 boots first. EP workers do not power on their VMs until
 Owner A has published DC_READY for the current cycle (so EP boot logons get Kerberos
 tickets and the pipeline has clock-offset pairs).

 Migrated to PC-B: share = \\192.168.50.98\evtx, account = kasuma\evtxwriter.

 USAGE (elevated):
   A (DC+Caldera, on B):  .\revert_and_wait.ps1 -Owner A
   B (EP-01, on B):       .\revert_and_wait.ps1 -Owner B
   S01 (EP-01 GUI):       add  -Gui
=====================================================================================
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('A','B')] [string]$Owner,
    [string]$SnapshotRef = '',

    [string]$VBoxDC='Windows Server 2025',
    [string]$VBoxEp01='Endpoint-01',
    [string]$VBoxCaldera='Caldera Ubuntu Server',

    [string]$DcIp='192.168.50.10',
    [string]$Ep01='192.168.50.21',
    [string]$CalderaIp='192.168.50.50',
    [int]$CalderaPort=8888,
    [string]$CalderaKey=$env:CALDERA_KEY,

    [switch]$Once,
    [switch]$NoCollect,
    [switch]$Gui,
    [int]$DcSettleSec=45,
    [int]$SettleBeforeReadySec=3,
    [int]$ReadyTimeoutSec=420,
    [int]$GoTimeoutSec=3600,
    [int]$DcReadyTimeoutSec=900,

    # share + sync  (PC-B)
    [string]$Share     = '\\192.168.50.98\evtx',
    [string]$ReadyDir  = '\\192.168.50.98\evtx\ready',
    [string]$ShareUser = 'kasuma\evtxwriter',
    [string]$SharePass = $env:SHARE_PW,

    # creds to WinRM into the guests for collection
    [string]$GuestUser = 'LAB\admin_it',
    [string]$GuestPass = $env:GUEST_PW
)

function Log($m){ Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m) }
function UtcZ(){ (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }

function Connect-Ready(){
    if($ShareUser){ cmd /c "net use $Share /user:$ShareUser $SharePass" 2>$null | Out-Null }
}
function Clear-MyFlag(){ Remove-Item (Join-Path $ReadyDir "READY_$Owner.txt") -ErrorAction SilentlyContinue }
function Set-MyFlag(){
    try {
        New-Item -ItemType Directory -Force -Path $ReadyDir -ErrorAction SilentlyContinue | Out-Null
        (UtcZ) | Out-File (Join-Path $ReadyDir "READY_$Owner.txt") -Encoding ascii
        Log "  wrote READY_$Owner"
    } catch { Log "  WARN: could not write ready flag ($($_.Exception.Message))" }
}
function Write-Collected($t){ "$t" | Out-File (Join-Path $ReadyDir "COLLECTED_$Owner.txt") -Encoding ascii }

# --- DC_READY boot-order gate -------------------------------------------------------
function Clear-DcReady(){ Remove-Item (Join-Path $ReadyDir 'DC_READY.txt') -ErrorAction SilentlyContinue }
function Write-DcReady(){
    New-Item -ItemType Directory -Force -Path $ReadyDir -ErrorAction SilentlyContinue | Out-Null
    (UtcZ) | Out-File (Join-Path $ReadyDir 'DC_READY.txt') -Encoding ascii
    Log "  wrote DC_READY (DC-01 up; endpoints may boot)"
}
function Read-DcReady(){
    $f = Join-Path $ReadyDir 'DC_READY.txt'
    if(Test-Path $f){ return ((Get-Content $f -Raw).Trim()) }
    return ''
}
function Wait-DcReady($last){
    Log "  waiting for DC_READY newer than '$last' (DC-01 must boot first) ..."
    $deadline=(Get-Date).AddSeconds($DcReadyTimeoutSec)
    while((Get-Date) -lt $deadline){
        $v = Read-DcReady
        if($v -and ($v -gt $last)){ Log "  DC_READY seen ($v) - booting endpoint"; return $v }
        Start-Sleep -Seconds 5
    }
    throw "timed out waiting for DC_READY - is Owner A (DC) running?"
}

function Read-Go(){
    $f = Join-Path $ReadyDir 'GO.txt'
    if(Test-Path $f){
        $parts = ((Get-Content $f -Raw).Trim()) -split '\s+'
        if($parts.Count -ge 2){ return @{ scen=$parts[0]; trial=[int]$parts[1] } }
    }
    return $null
}
function Wait-Go($last){
    Log "  waiting for GO (trial > $last) ..."
    $deadline=(Get-Date).AddSeconds($GoTimeoutSec)
    while((Get-Date) -lt $deadline){
        $g = Read-Go
        if($g -and $g.trial -gt $last){ Log ("  GO: {0} trial {1}" -f $g.scen,$g.trial); return $g }
        Start-Sleep -Seconds 5
    }
    throw "timed out waiting for GO"
}

$Sets = @{
  'A' = @(
        @{ name=$VBoxDC;      ip=$DcIp;      kind='dc';      revert=$true  }
        @{ name=$VBoxCaldera; ip=$CalderaIp; kind='caldera'; revert=$false }
      )
  'B' = @(
        @{ name=$VBoxEp01;    ip=$Ep01;      kind='win';     revert=$true  }
      )
}
$MyVMs = $Sets[$Owner]

function Revert-One($vm){
    Log ("  revert '{0}' -> current snapshot" -f $vm.name)
    VBoxManage controlvm $vm.name poweroff 2>$null | Out-Null
    Start-Sleep -Seconds 2
    if($SnapshotRef){ VBoxManage snapshot $vm.name restore $SnapshotRef 2>&1 | Out-Null }
    else            { VBoxManage snapshot $vm.name restorecurrent 2>&1 | Out-Null }
    if($LASTEXITCODE -ne 0){ throw ("snapshot restore failed for '{0}'" -f $vm.name) }
}
function Start-One($vm){
    $bootType = if($Gui){ 'gui' } else { 'headless' }
    Log ("  boot   '{0}'  (--type {1})" -f $vm.name, $bootType)
    VBoxManage startvm $vm.name --type $bootType 2>&1 | Out-Null
    if($LASTEXITCODE -ne 0){ throw ("startvm failed for '{0}'" -f $vm.name) }
}
function Wait-Port($ip,$port){
    $deadline=(Get-Date).AddSeconds($ReadyTimeoutSec)
    while((Get-Date) -lt $deadline){
        try { if((Test-NetConnection -ComputerName $ip -Port $port -WarningAction SilentlyContinue).TcpTestSucceeded){ return $true } } catch {}
        Start-Sleep -Seconds 4
    }
    return $false
}

function Wait-WinRM($ip,$sec=150){
    $d=(Get-Date).AddSeconds($sec)
    while((Get-Date) -lt $d){
        try { if((Test-NetConnection -ComputerName $ip -Port 5985 -WarningAction SilentlyContinue).TcpTestSucceeded){ return $true } } catch {}
        Start-Sleep -Seconds 4
    }
    return $false
}
function Collect-Guests($scn,$trial){
    $cred = New-Object System.Management.Automation.PSCredential($GuestUser,(ConvertTo-SecureString $GuestPass -AsPlainText -Force))
    $failed=@()
    foreach($vm in ($MyVMs | Where-Object { $_.kind -eq 'dc' -or $_.kind -eq 'win' })){
        Log ("  collect {0} ({1})" -f $vm.name, $vm.ip)
        if(-not (Wait-WinRM $vm.ip)){ Log ("    WARN: WinRM (5985) not up on {0} - trying anyway" -f $vm.ip) }
        $ok=$false
        for($a=1; $a -le 3 -and -not $ok; $a++){
            try {
                $out = Invoke-Command -ComputerName $vm.ip -Credential $cred -ErrorAction Stop -ScriptBlock {
                    param($scn,$trial,$Share,$ShareUser,$SharePass)
                    $chans=@('Security','System','Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-WinRM/Operational','Microsoft-Windows-PowerShell/Operational')
                    $h=$env:COMPUTERNAME; $tag="trial_{0:D2}" -f $trial
                    $dest=Join-Path (Join-Path (Join-Path $Share $scn) $tag) $h
                    $stage='C:\evtx_export'; New-Item -ItemType Directory -Force -Path $stage | Out-Null
                    $made=@(); foreach($ch in $chans){ $safe=($ch -replace '[\\/]','_'); $o=Join-Path $stage ("{0}_{1}.evtx" -f $h,$safe); try{ wevtutil epl "$ch" "$o" /ow:true 2>$null; if(Test-Path $o){$made+=$o} }catch{} }
                    cmd /c "net use $Share /delete /y" 2>$null | Out-Null
                    cmd /c "net use $Share /user:$ShareUser $SharePass" | Out-Null
                    New-Item -ItemType Directory -Force -Path $dest | Out-Null
                    $c=0; foreach($f in $made){ try{ Copy-Item $f $dest -Force -ErrorAction Stop; $c++ }catch{} }
                    "$h $c/$($made.Count) -> $dest"
                } -ArgumentList $scn,$trial,$Share,$ShareUser,$SharePass
                Log ("    {0}" -f $out); $ok=$true
            } catch {
                Log ("    attempt {0}/3 FAILED {1}: {2}" -f $a, $vm.ip, $_.Exception.Message)
                if($a -lt 3){ Start-Sleep -Seconds 8 }
            }
        }
        if(-not $ok){ $failed += $vm.name }
    }
    if($failed.Count -gt 0){
        Write-Host ("  *** MISSING on trial {0}: {1}  -> RE-FIRE THIS TRIAL ***" -f $trial, ($failed -join ',')) -ForegroundColor Red
        ("trial {0} missing: {1}" -f $trial, ($failed -join ',')) | Out-File (Join-Path $ReadyDir ("FAILED_{0}_{1}.txt" -f $Owner,$trial)) -Encoding ascii
    }
}

# ---- main ----
if(-not (Get-Command VBoxManage -ErrorAction SilentlyContinue)){
    throw "VBoxManage not on PATH. Add 'C:\Program Files\Oracle\VirtualBox' to PATH."
}
if(-not $GuestPass){ throw "Guest password not set. Do: `$env:GUEST_PW='...' (or pass -GuestPass)." }
try { Set-Item WSMan:\localhost\Client\TrustedHosts -Value '192.168.50.*' -Force -ErrorAction Stop }
catch { Log "WARN: could not set TrustedHosts (run as Administrator) - collect may fail." }

$haveDc = [bool]($MyVMs | Where-Object { $_.kind -eq 'dc' })

$myLast = 0
$lastDcReady = ''
do {
    Log "=== Owner $Owner : cycle (last collected trial $myLast) ==="
    Connect-Ready
    Clear-MyFlag
    if($haveDc){ Clear-DcReady }   # DC owner retracts the gate while DC is down

    # revert all my revertable VMs (disk reset; no boot yet)
    foreach($vm in ($MyVMs | Where-Object { $_.revert })){ Revert-One $vm }

    if($haveDc){
        # ---- Owner A: boot DC FIRST, then publish DC_READY ----
        $dc = $MyVMs | Where-Object { $_.kind -eq 'dc' }
        Start-One $dc
        Log "  waiting for DC LDAP ($($dc.ip):389) + Kerberos (88)..."
        $dcUp = (Wait-Port $dc.ip 389) -and (Wait-Port $dc.ip 88)
        if($dcUp){ Log "  DC up; settling ${DcSettleSec}s"; Start-Sleep -Seconds $DcSettleSec; Write-DcReady }
        else { Log "  WARN: DC 389/88 timeout - NOT writing DC_READY" }
    } else {
        # ---- Owner B: wait for DC before booting the endpoint ----
        $lastDcReady = Wait-DcReady $lastDcReady
    }

    # boot my non-DC revertable VMs (EP-01 for B; none for A)
    foreach($vm in ($MyVMs | Where-Object { $_.kind -ne 'dc' -and $_.revert })){ Start-One $vm }

    $allReady = $true
    foreach($vm in $MyVMs){
        switch($vm.kind){
            'dc'      { $ok = Wait-Port $vm.ip 389 }
            'caldera' { $ok = Wait-Port $vm.ip $CalderaPort }
            default   { $ok = Wait-Port $vm.ip 445 }
        }
        if($ok){ Log ("  READY: {0} ({1})" -f $vm.name, $vm.ip) }
        else   { $allReady=$false; Log ("  NOT READY: {0} ({1})" -f $vm.name, $vm.ip) }
    }
    if(-not $allReady){ Log "  one or more VMs not ready - retrying cycle"; continue }

    if($SettleBeforeReadySec -gt 0){ Start-Sleep -Seconds $SettleBeforeReadySec }
    Set-MyFlag

    if($NoCollect){
        Write-Host ("OWNER $Owner READY ({0}) - -NoCollect, run collect by hand." -f (UtcZ)) -ForegroundColor Green
        if(-not $Once){ Read-Host "Press ENTER to re-arm for next trial" }
    } else {
        $g = Wait-Go $myLast
        Collect-Guests $g.scen $g.trial
        Clear-MyFlag
        Write-Collected $g.trial
        $myLast = $g.trial
        Write-Host ("OWNER $Owner done trial $($g.trial) ({0})" -f (UtcZ)) -ForegroundColor Green
    }
} while (-not $Once)
