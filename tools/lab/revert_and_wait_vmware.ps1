<#
=====================================================================================
 revert_and_wait_vmware.ps1  -  COMBINED host loop (VMware, Owner C)  [B-migrated]
=====================================================================================
 VMware twin. Each cycle: clear READY_C -> revert EP-02 + EP-03 -> WAIT for a fresh
 DC_READY (DC-01 must boot first, v2.2 s10) -> boot EP-02/03 -> wait ready ->
 write READY_C -> wait GO -> collect over WinRM -> clear READY_C -> COLLECTED_C -> loop.

 Migrated to PC-B share: \\192.168.50.98\evtx, account kasuma\evtxwriter.

 PC-C facts: vmrun needs -vp <enc pw>; .vmx filenames are INVERTED vs roles:
   EP-02 (.22) = E:\VMware\Endpoint-02\Endpoint-03.vmx
   EP-03 (.23) = E:\VMware\Endpoint-03\Endpoint-02.vmx

 USAGE (elevated on PC-C):
   $env:VMENC_PW='...'; $env:SHARE_PW='...'
   .\revert_and_wait_vmware.ps1
=====================================================================================
#>

[CmdletBinding()]
param(
    [string]$Ep02Snap = 'clean-joined-logging-verirfied7',
    [string]$Ep03Snap = 'clean-joined-logging-verified 3',
    [string]$VmrunPath = 'C:\Program Files\VMware\VMware Workstation\vmrun.exe',

    [string]$EncPw = $env:VMENC_PW,

    [string]$Ep02Vmx = 'E:\VMware\Endpoint-02\Endpoint-03.vmx',
    [string]$Ep03Vmx = 'E:\VMware\Endpoint-03\Endpoint-02.vmx',
    [string]$Ep02Ip  = '192.168.50.22',
    [string]$Ep03Ip  = '192.168.50.23',

    [switch]$Once,
    [switch]$NoCollect,
    [switch]$CheckTrust,
    [pscredential]$TrustCred,
    [int]$SettleBeforeReadySec = 3,
    [int]$ReadyTimeoutSec = 420,
    [int]$GoTimeoutSec = 3600,
    [int]$DcReadyTimeoutSec = 900,

    [string]$Owner     = 'C',
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

function Connect-Ready(){ if($ShareUser){ cmd /c "net use $Share /user:$ShareUser $SharePass" 2>$null | Out-Null } }
function Clear-MyFlag(){ Remove-Item (Join-Path $ReadyDir "READY_$Owner.txt") -ErrorAction SilentlyContinue }
function Set-MyFlag(){
    try {
        New-Item -ItemType Directory -Force -Path $ReadyDir -ErrorAction SilentlyContinue | Out-Null
        (UtcZ) | Out-File (Join-Path $ReadyDir "READY_$Owner.txt") -Encoding ascii
        Log "  wrote READY_$Owner"
    } catch { Log "  WARN: could not write ready flag ($($_.Exception.Message))" }
}
function Write-Collected($t){ "$t" | Out-File (Join-Path $ReadyDir "COLLECTED_$Owner.txt") -Encoding ascii }

# --- DC_READY boot-order gate (C always waits; it has no DC) ------------------------
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
        if($v -and ($v -gt $last)){ Log "  DC_READY seen ($v) - booting endpoints"; return $v }
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

if(-not (Test-Path $VmrunPath)){ throw "vmrun not found at '$VmrunPath' - fix -VmrunPath." }
if(-not $EncPw){ throw "VM encryption password not set. Do: `$env:VMENC_PW='...' (or pass -EncPw)." }
if(-not $GuestPass){ throw "Guest password not set. Do: `$env:GUEST_PW='...' (or pass -GuestPass)." }

$MyVMs = @(
  @{ name='EP-02'; vmx=$Ep02Vmx; ip=$Ep02Ip; snap=$Ep02Snap }
  @{ name='EP-03'; vmx=$Ep03Vmx; ip=$Ep03Ip; snap=$Ep03Snap }
)

function Vmrun(){ & $VmrunPath -vp $EncPw -T ws @args }

function Revert-One($vm){
    if(-not (Test-Path $vm.vmx)){ throw ("vmx missing for {0}: '{1}'" -f $vm.name, $vm.vmx) }
    Log ("  stop+revert {0}  ({1} -> '{2}')" -f $vm.name, (Split-Path $vm.vmx -Leaf), $vm.snap)
    Vmrun stop $vm.vmx hard 2>$null | Out-Null
    Start-Sleep -Seconds 2
    Vmrun revertToSnapshot $vm.vmx $vm.snap 2>&1 | Out-Null
    if($LASTEXITCODE -ne 0){ throw ("revertToSnapshot '{0}' failed for {1} - exact name? (listSnapshots)." -f $vm.snap, $vm.name) }
}
function Is-Running($vmx){
    $list = (& $VmrunPath -T ws list) 2>$null
    return (($list -join "`n") -match [regex]::Escape($vmx))
}
function Start-One($vm){
    Log ("  boot   {0}" -f $vm.name)
    for($i=1; $i -le 6; $i++){
        if(Is-Running $vm.vmx){ return }
        Vmrun start $vm.vmx nogui 2>$null | Out-Null
        Start-Sleep -Seconds 8
        if(Is-Running $vm.vmx){ return }
        Log ("  start attempt {0} not confirmed; retrying..." -f $i)
        Vmrun stop $vm.vmx hard 2>$null | Out-Null   # clear any half-started/locked state
        Start-Sleep -Seconds 3
    }
    throw ("start failed for {0} after retries - check 'vmrun -T ws list' and host RAM" -f $vm.name)
}
function Wait-Port($ip,$port){
    $deadline=(Get-Date).AddSeconds($ReadyTimeoutSec)
    while((Get-Date) -lt $deadline){
        try { if((Test-NetConnection -ComputerName $ip -Port $port -WarningAction SilentlyContinue).TcpTestSucceeded){ return $true } } catch {}
        Start-Sleep -Seconds 4
    }
    return $false
}
function Check-Trust($ip){
    if(-not $TrustCred){ $script:TrustCred = Get-Credential -Message "Domain admin for trust check (e.g. LAB\admin_it)" }
    try {
        $ok = Invoke-Command -ComputerName $ip -Credential $TrustCred -ScriptBlock { Test-ComputerSecureChannel } -ErrorAction Stop
        if($ok){ Log "  trust OK on $ip"; return $true }
        Log "  TRUST BROKEN on $ip"; return $false
    } catch { Log "  WARN: trust check failed on $ip ($($_.Exception.Message))"; return $true }
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
    foreach($vm in $MyVMs){
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
try { Set-Item WSMan:\localhost\Client\TrustedHosts -Value '192.168.50.*' -Force -ErrorAction Stop }
catch { Log "WARN: could not set TrustedHosts (run as Administrator) - collect may fail." }

$myLast = 0
$lastDcReady = ''
do {
    Log "=== Owner C : cycle (last collected trial $myLast) ==="
    Connect-Ready
    Clear-MyFlag

    foreach($vm in $MyVMs){ Revert-One $vm }

    # v2.2 s10: do not boot endpoints until DC-01 is up for this cycle
    $lastDcReady = Wait-DcReady $lastDcReady

    # boot endpoints; vmrun start is intermittently flaky, so a failed pass
    # re-reverts and retries (DC stays up - no DC_READY re-wait) instead of crashing.
    $booted = $false
    for($pass=1; $pass -le 3 -and -not $booted; $pass++){
        try {
            foreach($vm in $MyVMs){ Start-One $vm }
            $booted = $true
        } catch {
            Log ("  boot pass {0} failed ({1}); re-reverting + retrying" -f $pass, $_.Exception.Message)
            foreach($vm in $MyVMs){ Vmrun stop $vm.vmx hard 2>$null | Out-Null }
            Start-Sleep -Seconds 5
            foreach($vm in $MyVMs){ Revert-One $vm }
        }
    }
    if(-not $booted){ Log "  ENDPOINTS WOULD NOT BOOT after 3 passes - check VMware Workstation + host RAM; retrying cycle." ; continue }

    $allReady = $true
    foreach($vm in $MyVMs){
        $ok = Wait-Port $vm.ip 445
        if($ok -and $CheckTrust){ $ok = (Check-Trust $vm.ip) }
        if($ok){ Log ("  READY: {0} ({1})" -f $vm.name, $vm.ip) }
        else   { $allReady=$false; Log ("  NOT READY: {0} ({1})" -f $vm.name, $vm.ip) }
    }
    if(-not $allReady){ Log "  one or more VMs not ready - retrying cycle"; continue }

    if($SettleBeforeReadySec -gt 0){ Start-Sleep -Seconds $SettleBeforeReadySec }
    Set-MyFlag

    if($NoCollect){
        Write-Host ("OWNER C READY ({0}) - -NoCollect, run collect by hand." -f (UtcZ)) -ForegroundColor Green
        if(-not $Once){ Read-Host "Press ENTER to re-arm for next trial" }
    } else {
        $g = Wait-Go $myLast
        Collect-Guests $g.scen $g.trial
        Clear-MyFlag
        Write-Collected $g.trial
        $myLast = $g.trial
        Write-Host ("OWNER C done trial $($g.trial) ({0})" -f (UtcZ)) -ForegroundColor Green
    }
} while (-not $Once)
