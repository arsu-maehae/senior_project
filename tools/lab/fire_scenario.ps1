<#
=====================================================================================
 fire_scenario.ps1  -  THE CONDUCTOR (runs on PC-A)
=====================================================================================
 Launches one scenario's Caldera operation(s) via REST, waits for completion, and
 writes a manifest row with UTC start/end. Replaces clicking "start operation" in
 the Caldera UI for every trial. Runs on PC-A, talks to Caldera over HTTP.

 Per trial:
   1. A, B, C each revert + boot + report READY (the workers write flags; READY means
      every VM they host answers on its ports).
   2. Run:  .\fire_scenario.ps1 -Scenario S02 -Trial 1 -WaitReady
      The readiness gate ALWAYS runs (-WaitReady is kept for old command lines): it waits
      for fresh READY_A, READY_B, READY_C and DC_READY, then probes every VM itself
      (DC-01 88/389, Caldera 8888, EP-01..03 445/5985). After WaitReadyTimeoutSec (15 min)
      it fires NOTHING, writes nothing, reports the missing PC flag / VM port, and stops.
   3. Fires the Caldera operation(s) and waits for 'finished' (OpTimeoutSec, 20 min).
      For S04 it pauses and tells C to run Track A by hand.
   4. Records start/end UTC to the manifest CSV.
   5. Writes OP_DONE.txt = "<scenario> <trial>" when the operation finished by itself.
      If it had to be forced to finished, OP_DONE is NOT written automatically: the
      operator confirms in Caldera, then presses ENTER (or writes OP_DONE.txt by hand).
   6. Waits TailSec (5 min) of tail, then writes GO; the workers collect only when
      OP_DONE matches GO, and report COLLECTED.
 No clock is synchronised by this script.

 First get your IDs:  $env:CALDERA_KEY='<key>'; .\fire_scenario.ps1 -List
 Key is read from $env:CALDERA_KEY (never hardcoded).
=====================================================================================
#>

[CmdletBinding()]
param(
    [ValidateSet('S01','S02','S03','S04','S05','S06','S07')]
    [string]$Scenario,
    [int]$Trial,

    [switch]$List,

    [string]$CalderaIp   = '192.168.50.50',
    [int]$CalderaPort    = 8888,
    [string]$CalderaKey  = $env:CALDERA_KEY,

    [string]$PlannerId   = 'aaa7c857-37a0-4c4a-85f7-4e9f7f30e31a',   # atomic planner (confirmed)
    [string]$SourceId    = 'ed32b9c3-9593-4c33-b0db-e2007315096b',   # basic source   (confirmed)

    [string]$ManifestPath = 'D:\evtx_share\manifest.csv',
    [int]$OpTimeoutSec    = 1200,
    [string]$Jitter       = '2/8',
    [string]$Obfuscator   = 'plain-text',

    [switch]$WaitReady,
    [string]$ReadyDir           = 'D:\evtx_share\ready',
    [int]$WaitReadyTimeoutSec   = 900,
    [int]$ReadyMaxAgeMin        = 30,
    [int]$CollectTimeoutSec     = 1800,
    [int]$TailSec               = 300,

    # VMs the readiness gate probes (same IPs as the workers)
    [string]$DcIp   = '192.168.50.10',
    [string]$Ep01Ip = '192.168.50.21',
    [string]$Ep02Ip = '192.168.50.22',
    [string]$Ep03Ip = '192.168.50.23',

    [switch]$DryRun
)

# Real adversary UUIDs (from Caldera, confirmed 2026-10-14). S01 is MANUAL (no adversary).
$AdversaryId = @{
    'S01' = ''
    'S02' = 'd842eb72-047e-42ce-93c7-d58c71b17857'    # Lab-S02-SMB-Service
    'S03' = '145ecf81-8371-436d-8eb2-13e0df5ea9d9'    # Lab-S03-WinRM
    'S04' = 'a376fd31-38c2-4941-9ada-e7eab3dd2fe1'    # Lab-S04B-Ablation (Track B; Track A manual)
    'S05H1'= 'c324f4e0-0edc-41f2-b511-5d346b5cf65e'   # Lab-S05-Hop1
    'S05H2'= '9d17f592-6f09-4a63-96a6-d7faf9f1d4b8'   # Lab-S05-Hop2
    'S06' = '0049e613-2f7d-449e-b773-b4d8d0bb2be4'    # Lab-S06-Benign
    'S07' = 'acffb643-0fb1-49af-9715-d9f5e56943d8'    # Lab-S07-Dual
}

$Group = @{
    'S01'='foothold'; 'S02'='foothold'; 'S03'='foothold_admin'; 'S04'='foothold'
    'S05H1'='foothold'; 'S05H2'='pivot_admin'; 'S06'='foothold'; 'S07'='foothold'
}

$Base = "http://$CalderaIp`:$CalderaPort/api/v2"
function Hdr(){ @{ KEY = $CalderaKey } }
function UtcZ(){ (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }
function Log($m){ Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m) }

if(-not $CalderaKey){ throw "Set the API key first:  `$env:CALDERA_KEY='<key>'" }

if($List){
    foreach($kind in 'adversaries','planners','sources'){
        Write-Host "`n===== $kind ====="
        try {
            $items = Invoke-RestMethod -Uri "$Base/$kind" -Headers (Hdr) -TimeoutSec 10
            foreach($i in $items){
                $id = $i.adversary_id; if(-not $id){ $id = $i.id }
                Write-Host ("  {0}   {1}" -f $id, $i.name)
            }
        } catch { Write-Host "  (failed: $($_.Exception.Message))" -ForegroundColor Red }
    }
    return
}

if(-not $Scenario -or -not $Trial){ throw "Pass -Scenario Sxx and -Trial N (or use -List)." }

# --- readiness gate: flags from every PC + DC_READY + live VM ports ----------------------
$ExpectedVMs = [ordered]@{
    'A' = @( @{ name='DC-01';   ip=$DcIp;      ports=@(88,389) },
             @{ name='Caldera'; ip=$CalderaIp; ports=@($CalderaPort) } )
    'B' = @( @{ name='EP-01';   ip=$Ep01Ip;    ports=@(445,5985) } )
    'C' = @( @{ name='EP-02';   ip=$Ep02Ip;    ports=@(445,5985) },
             @{ name='EP-03';   ip=$Ep03Ip;    ports=@(445,5985) } )
}
$FlagOwner = [ordered]@{ 'READY_A'='PC of owner A (DC-01 + Caldera)'; 'READY_B'='PC of owner B (EP-01)';
                         'READY_C'='PC of owner C (EP-02 + EP-03)';   'DC_READY'='owner A (DC-01 boot gate)' }

function Test-Port($ip,$port,$ms=3000){
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $ar = $c.BeginConnect($ip,$port,$null,$null)
        if($ar.AsyncWaitHandle.WaitOne($ms) -and $c.Connected){ $c.EndConnect($ar); return $true }
        return $false
    } catch { return $false } finally { $c.Close() }
}
function Test-FreshFlag($name){
    $f = Join-Path $ReadyDir "$name.txt"
    if(-not (Test-Path $f)){ return $false }
    $age = (New-TimeSpan -Start (Get-Item $f).LastWriteTime -End (Get-Date)).TotalMinutes
    return ($age -le $ReadyMaxAgeMin)
}
function Get-MissingFlags(){ return @($FlagOwner.Keys | Where-Object { -not (Test-FreshFlag $_) }) }
function Get-DeadVMs(){
    $dead = @()
    foreach($o in $ExpectedVMs.Keys){
        foreach($vm in $ExpectedVMs[$o]){
            $bad = @($vm.ports | Where-Object { -not (Test-Port $vm.ip $_) })
            if($bad.Count -gt 0){ $dead += ("owner {0}: {1} {2} no answer on port(s) {3}" -f $o, $vm.name, $vm.ip, ($bad -join '/')) }
        }
    }
    return $dead
}
function Wait-AllReady(){
    Log "readiness gate: READY_A/B/C + DC_READY in $ReadyDir, then live VM ports (timeout ${WaitReadyTimeoutSec}s) ..."
    $deadline = (Get-Date).AddSeconds($WaitReadyTimeoutSec)
    $missing = @(); $dead = @()
    while((Get-Date) -lt $deadline){
        $missing = @(Get-MissingFlags)
        if($missing.Count -eq 0){
            $dead = @(Get-DeadVMs)
            if($dead.Count -eq 0){ Log "  all READY flags + DC_READY present and every VM answers"; return $true }
            Write-Host ("  flags OK, but not answering: {0}   (waiting...)" -f ($dead -join '; ')) -ForegroundColor DarkYellow
        } else {
            Write-Host ("  missing flags: {0}   (waiting...)" -f ($missing -join ',')) -ForegroundColor DarkYellow
        }
        Start-Sleep -Seconds 10
    }
    # timeout: report who is missing; nothing has been fired or written
    if($missing.Count -gt 0){ $dead = @(Get-DeadVMs) }
    Write-Host ("`n*** NOT READY after {0}s - NO operation fired, NO GO / OP_DONE written. ***" -f $WaitReadyTimeoutSec) -ForegroundColor Red
    foreach($m in $missing){ Write-Host ("  missing flag {0}  <- {1}" -f $m, $FlagOwner[$m]) -ForegroundColor Red }
    foreach($d in $dead){ Write-Host ("  {0}" -f $d) -ForegroundColor Red }
    throw ("readiness gate timed out - missing flags: [{0}]; VMs not answering: [{1}]" -f ($missing -join ','), ($dead -join '; '))
}
function Clear-AllFlags(){
    foreach($o in 'A','B','C'){ Remove-Item (Join-Path $ReadyDir "READY_$o.txt") -ErrorAction SilentlyContinue }
}
function Write-Go($scn,$trial){
    New-Item -ItemType Directory -Force -Path $ReadyDir -ErrorAction SilentlyContinue | Out-Null
    # clear last trial's COLLECTED first so Wait-AllCollected cannot match a stale value
    foreach($o in 'A','B','C'){ Remove-Item (Join-Path $ReadyDir "COLLECTED_$o.txt") -ErrorAction SilentlyContinue }
    "$scn $trial" | Out-File (Join-Path $ReadyDir 'GO.txt') -Encoding ascii
    Log "  wrote GO ($scn $trial) - collectors (A,B,C) will pull logs"
}
# --- OP_DONE: the operation has finished (written here, or by hand) ----------------------
function Clear-OpDone(){ Remove-Item (Join-Path $ReadyDir 'OP_DONE.txt') -ErrorAction SilentlyContinue }
function Write-OpDone($scn,$trial){
    New-Item -ItemType Directory -Force -Path $ReadyDir -ErrorAction SilentlyContinue | Out-Null
    "$scn $trial" | Out-File (Join-Path $ReadyDir 'OP_DONE.txt') -Encoding ascii
    Log "  wrote OP_DONE ($scn $trial)"
}
function Test-OpDone($scn,$trial){
    $f = Join-Path $ReadyDir 'OP_DONE.txt'
    if(-not (Test-Path $f)){ return $false }
    $p = ((Get-Content $f -Raw).Trim()) -split '\s+'
    return ($p.Count -ge 2 -and $p[0] -eq $scn -and $p[1] -eq "$trial")
}
function Confirm-OpDone($scn,$trial){
    Write-Host "`n*** The Caldera operation did NOT finish by itself (forced after ${OpTimeoutSec}s). OP_DONE NOT written. ***" -ForegroundColor Yellow
    Write-Host "*** Check in Caldera that the operation has really finished, then press ENTER here," -ForegroundColor Yellow
    Write-Host ("*** or write OP_DONE.txt = '{0} {1}' in {2} by hand." -f $scn, $trial, $ReadyDir) -ForegroundColor Yellow
    try {
        while(-not (Test-OpDone $scn $trial)){
            if([Console]::KeyAvailable){
                if([Console]::ReadKey($true).Key -eq 'Enter'){ Write-OpDone $scn $trial; break }
            }
            Start-Sleep -Milliseconds 500
        }
    } catch {
        # no interactive console (e.g. redirected input): plain prompt
        Read-Host "Press ENTER once the operation has finished" | Out-Null
        if(-not (Test-OpDone $scn $trial)){ Write-OpDone $scn $trial }
    }
    if(Test-OpDone $scn $trial){ Log "  OP_DONE confirmed by operator" }
}

function Wait-AllCollected($trial){
    Log "  waiting for COLLECTED A,B,C == $trial ..."
    $deadline = (Get-Date).AddSeconds($CollectTimeoutSec)
    while((Get-Date) -lt $deadline){
        $have = @()
        foreach($o in 'A','B','C'){
            $f = Join-Path $ReadyDir "COLLECTED_$o.txt"
            if((Test-Path $f) -and ((Get-Content $f -Raw).Trim() -eq "$trial")){ $have += $o }
        }
        if($have.Count -eq 3){ Log "  all collected (A,B,C)"; return $true }
        Write-Host ("  collected: {0}   (waiting...)" -f ($have -join ',')) -ForegroundColor DarkYellow
        Start-Sleep -Seconds 5
    }
    Write-Host ("  WARN: collect timeout - only: {0}. Check that host workers are running." -f ($have -join ',')) -ForegroundColor Red
    return $false
}

# always gate (the -WaitReady switch is kept so existing command lines still work)
Wait-AllReady | Out-Null

if($DryRun){
    Write-Host "`n*** DRY RUN: handshake OK - NO Caldera operation fired, NO attack. ***" -ForegroundColor Cyan
    if($WaitReady){ Clear-AllFlags; Write-Host "  ready flags cleared." -ForegroundColor Cyan }
    return
}

function Invoke-Op([string]$advId,[string]$group,[string]$opName){
    if(-not $advId){ throw "No adversary UUID set for this scenario - fill in `$AdversaryId." }
    $body = @{
        name       = $opName
        adversary  = @{ adversary_id = $advId }
        planner    = @{ id = $PlannerId }
        source     = @{ id = $SourceId }
        group      = $group
        state      = 'running'
        autonomous = 1
        auto_close = $true
        obfuscator = $Obfuscator
        jitter     = $Jitter
    } | ConvertTo-Json -Depth 6

    $start = UtcZ
    Log "  firing '$opName'  (group=$group)"
    $op = Invoke-RestMethod -Uri "$Base/operations" -Method Post -Headers (Hdr) -ContentType 'application/json' -Body $body
    $opId = $op.id
    Log "  op id = $opId"

    $deadline = (Get-Date).AddSeconds($OpTimeoutSec)
    $state = $op.state
    while((Get-Date) -lt $deadline){
        Start-Sleep -Seconds 5
        try {
            $cur = Invoke-RestMethod -Uri "$Base/operations/$opId" -Headers (Hdr) -TimeoutSec 10
            $state = $cur.state
        } catch {}
        if($state -eq 'finished'){ break }
    }
    if($state -ne 'finished'){
        Log "  timeout - forcing op to finished"
        try { Invoke-RestMethod -Uri "$Base/operations/$opId" -Method Patch -Headers (Hdr) -ContentType 'application/json' -Body (@{state='finished'}|ConvertTo-Json) | Out-Null } catch {}
        $state = 'finished(forced)'
    }
    $end = UtcZ
    Log "  op '$opName' done (caldera state: $state)"
    # NOTE: 1053 'failed' links are COSMETIC - success is judged by telemetry later.

    # --- 0-decision guard: an op that ran NO abilities = void trial ---
    $linkCount = 0
    try { $lk = Invoke-RestMethod -Uri "$Base/operations/$opId/links" -Headers (Hdr) -TimeoutSec 10; $linkCount = @($lk).Count } catch {}
    if($linkCount -le 0){
        Write-Host ("  *** 0 DECISIONS for {0} - adversary executed NOTHING. TRIAL VOID. Check adversary/abilities/agents. ***" -f $opName) -ForegroundColor Red
        ("{0} trial {1}: {2} = ZERO DECISIONS" -f $Scenario, $Trial, $opName) | Out-File (Join-Path $ReadyDir ("ZERODEC_{0}_{1}.txt" -f $Scenario, $Trial)) -Encoding ascii
    } else {
        Log ("  abilities executed (links): {0}" -f $linkCount)
    }

    return [pscustomobject]@{ op=$opName; id=$opId; group=$group; start=$start; end=$end; state=$state; links=$linkCount }
}

function Write-Manifest($rows){
    $dir = Split-Path $ManifestPath -Parent
    if($dir -and -not (Test-Path $dir)){ New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    foreach($r in $rows){
        [pscustomobject]@{
            scenario = $Scenario; trial = $Trial
            op = $r.op; op_id = $r.id; group = $r.group
            start_utc = $r.start; end_utc = $r.end; caldera_state = $r.state; links = $r.links
        } | Export-Csv -Path $ManifestPath -Append -NoTypeInformation
    }
    Log "  manifest += $($rows.Count) row(s) -> $ManifestPath"
}

Log "=== Scenario $Scenario  trial $Trial ==="
Clear-OpDone   # a leftover OP_DONE from an earlier trial must not release this trial's collection
$rows = @()

switch($Scenario){
    'S05' {
        $rows += Invoke-Op $AdversaryId['S05H1'] $Group['S05H1'] "S05H1-t$Trial"
        Log "  hop 1 done; starting hop 2"
        $rows += Invoke-Op $AdversaryId['S05H2'] $Group['S05H2'] "S05H2-t$Trial"
    }
    'S04' {
        $rows += Invoke-Op $AdversaryId['S04'] $Group['S04'] "S04B-t$Trial"
        Write-Host "`n*** MANUAL STEP (Owner C): run S04 Track A by hand on EP-02 NOW (admin_it, HealthAgentSvc)." -ForegroundColor Yellow
        Write-Host "*** Aim for <=10s overlap with the Track B service install just fired." -ForegroundColor Yellow
        Read-Host "Press ENTER once Track A has been run"
    }
    'S01' {
        if($AdversaryId['S01']){
            $rows += Invoke-Op $AdversaryId['S01'] $Group['S01'] "S01-t$Trial"
        } else {
            Write-Host "`n*** S01 has no Caldera adversary - run the RDP step manually now." -ForegroundColor Yellow
            Read-Host "Press ENTER once the RDP logon has been performed"
            $rows += [pscustomobject]@{ op='S01-manual'; id='-'; group=$Group['S01']; start=(UtcZ); end=(UtcZ); state='manual' }
        }
    }
    default {
        $rows += Invoke-Op $AdversaryId[$Scenario] $Group[$Scenario] "$Scenario-t$Trial"
    }
}

Write-Manifest $rows

# --- OP_DONE: automatic only if every operation finished by itself ---
$forced = @($rows | Where-Object { $_.state -eq 'finished(forced)' })
if($forced.Count -gt 0){ Confirm-OpDone $Scenario $Trial }
else                   { Write-OpDone $Scenario $Trial }

# --- tail: late steps and log writes land before anything is exported ---
Log ("  waiting {0}s tail before GO ..." -f $TailSec)
Start-Sleep -Seconds $TailSec

# --- signal the host workers to collect, then wait for them ---
Write-Go $Scenario $Trial
$ok = Wait-AllCollected $Trial

Write-Host "`n==================== $Scenario trial $Trial DONE ====================" -ForegroundColor Green
if($ok){ Write-Host "Logs collected on share: \\192.168.50.98\evtx\$Scenario\trial_$('{0:D2}' -f $Trial)\" -ForegroundColor Green }
else   { Write-Host "Collect incomplete - inspect host workers before the next trial." -ForegroundColor Yellow }
