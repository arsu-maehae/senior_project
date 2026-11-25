<#
=====================================================================================
 fire_scenario.ps1  -  THE CONDUCTOR (runs on PC-A)
=====================================================================================
 Launches one scenario's Caldera operation(s) via REST, waits for completion, and
 writes a manifest row with UTC start/end. Replaces clicking "start operation" in
 the Caldera UI for every trial. Runs on PC-A, talks to Caldera over HTTP.

 Per trial:
   1. A, B, C each revert + report READY (the workers write flags).
   2. A runs:  .\fire_scenario.ps1 -Scenario S02 -Trial 1 -WaitReady
   3. For S04 it pauses and tells C to run Track A by hand.
   4. Records start/end UTC to the manifest CSV.
   5. Everyone exports (export_trial.ps1), then next trial.

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
    [int]$OpTimeoutSec    = 300,
    [string]$Jitter       = '2/8',
    [string]$Obfuscator   = 'plain-text',

    [switch]$WaitReady,
    [string]$ReadyDir           = 'D:\evtx_share\ready',
    [int]$WaitReadyTimeoutSec   = 1800,
    [int]$ReadyMaxAgeMin        = 30,
    [int]$CollectTimeoutSec     = 1800,

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

function Wait-AllReady(){
    Log "waiting for ready flags (A,B,C) in $ReadyDir ..."
    $deadline = (Get-Date).AddSeconds($WaitReadyTimeoutSec)
    while((Get-Date) -lt $deadline){
        $have = @()
        foreach($o in 'A','B','C'){
            $f = Join-Path $ReadyDir "READY_$o.txt"
            if(Test-Path $f){
                $age = (New-TimeSpan -Start (Get-Item $f).LastWriteTime -End (Get-Date)).TotalMinutes
                if($age -le $ReadyMaxAgeMin){ $have += $o }
            }
        }
        if($have.Count -eq 3){ Log "  all three READY (A,B,C)"; return $true }
        Write-Host ("  have: {0}   (waiting...)" -f ($have -join ',')) -ForegroundColor DarkYellow
        Start-Sleep -Seconds 5
    }
    throw "timed out waiting for ready flags - have only: $($have -join ',')"
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

if($WaitReady){ Wait-AllReady | Out-Null }

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

# --- signal the host workers to collect, then wait for them ---
Write-Go $Scenario $Trial
$ok = Wait-AllCollected $Trial

Write-Host "`n==================== $Scenario trial $Trial DONE ====================" -ForegroundColor Green
if($ok){ Write-Host "Logs collected on share: \\192.168.50.98\evtx\$Scenario\trial_$('{0:D2}' -f $Trial)\" -ForegroundColor Green }
else   { Write-Host "Collect incomplete - inspect host workers before the next trial." -ForegroundColor Yellow }
