[CmdletBinding()]
param(
    [string]$Url = "http://localhost:8000",
    [string]$ApiKey = "",
    [string]$StateFile = (Join-Path $env:USERPROFILE ".securewatch-windows-agent.json"),
    [string]$SourceId = "windows-security",
    [int]$IntervalSeconds = 15,
    [int]$LookbackMinutes = 10,
    [int]$BatchSize = 200,
    [switch]$Once
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $ApiKey) {
    if ($env:SW_INGEST_KEY) { $ApiKey = $env:SW_INGEST_KEY }
    elseif ($env:INGEST_KEY) { $ApiKey = $env:INGEST_KEY }
}
if (-not $ApiKey) {
    throw "Set SW_INGEST_KEY or pass -ApiKey."
}
if ($BatchSize -lt 1 -or $BatchSize -gt 500) {
    throw "BatchSize must be between 1 and 500."
}
if ($LookbackMinutes -lt 1) {
    throw "LookbackMinutes must be at least 1."
}

function Get-LastRecordId {
    if (-not (Test-Path -LiteralPath $StateFile)) { return [int64]0 }
    try {
        $state = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
        if ($state.source_id -eq $SourceId) { return [int64]$state.record_id }
    } catch {
        Write-Warning "Ignoring unreadable state file $StateFile"
    }
    return [int64]0
}

function Save-LastRecordId {
    param([int64]$RecordId)
    $directory = Split-Path -Parent $StateFile
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    $temporary = "$StateFile.tmp"
    @{ source_id = $SourceId; record_id = $RecordId } |
        ConvertTo-Json |
        Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $StateFile -Force
}

function Send-Events {
    param([object[]]$Events)
    if (-not $Events -or $Events.Count -eq 0) { return }
    $body = ConvertTo-Json -InputObject @{ events = @($Events) } -Depth 8 -Compress
    $headers = @{ "X-API-Key" = $ApiKey }
    $endpoint = "$($Url.TrimEnd('/'))/events/ingest"

    for ($attempt = 1; $attempt -le 5; $attempt++) {
        try {
            $result = Invoke-RestMethod -Uri $endpoint -Method Post -Headers $headers -ContentType "application/json" -Body $body -TimeoutSec 30
            Write-Output ("shipped {0} events: {1}" -f $Events.Count, ($result | ConvertTo-Json -Compress))
            return
        } catch {
            $status = $null
            if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
            if ($status -in @(400, 401, 403)) {
                throw "Ingestion rejected ($status): $($_.Exception.Message)"
            }
            if ($attempt -eq 5) { throw }
            Write-Warning "send failed (attempt $attempt/5): $($_.Exception.Message)"
            Start-Sleep -Seconds ([Math]::Min(2 * $attempt, 10))
        }
    }
}

function Convert-WinEvent {
    param($Record)
    $xml = [xml]$Record.ToXml()
    $data = @{}
    foreach ($item in $xml.Event.EventData.Data) {
        if ($item.Name) { $data[$item.Name] = [string]$item.'#text' }
    }

    $ip = $data["IpAddress"]
    if (-not $ip -or $ip -eq "-" -or $ip -eq "::1") { $ip = "0.0.0.0" }
    $user = $data["TargetUserName"]
    if (-not $user) { $user = "-" }

    $eventType = if ($Record.Id -eq 4625) { "login_failed" } else { "login_success" }
    $detail = "EventID=$($Record.Id) Status=$($data['Status']) SubStatus=$($data['SubStatus']) LogonType=$($data['LogonType']) Workstation=$($data['WorkstationName'])"
    $timestamp = ([DateTimeOffset]$Record.TimeCreated).ToUnixTimeSeconds()

    return [ordered]@{
        source_id = $SourceId
        ip = $ip
        user = $user
        event_type = $eventType
        country = "-"
        detail = $detail.Substring(0, [Math]::Min(4000, $detail.Length))
        role = $null
        ts = $timestamp
    }
}

$lastRecordId = Get-LastRecordId
Write-Output "watching Security log 4624/4625 from record $lastRecordId"

while ($true) {
    $startTime = (Get-Date).AddMinutes(-1 * $LookbackMinutes)
    try {
        $records = @(
            Get-WinEvent -FilterHashtable @{ LogName = "Security"; Id = @(4624, 4625); StartTime = $startTime } -ErrorAction Stop |
                Where-Object { [int64]$_.RecordId -gt $lastRecordId } |
                Sort-Object RecordId
        )
    } catch {
        if ($_.Exception.Message -match "No events were found") {
            $records = @()
        } else {
            throw "Cannot read the Security log. Run this agent as Administrator. $($_.Exception.Message)"
        }
    }

    $events = @($records | ForEach-Object { Convert-WinEvent -Record $_ })
    for ($index = 0; $index -lt $events.Count; $index += $BatchSize) {
        $end = [Math]::Min($index + $BatchSize, $events.Count) - 1
        $chunk = $events[$index..$end]
        Send-Events -Events $chunk
    }

    if ($records.Count -gt 0) {
        $lastRecordId = [int64]($records[-1].RecordId)
        Save-LastRecordId -RecordId $lastRecordId
    }

    if ($Once) { break }
    Start-Sleep -Seconds $IntervalSeconds
}
