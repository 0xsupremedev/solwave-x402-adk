# PowerShell script to check MicroAPI Hub service status
# Windows-safe version with proper quoting and error handling

param()

Write-Host "=== MicroAPI Hub Service Status ===" -ForegroundColor Cyan
Write-Host ""

# Helper function to make HTTP requests safely
function Get-JsonResponse {
    param(
        [string]$Url,
        [int]$TimeoutSeconds = 3
    )
    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec $TimeoutSeconds -ErrorAction Stop
        return $response.Content | ConvertFrom-Json
    } catch {
        return $null
    }
}

# Helper function to make POST requests
function Invoke-JsonPost {
    param(
        [string]$Url,
        [object]$Body,
        [int]$TimeoutSeconds = 5
    )
    try {
        $jsonBody = $Body | ConvertTo-Json -Depth 10
        $response = Invoke-RestMethod -Uri $Url -Method POST -ContentType "application/json" -Body $jsonBody -TimeoutSec $TimeoutSeconds -ErrorAction Stop
        return $response
    } catch {
        return $null
    }
}

# 1. Check Provider API Discovery
Write-Host "1. Provider API Discovery:" -ForegroundColor Yellow
$discoveryUrl = "http://localhost:8080/.well-known/x402"
$discovery = Get-JsonResponse -Url $discoveryUrl
if ($null -ne $discovery) {
    Write-Host "   Status: 200 OK" -ForegroundColor Green
    $endpointCount = if ($discovery.accepts) { $discovery.accepts.Count } else { 0 }
    Write-Host "   Endpoints: $endpointCount" -ForegroundColor Green
} else {
    Write-Host "   Status: Not running or unreachable" -ForegroundColor Red
}
Write-Host ""

# 2. Check Payment Verification
Write-Host "2. Payment Verification:" -ForegroundColor Yellow
$verifyUrl = "http://localhost:8787/verify"
$verifyBody = @{
    x402Version = 1
    paymentHeader = "dummy"
    paymentRequirements = @{
        scheme = "exact"
        network = "solana-devnet"
        maxAmountRequired = "1"
        resource = "GET /api/data"
        payTo = "EhYU3ZsB2LCW5yJS9tw5i12RNrhFiuVtr2Z5byZwKM3F"
        maxTimeoutSeconds = 60
        asset = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    }
}
$verifyResult = Invoke-JsonPost -Url $verifyUrl -Body $verifyBody
if ($null -ne $verifyResult) {
    Write-Host "   Status: 200 OK" -ForegroundColor Green
    Write-Host "   Valid: $($verifyResult.isValid)" -ForegroundColor $(if ($verifyResult.isValid) { "Green" } else { "Yellow" })
} else {
    Write-Host "   Status: Unreachable or error" -ForegroundColor Red
}
Write-Host ""

# 3. Check Facilitator Health
Write-Host "3. Facilitator Health:" -ForegroundColor Yellow
$healthUrl = "http://localhost:8787/health"
$health = Get-JsonResponse -Url $healthUrl
if ($null -ne $health) {
    Write-Host "   Status: 200 OK" -ForegroundColor Green
    Write-Host "   Network: $($health.network)" -ForegroundColor Green
    Write-Host "   Fee Payer: $($health.feePayer)" -ForegroundColor Green
    if ($health.settlementMode) {
        Write-Host "   Settlement Mode: $($health.settlementMode)" -ForegroundColor Green
    }
} else {
    Write-Host "   Status: Not running" -ForegroundColor Red
}
Write-Host ""

# 4. Check Web Client (if running)
Write-Host "4. Web Client:" -ForegroundColor Yellow
$webUrl = "http://localhost:3000"
try {
    $webResponse = Invoke-WebRequest -Uri $webUrl -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
    Write-Host "   Status: 200 OK" -ForegroundColor Green
    Write-Host "   URL: $webUrl" -ForegroundColor Green
} catch {
    Write-Host "   Status: Not running or starting" -ForegroundColor Yellow
}
Write-Host ""

# Summary
Write-Host "=== Summary ===" -ForegroundColor Cyan
$allServicesRunning = ($null -ne $discovery) -and ($null -ne $health)
if ($allServicesRunning) {
    Write-Host "All core services are running" -ForegroundColor Green
} else {
    Write-Host "Some services may not be running" -ForegroundColor Yellow
}
Write-Host ""
Write-Host "To start services:" -ForegroundColor Cyan
Write-Host "  Facilitator: cd services/facilitator && npm run dev" -ForegroundColor White
Write-Host "  Provider API: cd services/provider-api && npm run dev" -ForegroundColor White
Write-Host "  Web Client: cd clients/web && npm run dev" -ForegroundColor White
Write-Host ""

