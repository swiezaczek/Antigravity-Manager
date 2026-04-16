# ============================================================
# CZYSTY ZRZUT RUCHU ANTIGRAVITY IDE
# Metoda: Proxifier + mitmproxy
# ============================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " ANTIGRAVITY CLEAN CAPTURE" -ForegroundColor Cyan
Write-Host " Proxifier + mitmproxy" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# --- KROK 0: Wyłącz Manager ---
Write-Host "`n[0] Zamykam Manager..." -ForegroundColor Yellow
Get-Process -Name "*Antigravity*Manager*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# --- KROK 1: Certyfikat mitmproxy ---
$mitmCert = "$env:USERPROFILE\.mitmproxy\mitmproxy-ca-cert.cer"
Write-Host "[1] Certyfikat CA..." -ForegroundColor Yellow

if (-not (Test-Path $mitmCert)) {
    Write-Host "   Generuję certyfikat (uruchamiam mitmdump na chwilę)..." -ForegroundColor Yellow
    $tmp = Start-Process mitmdump -ArgumentList "--listen-port 19999" -PassThru -WindowStyle Hidden
    Start-Sleep 3; $tmp | Stop-Process -Force -ErrorAction SilentlyContinue
}

if (Test-Path $mitmCert) {
    $installed = Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | Where-Object { $_.Subject -like "*mitmproxy*" }
    if (-not $installed) {
        Write-Host "   Instaluję certyfikat do Trusted Root..." -ForegroundColor Yellow
        certutil -addstore root $mitmCert 2>$null | Out-Null
    }
    Write-Host "   Certyfikat OK" -ForegroundColor Green
} else {
    Write-Host "   UWAGA: Brak certyfikatu. Wygeneruj ręcznie." -ForegroundColor Red
}

# --- KROK 2: Przygotuj plik zrzutu ---
$DUMP_FILE = "C:\test\clean_antigravity_$(Get-Date -Format 'MMdd-HHmmss').mitm"
if (-not (Test-Path "C:\test")) { New-Item -ItemType Directory "C:\test" -Force | Out-Null }

# --- KROK 3: Uruchom mitmdump jako SOCKS5 (8080) ---
Write-Host "[2] Uruchamiam mitmdump (port 8080, HTTPS + SOCKS5)..." -ForegroundColor Yellow
$mitm = Start-Process mitmdump -ArgumentList "--mode regular --listen-port 8080 -w `"$DUMP_FILE`" --set flow_detail=0" -PassThru
Start-Sleep 2

if ($mitm.HasExited) {
    Write-Host "   BŁĄD: mitmdump nie wystartował (port 8080 zajęty?)" -ForegroundColor Red
    exit 1
}
Write-Host "   mitmdump PID: $($mitm.Id)" -ForegroundColor Green
Write-Host "   Zapis do: $DUMP_FILE" -ForegroundColor Green

# --- INSTRUKCJA PROXIFIER ---
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " INSTRUKCJA PROXIFIER" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Otwórz Proxifier" -ForegroundColor White
Write-Host ""
Write-Host "2. Profile -> Proxy Servers -> Add:" -ForegroundColor White
Write-Host "   Address: 127.0.0.1" -ForegroundColor Green
Write-Host "   Port:    8080" -ForegroundColor Green
Write-Host "   Protocol: HTTPS" -ForegroundColor Green
Write-Host "   [OK]" -ForegroundColor Gray
Write-Host ""
Write-Host "3. Profile -> Proxification Rules -> Add:" -ForegroundColor White
Write-Host "   Name:         Antigravity Capture" -ForegroundColor Green
Write-Host "   Applications: Antigravity.exe; antigravity.exe" -ForegroundColor Green
Write-Host "   Action:       Proxy HTTPS 127.0.0.1:8080" -ForegroundColor Green
Write-Host "   [OK]" -ForegroundColor Gray
Write-Host ""
Write-Host "4. WAŻNE - Default Rule:" -ForegroundColor Yellow
Write-Host "   Ustaw na: Direct (żeby inne apki NIE szły przez proxy)" -ForegroundColor Yellow
Write-Host ""
Write-Host "5. Upewnij się że reguła 'Antigravity Capture'" -ForegroundColor White
Write-Host "   jest POWYŻEJ Default Rule" -ForegroundColor Yellow
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Gdy Proxifier jest skonfigurowany," -ForegroundColor White
Write-Host "uruchom Antigravity IDE normalnie" -ForegroundColor White
Write-Host "(z menu Start lub skrótem)." -ForegroundColor White
Write-Host ""
Write-Host "Proxifier automatycznie przekieruje CAŁY ruch" -ForegroundColor Green
Write-Host "procesu Antigravity.exe przez mitmproxy." -ForegroundColor Green
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " CO ZROBIĆ W ANTIGRAVITY IDE:" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  1. Zaloguj się na konto Google" -ForegroundColor White
Write-Host "  2. Poczekaj na pełne załadowanie" -ForegroundColor White
Write-Host "  3. Otwórz chat, zadaj pytanie" -ForegroundColor White
Write-Host "  4. Poczekaj na odpowiedź" -ForegroundColor White
Write-Host "  5. (Opcja) Wyloguj się" -ForegroundColor White
Write-Host "  6. Zamknij IDE" -ForegroundColor White
Write-Host ""
Write-Host "========================================" -ForegroundColor Yellow
Write-Host ""

Read-Host "Gdy skończysz -> naciśnij [Enter] aby zatrzymać przechwytywanie"

# --- CLEANUP ---
Write-Host "`nZatrzymuję mitmdump..." -ForegroundColor Yellow
$mitm | Stop-Process -Force -ErrorAction SilentlyContinue

$fileSize = (Get-Item $DUMP_FILE -ErrorAction SilentlyContinue).Length
$fileSizeMB = if ($fileSize) { [math]::Round($fileSize / 1MB, 2) } else { 0 }

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host " GOTOWE!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host " Zrzut: $DUMP_FILE" -ForegroundColor Cyan
Write-Host " Rozmiar: $fileSizeMB MB" -ForegroundColor Cyan
Write-Host ""
Write-Host "Szybki podgląd URL-ów:" -ForegroundColor White
Write-Host "  mitmdump -n -r `"$DUMP_FILE`" 2>`$null" -ForegroundColor Gray
Write-Host ""
Write-Host "PAMIĘTAJ: Wyłącz regułę w Proxifier" -ForegroundColor Yellow
Write-Host "po zakończeniu przechwytywania!" -ForegroundColor Yellow
