#!/bin/bash

# File Transfer Script with Menu
# Enhanced with dependency checking, installation, and error handling

INI_FILE="$HOME/.file_transfer_devices.ini"
LOG_FILE="$HOME/.file_transfer.log"
REMOTE_LOG_PATH="$HOME/.file_transfer.log"
TRANSFER_METHOD=""  # Will be set based on available tools

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to detect package manager
detect_package_manager() {
    if command -v apt-get &> /dev/null; then
        echo "apt"
    elif command -v yum &> /dev/null; then
        echo "yum"
    elif command -v dnf &> /dev/null; then
        echo "dnf"
    elif command -v pacman &> /dev/null; then
        echo "pacman"
    elif command -v zypper &> /dev/null; then
        echo "zypper"
    else
        echo "unknown"
    fi
}

# Function to install package
install_package() {
    local package="$1"
    local pkg_manager=$(detect_package_manager)
    
    echo -e "${YELLOW}Attempting to install $package...${NC}"
    
    case $pkg_manager in
        apt)
            sudo apt-get update && sudo apt-get install -y "$package"
            ;;
        yum)
            sudo yum install -y "$package"
            ;;
        dnf)
            sudo dnf install -y "$package"
            ;;
        pacman)
            sudo pacman -S --noconfirm "$package"
            ;;
        zypper)
            sudo zypper install -y "$package"
            ;;
        *)
            echo -e "${RED}Unknown package manager. Please install $package manually.${NC}"
            return 1
            ;;
    esac
    
    return $?
}

# Function to check and install dependencies
check_dependencies() {
    echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║   CHECKING SYSTEM DEPENDENCIES...      ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
    echo ""
    
    local all_good=true
    
    # Check for essential tools
    echo -e "${BLUE}Checking essential tools...${NC}"
    
    # Check SSH
    if command -v ssh &> /dev/null; then
        echo -e "${GREEN}✓ SSH found${NC}"
    else
        echo -e "${RED}✗ SSH not found${NC}"
        echo -e "${YELLOW}SSH is required for remote connections.${NC}"
        echo -e "${BLUE}Do you want to install openssh-client? (y/n)${NC}"
        read -r response
        if [[ "$response" == "y" ]]; then
            if install_package "openssh-client"; then
                echo -e "${GREEN}✓ SSH installed successfully${NC}"
            else
                echo -e "${RED}✗ Failed to install SSH${NC}"
                all_good=false
            fi
        else
            all_good=false
        fi
    fi
    
    # Check for transfer methods (rsync, sftp, ftp)
    echo ""
    echo -e "${BLUE}Checking file transfer methods...${NC}"
    
    # Check rsync (preferred)
    if command -v rsync &> /dev/null; then
        echo -e "${GREEN}✓ rsync found (recommended method)${NC}"
        TRANSFER_METHOD="rsync"
    else
        echo -e "${YELLOW}✗ rsync not found${NC}"
        echo -e "${BLUE}rsync is the recommended method for efficient file transfers.${NC}"
        echo -e "${BLUE}Do you want to install rsync? (y/n)${NC}"
        read -r response
        if [[ "$response" == "y" ]]; then
            if install_package "rsync"; then
                echo -e "${GREEN}✓ rsync installed successfully${NC}"
                TRANSFER_METHOD="rsync"
            else
                echo -e "${RED}✗ Failed to install rsync${NC}"
            fi
        fi
    fi
    
    # Check sftp (fallback)
    if [ -z "$TRANSFER_METHOD" ]; then
        if command -v sftp &> /dev/null; then
            echo -e "${GREEN}✓ sftp found (fallback method)${NC}"
            TRANSFER_METHOD="sftp"
        else
            echo -e "${YELLOW}✗ sftp not found${NC}"
        fi
    else
        if command -v sftp &> /dev/null; then
            echo -e "${GREEN}✓ sftp available as fallback${NC}"
        fi
    fi
    
    # Check ftp (last resort)
    if [ -z "$TRANSFER_METHOD" ]; then
        if command -v ftp &> /dev/null; then
            echo -e "${YELLOW}✓ ftp found (least secure, not recommended)${NC}"
            TRANSFER_METHOD="ftp"
        else
            echo -e "${RED}✗ ftp not found${NC}"
            echo -e "${RED}No file transfer methods available!${NC}"
            all_good=false
        fi
    else
        if command -v ftp &> /dev/null; then
            echo -e "${YELLOW}✓ ftp available (not recommended due to security)${NC}"
        fi
    fi
    
    # Check optional tools
    echo ""
    echo -e "${BLUE}Checking optional tools...${NC}"
    
    if command -v nmap &> /dev/null; then
        echo -e "${GREEN}✓ nmap found (for network scanning)${NC}"
    else
        echo -e "${YELLOW}○ nmap not found (optional, improves network scanning)${NC}"
    fi
    
    if command -v nc &> /dev/null; then
        echo -e "${GREEN}✓ netcat found (for connectivity testing)${NC}"
    else
        echo -e "${YELLOW}○ netcat not found (optional, for connectivity testing)${NC}"
    fi
    
    # Summary
    echo ""
    echo -e "${CYAN}════════════════════════════════════════${NC}"
    
    if [ "$all_good" = true ] && [ -n "$TRANSFER_METHOD" ]; then
        echo -e "${GREEN}✓ All required dependencies satisfied${NC}"
        echo -e "${GREEN}✓ Transfer method: $TRANSFER_METHOD${NC}"
        echo -e "${CYAN}════════════════════════════════════════${NC}"
        echo ""
        return 0
    else
        echo -e "${RED}✗ Missing critical dependencies${NC}"
        echo -e "${RED}Please install missing packages manually or run as root/sudo${NC}"
        echo -e "${CYAN}════════════════════════════════════════${NC}"
        echo ""
        return 1
    fi
}

# Function to test connectivity
test_connectivity() {
    local host="$1"
    local timeout=3
    local show_progress="$2"  # Optional: show progress indicator
    
    if [ "$show_progress" == "true" ]; then
        (
            # Try ping first
            if ping -c 1 -W "$timeout" "$host" &>/dev/null; then
                exit 0
            fi
            
            # Try nc if available
            if command -v nc &> /dev/null; then
                if nc -z -w "$timeout" "$host" 22 &>/dev/null; then
                    exit 0
                fi
            fi
            exit 1
        ) &
        local test_pid=$!
        show_spinner $test_pid "Testing connectivity to $host..."
        wait $test_pid
        return $?
    else
        # Try ping first
        if ping -c 1 -W "$timeout" "$host" &>/dev/null; then
            return 0
        fi
        
        # Try nc if available
        if command -v nc &> /dev/null; then
            if nc -z -w "$timeout" "$host" 22 &>/dev/null; then
                return 0
            fi
        fi
        
        return 1
    fi
}

# Function to validate IP address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Function to validate path
validate_path() {
    local path="$1"
    local check_exists="$2"
    
    if [ -z "$path" ]; then
        echo -e "${RED}Error: Path cannot be empty${NC}"
        return 1
    fi
    
    if [ "$check_exists" == "true" ] && [ ! -e "$path" ]; then
        echo -e "${RED}Error: Path does not exist: $path${NC}"
        return 1
    fi
    
    return 0
}

# Function to log messages with error handling
log_message() {
    local message="$1"
    local log_entry="[$(date '+%Y-%m-%d %H:%M:%S')] $message"
    
    # Try to write to log file
    if echo "$log_entry" >> "$LOG_FILE" 2>/dev/null; then
        return 0
    else
        echo -e "${YELLOW}Warning: Could not write to log file: $LOG_FILE${NC}"
        # Try to create the log file with proper permissions
        touch "$LOG_FILE" 2>/dev/null || {
            echo -e "${RED}Error: Cannot create log file. Check permissions.${NC}"
            return 1
        }
        echo "$log_entry" >> "$LOG_FILE"
    fi
}

# Function to get local IP address
get_local_ip() {
    local ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [ -z "$ip" ]; then
        ip=$(ip route get 1 2>/dev/null | awk '{print $7; exit}')
    fi
    if [ -z "$ip" ]; then
        ip="127.0.0.1"
    fi
    echo "$ip"
}

# Function to get hostname
get_hostname() {
    hostname 2>/dev/null || echo "unknown"
}

# Function to show a spinner
show_spinner() {
    local pid=$1
    local message=$2
    local spin='-\|/'
    local i=0
    
    while kill -0 $pid 2>/dev/null; do
        i=$(( (i+1) %4 ))
        printf "\r${CYAN}${spin:$i:1} ${message}${NC}"
        sleep 0.1
    done
    printf "\r"
}

# Function to show progress bar
show_progress_bar() {
    local current=$1
    local total=$2
    local width=50
    local percentage=$((current * 100 / total))
    local completed=$((width * current / total))
    local remaining=$((width - completed))
    
    printf "\r${CYAN}["
    printf "%${completed}s" | tr ' ' '='
    printf "%${remaining}s" | tr ' ' '-'
    printf "] ${percentage}%% (${current}/${total})${NC}"
    
    if [ $current -eq $total ]; then
        printf "\n"
    fi
}

# Function to get manufacturer from MAC address
get_manufacturer() {
    local mac="$1"
    
    # Extract first 3 octets (OUI - Organizationally Unique Identifier)
    local oui=$(echo "$mac" | tr '[:lower:]' '[:upper:]' | sed 's/[:-]//g' | cut -c1-6)
    
    # Common manufacturers based on OUI prefixes
    case "$oui" in
        000320|000321|000322|000323|000324|000325|000326|000327|000328|000329|00032A|00032B|00032C|00032D|00032E|00032F|001CB3|0019E3|0021E9|002332|00254B|002500|0026BB|00269E|0050E4|001124|001D4F|001E52|001EC2|001F5B|001FF3)
            echo "Apple"
            ;;
        B827EB|DCA632|E45F01|DC2395)
            echo "Raspberry Pi Foundation"
            ;;
        00156D|001517|001E67|001F3C|002170|0022FA|00235A|0024D7|002655|D8D380|D8D381|D8D382|D8D383|D8D384|D8D385|D8D386|D8D387|D8D388|D8D389|D8D38A|D8D38B|D8D38C|D8D38D|D8D38E|D8D38F)
            echo "Intel"
            ;;
        000874|000BDB|000D56|000E0C|000F1F|001372|001422|0015C5|001676|001731|0018FE|001A4B|001B78|001D09|001E4F|001EC9|002219|00234E|0025B3|002564|00304B|5C2609|B8CA3A)
            echo "Dell"
            ;;
        001279|0016B9|001A4B|001B78|001D09|001E0B|001F28|002264|0024A5|0025B3|0030C1|9C8E99|2C27D7|A0D3C1)
            echo "HP"
            ;;
        0001C7|000142|000163|000164|000D65|000ED7|000F8F|001046|0011BB|001192|00179A|0018B9|001A2F|001B0C|001C0E|001D70|001E13|001E14|001E79|001F27|001F6C|001FC9|002155)
            echo "Cisco"
            ;;
        001B11|002722|002723|080022|080023|0C8268|188B9D|1C3BF3|2C3033|3094ED|4C09B4|5C4CA9|64517E|74EA3A|7CF05F|8416F9|90F652|98DED0|A0F3C1|C0A0BB|D46E0E|EC172F|F0B429|F4EC38|F8D111)
            echo "TP-Link"
            ;;
        000562|00055D|000D88|001195|001346|0015E9|001CF0|001E58|001B11|00179A|002191|0022B0|0024B2|14D64D|28107B|3C1E04|5CD998|C0A0BB)
            echo "D-Link"
            ;;
        00072F|000EA6|000F66|001109|001731|001D60|001E8C|001FC6|002618|00E018|04421A|107B44|10BF48|10C37B|14DDA9|1C872C|2C56DC|30852E|382C4A|3C970E|40167E|50465D|54A050|60A44C|704D7B|742F68|78542E|7C2664|88D7F6|9C5C8E|AC220B|AC9E17|B06EBF|BC773E|C86000|D017C2|F832E4)
            echo "ASUS"
            ;;
        0002FC|000690|0007AB|000825|000E92|000EED|000F44|001083|0013E0|001485|0015B9|0016DB|0018AF|001974|001A8A|001D25|001E7D|001EE1|001EE2|002566|0026FC|0050BF|1866DA|3451C9|5C0A5B|60D0A9|68A3C4|7825AD|889BDD|8C77C3|9003B7|A02195|A06518|A4EB12|ACF7F3|B07994|B4EF39|C0145D|C85B76|CC07AB|D07AE2|D0DF9A|D49A20|D8635B|E81132|E820E8|EC9BF3|F0257E)
            echo "Samsung"
            ;;
        00095B|000FB5|001B2F|001E2A|001F33|002275|00223F|002462|002463|002464|002465|002CF1|0024B2|08028E|08863B|0C3000|10BF48|10DA43|2C3033|30469A|3448ED|406CB9|4CB16D|84B243|84D47E|A0155C|A21274|A42B8C|B0B98A|C05626|C43DC7|E091F5|E0469A)
            echo "Netgear"
            ;;
        001132|00112C|001322)
            echo "Synology"
            ;;
        001C10|0050F6|24F5AA)
            echo "QNAP"
            ;;
        000569|000C29|005056)
            echo "VMware"
            ;;
        080027)
            echo "VirtualBox"
            ;;
        00032D|000D3A|001DD8|002248|002713|00D1D2|10604B|182666|1C697A|281878|281879|34E2FD|38EAA7|48BC5E|5C7CDB|60F8A0|60F81D|68A3C4|784521|7C5049|807C10|807C11|807C12|807C13|807C14|807C15|807C16|807C17|807C18|807C19|989096|98F2B3|9CD917|A4341A|A83E51|A83E52|B46BFC|C80AA9|D0176A|D8CB8A|E0D55E|E80910|F4A7F7)
            echo "Microsoft"
            ;;
        00FC8B|081F71|50A52B|747548|84E0F4|B0FC36|C44F33|E86CB8|F0D2F1)
            echo "Amazon"
            ;;
        3C5A37|54E43A|6476BA|68CAE4|786A89|B4F61C|CC2940|CC2941|CC2942|CC2943|CC2944|CC2945|CC2946|CC2947|CC2948|CC2949|D86612|E4F04C|F4F5E8)
            echo "Google"
            ;;
        *)
            echo "Unknown"
            ;;
    esac
}


# Function to scan network for devices with enhanced detection
scan_network() {
    local local_ip=$(get_local_ip)
    local network=$(echo "$local_ip" | cut -d'.' -f1-3).0/24
    
    echo -e "${YELLOW}Scanning network $network for active devices...${NC}" >&2
    
    # Check if nmap is available
    if ! command -v nmap &> /dev/null; then
        echo -e "${RED}Error: nmap is required for network discovery${NC}" >&2
        echo -e "${YELLOW}Install nmap:${NC}" >&2
        echo -e "  Ubuntu/Debian: ${CYAN}sudo apt-get install nmap${NC}" >&2
        return 1
    fi
    
    echo -e "${CYAN}Using nmap -sn...${NC}" >&2
    
    # Check if running as root/sudo for MAC detection
    local sudo_prefix=""
    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}Note: Run with sudo for MAC address detection${NC}" >&2
        echo -e "${BLUE}Use sudo? (y/n)${NC}" >&2
        read -r -t 5 use_sudo || use_sudo="n"
        if [[ "$use_sudo" == "y" ]]; then
            sudo_prefix="sudo"
        fi
    fi
    
    # Run nmap and capture output
    echo -e "${CYAN}Scanning (please wait 5-10 seconds)...${NC}" >&2
    
    local nmap_output
    if [ -n "$sudo_prefix" ]; then
        nmap_output=$($sudo_prefix nmap -sn "$network" 2>/dev/null)
    else
        nmap_output=$(nmap -sn "$network" 2>/dev/null)
    fi
    
    echo -e "${GREEN}✓ Scan complete${NC}" >&2
    echo "" >&2
    
    # Parse output
    local current_ip=""
    local current_hostname=""
    local current_mac=""
    local current_vendor=""
    
    while IFS= read -r line; do
        if [[ "$line" =~ Nmap\ scan\ report\ for\ ([^\ ]+)\ \(([0-9.]+)\) ]]; then
            # Save previous entry
            if [ -n "$current_ip" ]; then
                local mfr="Unknown"
                if [ -n "$current_mac" ]; then
                    mfr=$(get_manufacturer "$current_mac")
                    [ "$mfr" == "Unknown" ] && [ -n "$current_vendor" ] && mfr="$current_vendor"
                fi
                echo "$current_ip|$current_hostname|${current_mac:-N/A}|${mfr}"
            fi
            current_hostname="${BASH_REMATCH[1]}"
            current_ip="${BASH_REMATCH[2]}"
            current_mac=""
            current_vendor=""
            
        elif [[ "$line" =~ Nmap\ scan\ report\ for\ ([0-9.]+) ]]; then
            # Save previous entry
            if [ -n "$current_ip" ]; then
                local mfr="Unknown"
                if [ -n "$current_mac" ]; then
                    mfr=$(get_manufacturer "$current_mac")
                    [ "$mfr" == "Unknown" ] && [ -n "$current_vendor" ] && mfr="$current_vendor"
                fi
                echo "$current_ip|$current_hostname|${current_mac:-N/A}|${mfr}"
            fi
            current_ip="${BASH_REMATCH[1]}"
            current_hostname="$current_ip"
            current_mac=""
            current_vendor=""
            
        elif [[ "$line" =~ MAC\ Address:\ ([0-9A-Fa-f:]{17})\ \((.+)\) ]]; then
            current_mac="${BASH_REMATCH[1]}"
            current_vendor="${BASH_REMATCH[2]}"
        fi
    done <<< "$nmap_output"
    
    # Save last entry
    if [ -n "$current_ip" ]; then
        local mfr="Unknown"
        if [ -n "$current_mac" ]; then
            mfr=$(get_manufacturer "$current_mac")
            [ "$mfr" == "Unknown" ] && [ -n "$current_vendor" ] && mfr="$current_vendor"
        fi
        echo "$current_ip|$current_hostname|${current_mac:-N/A}|${mfr}"
    fi
}

# Function to auto-discover and add network devices
auto_discover_devices() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║     AUTO-DISCOVER NETWORK DEVICES      ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
    echo ""
    
    local local_ip=$(get_local_ip)
    
    echo -e "${BLUE}Starting network scan...${NC}"
    echo ""
    
    # Perform scan
    local scan_results=$(mktemp)
    scan_network > "$scan_results"
    
    if [ ! -s "$scan_results" ]; then
        echo -e "${YELLOW}No devices found on network${NC}"
        rm -f "$scan_results"
        return 1
    fi
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                          DISCOVERED DEVICES                                ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Print header
    printf "${CYAN}%-4s %-15s %-25s %-19s %-20s${NC}\n" "ID" "IP Address" "Hostname" "MAC Address" "Manufacturer"
    printf "${CYAN}%-4s %-15s %-25s %-19s %-20s${NC}\n" "----" "---------------" "-------------------------" "-------------------" "--------------------"
    
    # Read existing devices to avoid duplicates
    declare -A existing_devices
    if [ -f "$INI_FILE" ]; then
        while IFS='|' read -r type ip hostname; do
            [ -z "$ip" ] && continue
            [[ "$ip" =~ ^#.*$ ]] && continue
            existing_devices["$ip"]=1
        done < "$INI_FILE"
    fi
    
    # Display discovered devices in table format
    local count=0
    declare -A new_devices
    
    while IFS='|' read -r ip hostname mac manufacturer; do
        [ -z "$ip" ] && continue
        
        # Skip local IP
        if [ "$ip" == "$local_ip" ]; then
            continue
        fi
        
        # Truncate long names for display
        local display_hostname=$(echo "$hostname" | cut -c1-25)
        local display_manufacturer=$(echo "$manufacturer" | cut -c1-20)
        
        # Check if already in INI
        if [ -n "${existing_devices[$ip]}" ]; then
            printf "${YELLOW}%-4s${NC} %-15s %-25s %-19s %-20s ${YELLOW}[EXISTS]${NC}\n" \
                "-" "$ip" "$display_hostname" "$mac" "$display_manufacturer"
        else
            ((count++))
            new_devices["$count"]="$ip|$hostname|$mac|$manufacturer"
            printf "${GREEN}%-4s${NC} %-15s %-25s %-19s %-20s ${GREEN}[NEW]${NC}\n" \
                "$count" "$ip" "$display_hostname" "$mac" "$display_manufacturer"
        fi
    done < "$scan_results"
    
    rm -f "$scan_results"
    
    if [ $count -eq 0 ]; then
        echo ""
        echo -e "${YELLOW}No new devices to add${NC}"
        return 0
    fi
    
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Found $count new device(s)${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    echo -e "${BLUE}Add devices to configuration:${NC}"
    echo -e "  ${CYAN}1.${NC} Add all new devices"
    echo -e "  ${CYAN}2.${NC} Add selected devices"
    echo -e "  ${CYAN}3.${NC} Skip"
    read -r choice
    
    case $choice in
        1)
            # Add all devices
            echo ""
            echo -e "${CYAN}Adding all devices...${NC}"
            for key in "${!new_devices[@]}"; do
                IFS='|' read -r ip hostname mac manufacturer <<< "${new_devices[$key]}"
                echo "REMOTE|$ip|$hostname" >> "$INI_FILE"
                echo -e "${GREEN}✓ Added: $hostname ($ip) [$manufacturer]${NC}"
                log_message "AUTO-DISCOVERED|$hostname|$ip|$mac|$manufacturer"
            done
            echo -e "${GREEN}✓ All devices added successfully${NC}"
            ;;
        2)
            # Add selected devices
            echo ""
            echo -e "${BLUE}Enter device IDs to add (space-separated, e.g., 1 3 5):${NC}"
            read -r selections
            
            for num in $selections; do
                if [ -n "${new_devices[$num]}" ]; then
                    IFS='|' read -r ip hostname mac manufacturer <<< "${new_devices[$num]}"
                    echo "REMOTE|$ip|$hostname" >> "$INI_FILE"
                    echo -e "${GREEN}✓ Added: $hostname ($ip) [$manufacturer]${NC}"
                    log_message "AUTO-DISCOVERED|$hostname|$ip|$mac|$manufacturer"
                else
                    echo -e "${RED}✗ Invalid selection: $num${NC}"
                fi
            done
            ;;
        3)
            echo -e "${YELLOW}Skipped adding devices${NC}"
            return 0
            ;;
        *)
            echo -e "${RED}Invalid choice${NC}"
            return 1
            ;;
    esac
    
    return 0
}

# Function to create or update INI file with error handling
update_ini_file() {
    local mode="$1"
    
    # Check if we can write to the file
    if [ -f "$INI_FILE" ] && [ ! -w "$INI_FILE" ]; then
        echo -e "${RED}Error: INI file exists but is not writable: $INI_FILE${NC}"
        return 1
    fi
    
    if [ "$mode" == "create" ] || [ ! -f "$INI_FILE" ]; then
        echo -e "${GREEN}Creating INI file: $INI_FILE${NC}"
        
        if ! cat > "$INI_FILE" 2>/dev/null <<EOF
# File Transfer Devices Configuration
# Format: TYPE|IP|HOSTNAME
# TYPE can be: LOCAL, REMOTE

EOF
        then
            echo -e "${RED}Error: Cannot create INI file. Check permissions.${NC}"
            return 1
        fi
        
        # Add local device
        local local_ip=$(get_local_ip)
        local local_host=$(get_hostname)
        echo "LOCAL|$local_ip|$local_host" >> "$INI_FILE"
        
        log_message "INI file created with local device: $local_host ($local_ip)"
    fi
    
    echo ""
    echo -e "${BLUE}How would you like to add devices?${NC}"
    echo -e "  ${CYAN}1.${NC} Auto-discover devices on network (recommended)"
    echo -e "  ${CYAN}2.${NC} Add devices manually"
    echo -e "  ${CYAN}3.${NC} Skip for now"
    read -r add_method
    
    case $add_method in
        1)
            auto_discover_devices
            ;;
        2)
            # Manual entry
            while true; do
                echo ""
                echo -e "${BLUE}Enter remote device IP address (or 'done' to finish):${NC}"
                read -r remote_ip
                
                [ "$remote_ip" == "done" ] && break
                
                # Validate IP
                if ! validate_ip "$remote_ip"; then
                    echo -e "${RED}Invalid IP address format${NC}"
                    continue
                fi
                
                # Check if already exists
                if grep -q "|$remote_ip|" "$INI_FILE" 2>/dev/null; then
                    echo -e "${YELLOW}Device with IP $remote_ip already exists${NC}"
                    continue
                fi
                
                # Test connectivity
                echo -e "${YELLOW}Testing connectivity to $remote_ip...${NC}"
                if test_connectivity "$remote_ip" "true"; then
                    echo -e "${GREEN}✓ Host is reachable${NC}"
                else
                    echo -e "${YELLOW}⚠ Warning: Cannot reach host (may be firewalled)${NC}"
                    echo -e "${BLUE}Add anyway? (y/n)${NC}"
                    read -r add_anyway
                    if [[ "$add_anyway" != "y" ]]; then
                        continue
                    fi
                fi
                
                echo -e "${BLUE}Enter hostname for $remote_ip:${NC}"
                read -r remote_host
                
                if [ -z "$remote_host" ]; then
                    echo -e "${RED}Hostname cannot be empty${NC}"
                    continue
                fi
                
                echo "REMOTE|$remote_ip|$remote_host" >> "$INI_FILE"
                echo -e "${GREEN}✓ Added: $remote_host ($remote_ip)${NC}"
                log_message "Added remote device: $remote_host ($remote_ip)"
            done
            ;;
        3)
            echo -e "${YELLOW}Skipped adding devices${NC}"
            ;;
        *)
            echo -e "${RED}Invalid choice${NC}"
            ;;
    esac
    
    return 0
}

# Function to manually add a single device
add_device_manually() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║       ADD DEVICE MANUALLY              ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
    echo ""
    
    # Ensure INI file exists
    if [ ! -f "$INI_FILE" ]; then
        echo -e "${YELLOW}Creating configuration file...${NC}"
        update_ini_file "create"
    fi
    
    while true; do
        echo ""
        echo -e "${BLUE}Enter remote device IP address (or 'done' to finish):${NC}"
        read -r remote_ip
        
        if [ "$remote_ip" == "done" ] || [ -z "$remote_ip" ]; then
            break
        fi
        
        # Validate IP
        if ! validate_ip "$remote_ip"; then
            echo -e "${RED}Invalid IP address format${NC}"
            echo -e "${YELLOW}Example: 192.168.1.100${NC}"
            continue
        fi
        
        # Check if already exists
        if grep -q "|$remote_ip|" "$INI_FILE" 2>/dev/null; then
            echo -e "${YELLOW}Device with IP $remote_ip already exists in configuration${NC}"
            echo -e "${BLUE}View existing devices? (y/n)${NC}"
            read -r view_devices
            if [[ "$view_devices" == "y" ]]; then
                display_devices
            fi
            continue
        fi
        
        # Test connectivity
        echo ""
        echo -e "${YELLOW}Testing connectivity to $remote_ip...${NC}"
        if test_connectivity "$remote_ip" "true"; then
            echo -e "${GREEN}✓ Host is reachable${NC}"
            
            # Try to get hostname automatically
            echo -e "${CYAN}Attempting to resolve hostname...${NC}"
            local auto_hostname=$(host "$remote_ip" 2>/dev/null | awk '{print $NF}' | sed 's/\.$//')
            if [ -n "$auto_hostname" ] && [[ ! "$auto_hostname" =~ "not found" ]] && [[ ! "$auto_hostname" =~ "NXDOMAIN" ]]; then
                echo -e "${GREEN}✓ Found hostname: $auto_hostname${NC}"
                echo -e "${BLUE}Use this hostname? (y/n)${NC}"
                read -r use_auto
                if [[ "$use_auto" == "y" ]]; then
                    remote_host="$auto_hostname"
                else
                    echo -e "${BLUE}Enter custom hostname for $remote_ip:${NC}"
                    read -r remote_host
                fi
            else
                echo -e "${YELLOW}Could not resolve hostname automatically${NC}"
                echo -e "${BLUE}Enter hostname for $remote_ip:${NC}"
                read -r remote_host
            fi
        else
            echo -e "${YELLOW}⚠ Warning: Cannot reach host${NC}"
            echo -e "${YELLOW}Possible reasons:${NC}"
            echo -e "  • Host is offline"
            echo -e "  • Firewall blocking ICMP"
            echo -e "  • Wrong IP address"
            echo ""
            echo -e "${BLUE}Add anyway? (y/n)${NC}"
            read -r add_anyway
            if [[ "$add_anyway" != "y" ]]; then
                continue
            fi
            
            echo -e "${BLUE}Enter hostname for $remote_ip:${NC}"
            read -r remote_host
        fi
        
        # Validate hostname
        if [ -z "$remote_host" ]; then
            echo -e "${RED}Hostname cannot be empty${NC}"
            continue
        fi
        
        # Add to INI file
        echo "REMOTE|$remote_ip|$remote_host" >> "$INI_FILE"
        echo ""
        echo -e "${GREEN}✓ Successfully added device:${NC}"
        echo -e "  IP:       ${CYAN}$remote_ip${NC}"
        echo -e "  Hostname: ${CYAN}$remote_host${NC}"
        log_message "MANUALLY_ADDED|$remote_host|$remote_ip|$(whoami)"
        
        echo ""
        echo -e "${BLUE}Add another device? (y/n)${NC}"
        read -r add_more
        if [[ "$add_more" != "y" ]]; then
            break
        fi
    done
    
    echo ""
    echo -e "${GREEN}Device configuration complete${NC}"
    return 0
}
display_devices() {
    if [ ! -f "$INI_FILE" ]; then
        echo -e "${RED}INI file not found. Creating...${NC}"
        if ! update_ini_file "create"; then
            return 1
        fi
    fi
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║         LOCAL DEVICE INFO              ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    local local_ip=$(get_local_ip)
    local local_host=$(get_hostname)
    echo -e "  IP Address: ${CYAN}$local_ip${NC}"
    echo -e "  Hostname:   ${CYAN}$local_host${NC}"
    echo -e "  User:       ${CYAN}$(whoami)${NC}"
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║        REMOTE DEVICES                  ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    
    local count=0
    while IFS='|' read -r type ip hostname; do
        [ -z "$ip" ] && continue
        [[ "$ip" =~ ^#.*$ ]] && continue
        if [ "$type" == "REMOTE" ]; then
            ((count++))
            echo -ne "  ${BLUE}[$count]${NC} $hostname - $ip "
            if test_connectivity "$ip"; then
                echo -e "${GREEN}[ONLINE]${NC}"
            else
                echo -e "${RED}[OFFLINE]${NC}"
            fi
        fi
    done < "$INI_FILE"
    
    if [ $count -eq 0 ]; then
        echo -e "${YELLOW}  No remote devices configured${NC}"
        echo -e "${BLUE}  Use option 1 to add devices${NC}"
    fi
    
    return 0
}

# Function to select remote host with validation
select_remote_host() {
    if ! display_devices; then
        return 1
    fi
    
    echo ""
    echo -e "${BLUE}Enter device number or IP address:${NC}"
    read -r selection
    
    if [ -z "$selection" ]; then
        echo -e "${RED}No selection made${NC}"
        return 1
    fi
    
    # Check if it's a number
    if [[ "$selection" =~ ^[0-9]+$ ]]; then
        local count=0
        while IFS='|' read -r type ip hostname; do
            [ -z "$ip" ] && continue
            [[ "$ip" =~ ^#.*$ ]] && continue
            if [ "$type" == "REMOTE" ]; then
                ((count++))
                if [ $count -eq "$selection" ]; then
                    REMOTE_IP="$ip"
                    REMOTE_HOST="$hostname"
                    
                    # Test connectivity with progress
                    echo -e "${YELLOW}Testing connection to $REMOTE_HOST ($REMOTE_IP)...${NC}"
                    if test_connectivity "$REMOTE_IP" "true"; then
                        echo -e "${GREEN}✓ Connection OK${NC}"
                        return 0
                    else
                        echo -e "${YELLOW}⚠ Warning: Cannot reach host${NC}"
                        echo -e "${BLUE}Continue anyway? (y/n)${NC}"
                        read -r cont
                        if [[ "$cont" == "y" ]]; then
                            return 0
                        else
                            return 1
                        fi
                    fi
                fi
            fi
        done < "$INI_FILE"
        echo -e "${RED}Invalid selection number${NC}"
        return 1
    else
        # Treat as IP address
        if ! validate_ip "$selection"; then
            echo -e "${RED}Invalid IP address format${NC}"
            return 1
        fi
        REMOTE_IP="$selection"
        REMOTE_HOST="$selection"
        
        # Test connectivity with progress
        echo -e "${YELLOW}Testing connection to $REMOTE_IP...${NC}"
        if test_connectivity "$REMOTE_IP" "true"; then
            echo -e "${GREEN}✓ Connection OK${NC}"
            return 0
        else
            echo -e "${YELLOW}⚠ Warning: Cannot reach host${NC}"
            echo -e "${BLUE}Continue anyway? (y/n)${NC}"
            read -r cont
            if [[ "$cont" == "y" ]]; then
                return 0
            else
                return 1
            fi
        fi
    fi
}

# Function to transfer files using rsync with progress
transfer_rsync() {
    local direction="$1"  # "send" or "receive"
    local source="$2"
    local destination="$3"
    local user="$4"
    local remote_ip="$5"
    local mode="$6"  # "all" or "changed"
    
    local rsync_opts="-avz --progress -h"
    
    if [ "$mode" == "changed" ]; then
        rsync_opts="$rsync_opts --update"
    fi
    
    # Add error handling options
    rsync_opts="$rsync_opts --partial --timeout=30"
    
    # Create a temporary file for capturing rsync output
    local temp_output=$(mktemp)
    
    if [ "$direction" == "send" ]; then
        rsync $rsync_opts "$source" "$user@$remote_ip:$destination" 2>&1 | tee "$temp_output" | while IFS= read -r line; do
            # Enhanced progress display
            if [[ $line =~ ^.*[0-9]+%.*$ ]]; then
                echo -ne "\r${CYAN}$line${NC}"
            elif [[ $line =~ ^sending.*$ ]] || [[ $line =~ ^sent.*$ ]]; then
                echo -e "\n${GREEN}$line${NC}"
            elif [[ $line =~ ^total\ size.*$ ]]; then
                echo -e "${BLUE}$line${NC}"
            fi
        done
    else
        rsync $rsync_opts "$user@$remote_ip:$source" "$destination" 2>&1 | tee "$temp_output" | while IFS= read -r line; do
            # Enhanced progress display
            if [[ $line =~ ^.*[0-9]+%.*$ ]]; then
                echo -ne "\r${CYAN}$line${NC}"
            elif [[ $line =~ ^receiving.*$ ]] || [[ $line =~ ^received.*$ ]]; then
                echo -e "\n${GREEN}$line${NC}"
            elif [[ $line =~ ^total\ size.*$ ]]; then
                echo -e "${BLUE}$line${NC}"
            fi
        done
    fi
    
    local exit_code=$?
    rm -f "$temp_output"
    return $exit_code
}

# Function to transfer files using sftp with progress
transfer_sftp() {
    local direction="$1"
    local source="$2"
    local destination="$3"
    local user="$4"
    local remote_ip="$5"
    
    echo -e "${YELLOW}Using SFTP for transfer...${NC}"
    echo -e "${CYAN}Note: SFTP provides less detailed progress than rsync${NC}"
    
    if [ "$direction" == "send" ]; then
        echo -e "${BLUE}Uploading files...${NC}"
        (sftp "$user@$remote_ip" <<EOF
put -r "$source" "$destination"
bye
EOF
) &
        local sftp_pid=$!
        show_spinner $sftp_pid "Transferring files via SFTP..."
        wait $sftp_pid
        return $?
    else
        echo -e "${BLUE}Downloading files...${NC}"
        (sftp "$user@$remote_ip" <<EOF
get -r "$source" "$destination"
bye
EOF
) &
        local sftp_pid=$!
        show_spinner $sftp_pid "Transferring files via SFTP..."
        wait $sftp_pid
        return $?
    fi
}

# Function to transfer files to remote
transfer_to_remote() {
    if ! select_remote_host; then
        return 1
    fi
    
    echo ""
    echo -e "${BLUE}Enter source path (file or directory):${NC}"
    read -r source_path
    
    if ! validate_path "$source_path" "true"; then
        return 1
    fi
    
    echo -e "${BLUE}Enter destination path on remote host:${NC}"
    read -r dest_path
    
    if ! validate_path "$dest_path" "false"; then
        return 1
    fi
    
    echo -e "${BLUE}Transfer mode:${NC}"
    echo -e "  ${CYAN}1.${NC} All files"
    echo -e "  ${CYAN}2.${NC} Only changed files"
    read -r mode_choice
    
    local transfer_mode="all"
    if [ "$mode_choice" == "2" ]; then
        transfer_mode="changed"
    fi
    
    local user=$(whoami)
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║        TRANSFER IN PROGRESS...         ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
    echo -e "From:   ${GREEN}$source_path${NC}"
    echo -e "To:     ${GREEN}$user@$REMOTE_IP:$dest_path${NC}"
    echo -e "Mode:   ${GREEN}$transfer_mode${NC}"
    echo -e "Method: ${GREEN}$TRANSFER_METHOD${NC}"
    echo ""
    
    local success=false
    
    case $TRANSFER_METHOD in
        rsync)
            if transfer_rsync "send" "$source_path" "$dest_path" "$user" "$REMOTE_IP" "$transfer_mode"; then
                success=true
            fi
            ;;
        sftp)
            if transfer_sftp "send" "$source_path" "$dest_path" "$user" "$REMOTE_IP"; then
                success=true
            fi
            ;;
        *)
            echo -e "${RED}No transfer method available${NC}"
            return 1
            ;;
    esac
    
    if [ "$success" = true ]; then
        echo ""
        echo -e "${GREEN}════════════════════════════════════════${NC}"
        echo -e "${GREEN}✓ Transfer completed successfully${NC}"
        echo -e "${GREEN}════════════════════════════════════════${NC}"
        local log_msg="SEND|$(get_hostname)|$(get_local_ip)|$user|$REMOTE_HOST|$REMOTE_IP|$source_path|$dest_path|$TRANSFER_METHOD"
        log_message "$log_msg"
        
        # Attempt to log on remote with timeout
        echo -e "${CYAN}Updating remote log...${NC}"
        if timeout 5 ssh -o ConnectTimeout=3 -o BatchMode=yes "$user@$REMOTE_IP" "echo '[$(date '+%Y-%m-%d %H:%M:%S')] RECEIVE|$REMOTE_HOST|$REMOTE_IP|$user|$(get_hostname)|$(get_local_ip)|$dest_path|$source_path|$TRANSFER_METHOD' >> $REMOTE_LOG_PATH" 2>/dev/null; then
            echo -e "${GREEN}✓ Remote log updated${NC}"
        else
            echo -e "${YELLOW}⚠ Could not update remote log${NC}"
            echo -e "${BLUE}Note: Remote logging requires SSH key authentication${NC}"
            echo -e "${BLUE}To enable automatic remote logging, set up SSH keys:${NC}"
            echo -e "  ${CYAN}1. Generate key: ssh-keygen -t rsa -b 4096${NC}"
            echo -e "  ${CYAN}2. Copy to remote: ssh-copy-id $user@$REMOTE_IP${NC}"
            echo -e "${YELLOW}The script will continue to work, but remote logs won't be updated automatically.${NC}"
        fi
        return 0
    else
        echo ""
        echo -e "${RED}✗ Transfer failed${NC}"
        echo -e "${YELLOW}Common issues:${NC}"
        echo -e "  • SSH keys not configured"
        echo -e "  • Insufficient permissions"
        echo -e "  • Network connectivity problems"
        echo -e "  • Remote path doesn't exist"
        return 1
    fi
}

# Function to receive files from remote
receive_from_remote() {
    if ! select_remote_host; then
        return 1
    fi
    
    echo ""
    echo -e "${BLUE}Enter source path on remote host:${NC}"
    read -r source_path
    
    if ! validate_path "$source_path" "false"; then
        return 1
    fi
    
    echo -e "${BLUE}Enter local destination path:${NC}"
    read -r dest_path
    
    # Create destination if it doesn't exist
    if [ ! -d "$dest_path" ]; then
        echo -e "${YELLOW}Destination directory doesn't exist.${NC}"
        echo -e "${BLUE}Create it? (y/n)${NC}"
        read -r create_dir
        if [[ "$create_dir" == "y" ]]; then
            if ! mkdir -p "$dest_path" 2>/dev/null; then
                echo -e "${RED}Failed to create directory${NC}"
                return 1
            fi
        else
            return 1
        fi
    fi
    
    echo -e "${BLUE}Transfer mode:${NC}"
    echo -e "  ${CYAN}1.${NC} All files"
    echo -e "  ${CYAN}2.${NC} Only changed files"
    read -r mode_choice
    
    local transfer_mode="all"
    if [ "$mode_choice" == "2" ]; then
        transfer_mode="changed"
    fi
    
    local user=$(whoami)
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║        TRANSFER IN PROGRESS...         ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
    echo -e "From:   ${GREEN}$user@$REMOTE_IP:$source_path${NC}"
    echo -e "To:     ${GREEN}$dest_path${NC}"
    echo -e "Mode:   ${GREEN}$transfer_mode${NC}"
    echo -e "Method: ${GREEN}$TRANSFER_METHOD${NC}"
    echo ""
    
    local success=false
    
    case $TRANSFER_METHOD in
        rsync)
            if transfer_rsync "receive" "$source_path" "$dest_path" "$user" "$REMOTE_IP" "$transfer_mode"; then
                success=true
            fi
            ;;
        sftp)
            if transfer_sftp "receive" "$source_path" "$dest_path" "$user" "$REMOTE_IP"; then
                success=true
            fi
            ;;
        *)
            echo -e "${RED}No transfer method available${NC}"
            return 1
            ;;
    esac
    
    if [ "$success" = true ]; then
        echo ""
        echo -e "${GREEN}════════════════════════════════════════${NC}"
        echo -e "${GREEN}✓ Transfer completed successfully${NC}"
        echo -e "${GREEN}════════════════════════════════════════${NC}"
        local log_msg="RECEIVE|$(get_hostname)|$(get_local_ip)|$user|$REMOTE_HOST|$REMOTE_IP|$dest_path|$source_path|$TRANSFER_METHOD"
        log_message "$log_msg"
        
        # Attempt to log on remote with timeout
        echo -e "${CYAN}Updating remote log...${NC}"
        if timeout 5 ssh -o ConnectTimeout=3 -o BatchMode=yes "$user@$REMOTE_IP" "echo '[$(date '+%Y-%m-%d %H:%M:%S')] SEND|$REMOTE_HOST|$REMOTE_IP|$user|$(get_hostname)|$(get_local_ip)|$source_path|$dest_path|$TRANSFER_METHOD' >> $REMOTE_LOG_PATH" 2>/dev/null; then
            echo -e "${GREEN}✓ Remote log updated${NC}"
        else
            echo -e "${YELLOW}⚠ Could not update remote log${NC}"
            echo -e "${BLUE}Note: Remote logging requires SSH key authentication${NC}"
            echo -e "${BLUE}To enable automatic remote logging, set up SSH keys:${NC}"
            echo -e "  ${CYAN}1. Generate key: ssh-keygen -t rsa -b 4096${NC}"
            echo -e "  ${CYAN}2. Copy to remote: ssh-copy-id $user@$REMOTE_IP${NC}"
            echo -e "${YELLOW}The script will continue to work, but remote logs won't be updated automatically.${NC}"
        fi
        return 0
    else
        echo ""
        echo -e "${RED}✗ Transfer failed${NC}"
        echo -e "${YELLOW}Common issues:${NC}"
        echo -e "  • SSH keys not configured"
        echo -e "  • Insufficient permissions"
        echo -e "  • Network connectivity problems"
        echo -e "  • Source path doesn't exist on remote"
        return 1
    fi
}

# Function to deploy script to remote host
deploy_script_to_remote() {
    if ! select_remote_host; then
        return 1
    fi
    
    local script_path="$0"
    local script_name=$(basename "$script_path")
    local user=$(whoami)
    
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║     DEPLOY SCRIPT TO REMOTE HOST       ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Target Host: ${GREEN}$REMOTE_HOST ($REMOTE_IP)${NC}"
    echo -e "${BLUE}Script: ${GREEN}$script_name${NC}"
    echo ""
    echo -e "${YELLOW}Choose deployment location:${NC}"
    echo -e "  ${CYAN}1.${NC} /usr/local/bin/$script_name (system-wide, requires sudo)"
    echo -e "  ${CYAN}2.${NC} ~/bin/$script_name (user directory)"
    echo -e "  ${CYAN}3.${NC} ~/$script_name (home directory)"
    echo -e "  ${CYAN}4.${NC} Custom path"
    read -r location_choice
    
    local remote_path
    case $location_choice in
        1)
            remote_path="/usr/local/bin/$script_name"
            ;;
        2)
            remote_path="~/bin/$script_name"
            ;;
        3)
            remote_path="~/$script_name"
            ;;
        4)
            echo -e "${BLUE}Enter custom path on remote host:${NC}"
            read -r remote_path
            ;;
        *)
            echo -e "${RED}Invalid choice${NC}"
            return 1
            ;;
    esac
    
    echo ""
    echo -e "${YELLOW}Deployment Summary:${NC}"
    echo -e "  Source: ${GREEN}$script_path${NC}"
    echo -e "  Destination: ${GREEN}$user@$REMOTE_IP:$remote_path${NC}"
    echo ""
    echo -e "${BLUE}Proceed with deployment? (y/n)${NC}"
    read -r confirm
    
    if [[ "$confirm" != "y" ]]; then
        echo -e "${YELLOW}Deployment cancelled${NC}"
        return 1
    fi
    
    echo ""
    echo -e "${CYAN}Starting deployment...${NC}"
    
    # Step 1: Create directory if needed
    echo -e "${BLUE}[1/5]${NC} Creating remote directory..."
    if ssh "$user@$REMOTE_IP" "mkdir -p $(dirname $remote_path)" 2>/dev/null; then
        echo -e "${GREEN}✓ Directory ready${NC}"
    else
        echo -e "${RED}✗ Failed to create directory${NC}"
        return 1
    fi
    
    # Step 2: Transfer the script
    echo -e "${BLUE}[2/5]${NC} Transferring script..."
    if scp "$script_path" "$user@$REMOTE_IP:$remote_path" &>/dev/null; then
        echo -e "${GREEN}✓ Script transferred${NC}"
    else
        echo -e "${RED}✗ Transfer failed${NC}"
        echo -e "${YELLOW}Make sure SSH key authentication is set up${NC}"
        return 1
    fi
    
    # Step 3: Make executable
    echo -e "${BLUE}[3/5]${NC} Making script executable..."
    if ssh "$user@$REMOTE_IP" "chmod +x $remote_path" 2>/dev/null; then
        echo -e "${GREEN}✓ Script is now executable${NC}"
    else
        echo -e "${RED}✗ Failed to set execute permissions${NC}"
        return 1
    fi
    
    # Step 4: Transfer INI file if exists
    echo -e "${BLUE}[4/5]${NC} Syncing configuration..."
    if [ -f "$INI_FILE" ]; then
        local remote_ini="${INI_FILE/#\~/$HOME}"
        if scp "$INI_FILE" "$user@$REMOTE_IP:$remote_ini" &>/dev/null; then
            echo -e "${GREEN}✓ Configuration synced${NC}"
        else
            echo -e "${YELLOW}⚠ Configuration sync failed (not critical)${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ No configuration file to sync${NC}"
    fi
    
    # Step 5: Verify installation
    echo -e "${BLUE}[5/5]${NC} Verifying installation..."
    if ssh "$user@$REMOTE_IP" "test -x $remote_path" 2>/dev/null; then
        echo -e "${GREEN}✓ Verification successful${NC}"
    else
        echo -e "${RED}✗ Verification failed${NC}"
        return 1
    fi
    
    # Show success message
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   DEPLOYMENT COMPLETED SUCCESSFULLY    ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Remote host can now run the script:${NC}"
    if [[ "$remote_path" == /usr/local/bin/* ]]; then
        echo -e "  ${GREEN}$script_name${NC}"
    else
        echo -e "  ${GREEN}$remote_path${NC}"
    fi
    echo ""
    echo -e "${YELLOW}Optional: Add to PATH on remote host${NC}"
    echo -e "  Run on remote: ${CYAN}echo 'export PATH=\$PATH:$(dirname $remote_path)' >> ~/.bashrc${NC}"
    echo ""
    
    # Log deployment
    log_message "DEPLOY|$(get_hostname)|$(get_local_ip)|$user|$REMOTE_HOST|$REMOTE_IP|$script_path|$remote_path"
    
    # Ask if user wants to test remote execution
    echo -e "${BLUE}Test script execution on remote host? (y/n)${NC}"
    read -r test_exec
    
    if [[ "$test_exec" == "y" ]]; then
        echo ""
        echo -e "${CYAN}Testing remote execution...${NC}"
        ssh -t "$user@$REMOTE_IP" "$remote_path" 2>/dev/null || {
            echo -e "${YELLOW}Note: Manual interaction may be needed on remote host${NC}"
        }
    fi
    
    return 0
}

# Function to deploy to multiple hosts
deploy_to_all_hosts() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║    DEPLOY TO ALL REMOTE HOSTS          ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
    echo ""
    
    if [ ! -f "$INI_FILE" ]; then
        echo -e "${RED}No devices configured. Please add devices first.${NC}"
        return 1
    fi
    
    # Count remote hosts
    local host_count=0
    while IFS='|' read -r type ip hostname; do
        [ -z "$ip" ] && continue
        [[ "$ip" =~ ^#.*$ ]] && continue
        if [ "$type" == "REMOTE" ]; then
            ((host_count++))
        fi
    done < "$INI_FILE"
    
    if [ $host_count -eq 0 ]; then
        echo -e "${YELLOW}No remote hosts configured${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}Found $host_count remote host(s)${NC}"
    echo -e "${BLUE}Deploy to all? (y/n)${NC}"
    read -r confirm
    
    if [[ "$confirm" != "y" ]]; then
        echo -e "${YELLOW}Deployment cancelled${NC}"
        return 1
    fi
    
    local script_path="$0"
    local script_name=$(basename "$script_path")
    local user=$(whoami)
    
    echo ""
    echo -e "${YELLOW}Choose deployment location for all hosts:${NC}"
    echo -e "  ${CYAN}1.${NC} ~/bin/$script_name (recommended)"
    echo -e "  ${CYAN}2.${NC} ~/$script_name"
    read -r location_choice
    
    local remote_path
    case $location_choice in
        1)
            remote_path="~/bin/$script_name"
            ;;
        2)
            remote_path="~/$script_name"
            ;;
        *)
            echo -e "${RED}Invalid choice${NC}"
            return 1
            ;;
    esac
    
    echo ""
    echo -e "${CYAN}Starting batch deployment...${NC}"
    echo ""
    
    local success_count=0
    local fail_count=0
    local current=0
    
    while IFS='|' read -r type ip hostname; do
        [ -z "$ip" ] && continue
        [[ "$ip" =~ ^#.*$ ]] && continue
        if [ "$type" == "REMOTE" ]; then
            ((current++))
            echo -e "${BLUE}[$current/$host_count]${NC} Deploying to ${GREEN}$hostname ($ip)${NC}..."
            
            # Quick connectivity check
            if ! ping -c 1 -W 2 "$ip" &>/dev/null; then
                echo -e "${RED}  ✗ Host unreachable, skipping${NC}"
                ((fail_count++))
                echo ""
                continue
            fi
            
            # Deploy
            if ssh "$user@$ip" "mkdir -p $(dirname $remote_path)" 2>/dev/null && \
               scp "$script_path" "$user@$ip:$remote_path" &>/dev/null && \
               ssh "$user@$ip" "chmod +x $remote_path" 2>/dev/null; then
                echo -e "${GREEN}  ✓ Deployment successful${NC}"
                ((success_count++))
                
                # Sync config
                if [ -f "$INI_FILE" ]; then
                    scp "$INI_FILE" "$user@$ip:$INI_FILE" &>/dev/null && \
                    echo -e "${GREEN}  ✓ Configuration synced${NC}"
                fi
                
                log_message "DEPLOY|$(get_hostname)|$(get_local_ip)|$user|$hostname|$ip|$script_path|$remote_path"
            else
                echo -e "${RED}  ✗ Deployment failed${NC}"
                ((fail_count++))
            fi
            echo ""
        fi
    done < "$INI_FILE"
    
    # Summary
    echo -e "${CYAN}════════════════════════════════════════${NC}"
    echo -e "${GREEN}Successful: $success_count${NC}"
    echo -e "${RED}Failed: $fail_count${NC}"
    echo -e "${CYAN}════════════════════════════════════════${NC}"
    
    return 0
}
view_history() {
    if [ ! -f "$LOG_FILE" ]; then
        echo -e "${YELLOW}No transfer history found${NC}"
        return
    fi
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║       TRANSFER HISTORY (Last 20)       ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    echo ""
    
    tail -n 20 "$LOG_FILE" | while IFS= read -r line; do
        # Color code based on operation
        if [[ $line == *"SEND"* ]]; then
            echo -e "${CYAN}$line${NC}"
        elif [[ $line == *"RECEIVE"* ]]; then
            echo -e "${BLUE}$line${NC}"
        else
            echo "$line"
        fi
    done
    
    echo ""
    echo -e "${YELLOW}Full log: $LOG_FILE${NC}"
    echo -e "${BLUE}View full log? (y/n)${NC}"
    read -r view_full
    if [[ "$view_full" == "y" ]]; then
        less "$LOG_FILE"
    fi
}

# Main menu
show_menu() {
    clear
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   FILE TRANSFER MANAGEMENT SYSTEM      ║${NC}"
    echo -e "${GREEN}║         Enhanced Version 2.0           ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Transfer Method: ${GREEN}$TRANSFER_METHOD${NC}"
    echo ""
    echo -e "${BLUE}1.${NC} Configure/Update Device List"
    echo -e "${BLUE}2.${NC} Show Local and Remote Devices"
    echo -e "${BLUE}3.${NC} Auto-Discover Network Devices"
    echo -e "${BLUE}4.${NC} Add Device Manually"
    echo -e "${BLUE}5.${NC} Transfer Files/Folders to Remote"
    echo -e "${BLUE}6.${NC} Receive Files/Folders from Remote"
    echo -e "${BLUE}7.${NC} View Transfer History"
    echo -e "${BLUE}8.${NC} Test System Dependencies"
    echo -e "${BLUE}9.${NC} Deploy Script to Remote Host"
    echo -e "${BLUE}10.${NC} Deploy Script to All Remote Hosts"
    echo -e "${BLUE}11.${NC} Exit"
    echo ""
    echo -e "${YELLOW}Enter your choice [1-11]:${NC}"
}

# Main program
main() {
    # Initial dependency check
    echo -e "${CYAN}Starting File Transfer Management System...${NC}"
    echo ""
    
    if ! check_dependencies; then
        echo ""
        echo -e "${RED}Critical dependencies missing!${NC}"
        echo -e "${YELLOW}Please install required packages and try again.${NC}"
        echo ""
        echo -e "${BLUE}Continue anyway? (not recommended) (y/n)${NC}"
        read -r continue_anyway
        if [[ "$continue_anyway" != "y" ]]; then
            exit 1
        fi
    fi
    
    # Verify we have at least one transfer method
    if [ -z "$TRANSFER_METHOD" ]; then
        echo -e "${RED}FATAL: No file transfer method available${NC}"
        echo -e "${YELLOW}Please install rsync, sftp, or ftp${NC}"
        exit 1
    fi
    
    echo ""
    echo -e "${GREEN}Press Enter to continue to main menu...${NC}"
    read -r
    
    # Create INI file if it doesn't exist
    if [ ! -f "$INI_FILE" ]; then
        if ! update_ini_file "create"; then
            echo -e "${RED}Failed to create INI file. Exiting.${NC}"
            exit 1
        fi
    fi
    
    # Main loop
    while true; do
        show_menu
        read -r choice
        
        case $choice in
            1)
                if ! update_ini_file "update"; then
                    echo -e "${RED}Failed to update INI file${NC}"
                fi
                echo ""
                read -p "Press Enter to continue..."
                ;;
            2)
                if ! display_devices; then
                    echo -e "${RED}Failed to display devices${NC}"
                fi
                echo ""
                read -p "Press Enter to continue..."
                ;;
            3)
                auto_discover_devices
                echo ""
                read -p "Press Enter to continue..."
                ;;
            4)
                add_device_manually
                echo ""
                read -p "Press Enter to continue..."
                ;;
            5)
                transfer_to_remote
                echo ""
                read -p "Press Enter to continue..."
                ;;
            6)
                receive_from_remote
                echo ""
                read -p "Press Enter to continue..."
                ;;
            7)
                view_history
                echo ""
                read -p "Press Enter to continue..."
                ;;
            8)
                check_dependencies
                echo ""
                read -p "Press Enter to continue..."
                ;;
            9)
                deploy_script_to_remote
                echo ""
                read -p "Press Enter to continue..."
                ;;
            10)
                deploy_to_all_hosts
                echo ""
                read -p "Press Enter to continue..."
                ;;
            11)
                echo ""
                echo -e "${GREEN}Thank you for using File Transfer Management System${NC}"
                echo -e "${CYAN}Goodbye!${NC}"
                log_message "System shutdown by user $(whoami)"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid choice. Please enter 1-11${NC}"
                sleep 2
                ;;
        esac
    done
}

# Trap errors and cleanup
trap 'echo -e "\n${RED}Script interrupted${NC}"; exit 130' INT TERM

# Run main program
main
