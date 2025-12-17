#!/bin/bash

# Parse command-line arguments
AUTO_EXTRACT=false
for arg in "$@"; do
    case "$arg" in
        --extract)
            AUTO_EXTRACT=true
            shift
            ;;
        *)
            shift
            ;;
    esac
done

# Dependency checks
check_dependencies() {
    local dependencies=(curl unzip yara find)
    for cmd in "${dependencies[@]}"; do
        if ! command -v "$cmd" > /dev/null 2>&1; then
            echo "Error: $cmd is not installed." >&2
            exit 1
        fi
    done

    # Check for a hash utility: either sha256sum or shasum must exist.
    if ! command -v sha256sum > /dev/null 2>&1 && ! command -v shasum > /dev/null 2>&1; then
        echo "Error: Neither sha256sum nor shasum is installed." >&2
        exit 1
    fi
}

# Directory Assumptions: Create directories if they don't exist
prepare_directories() {
    local dirs=(./runtime/rules ./runtime/inames ./runtime/run ./results/csv ./results/logs ./results/extracts)
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            echo "Created directory: $dir"
        fi
    done
}

check_dependencies
prepare_directories

display_ascii_art() {
    cat << "EOF"
    .-"^`\                                        /`^"-.
  .'   ___\                                      /___   `.
 /    /.---.                                    .---.\    \
|    //     '-.  ___________________________ .-'     \\    |
|   ;|         \/--------------------------//         |;   |
\   ||       |\_)          YAREX          (_/|       ||   /
 \  | \  . \ ;  |   YARA scans made easy   || ; / .  / |  /
  '\_\ \\ \ \ \ |                          ||/ / / // /_/'
        \\ \ \ \|       Release 1.0        |/ / / //
         `'-\_\_\                          /_/_/-'`
                '--------------------------'
EOF
}

log_message() {
    echo -e "\033[0;37m$(date '+[%Y-%m-%d %H:%M:%S]')\033[0;37m $1 \033[0m"
}

# Check internet connection
check_internet() {
    if curl -s https://www.github.com > /dev/null 2>&1; then
        return 0
    else
        log_message "\033[1;31mNo internet connection. Proceeding without updating rules."
        return 1
    fi
}

# Update YARA rules from yara forge github
update_yara_rules() {
    log_message "Updating YARA rules..."
    TEMP_DIR=$(mktemp -d)
    DOWNLOAD_URLS=$(curl -s https://api.github.com/repos/YARAHQ/yara-forge/releases/latest \
        | grep '"browser_download_url"' \
        | grep '\.zip' \
        | cut -d '"' -f 4)

    if [[ -z "$DOWNLOAD_URLS" ]]; then
        log_message "Failed to retrieve the latest release URLs."
        rm -rf "$TEMP_DIR"
        return 1
    fi

    for URL in $DOWNLOAD_URLS; do
        FILENAME=$(basename "$URL")
        curl -sL "$URL" -o "$TEMP_DIR/$FILENAME"

        if [[ $? -ne 0 ]]; then
            log_message "Failed to download $FILENAME. Skipping."
            continue
        fi

        unzip -j "$TEMP_DIR/$FILENAME" '*.yar' -d "$TEMP_DIR" > /dev/null 2>&1
        if [[ $? -ne 0 ]]; then
            log_message "Failed to extract $FILENAME. Skipping."
            continue
        fi
    done

    for RULE_FILE in "$TEMP_DIR"/*.yar; do
        BASENAME=$(basename "$RULE_FILE")
        case $BASENAME in
            yara-rules-core.yar) mv "$RULE_FILE" ./runtime/rules/yara-rules-core.yar ;;
            yara-rules-extended.yar) mv "$RULE_FILE" ./runtime/rules/yara-rules-extended.yar ;;
            yara-rules-full.yar) mv "$RULE_FILE" ./runtime/rules/yara-rules-full.yar ;;
            *) log_message "Unknown rule file: $BASENAME. Skipping." ;;
        esac
    done

    log_message "YARA rules updated successfully."
    rm -rf "$TEMP_DIR"
}

# Prompt for directories to scan
get_scan_locations() {
    local recommended_dirs=(
        "/bin" "/sbin" "/usr" "/Users" "/Library/Extensions"
        "/Library/LaunchAgents" "/Library/LaunchDaemons"
        "/System/Library/LaunchAgents" "/System/Library/LaunchDaemons"
        "/etc" "/var/root" "/var/log" "/Library/Application Support"
        "/Library/Caches" "/System/Library/Extensions"
    )
    echo ""
    echo "Recommended directories to scan:"
    for d in "${recommended_dirs[@]}"; do
        echo "  - $d"
    done
    echo

    TO_SCAN=()
    read -e -p "Press Enter to use this list or type 'custom' to specify your own directories: " choice

    if [[ -z "$choice" ]]; then
        TO_SCAN=("${recommended_dirs[@]}")
        echo "Using recommended directories:"
    else
        echo "Please enter the directories to scan, one per line."
        echo "When you're done, press Enter on a blank line to finish."
        while true; do
            read -e -p "Directory: " dir
            if [[ -z "$dir" ]]; then
                break
            elif [[ -d "$dir" ]]; then
                TO_SCAN+=("$dir")
                echo "Added: $dir"
                echo "Current selection: ${TO_SCAN[*]}"
            else
                echo "Invalid directory: $dir"
            fi
        done

        if [[ ${#TO_SCAN[@]} -eq 0 ]]; then
            TO_SCAN=("/Users")
            echo "No directories entered. Defaulting to /Users."
        else
            echo "Your final selection of directories:"
            printf '%s\n' "${TO_SCAN[@]}"
        fi
    fi
}

# Prompt for exclusions
select_exclusions() {
    echo ""
    echo "Choose which exclusions to apply (default: all):"
    echo "1. Archives"
    echo "2. Audio"
    echo "3. Databases"
    echo "4. Images"
    echo "5. Video"
    echo "6. Virtual Machines"
    echo "7. All (default)"
    read -e -p "Enter choices (comma-separated, e.g., 1,2,3): " EXCLUSION_CHOICES

    if [[ -z "$EXCLUSION_CHOICES" ]]; then
        EXCLUSION_CHOICES="7"
    fi

    IFS=',' read -r -a CHOICES <<< "$EXCLUSION_CHOICES"
    EXCLUSION_FILES=()
    for CHOICE in "${CHOICES[@]}"; do
        case $CHOICE in
            1) EXCLUSION_FILES+=("./runtime/inames/archives.inm") ;;
            2) EXCLUSION_FILES+=("./runtime/inames/audio.inm") ;;
            3) EXCLUSION_FILES+=("./runtime/inames/databases.inm") ;;
            4) EXCLUSION_FILES+=("./runtime/inames/images.inm") ;;
            5) EXCLUSION_FILES+=("./runtime/inames/video.inm") ;;
            6) EXCLUSION_FILES+=("./runtime/inames/vm.inm") ;;
            7) EXCLUSION_FILES=("./runtime/inames/archives.inm" "./runtime/inames/audio.inm" "./runtime/inames/databases.inm" "./runtime/inames/images.inm" "./runtime/inames/video.inm" "./runtime/inames/vm.inm") ;;
            *) echo "Invalid choice: $CHOICE. Skipping." ;;
        esac
    done
}

# Prompt for maximum file size
select_max_file_size() {
    DEFAULT_MAX_SIZE=750000000  # 750MB in bytes
    echo ""
    echo "Enter the maximum file size to scan (in bytes)."
    echo "The default value is 750,000,000 bytes (750MB)."
    read -e -p "Value: " MAX_SIZE
    MAX_SIZE=${MAX_SIZE:-$DEFAULT_MAX_SIZE}
}

# Prompt for YARA rule set
select_yara_rules_set() {
    echo ""
    echo "Choose YARA rule set:"
    echo "1. Core"
    echo "2. Extended (default)"
    echo "3. Full"
    read -e -p "Enter choice (1, 2 or 3, default: 2): " RULE_CHOICE
    case $RULE_CHOICE in
        1) RULE_FILE="./runtime/rules/yara-rules-core.yar" ;;
        2|"") RULE_FILE="./runtime/rules/yara-rules-extended.yar" ;;
        3) RULE_FILE="./runtime/rules/yara-rules-full.yar" ;;
        *) echo "Invalid choice. Using Extended rules by default."; RULE_FILE="./runtime/rules/yara-rules-extended.yar" ;;
    esac
}

SCRIPT_DIR=$(pwd)

# Scan selected directories
scan_all_directories() {
    rm -f ./runtime/run/included ./runtime/run/excluded ./runtime/run/diff
    mkdir -p ./runtime/run
    touch ./runtime/run/included ./runtime/run/excluded ./runtime/run/diff

    echo "Rule,File,SHA256" > "$NAME_OUTPUT"

    echo ""
    for SCAN in "${TO_SCAN[@]}"; do
        log_message "Gathering file list from $SCAN ..."
        find "$SCAN" -type f \
            ! -path "$SCRIPT_DIR/*" \
            ! -path "/System/Volumes/Preboot/*" \
            ! -name "yara-rules-core.yar" \
            ! -name "yara-rules-extended.yar" \
            ! -name "yara-rules-full.yar" \
            ! -name "yara-rules-core.compiled" \
            ! -name "yara-rules-extended.compiled" \
            ! -name "yara-rules-full.compiled" \
            >> ./runtime/run/included 2>/dev/null

        for SOURCE in "${EXCLUSION_FILES[@]}"; do
            EXCLUSIONS=$(cat "$SOURCE")
            if [[ -n "$EXCLUSIONS" ]]; then
                eval "find \"$SCAN\" -type f \\( $EXCLUSIONS \\)" >> ./runtime/run/excluded 2>/dev/null
            fi
        done
    done

    log_message "Finished building included and excluded lists."
    sort ./runtime/run/included ./runtime/run/excluded | uniq -u > ./runtime/run/diff

    local included_count excluded_count final_count
    included_count=$(wc -l < ./runtime/run/included)
    excluded_count=$(wc -l < ./runtime/run/excluded)
    final_count=$(wc -l < ./runtime/run/diff)
    echo ""
    log_message "\033[1;37m############################################"
    echo ""
    log_message "\033[1;37mTotal included files: \033[1;37m $included_count"
    log_message "\033[1;37mTotal excluded files: \033[1;32m $excluded_count"
    echo ""
    log_message "\033[1;37mFiles to be scanned: \033[1;33m $final_count"
    echo ""
    log_message "\033[1;37m############################################"
    echo ""
    log_message "Running YARA scan ..."

    if [[ "$RULE_FILE" =~ \.compiled$ ]]; then
        yara_cmd=(yara -C "$RULE_FILE" -N --skip-larger="$MAX_SIZE" --scan-list ./runtime/run/diff)
    else
        yara_cmd=(yara -w "$RULE_FILE" -N --skip-larger="$MAX_SIZE" --scan-list ./runtime/run/diff)
    fi

    if command -v stdbuf > /dev/null 2>&1; then
        yara_cmd=(stdbuf -oL -eL "${yara_cmd[@]}")
    elif command -v gstdbuf > /dev/null 2>&1; then
        yara_cmd=(gstdbuf -oL -eL "${yara_cmd[@]}")
    fi

    "${yara_cmd[@]}" 2> "$ERRORS_OUTPUT" |
    while IFS=' ' read -r rule matched_file; do
        if [[ -f "$matched_file" ]]; then
            if command -v sha256sum &> /dev/null; then
                file_hash=$(sha256sum "$matched_file" | awk '{print $1}')
            elif command -v shasum &> /dev/null; then
                file_hash=$(shasum -a 256 "$matched_file" | awk '{print $1}')
            else
                file_hash="HASH_ERROR"
            fi
        else
            file_hash="FILE_NOT_FOUND"
        fi
        echo "$rule,$matched_file,$file_hash"
    done >> "$NAME_OUTPUT"
    echo ""
    log_message "\033[1;32m############################################"
    echo ""
    log_message "\033[1;32mScan completed. Results in --> \033[0m $NAME_OUTPUT"
    echo ""
    log_message "\033[1;32m############################################"
}

extract_flagged_files() {
    echo ""
    log_message "Extracting flagged files ..."
    echo ""
    mkdir -p ./results/extracts
    while IFS=, read -r rule matched_file file_hash; do
        if [[ "$rule" == "Rule" && "$matched_file" == "File" ]]; then
            continue
        fi
        if [[ -f "$matched_file" ]]; then
            relative_path=$(dirname "$matched_file")
            output_path="./results/extracts/${CASE_NAME}${relative_path}"
            mkdir -p "$output_path"
            cp -p "$matched_file" "$output_path/"
            log_message "\033[1;32mExtracted:\033[0m $matched_file (SHA-256: $file_hash)"
        else
            log_message "\033[1;31mFile not found:\033[0m $matched_file (skipping)"
        fi
    done < "$NAME_OUTPUT"

    echo ""
    log_message "\033[1;32m############################################"
    echo ""
    log_message "\033[1;32mExtraction complete. Suspected files in -->\033[0m ./results/extracts/${CASE_NAME}/"
    echo ""
    log_message "\033[1;32m############################################"
}

# Main exec
display_ascii_art
read -e -p "Enter scan name (no spaces): " CASE_NAME
CASE_NAME=${CASE_NAME:-"default_case"}

RANDOM_NUMBERS=$(printf "%04d" $((RANDOM % 10000)))
NAME_OUTPUT="./results/csv/${CASE_NAME}_scan_$(date '+%Y-%m-%d')_${RANDOM_NUMBERS}.csv"
ERRORS_OUTPUT="./results/logs/${CASE_NAME}_scan_errors_$(date '+%Y-%m-%d')_${RANDOM_NUMBERS}.log"
EXTRACTS_DIR="./results/extracts/${CASE_NAME}/"
mkdir -p "$EXTRACTS_DIR"

if check_internet; then
    read -e -p "Would you like to update YARA rules now? (y/n): " update_choice
    update_choice=${update_choice:-Y}
    case "$update_choice" in
        [Yy]*)
            update_yara_rules
            ;;
        *)
            ;;
    esac
fi

get_scan_locations
select_max_file_size
select_yara_rules_set

# Prompt user to compile the selected YARA rules for better performance.
if command -v yarac >/dev/null 2>&1; then
    echo ""
    read -e -p "Would you like to compile the selected YARA rules for better performance? (y/n): " compile_choice
    compile_choice=${compile_choice:-y}
    if [[ $compile_choice =~ ^[Yy] ]]; then
        COMPILED_RULE_FILE="${RULE_FILE%.yar}.compiled"
        if yarac "$RULE_FILE" "$COMPILED_RULE_FILE"; then
            RULE_FILE="$COMPILED_RULE_FILE"
            log_message "Successfully compiled YARA rules to $COMPILED_RULE_FILE"
        else
            log_message "Compilation failed. Proceeding with uncompiled rules."
        fi
    fi
else
    log_message "yarac is not installed. Skipping rule compilation."
fi

select_exclusions
scan_all_directories

# If --extract argument was provided, automatically extract flagged files,
# otherwise prompt the user.
if [ "$AUTO_EXTRACT" = true ]; then
    extract_flagged_files
else
    read -e -p "Would you like to extract the flagged files? (y/n): " extract_choice
    extract_choice=${extract_choice:-Y}
    case "$extract_choice" in
        [Yy]*)
            extract_flagged_files
            ;;
        *)
            ;;
    esac
fi
