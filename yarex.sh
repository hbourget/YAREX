#!/usr/bin/env bash
#
# YAREX - YARA scans made easy
#
# Usage: ./yarex.sh [--extract] [--help]
#

set -o pipefail

# Always operate relative to the script's own directory, not the caller's cwd.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
cd "$SCRIPT_DIR" || exit 1

RUN_DIR="./runtime/run"

# Colors are emitted only when stdout is a terminal, so redirected output stays clean.
if [ -t 1 ]; then
    C_RESET=$'\033[0m'
    C_GRAY=$'\033[0;37m'
    C_WHITE=$'\033[1;37m'
    C_RED=$'\033[1;31m'
    C_GREEN=$'\033[1;32m'
    C_YELLOW=$'\033[1;33m'
else
    C_RESET='' C_GRAY='' C_WHITE='' C_RED='' C_GREEN='' C_YELLOW=''
fi

usage() {
    cat <<EOF
YAREX - YARA scans made easy

Usage: ./yarex.sh [OPTIONS]

Options:
  --extract    Extract flagged files at the end of the scan without prompting.
  -h, --help   Show this help and exit.

The script is interactive and will prompt for the scan name, rule set,
locations, file size limit and exclusions.
EOF
}

# Parse command-line arguments
AUTO_EXTRACT=false
while [ $# -gt 0 ]; do
    case "$1" in
        --extract)
            AUTO_EXTRACT=true
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'Error: unknown argument: %s\n\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

# Print a timestamped message. The message is printed verbatim (%s), so file
# paths containing backslashes are never mangled by escape interpretation.
log_message() {
    printf '%s[%s]%s %s\n' "$C_GRAY" "$(date '+%Y-%m-%d %H:%M:%S')" "$C_RESET" "$*"
}

# Read one answer into the named variable. Aborts on EOF rather than falling
# back to defaults, so a non-interactive invocation can never silently start
# scanning the whole filesystem.
prompt() {
    local __var=$1 __text=$2 __reply
    if ! IFS= read -e -r -p "$__text" __reply; then
        echo ""
        log_message "${C_RED}Input stream closed - YAREX needs an interactive terminal. Aborting.${C_RESET}"
        exit 1
    fi
    printf -v "$__var" '%s' "$__reply"
}

# Dependency checks
HASH_CMD=""
check_dependencies() {
    local dependencies=(curl unzip yara find sort grep awk sed)
    local cmd
    for cmd in "${dependencies[@]}"; do
        if ! command -v "$cmd" > /dev/null 2>&1; then
            echo "Error: $cmd is not installed." >&2
            exit 1
        fi
    done

    # Pick the hash utility once instead of probing for every matched file.
    if command -v sha256sum > /dev/null 2>&1; then
        HASH_CMD="sha256sum"
    elif command -v shasum > /dev/null 2>&1; then
        HASH_CMD="shasum -a 256"
    else
        echo "Error: Neither sha256sum nor shasum is installed." >&2
        exit 1
    fi
}

compute_hash() {
    $HASH_CMD -- "$1" 2>/dev/null | awk '{print $1; exit}'
}

# Directory Assumptions: Create directories if they don't exist
prepare_directories() {
    local dirs=(./runtime/rules ./runtime/inames "$RUN_DIR" ./results/csv ./results/logs ./results/extracts)
    local dir
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            echo "Created directory: $dir"
        fi
    done
}

# Remove the rules download staging area on exit, including Ctrl-C.
TEMP_DIR=""
cleanup() {
    [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ] && rm -rf "$TEMP_DIR"
}
trap cleanup EXIT INT TERM

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

# Check internet connection against the endpoint actually used for updates.
check_internet() {
    if curl -fsS --max-time 8 -o /dev/null https://api.github.com > /dev/null 2>&1; then
        return 0
    else
        log_message "${C_RED}No internet connection. Proceeding without updating rules.${C_RESET}"
        return 1
    fi
}

# Update YARA rules from the yara-forge GitHub releases.
# Only the archive matching the selected rule set is downloaded.
update_yara_rules() {
    local want="$1"
    local download_urls wanted_urls url filename rule_file basename_rf moved

    log_message "Updating YARA rules ($want) ..."
    TEMP_DIR=$(mktemp -d) || { log_message "${C_RED}Could not create a temporary directory.${C_RESET}"; return 1; }

    download_urls=$(curl -fsSL --max-time 30 https://api.github.com/repos/YARAHQ/yara-forge/releases/latest \
        | grep '"browser_download_url"' \
        | grep '\.zip' \
        | cut -d '"' -f 4)

    if [[ -z "$download_urls" ]]; then
        log_message "${C_RED}Failed to retrieve the latest release URLs.${C_RESET}"
        rm -rf "$TEMP_DIR"; TEMP_DIR=""
        return 1
    fi

    # Fetch only the requested set; fall back to everything if naming changed.
    wanted_urls=$(printf '%s\n' "$download_urls" | grep -i -- "-${want}\.zip")
    if [[ -z "$wanted_urls" ]]; then
        log_message "${C_YELLOW}Could not identify the '${want}' archive; downloading all rule archives.${C_RESET}"
        wanted_urls="$download_urls"
    fi

    while IFS= read -r url; do
        [ -n "$url" ] || continue
        filename=$(basename "$url")

        # -f makes curl fail on HTTP errors instead of saving the error page.
        if ! curl -fsSL --max-time 600 "$url" -o "$TEMP_DIR/$filename"; then
            log_message "${C_YELLOW}Failed to download $filename. Skipping.${C_RESET}"
            continue
        fi

        if ! unzip -o -j "$TEMP_DIR/$filename" '*.yar' -d "$TEMP_DIR" > /dev/null 2>&1; then
            log_message "${C_YELLOW}Failed to extract $filename. Skipping.${C_RESET}"
            continue
        fi
    done <<< "$wanted_urls"

    moved=0
    for rule_file in "$TEMP_DIR"/*.yar; do
        [ -e "$rule_file" ] || continue   # guard against an unmatched glob
        basename_rf=$(basename "$rule_file")
        case $basename_rf in
            yara-rules-core.yar|yara-rules-extended.yar|yara-rules-full.yar)
                mv "$rule_file" "./runtime/rules/$basename_rf" && moved=$((moved + 1))
                ;;
            *)
                log_message "Unknown rule file: $basename_rf. Skipping."
                ;;
        esac
    done

    rm -rf "$TEMP_DIR"; TEMP_DIR=""

    if [ "$moved" -eq 0 ]; then
        log_message "${C_RED}No rule files were updated.${C_RESET}"
        return 1
    fi

    log_message "${C_GREEN}YARA rules updated successfully ($moved file(s)).${C_RESET}"
    return 0
}

# Resolve a directory to an absolute, symlink-free path.
abs_path() {
    (cd -- "$1" 2>/dev/null && pwd -P)
}

# Prompt for directories to scan
get_scan_locations() {
    local recommended_dirs d
    if [ "$(uname -s)" = "Darwin" ]; then
        recommended_dirs=(
            "/bin" "/sbin" "/usr" "/Users" "/Library/Extensions"
            "/Library/LaunchAgents" "/Library/LaunchDaemons"
            "/System/Library/LaunchAgents" "/System/Library/LaunchDaemons"
            "/etc" "/var/root" "/var/log" "/Library/Application Support"
            "/Library/Caches" "/System/Library/Extensions"
        )
    else
        recommended_dirs=(
            "/bin" "/sbin" "/usr" "/opt" "/srv" "/home" "/root"
            "/etc" "/var/log" "/var/tmp" "/tmp"
        )
    fi

    echo ""
    echo "Recommended directories to scan:"
    for d in "${recommended_dirs[@]}"; do
        echo "  - $d"
    done
    echo

    TO_SCAN=()
    local choice dir resolved_dir
    prompt choice "Press Enter to use this list or type 'custom' to specify your own directories: "

    if [[ -z "$choice" ]]; then
        # Silently drop entries that do not exist on this system.
        for d in "${recommended_dirs[@]}"; do
            if [[ -d "$d" ]]; then
                resolved_dir=$(abs_path "$d")
                [ -n "$resolved_dir" ] && TO_SCAN+=("$resolved_dir")
            fi
        done
        echo "Using recommended directories present on this system:"
        printf '  %s\n' "${TO_SCAN[@]}"
    else
        echo "Please enter the directories to scan, one per line."
        echo "When you're done, press Enter on a blank line to finish."
        while true; do
            prompt dir "Directory: "
            if [[ -z "$dir" ]]; then
                break
            elif [[ -d "$dir" ]]; then
                resolved_dir=$(abs_path "$dir")
                if [ -z "$resolved_dir" ]; then
                    echo "Cannot access directory: $dir"
                    continue
                fi
                TO_SCAN+=("$resolved_dir")
                echo "Added: $resolved_dir"
            else
                echo "Invalid directory: $dir"
            fi
        done

        if [[ ${#TO_SCAN[@]} -eq 0 ]]; then
            resolved_dir=$(abs_path "/Users")
            [ -z "$resolved_dir" ] && resolved_dir=$(abs_path "/home")
            if [ -z "$resolved_dir" ]; then
                echo "No directories entered and no default available."
                exit 1
            fi
            TO_SCAN=("$resolved_dir")
            echo "No directories entered. Defaulting to $resolved_dir."
        else
            echo "Your final selection of directories:"
            printf '  %s\n' "${TO_SCAN[@]}"
        fi
    fi

    if [[ ${#TO_SCAN[@]} -eq 0 ]]; then
        log_message "${C_RED}No valid directories to scan.${C_RESET}"
        exit 1
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
    echo "8. None (no exclusions)"
    prompt EXCLUSION_CHOICES "Enter choices (comma-separated, e.g., 1,2,3): "

    if [[ -z "$EXCLUSION_CHOICES" ]]; then
        EXCLUSION_CHOICES="7"
    fi

    local CHOICES CHOICE
    IFS=',' read -r -a CHOICES <<< "$EXCLUSION_CHOICES"
    EXCLUSION_FILES=()
    for CHOICE in "${CHOICES[@]}"; do
        CHOICE=$(printf '%s' "$CHOICE" | tr -d '[:space:]')
        case $CHOICE in
            1) EXCLUSION_FILES+=("./runtime/inames/archives.inm") ;;
            2) EXCLUSION_FILES+=("./runtime/inames/audio.inm") ;;
            3) EXCLUSION_FILES+=("./runtime/inames/databases.inm") ;;
            4) EXCLUSION_FILES+=("./runtime/inames/images.inm") ;;
            5) EXCLUSION_FILES+=("./runtime/inames/video.inm") ;;
            6) EXCLUSION_FILES+=("./runtime/inames/vm.inm") ;;
            7) EXCLUSION_FILES=("./runtime/inames/archives.inm" "./runtime/inames/audio.inm" "./runtime/inames/databases.inm" "./runtime/inames/images.inm" "./runtime/inames/video.inm" "./runtime/inames/vm.inm") ;;
            8) EXCLUSION_FILES=() ;;
            *) echo "Invalid choice: $CHOICE. Skipping." ;;
        esac
    done

    build_exclusion_regex
}

# Convert a shell glob (as used by find -iname) into an extended regex that
# matches the file's base name.
glob_to_regex() {
    printf '%s' "$1" | awk '{
        out = ""
        n = length($0)
        for (i = 1; i <= n; i++) {
            c = substr($0, i, 1)
            if (c == "*")      out = out "[^/]*"
            else if (c == "?") out = out "[^/]"
            else if (index(".[]()+^$|{}\\", c) > 0) out = out "\\" c
            else out = out c
        }
        print out
    }'
}

# Build one regex from the selected .inm files. The exclusions are then applied
# as a single in-memory pass over the file list instead of one extra
# filesystem traversal per exclusion file.
EXCLUDE_REGEX=""
build_exclusion_regex() {
    EXCLUDE_REGEX=""
    local file pattern regex
    for file in "${EXCLUSION_FILES[@]}"; do
        if [[ ! -f "$file" ]]; then
            log_message "${C_YELLOW}Exclusion file not found, ignoring: $file${C_RESET}"
            continue
        fi
        while IFS= read -r pattern; do
            [ -n "$pattern" ] || continue
            regex=$(glob_to_regex "$pattern")
            if [[ -z "$EXCLUDE_REGEX" ]]; then
                EXCLUDE_REGEX="/${regex}\$"
            else
                EXCLUDE_REGEX="${EXCLUDE_REGEX}|/${regex}\$"
            fi
        done < <(grep -oE '\-iname[[:space:]]+"[^"]+"' "$file" | sed -E 's/.*"(.*)"/\1/')
    done
}

# Prompt for maximum file size
select_max_file_size() {
    local DEFAULT_MAX_SIZE=750000000  # 750MB in bytes
    echo ""
    echo "Enter the maximum file size to scan (in bytes)."
    echo "The default value is 750,000,000 bytes (750MB)."
    while true; do
        prompt MAX_SIZE "Value: "
        MAX_SIZE=${MAX_SIZE:-$DEFAULT_MAX_SIZE}
        # Accept 750,000,000 and 750 000 000 as well.
        MAX_SIZE=$(printf '%s' "$MAX_SIZE" | tr -d ' ,_')
        case $MAX_SIZE in
            ''|*[!0-9]*)
                echo "Please enter a positive whole number of bytes."
                ;;
            *)
                if [ "$MAX_SIZE" -gt 0 ] 2>/dev/null; then
                    break
                fi
                echo "Please enter a positive whole number of bytes."
                ;;
        esac
    done
}

# Prompt for YARA rule set
select_yara_rules_set() {
    echo ""
    echo "Choose YARA rule set:"
    echo "1. Core"
    echo "2. Extended (default)"
    echo "3. Full"
    prompt RULE_CHOICE "Enter choice (1, 2 or 3, default: 2): "
    case $RULE_CHOICE in
        1) RULE_SET="core" ;;
        2|"") RULE_SET="extended" ;;
        3) RULE_SET="full" ;;
        *) echo "Invalid choice. Using Extended rules by default."; RULE_SET="extended" ;;
    esac
    RULE_FILE="./runtime/rules/yara-rules-${RULE_SET}.yar"
}

require_rule_file() {
    if [[ ! -f "$RULE_FILE" ]]; then
        echo ""
        log_message "${C_RED}Rule file not found: $RULE_FILE${C_RESET}"
        log_message "${C_RED}Run YAREX again and accept the rules update, or place the file there manually.${C_RESET}"
        exit 1
    fi
}

# Escape glob metacharacters so a path can be used safely with find -path.
escape_glob() {
    printf '%s' "$1" | sed 's/[][*?\\]/\\&/g'
}

# Quote a CSV field per RFC 4180 and neutralize spreadsheet formula injection.
csv_field() {
    local value=$1
    case $value in
        [=+@-]*|$'\t'*|$'\r'*) value="'$value" ;;
    esac
    value=${value//\"/\"\"}
    printf '"%s"' "$value"
}

SCAN_OK=true

# Scan selected directories
scan_all_directories() {
    local script_dir_pattern
    script_dir_pattern=$(escape_glob "$SCRIPT_DIR")

    rm -f "$RUN_DIR/candidates" "$RUN_DIR/excluded" "$RUN_DIR/diff" \
          "$RUN_DIR/matches" "$RUN_DIR/yara_status"
    mkdir -p "$RUN_DIR"
    : > "$RUN_DIR/candidates"

    printf 'Rule,File,SHA256\n' > "$NAME_OUTPUT"
    : > "$RUN_DIR/matches"

    echo ""
    local SCAN
    for SCAN in "${TO_SCAN[@]}"; do
        log_message "Gathering file list from $SCAN ..."
        # One traversal per location. The size limit is applied here because
        # YARA's --skip-larger is ignored when reading a --scan-list.
        find "$SCAN" \
            \( -path "$script_dir_pattern" \
               -o -path "/System/Volumes/Preboot" \
               -o -path "/proc" -o -path "/sys" -o -path "/dev" \) -prune \
            -o \( -type f -size -"${MAX_SIZE}"c -print \) \
            >> "$RUN_DIR/candidates" 2>> "$ERRORS_OUTPUT"
    done

    # Deduplicate so overlapping scan roots cannot list a file twice.
    sort -u "$RUN_DIR/candidates" -o "$RUN_DIR/candidates"

    log_message "Applying exclusions ..."
    if [[ -n "$EXCLUDE_REGEX" ]]; then
        grep -Ei -e "$EXCLUDE_REGEX" "$RUN_DIR/candidates" > "$RUN_DIR/excluded" || true
        grep -Evi -e "$EXCLUDE_REGEX" "$RUN_DIR/candidates" > "$RUN_DIR/diff" || true
    else
        : > "$RUN_DIR/excluded"
        cp "$RUN_DIR/candidates" "$RUN_DIR/diff"
    fi

    log_message "Finished building included and excluded lists."

    local candidate_count excluded_count final_count
    candidate_count=$(wc -l < "$RUN_DIR/candidates" | tr -d '[:space:]')
    excluded_count=$(wc -l < "$RUN_DIR/excluded" | tr -d '[:space:]')
    final_count=$(wc -l < "$RUN_DIR/diff" | tr -d '[:space:]')
    echo ""
    log_message "${C_WHITE}############################################${C_RESET}"
    echo ""
    log_message "${C_WHITE}Files found within the size limit: ${C_WHITE}$candidate_count${C_RESET}"
    log_message "${C_WHITE}Excluded by file type: ${C_GREEN}$excluded_count${C_RESET}"
    echo ""
    log_message "${C_WHITE}Files to be scanned: ${C_YELLOW}$final_count${C_RESET}"
    echo ""
    log_message "${C_WHITE}############################################${C_RESET}"
    echo ""

    if [ "$final_count" -eq 0 ]; then
        log_message "${C_YELLOW}Nothing to scan. Review your locations, size limit and exclusions.${C_RESET}"
        SCAN_OK=false
        return 1
    fi

    log_message "Running YARA scan ..."

    local yara_cmd cores
    yara_cmd=(yara)

    # YARA defaults to 8 worker threads; raise it on larger machines.
    cores=$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 0)
    case $cores in
        ''|*[!0-9]*) cores=0 ;;
    esac
    if [ "$cores" -gt 8 ]; then
        yara_cmd+=(-p "$cores")
    fi

    if [[ "$RULE_FILE" =~ \.compiled$ ]]; then
        yara_cmd+=(-C "$RULE_FILE")
    else
        yara_cmd+=(-w "$RULE_FILE")
    fi
    yara_cmd+=(-N --scan-list "$RUN_DIR/diff")

    if command -v stdbuf > /dev/null 2>&1; then
        yara_cmd=(stdbuf -oL -eL "${yara_cmd[@]}")
    elif command -v gstdbuf > /dev/null 2>&1; then
        yara_cmd=(gstdbuf -oL -eL "${yara_cmd[@]}")
    fi

    local rule matched_file file_hash match_count=0
    # Process substitution keeps the loop in the current shell so match_count
    # survives, while YARA's exit status is captured through a file.
    while IFS= read -r line; do
        rule=${line%% *}
        matched_file=${line#* }
        [ -n "$rule" ] || continue
        [ "$matched_file" != "$line" ] || continue

        if [ -f "$matched_file" ]; then
            file_hash=$(compute_hash "$matched_file")
            [ -n "$file_hash" ] || file_hash="HASH_ERROR"
        else
            file_hash="FILE_NOT_FOUND"
        fi

        # Human/spreadsheet facing report.
        printf '%s,%s,%s\n' \
            "$(csv_field "$rule")" \
            "$(csv_field "$matched_file")" \
            "$(csv_field "$file_hash")" >> "$NAME_OUTPUT"
        # Faithful NUL-delimited sidecar used by the extraction step.
        printf '%s\0%s\0%s\0' "$rule" "$matched_file" "$file_hash" >> "$RUN_DIR/matches"
        match_count=$((match_count + 1))
    done < <( { "${yara_cmd[@]}" 2>> "$ERRORS_OUTPUT"; printf '%s' "$?" > "$RUN_DIR/yara_status"; } )

    local yara_status
    yara_status=$(cat "$RUN_DIR/yara_status" 2>/dev/null)
    case $yara_status in
        ''|*[!0-9]*) yara_status=1 ;;
    esac

    echo ""
    if [ "$yara_status" -ne 0 ]; then
        SCAN_OK=false
        log_message "${C_RED}############################################${C_RESET}"
        echo ""
        log_message "${C_RED}YARA exited with status $yara_status - the scan is INCOMPLETE.${C_RESET}"
        log_message "${C_RED}Do not read these results as a clean scan.${C_RESET}"
        log_message "${C_RED}Details: $ERRORS_OUTPUT${C_RESET}"
        echo ""
        log_message "${C_RED}############################################${C_RESET}"
        return 1
    fi

    if [ -s "$ERRORS_OUTPUT" ]; then
        local err_lines
        err_lines=$(wc -l < "$ERRORS_OUTPUT" | tr -d '[:space:]')
        log_message "${C_YELLOW}$err_lines line(s) logged to $ERRORS_OUTPUT (unreadable files, permissions, ...)${C_RESET}"
    fi

    log_message "${C_GREEN}############################################${C_RESET}"
    echo ""
    log_message "${C_GREEN}Scan completed. $match_count match(es).${C_RESET}"
    log_message "${C_GREEN}Results in -->${C_RESET} $NAME_OUTPUT"
    echo ""
    log_message "${C_GREEN}############################################${C_RESET}"
    return 0
}

extract_flagged_files() {
    echo ""
    if [ ! -s "$RUN_DIR/matches" ]; then
        log_message "No flagged files to extract."
        return 0
    fi

    log_message "Extracting flagged files ..."
    echo ""
    mkdir -p "$EXTRACTS_DIR"

    local rule matched_file file_hash output_path copied=0 skipped=0 new_hash
    # Records are NUL-delimited, so commas or quotes in paths are handled.
    while IFS= read -r -d '' rule \
       && IFS= read -r -d '' matched_file \
       && IFS= read -r -d '' file_hash; do
        if [ ! -f "$matched_file" ]; then
            log_message "${C_RED}File not found:${C_RESET} $matched_file (skipping)"
            skipped=$((skipped + 1))
            continue
        fi

        output_path="${EXTRACTS_DIR}$(dirname "$matched_file")"
        if ! mkdir -p "$output_path"; then
            log_message "${C_RED}Could not create:${C_RESET} $output_path (skipping)"
            skipped=$((skipped + 1))
            continue
        fi

        if ! cp -p "$matched_file" "$output_path/"; then
            log_message "${C_RED}Copy failed:${C_RESET} $matched_file (skipping)"
            skipped=$((skipped + 1))
            continue
        fi

        # Confirm the evidence copy matches what was recorded during the scan.
        new_hash=$(compute_hash "$output_path/$(basename "$matched_file")")
        if [ -n "$file_hash" ] && [ "$file_hash" != "HASH_ERROR" ] && [ "$file_hash" != "FILE_NOT_FOUND" ] \
           && [ "$new_hash" != "$file_hash" ]; then
            log_message "${C_YELLOW}Hash mismatch after copy:${C_RESET} $matched_file (file changed on disk since the scan)"
        fi

        log_message "${C_GREEN}Extracted:${C_RESET} $matched_file (SHA-256: $file_hash)"
        copied=$((copied + 1))
    done < "$RUN_DIR/matches"

    echo ""
    log_message "${C_GREEN}############################################${C_RESET}"
    echo ""
    log_message "${C_GREEN}Extraction complete.${C_RESET} $copied copied, $skipped skipped."
    log_message "${C_GREEN}Suspected files in -->${C_RESET} ${EXTRACTS_DIR}/"
    echo ""
    log_message "${C_GREEN}############################################${C_RESET}"
}

# Main exec
display_ascii_art
prompt CASE_NAME "Enter scan name (no spaces): "
# Keep the name usable as a path component.
CASE_NAME=$(printf '%s' "$CASE_NAME" | tr -c 'A-Za-z0-9._-' '_')
CASE_NAME=${CASE_NAME:-"default_case"}

RANDOM_NUMBERS=$(printf "%04d" $((RANDOM % 10000)))
NAME_OUTPUT="./results/csv/${CASE_NAME}_scan_$(date '+%Y-%m-%d')_${RANDOM_NUMBERS}.csv"
ERRORS_OUTPUT="./results/logs/${CASE_NAME}_scan_errors_$(date '+%Y-%m-%d')_${RANDOM_NUMBERS}.log"
EXTRACTS_DIR="./results/extracts/${CASE_NAME}"
mkdir -p "$EXTRACTS_DIR"
: > "$ERRORS_OUTPUT"

# The rule set is chosen first so the update only downloads what is needed.
select_yara_rules_set

if check_internet; then
    prompt update_choice "Would you like to update YARA rules now? (y/n): "
    update_choice=${update_choice:-Y}
    case "$update_choice" in
        [Yy]*)
            update_yara_rules "$RULE_SET"
            ;;
        *)
            ;;
    esac
fi

require_rule_file

# Prompt user to compile the selected YARA rules for better performance.
if command -v yarac >/dev/null 2>&1; then
    echo ""
    prompt compile_choice "Would you like to compile the selected YARA rules for better performance? (y/n): "
    compile_choice=${compile_choice:-y}
    if [[ $compile_choice =~ ^[Yy] ]]; then
        COMPILED_RULE_FILE="${RULE_FILE%.yar}.compiled"
        if [ -f "$COMPILED_RULE_FILE" ] && [ "$COMPILED_RULE_FILE" -nt "$RULE_FILE" ]; then
            RULE_FILE="$COMPILED_RULE_FILE"
            log_message "Reusing up-to-date compiled rules: $COMPILED_RULE_FILE"
        elif yarac "$RULE_FILE" "$COMPILED_RULE_FILE"; then
            RULE_FILE="$COMPILED_RULE_FILE"
            log_message "Successfully compiled YARA rules to $COMPILED_RULE_FILE"
        else
            rm -f "$COMPILED_RULE_FILE"
            log_message "${C_YELLOW}Compilation failed. Proceeding with uncompiled rules.${C_RESET}"
        fi
    fi
else
    log_message "yarac is not installed. Skipping rule compilation."
fi

get_scan_locations
select_max_file_size
select_exclusions
scan_all_directories

# If --extract argument was provided, automatically extract flagged files,
# otherwise prompt the user.
if [ "$SCAN_OK" = true ]; then
    if [ "$AUTO_EXTRACT" = true ]; then
        extract_flagged_files
    else
        prompt extract_choice "Would you like to extract the flagged files? (y/n): "
        extract_choice=${extract_choice:-Y}
        case "$extract_choice" in
            [Yy]*)
                extract_flagged_files
                ;;
            *)
                ;;
        esac
    fi
    exit 0
fi

exit 1
