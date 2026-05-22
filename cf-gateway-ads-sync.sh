#!/usr/bin/env bash
set -Eeuo pipefail

# Cloudflare Gateway Ad Block Sync
# Required environment:
#   CF_API_TOKEN   or CLOUDFLARE_API_TOKEN or API_TOKEN
#   CF_ACCOUNT_ID  or CLOUDFLARE_ACCOUNT_ID or ACCOUNT_ID
#
# Optional environment:
#   LIST_PREFIX="Block ads"
#   RULE_NAME="Block ads"
#   BLOCKLIST_URL="https://small.oisd.nl/domainswild2"
#   MAX_LIST_SIZE=1000
#   MAX_LISTS=100
#   CLOUDFLARE_LIST_LIMIT=100
#   RULE_PRECEDENCE=90
#   DELETE_EXCESS_LISTS=1

CF_API_TOKEN="${CF_API_TOKEN:-${CLOUDFLARE_API_TOKEN:-${API_TOKEN:-}}}"
CF_ACCOUNT_ID="${CF_ACCOUNT_ID:-${CLOUDFLARE_ACCOUNT_ID:-${ACCOUNT_ID:-}}}"

LIST_PREFIX="${LIST_PREFIX:-Block ads}"
RULE_NAME="${RULE_NAME:-Block ads}"
BLOCKLIST_URL="${BLOCKLIST_URL:-https://small.oisd.nl/domainswild2}"
MAX_LIST_SIZE="${MAX_LIST_SIZE:-1000}"
MAX_LISTS="${MAX_LISTS:-100}"
CLOUDFLARE_LIST_LIMIT="${CLOUDFLARE_LIST_LIMIT:-100}"
RULE_PRECEDENCE="${RULE_PRECEDENCE:-90}"
DELETE_EXCESS_LISTS="${DELETE_EXCESS_LISTS:-1}"

CF_API_BASE="https://api.cloudflare.com/client/v4"

fail() {
    printf 'ERROR: %s\n' "$1" >&2
    exit 1
}

info() {
    printf '[sync] %s\n' "$1"
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

validate_config() {
    [[ -n "$CF_API_TOKEN" ]] || fail "Missing CF_API_TOKEN / CLOUDFLARE_API_TOKEN / API_TOKEN"
    [[ -n "$CF_ACCOUNT_ID" ]] || fail "Missing CF_ACCOUNT_ID / CLOUDFLARE_ACCOUNT_ID / ACCOUNT_ID"

    [[ "$MAX_LIST_SIZE" =~ ^[0-9]+$ ]] || fail "MAX_LIST_SIZE must be numeric"
    [[ "$MAX_LISTS" =~ ^[0-9]+$ ]] || fail "MAX_LISTS must be numeric"
    [[ "$CLOUDFLARE_LIST_LIMIT" =~ ^[0-9]+$ ]] || fail "CLOUDFLARE_LIST_LIMIT must be numeric"
    [[ "$RULE_PRECEDENCE" =~ ^[0-9]+$ ]] || fail "RULE_PRECEDENCE must be numeric"
    [[ "$DELETE_EXCESS_LISTS" =~ ^[01]$ ]] || fail "DELETE_EXCESS_LISTS must be 0 or 1"

    (( MAX_LIST_SIZE > 0 )) || fail "MAX_LIST_SIZE must be greater than zero"
    (( MAX_LISTS > 0 )) || fail "MAX_LISTS must be greater than zero"
    (( CLOUDFLARE_LIST_LIMIT > 0 )) || fail "CLOUDFLARE_LIST_LIMIT must be greater than zero"
}

api_request() {
    local method="$1"
    local path="$2"
    local data="${3-}"
    local response_file
    local http_code
    local error_text

    response_file="$(mktemp)"

    if [[ -n "$data" ]]; then
        http_code="$(
            curl -sS \
                --retry 5 \
                --retry-delay 2 \
                --retry-all-errors \
                -X "$method" \
                -H "Authorization: Bearer ${CF_API_TOKEN}" \
                -H "Content-Type: application/json" \
                -o "$response_file" \
                -w "%{http_code}" \
                --data "$data" \
                "${CF_API_BASE}${path}"
        )"
    else
        http_code="$(
            curl -sS \
                --retry 5 \
                --retry-delay 2 \
                --retry-all-errors \
                -X "$method" \
                -H "Authorization: Bearer ${CF_API_TOKEN}" \
                -H "Content-Type: application/json" \
                -o "$response_file" \
                -w "%{http_code}" \
                "${CF_API_BASE}${path}"
        )"
    fi

    if [[ ! "$http_code" =~ ^2 ]]; then
        error_text="$(jq -r '[.errors[]?.message] | join("; ")' "$response_file" 2>/dev/null || true)"
        rm -f "$response_file"
        [[ -n "$error_text" ]] || error_text="Cloudflare API returned HTTP ${http_code}"
        fail "$error_text"
    fi

    if ! jq -e '.success == true' "$response_file" >/dev/null 2>&1; then
        error_text="$(jq -r '[.errors[]?.message] | join("; ")' "$response_file" 2>/dev/null || true)"
        rm -f "$response_file"
        [[ -n "$error_text" ]] || error_text="Cloudflare API response was not successful"
        fail "$error_text"
    fi

    cat "$response_file"
    rm -f "$response_file"
}

normalize_blocklist() {
    local raw_file="$1"
    local domains_file="$2"

    awk '
    function trim(value) {
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
        return value
    }

    function valid_domain(domain, parts, total, i) {
        if (domain !~ /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?$/) {
            return 0
        }

        total = split(domain, parts, ".")
        for (i = 1; i <= total; i++) {
            if (length(parts[i]) > 63) {
                return 0
            }
        }

        return 1
    }

    {
        sub(/\r$/, "", $0)
        sub(/[[:space:]]+#.*$/, "", $0)

        domain = trim($0)

        if (domain == "" || domain ~ /^#/) {
            next
        }

        sub(/^\|\|/, "", domain)
        sub(/\^$/, "", domain)
        sub(/^\*\./, "", domain)
        sub(/^\.+/, "", domain)

        domain = tolower(domain)

        if (domain ~ /(^|\.)localhost$/) {
            next
        }

        if (valid_domain(domain)) {
            print domain
        }
    }
    ' "$raw_file" | sort -u > "$domains_file"
}

json_items_from_file() {
    local file="$1"

    jq -R -s '
        split("\n")
        | map(select(length > 0))
        | map({value: .})
    ' "$file"
}

get_existing_list_id() {
    local current_lists="$1"
    local list_name="$2"

    jq -r --arg name "$list_name" '
        .result[]?
        | select(.name == $name)
        | .id
    ' <<< "$current_lists" | head -n 1
}

build_traffic_expression() {
    local expression=""
    local list_id
    local condition

    for list_id in "$@"; do
        condition="(any(dns.domains[*] in \$$list_id) or dns.fqdn in \$$list_id)"

        if [[ -z "$expression" ]]; then
            expression="$condition"
        else
            expression="${expression} or ${condition}"
        fi
    done

    printf '%s\n' "$expression"
}

main() {
    require_cmd curl
    require_cmd jq
    require_cmd awk
    require_cmd sort
    require_cmd split
    require_cmd find
    require_cmd wc

    validate_config

    local workdir
    local raw_file
    local domains_file
    local total_domains
    local total_chunks
    local current_lists
    local current_rules
    local existing_total_count
    local existing_managed_count
    local existing_non_managed_count
    local list_budget_needed
    local chunk_files
    local used_list_ids
    local chunk_file
    local index
    local list_number
    local list_name
    local list_description
    local existing_list_id
    local items_json
    local payload
    local response
    local created_list_id
    local traffic
    local rule_id
    local rule_payload
    local managed_prefix
    local expression_length

    workdir="$(mktemp -d)"
    raw_file="${workdir}/blocklist.raw.txt"
    domains_file="${workdir}/domains.normalized.txt"
    managed_prefix="${LIST_PREFIX} - "
    used_list_ids=()

    trap 'rm -rf "$workdir"' EXIT

    info "Downloading blocklist"
    curl -fsSL \
        --retry 5 \
        --retry-delay 2 \
        --retry-all-errors \
        "$BLOCKLIST_URL" \
        -o "$raw_file"

    info "Normalizing blocklist"
    normalize_blocklist "$raw_file" "$domains_file"

    total_domains="$(wc -l < "$domains_file" | tr -d '[:space:]')"
    (( total_domains > 0 )) || fail "Normalized blocklist is empty"

    total_chunks=$(( (total_domains + MAX_LIST_SIZE - 1) / MAX_LIST_SIZE ))

    (( total_chunks <= MAX_LISTS )) || fail "Need ${total_chunks} lists, but MAX_LISTS is ${MAX_LISTS}"

    info "Domains: ${total_domains}"
    info "Required Cloudflare lists: ${total_chunks}"

    info "Fetching existing Cloudflare Gateway lists"
    current_lists="$(api_request "GET" "/accounts/${CF_ACCOUNT_ID}/gateway/lists?per_page=1000")"

    existing_total_count="$(jq -r '.result | length' <<< "$current_lists")"
    existing_managed_count="$(
        jq -r --arg prefix "$managed_prefix" '
            [.result[]? | select(.name | startswith($prefix))] | length
        ' <<< "$current_lists"
    )"

    existing_non_managed_count=$(( existing_total_count - existing_managed_count ))
    list_budget_needed=$(( existing_non_managed_count + total_chunks ))

    if (( list_budget_needed > CLOUDFLARE_LIST_LIMIT )); then
        fail "Cloudflare list limit exceeded. Existing non-managed lists: ${existing_non_managed_count}, needed managed lists: ${total_chunks}, limit: ${CLOUDFLARE_LIST_LIMIT}"
    fi

    split -d -a 3 -l "$MAX_LIST_SIZE" "$domains_file" "${workdir}/chunk-"
    mapfile -t chunk_files < <(find "$workdir" -maxdepth 1 -type f -name 'chunk-*' | sort)

    for index in "${!chunk_files[@]}"; do
        chunk_file="${chunk_files[$index]}"
        list_number=$(( index + 1 ))
        list_name="${LIST_PREFIX} - $(printf '%03d' "$list_number")"
        list_description="Managed by cf-gateway-ads-sync.sh. Source blocklist is normalized before upload."

        existing_list_id="$(get_existing_list_id "$current_lists" "$list_name")"
        items_json="$(json_items_from_file "$chunk_file")"

        if [[ -n "$existing_list_id" && "$existing_list_id" != "null" ]]; then
            info "Updating list: ${list_name}"

            payload="$(
                jq -n \
                    --arg name "$list_name" \
                    --arg description "$list_description" \
                    --argjson items "$items_json" \
                    '{
                        name: $name,
                        description: $description,
                        items: $items
                    }'
            )"

            response="$(api_request "PUT" "/accounts/${CF_ACCOUNT_ID}/gateway/lists/${existing_list_id}" "$payload")"
            created_list_id="$(jq -r '.result.id // empty' <<< "$response")"
            [[ -n "$created_list_id" ]] || created_list_id="$existing_list_id"
            used_list_ids+=("$created_list_id")
        else
            info "Creating list: ${list_name}"

            payload="$(
                jq -n \
                    --arg name "$list_name" \
                    --arg description "$list_description" \
                    --argjson items "$items_json" \
                    '{
                        name: $name,
                        description: $description,
                        type: "DOMAIN",
                        items: $items
                    }'
            )"

            response="$(api_request "POST" "/accounts/${CF_ACCOUNT_ID}/gateway/lists" "$payload")"
            created_list_id="$(jq -r '.result.id // empty' <<< "$response")"
            [[ -n "$created_list_id" ]] || fail "Cloudflare did not return a list ID for ${list_name}"
            used_list_ids+=("$created_list_id")
        fi
    done

    if [[ "$DELETE_EXCESS_LISTS" == "1" ]]; then
        while IFS=$'\t' read -r list_name existing_list_id; do
            [[ -n "$list_name" && -n "$existing_list_id" ]] || continue

            local suffix
            local numeric_suffix

            suffix="${list_name#${managed_prefix}}"

            if [[ "$suffix" =~ ^[0-9]{3}$ ]]; then
                numeric_suffix=$((10#$suffix))

                if (( numeric_suffix > total_chunks )); then
                    info "Deleting excess list: ${list_name}"
                    api_request "DELETE" "/accounts/${CF_ACCOUNT_ID}/gateway/lists/${existing_list_id}" >/dev/null
                fi
            fi
        done < <(
            jq -r --arg prefix "$managed_prefix" '
                .result[]?
                | select(.name | startswith($prefix))
                | [.name, .id]
                | @tsv
            ' <<< "$current_lists"
        )
    fi

    traffic="$(build_traffic_expression "${used_list_ids[@]}")"
    expression_length="${#traffic}"

    (( expression_length > 0 )) || fail "Traffic expression is empty"
    (( expression_length < 140000 )) || fail "Traffic expression is too long: ${expression_length} characters"

    info "Fetching existing Cloudflare Gateway rules"
    current_rules="$(api_request "GET" "/accounts/${CF_ACCOUNT_ID}/gateway/rules?per_page=1000")"

    rule_id="$(
        jq -r --arg name "$RULE_NAME" '
            .result[]?
            | select(.name == $name)
            | .id
        ' <<< "$current_rules" | head -n 1
    )"

    rule_payload="$(
        jq -n \
            --arg name "$RULE_NAME" \
            --arg description "Managed by cf-gateway-ads-sync.sh. Blocks domains from managed Cloudflare Gateway lists." \
            --arg traffic "$traffic" \
            --argjson precedence "$RULE_PRECEDENCE" \
            '{
                name: $name,
                description: $description,
                precedence: $precedence,
                enabled: true,
                action: "block",
                filters: ["dns"],
                traffic: $traffic,
                identity: ""
            }'
    )"

    if [[ -n "$rule_id" && "$rule_id" != "null" ]]; then
        info "Updating DNS Gateway rule: ${RULE_NAME}"
        api_request "PUT" "/accounts/${CF_ACCOUNT_ID}/gateway/rules/${rule_id}" "$rule_payload" >/dev/null
    else
        info "Creating DNS Gateway rule: ${RULE_NAME}"
        api_request "POST" "/accounts/${CF_ACCOUNT_ID}/gateway/rules" "$rule_payload" >/dev/null
    fi

    info "Done"
}

main "$@"