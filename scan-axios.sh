#!/usr/bin/env bash
set -eo pipefail

# scan-axios.sh — detect indicators of the axios supply chain compromise
# scans for compromised versions, phantom dependencies, RAT artifacts, and C2 traffic
# usage: ./scan-axios.sh [directory-to-scan]
#        curl -sL https://raw.githubusercontent.com/mikero1988/axios-attack-guide/main/scan-axios.sh | bash

SCAN_ROOT="${1:-$HOME}"
REPORT_FILE="axios-scan-report-$(date +%Y%m%d-%H%M%S).txt"

# known bad
BAD_VERSIONS=("1.14.1" "0.30.4")
PHANTOM_DEP="plain-crypto-js"
C2_IP="142.11.206.73"
C2_DOMAIN="sfrclak.com"
RAT_PATHS_MAC=("/Library/Caches/com.apple.act.mond")
RAT_PATHS_LINUX=("/tmp/ld.py")
RAT_PATHS_WIN=() # not applicable on this OS but listed for completeness

# counters
ISSUES=0
SCANNED=0

log()  { printf '%s\n' "$1"; }
warn() { printf '\033[1;31m[!] %s\033[0m\n' "$1"; }
ok()   { printf '\033[0;32m[+] %s\033[0m\n' "$1"; }
info() { printf '\033[0;36m[-] %s\033[0m\n' "$1"; }

report() {
    printf '%s\n' "$1" >> "$REPORT_FILE"
}

header() {
    log ""
    log "╔══════════════════════════════════════════════════╗"
    log "║       axios supply chain compromise scanner      ║"
    log "╚══════════════════════════════════════════════════╝"
    log ""
    info "scan root: $SCAN_ROOT"
    info "report: $REPORT_FILE"
    info "date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    log ""

    report "axios compromise scan — $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    report "scan root: $SCAN_ROOT"
    report "---"
}

# ── phase 1: find every axios installation and check versions ──

scan_axios_versions() {
    log "── phase 1: scanning for axios installations ──"
    log ""

    local found=0

    while IFS= read -r -d '' pkg; do
        # parse version out of package.json without jq (not everyone has it)
        local ver
        ver=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$pkg" 2>/dev/null | head -1)

        [ -z "$ver" ] && continue

        ((SCANNED++)) || true
        found=1

        local is_bad=0
        for bv in "${BAD_VERSIONS[@]}"; do
            if [ "$ver" = "$bv" ]; then
                is_bad=1
                break
            fi
        done

        local dir
        dir=$(dirname "$pkg")

        if [ "$is_bad" -eq 1 ]; then
            warn "COMPROMISED  axios@$ver  ← $dir"
            report "COMPROMISED: axios@$ver at $dir"
            ((ISSUES++)) || true
        else
            ok "ok  axios@$ver  ← $dir"
        fi
    done < <(find "$SCAN_ROOT" -maxdepth 8 -path "*/node_modules/axios/package.json" -print0 2>/dev/null || true)

    # also check global npm if available
    if command -v npm &>/dev/null; then
        local gver
        gver=$(npm ls -g axios --depth=0 2>/dev/null | grep -oE 'axios@[0-9.]+' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || true)
        if [ -n "$gver" ]; then
            found=1
            ((SCANNED++)) || true
            local is_bad=0
            for bv in "${BAD_VERSIONS[@]}"; do
                [ "$gver" = "$bv" ] && is_bad=1
            done
            if [ "$is_bad" -eq 1 ]; then
                warn "COMPROMISED  axios@$gver  (global npm)"
                report "COMPROMISED: axios@$gver (global)"
                ((ISSUES++)) || true
            else
                ok "ok  axios@$gver  (global npm)"
            fi
        fi
    fi

    if [ "$found" -eq 0 ]; then
        info "no axios installations found under $SCAN_ROOT"
    fi
    log ""
}

# ── phase 2: grep lockfiles for the phantom dependency ──

scan_lockfiles() {
    log "── phase 2: checking lockfiles for $PHANTOM_DEP ──"
    log ""

    local found=0

    while IFS= read -r -d '' lockfile; do
        if grep -q "$PHANTOM_DEP" "$lockfile" 2>/dev/null; then
            warn "phantom dep found in $lockfile"
            report "PHANTOM DEP: $PHANTOM_DEP in $lockfile"
            ((ISSUES++)) || true
            found=1
        fi
    done < <(find "$SCAN_ROOT" -maxdepth 6 \( -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \) -not -path "*/node_modules/*" -print0 2>/dev/null || true)

    if [ "$found" -eq 0 ]; then
        ok "no lockfiles reference $PHANTOM_DEP"
    fi
    log ""
}

# ── phase 3: git history forensics ──

scan_git_history() {
    log "── phase 3: searching git history for past exposure ──"
    log ""

    local found=0

    if ! command -v git &>/dev/null; then
        info "git not available, skipping history scan"
        log ""
        return
    fi

    # find all git repos under the scan root
    while IFS= read -r -d '' gitdir; do
        local repo_root
        repo_root=$(dirname "$gitdir")

        # search all branches for the phantom dep or bad versions in lockfiles
        local hits
        hits=$(git -C "$repo_root" log --all -p -- package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null \
            | grep -E "(plain-crypto-js|\"axios\": \"1\.14\.1\"|\"axios\": \"0\.30\.4\"|axios@1\.14\.1|axios@0\.30\.4)" \
            | head -5 || true)

        if [ -n "$hits" ]; then
            warn "exposure found in repo: $repo_root"
            while IFS= read -r line; do
                info "  $line"
            done <<< "$hits"
            report "GIT HISTORY: compromise traces in $repo_root"
            ((ISSUES++)) || true
            found=1
        fi
    done < <(find "$SCAN_ROOT" -maxdepth 6 -name ".git" -type d -print0 2>/dev/null || true)

    if [ "$found" -eq 0 ]; then
        ok "no compromise traces in git history"
    fi
    log ""
}

# ── phase 4: check for RAT files ──

scan_rat_artifacts() {
    log "── phase 4: checking for RAT file artifacts ──"
    log ""

    local found=0
    local os_type
    os_type=$(uname -s)

    local paths=()
    case "$os_type" in
        Darwin) paths=("${RAT_PATHS_MAC[@]}") ;;
        Linux)  paths=("${RAT_PATHS_LINUX[@]}") ;;
        *)      info "skipping RAT file check (unsupported OS: $os_type)" ; return ;;
    esac

    for p in "${paths[@]}"; do
        if [ -e "$p" ]; then
            warn "RAT artifact found: $p"
            # grab file metadata for the report
            local meta
            meta=$(ls -la "$p" 2>/dev/null || echo "could not stat")
            report "RAT ARTIFACT: $p ($meta)"
            ((ISSUES++)) || true
            found=1
        else
            ok "clean: $p"
        fi
    done

    # bonus: look for the plain-crypto-js node_modules dir itself
    while IFS= read -r -d '' pdir; do
        warn "phantom package on disk: $pdir"
        report "PHANTOM PACKAGE DIR: $pdir"
        ((ISSUES++)) || true
        found=1
    done < <(find "$SCAN_ROOT" -maxdepth 8 -type d -name "plain-crypto-js" -path "*/node_modules/*" -print0 2>/dev/null || true)

    if [ "$found" -eq 0 ]; then
        ok "no RAT artifacts or phantom package directories found"
    fi
    log ""
}

# ── phase 5: look for C2 connections ──

scan_network() {
    log "── phase 5: checking for C2 network activity ──"
    log ""

    local found=0

    # try ss first, fall back to netstat
    local net_output=""
    if command -v ss &>/dev/null; then
        net_output=$(ss -tnp 2>/dev/null | grep "$C2_IP" || true)
    elif command -v netstat &>/dev/null; then
        net_output=$(netstat -an 2>/dev/null | grep "$C2_IP" || true)
    else
        info "neither ss nor netstat available, skipping network check"
        log ""
        return
    fi

    if [ -n "$net_output" ]; then
        warn "active connection to C2 IP $C2_IP detected!"
        log "$net_output"
        report "C2 CONNECTION: $net_output"
        ((ISSUES++)) || true
        found=1
    fi

    # check if the c2 domain resolves (might indicate dns hasn't been blocked)
    if command -v host &>/dev/null; then
        local dns
        dns=$(host "$C2_DOMAIN" 2>/dev/null | grep -v "not found" | head -1 || true)
        if [ -n "$dns" ]; then
            info "note: $C2_DOMAIN still resolves — consider blocking at DNS level"
            info "  $dns"
        fi
    fi

    if [ "$found" -eq 0 ]; then
        ok "no active C2 connections"
    fi
    log ""
}

# ── phase 6: system log scan for C2 domain ──

scan_dns_logs() {
    log "── phase 6: searching system logs for C2 domain queries ──"
    log ""

    local found=0
    local os_type
    os_type=$(uname -s)

    case "$os_type" in
        Darwin)
            # macOS unified log — search last 7 days for the C2 domain
            local log_hits
            log_hits=$(log show --predicate "eventMessage CONTAINS '$C2_DOMAIN'" --style compact --last 7d 2>/dev/null | head -10 || true)
            if [ -n "$log_hits" ]; then
                warn "C2 domain found in macOS unified log!"
                while IFS= read -r line; do
                    info "  $line"
                done <<< "$log_hits"
                report "DNS LOG: $C2_DOMAIN found in macOS unified log"
                ((ISSUES++)) || true
                found=1
            fi
            ;;
        Linux)
            # check common log files we can read without sudo
            local log_files=("/var/log/syslog" "/var/log/messages" "/var/log/daemon.log" "/var/log/dnsmasq.log")

            # also pick up systemd-resolved logs if journalctl is available
            if command -v journalctl &>/dev/null; then
                local journal_hits
                journal_hits=$(journalctl -u systemd-resolved --since "7 days ago" --no-pager 2>/dev/null | grep "$C2_DOMAIN" | head -5 || true)
                if [ -n "$journal_hits" ]; then
                    warn "C2 domain found in systemd-resolved journal!"
                    while IFS= read -r line; do
                        info "  $line"
                    done <<< "$journal_hits"
                    report "DNS LOG: $C2_DOMAIN found in systemd-resolved journal"
                    ((ISSUES++)) || true
                    found=1
                fi
            fi

            for logfile in "${log_files[@]}"; do
                [ -r "$logfile" ] || continue
                local hits
                hits=$(grep "$C2_DOMAIN" "$logfile" 2>/dev/null | tail -5 || true)
                if [ -n "$hits" ]; then
                    warn "C2 domain found in $logfile!"
                    while IFS= read -r line; do
                        info "  $line"
                    done <<< "$hits"
                    report "DNS LOG: $C2_DOMAIN found in $logfile"
                    ((ISSUES++)) || true
                    found=1
                fi
            done
            ;;
        *)
            info "log scanning not supported on $os_type"
            ;;
    esac

    if [ "$found" -eq 0 ]; then
        ok "no C2 domain queries found in system logs"
    fi
    log ""
}

# ── summary ──

summary() {
    log "══════════════════════════════════════════════════"
    if [ "$ISSUES" -gt 0 ]; then
        warn "SCAN COMPLETE — $ISSUES issue(s) found across $SCANNED axios installation(s)"
        log ""
        warn "you should:"
        log "  1. disconnect from the network immediately"
        log "  2. block sfrclak.com / 142.11.206.73 at your firewall"
        log "  3. rotate every credential accessible from this machine"
        log "  4. downgrade axios to 1.14.0 / 0.30.3"
        log "  5. delete node_modules/plain-crypto-js everywhere"
        log "  6. audit your CI/CD for builds that used the bad versions"
        log "  7. seriously consider a clean OS reinstall"
        report "---"
        report "RESULT: $ISSUES issue(s) found — action required"
    else
        ok "SCAN COMPLETE — no indicators of compromise found"
        report "---"
        report "RESULT: clean"
    fi
    log ""
    info "full report saved to $REPORT_FILE"
    log ""
}

# ── main ──

header
scan_axios_versions
scan_lockfiles
scan_git_history
scan_rat_artifacts
scan_network
scan_dns_logs
summary
