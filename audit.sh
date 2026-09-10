#!/usr/bin/env bash
# audit.sh — read-only endpoint hardening audit.
#
# Checks a workstation's security posture against a baseline drawn from common
# hardening guidance (CIS-style): disk encryption, firewall, screen lock,
# automatic updates, remote access, and exposed listening services.
#
# READ-ONLY BY DESIGN. This script inspects configuration and changes nothing.
# It contains no remediation, no privilege escalation, and makes no network
# connections. Every check is a query you could run by hand.
#
# Usage:
#   ./audit.sh                 human-readable report
#   ./audit.sh --json          machine-readable, for fleet collection
#   ./audit.sh --strict        exit 1 if any check FAILs (for CI / MDM)
#
# MIT licensed.

set -uo pipefail

JSON=0
STRICT=0
while [ $# -gt 0 ]; do
  case "$1" in
    --json) JSON=1; shift ;;
    --strict) STRICT=1; shift ;;
    -h|--help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

OS="$(uname -s)"
PASS=0; WARN=0; FAIL=0; SKIP=0
ROWS=()

have() { command -v "$1" >/dev/null 2>&1; }

# record <status> <check> <detail>
record() {
  local status="$1" check="$2" detail="$3"
  case "$status" in
    PASS) PASS=$((PASS+1)) ;;
    WARN) WARN=$((WARN+1)) ;;
    FAIL) FAIL=$((FAIL+1)) ;;
    SKIP) SKIP=$((SKIP+1)) ;;
  esac
  ROWS+=("${status}|${check}|${detail}")
}

# ------------------------------------------------------------ disk encryption
check_encryption() {
  if [ "$OS" = "Darwin" ]; then
    if have fdesetup; then
      if fdesetup status 2>/dev/null | grep -qi "FileVault is On"; then
        record PASS "Disk encryption" "FileVault enabled"
      else
        record FAIL "Disk encryption" "FileVault is OFF — data readable if the device is stolen"
      fi
    else
      record SKIP "Disk encryption" "fdesetup unavailable"
    fi
  else
    if have lsblk && lsblk -o TYPE 2>/dev/null | grep -q crypt; then
      record PASS "Disk encryption" "LUKS volume present"
    else
      record WARN "Disk encryption" "no LUKS volume detected — verify manually"
    fi
  fi
}

# -------------------------------------------------------------------- firewall
check_firewall() {
  if [ "$OS" = "Darwin" ]; then
    local state
    state=$(defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null)
    case "${state:-}" in
      1|2) record PASS "Firewall" "application firewall enabled (state $state)" ;;
      0)   record FAIL "Firewall" "application firewall is OFF" ;;
      *)   record SKIP "Firewall" "state unreadable without elevated rights" ;;
    esac
  else
    if have ufw && ufw status 2>/dev/null | grep -qi "Status: active"; then
      record PASS "Firewall" "ufw active"
    elif have firewall-cmd && firewall-cmd --state 2>/dev/null | grep -qi running; then
      record PASS "Firewall" "firewalld running"
    elif have nft && [ -n "$(nft list ruleset 2>/dev/null)" ]; then
      record PASS "Firewall" "nftables ruleset present"
    else
      record WARN "Firewall" "no active firewall detected"
    fi
  fi
}

# ------------------------------------------------------------------ screen lock
check_screenlock() {
  if [ "$OS" = "Darwin" ]; then
    local ask delay
    ask=$(defaults read com.apple.screensaver askForPassword 2>/dev/null)
    delay=$(defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null)
    if [ "${ask:-0}" = "1" ]; then
      # a long grace period defeats the lock — anything over a minute is a gap
      if [ -n "${delay:-}" ] && [ "${delay%.*}" -gt 60 ] 2>/dev/null; then
        record WARN "Screen lock" "password required, but only after ${delay%.*}s"
      else
        record PASS "Screen lock" "password required on wake (delay ${delay:-0}s)"
      fi
    else
      record FAIL "Screen lock" "no password required on wake"
    fi
  else
    record SKIP "Screen lock" "desktop-environment specific — verify manually"
  fi
}

# ------------------------------------------------------------ automatic updates
check_updates() {
  if [ "$OS" = "Darwin" ]; then
    local auto
    auto=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null)
    if [ "${auto:-0}" = "1" ]; then
      record PASS "Automatic updates" "update checks enabled"
    else
      record WARN "Automatic updates" "automatic checks disabled or unreadable"
    fi
  elif have systemctl && systemctl is-enabled unattended-upgrades >/dev/null 2>&1; then
    record PASS "Automatic updates" "unattended-upgrades enabled"
  else
    record WARN "Automatic updates" "no automatic update mechanism detected"
  fi
}

# -------------------------------------------------------------- remote access
check_remote_access() {
  if [ "$OS" = "Darwin" ]; then
    if have systemsetup; then
      local ssh
      ssh=$(systemsetup -getremotelogin 2>/dev/null)
      case "$ssh" in
        *On*) record WARN "Remote login (SSH)" "enabled — confirm this is intended" ;;
        *Off*) record PASS "Remote login (SSH)" "disabled" ;;
        *) record SKIP "Remote login (SSH)" "requires elevated rights to read" ;;
      esac
    else
      record SKIP "Remote login (SSH)" "systemsetup unavailable"
    fi
  else
    if have systemctl && systemctl is-active sshd >/dev/null 2>&1; then
      record WARN "Remote login (SSH)" "sshd running — confirm this is intended"
    else
      record PASS "Remote login (SSH)" "sshd not running"
    fi
  fi
}

# ----------------------------------------------------------- sshd config audit
check_sshd_config() {
  local cfg="/etc/ssh/sshd_config"
  if [ ! -r "$cfg" ]; then
    record SKIP "SSH root login" "sshd_config not readable"
    record SKIP "SSH password auth" "sshd_config not readable"
    return
  fi
  # take the LAST occurrence: later directives override earlier ones
  local root pw
  root=$(grep -Ei '^[[:space:]]*PermitRootLogin' "$cfg" 2>/dev/null | tail -1 | awk '{print tolower($2)}')
  pw=$(grep -Ei '^[[:space:]]*PasswordAuthentication' "$cfg" 2>/dev/null | tail -1 | awk '{print tolower($2)}')

  case "${root:-}" in
    no|prohibit-password) record PASS "SSH root login" "PermitRootLogin ${root}" ;;
    yes) record FAIL "SSH root login" "PermitRootLogin yes — root is directly reachable" ;;
    *) record WARN "SSH root login" "not explicitly set (defaults vary by build)" ;;
  esac
  case "${pw:-}" in
    no) record PASS "SSH password auth" "keys only" ;;
    yes) record WARN "SSH password auth" "passwords accepted — brute-forceable" ;;
    *) record WARN "SSH password auth" "not explicitly set" ;;
  esac
}

# ------------------------------------------------------- listening on the world
check_listening() {
  local rows="" count=0
  if have lsof; then
    rows=$(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {print $1, $9}')
  elif have ss; then
    rows=$(ss -lntp 2>/dev/null | awk 'NR>1 {print $NF, $4}')
  fi
  if [ -z "$rows" ]; then
    record SKIP "Externally bound services" "no socket tool available"
    return
  fi
  # 0.0.0.0 / [::] means reachable from the network, not just this machine
  local external
  external=$(echo "$rows" | grep -E '(\*|0\.0\.0\.0|\[::\]):[0-9]+' | awk '{print $1}' | sort -u | paste -sd, - | sed 's/,/, /g')
  count=$(echo "$rows" | grep -cE '(\*|0\.0\.0\.0|\[::\]):[0-9]+')
  if [ "$count" -eq 0 ]; then
    record PASS "Externally bound services" "all listeners bound to loopback"
  else
    record WARN "Externally bound services" "$count listening on all interfaces: ${external}"
  fi
}

# --------------------------------------------------------------- guest account
check_guest() {
  if [ "$OS" = "Darwin" ]; then
    local guest
    guest=$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)
    case "${guest:-}" in
      0) record PASS "Guest account" "disabled" ;;
      1) record FAIL "Guest account" "guest login enabled" ;;
      *) record SKIP "Guest account" "state unreadable" ;;
    esac
  else
    record SKIP "Guest account" "distribution specific — verify manually"
  fi
}

run_all() {
  check_encryption
  check_firewall
  check_screenlock
  check_updates
  check_remote_access
  check_sshd_config
  check_listening
  check_guest
}

render_text() {
  echo "Endpoint Hardening Audit — $(hostname) — $(date '+%Y-%m-%d %H:%M')"
  echo
  printf "%-6s %-28s %s\n" "RESULT" "CHECK" "DETAIL"
  printf "%-6s %-28s %s\n" "------" "----------------------------" "----------------------------------------"
  local row status check detail
  for row in "${ROWS[@]}"; do
    status="${row%%|*}"; row="${row#*|}"
    check="${row%%|*}"; detail="${row#*|}"
    printf "%-6s %-28s %s\n" "$status" "$check" "$detail"
  done
  echo
  echo "Summary: ${PASS} pass · ${WARN} warn · ${FAIL} fail · ${SKIP} skipped"
  [ "$FAIL" -gt 0 ] && echo "Action required: ${FAIL} check(s) failed."
  return 0
}

render_json() {
  local first=1
  printf '{\n  "host": "%s",\n  "generated": "%s",\n' "$(hostname)" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf '  "summary": {"pass": %d, "warn": %d, "fail": %d, "skip": %d},\n  "checks": [\n' \
    "$PASS" "$WARN" "$FAIL" "$SKIP"
  local row status check detail
  for row in "${ROWS[@]}"; do
    status="${row%%|*}"; row="${row#*|}"
    check="${row%%|*}"; detail="${row#*|}"
    [ $first -eq 0 ] && printf ',\n'
    first=0
    printf '    {"check": "%s", "status": "%s", "detail": "%s"}' \
      "$check" "$status" "$(echo "$detail" | sed 's/"/\\"/g')"
  done
  printf '\n  ]\n}\n'
}

run_all
if [ "$JSON" -eq 1 ]; then render_json; else render_text; fi
if [ "$STRICT" -eq 1 ] && [ "$FAIL" -gt 0 ]; then exit 1; fi
exit 0
