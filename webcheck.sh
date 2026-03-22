#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║   WEBCHECK v1.1 — HTTP Security Auditor                    ║
# ║   Author  : krypthane | wavegxz-design                     ║
# ║   Site    : krypthane.workernova.workers.dev                ║
# ║   GitHub  : github.com/wavegxz-design/webcheck             ║
# ║   License : MIT                                             ║
# ║                                                              ║
# ║   USE ONLY ON TARGETS YOU OWN OR HAVE PERMISSION TO TEST.  ║
# ╚══════════════════════════════════════════════════════════════╝
#
# INTENTIONALLY no set -euo pipefail globally.
# grep/openssl/curl return non-zero on "not found" — that is not an error.
# Every command handles its own exit code explicitly. Senior pattern.

# ─────────────────────────────────────────────────────────────────────────────
# VERSION
# ─────────────────────────────────────────────────────────────────────────────
readonly VERSION="1.1.0"
readonly SITE="krypthane.workernova.workers.dev"
readonly TIMEOUT=15
readonly UA="webcheck/${VERSION} (github.com/wavegxz-design/webcheck)"

# ─────────────────────────────────────────────────────────────────────────────
# COLORS — all defined before any function that uses them
# ─────────────────────────────────────────────────────────────────────────────
R='\033[0;31m'
G='\033[0;32m'
Y='\033[1;33m'
B='\033[0;34m'
C='\033[0;36m'
M='\033[0;35m'
W='\033[1;37m'
DIM='\033[2m'
BOLD='\033[1m'
N='\033[0m'

# FIX: consistent naming — all uppercase, no ambiguity
LVL_CRITICAL="${R}[CRITICAL]${N}"
LVL_HIGH="${R}[HIGH]    ${N}"
LVL_MEDIUM="${Y}[MEDIUM]  ${N}"
LVL_LOW="${B}[LOW]     ${N}"
LVL_INFO="${C}[INFO]    ${N}"
LVL_OK="${G}[OK]      ${N}"

# ─────────────────────────────────────────────────────────────────────────────
# RUNTIME STATE
# ─────────────────────────────────────────────────────────────────────────────
TARGET=""          # sanitized hostname
TARGET_URL=""      # https://hostname
SCORE=100
FINDINGS=()        # "LEVEL|message"
HEADERS_FILE=""
START_TIME=$(date +%s)

# ─────────────────────────────────────────────────────────────────────────────
# CLEANUP — always runs on exit
# ─────────────────────────────────────────────────────────────────────────────
_cleanup() {
  [[ -n "${HEADERS_FILE:-}" ]] && rm -f "$HEADERS_FILE" 2>/dev/null || true
}
trap '_cleanup' EXIT INT TERM

# ─────────────────────────────────────────────────────────────────────────────
# UI HELPERS
# ─────────────────────────────────────────────────────────────────────────────
sep()      { echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"; }
sep_thin() { echo -e "${DIM}──────────────────────────────────────────────────────────────${N}"; }

section() {
  echo ""
  echo -e " ${M}┌─────────────────────────────────────────────┐${N}"
  printf  " ${M}│${N}  ${W}${BOLD}%-43s${N}\n" "$*"
  echo -e " ${M}└─────────────────────────────────────────────┘${N}"
  echo ""
}

# FIX: single finding function, all level vars defined at top, no unbound risk
finding() {
  local level="$1"
  local msg="$2"
  local detail="${3:-}"

  FINDINGS+=("${level}|${msg}")

  case "$level" in
    CRITICAL)
      echo -e "  ${LVL_CRITICAL} ${W}${msg}${N}"
      SCORE=$(( SCORE - 20 ))
      ;;
    HIGH)
      echo -e "  ${LVL_HIGH} ${W}${msg}${N}"
      SCORE=$(( SCORE - 15 ))
      ;;
    MEDIUM)
      echo -e "  ${LVL_MEDIUM} ${msg}"
      SCORE=$(( SCORE - 8 ))
      ;;
    LOW)
      echo -e "  ${LVL_LOW} ${msg}"
      SCORE=$(( SCORE - 3 ))
      ;;
    INFO)
      echo -e "  ${LVL_INFO} ${msg}"
      ;;
    OK)
      echo -e "  ${LVL_OK} ${G}${msg}${N}"
      ;;
  esac

  [[ -n "$detail" ]] && echo -e "  ${DIM}         → ${detail}${N}"
}

banner() {
  clear
  echo ""
  echo -e "${C}  ██╗    ██╗███████╗██████╗  ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗${N}"
  echo -e "${C}  ██║    ██║██╔════╝██╔══██╗██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝${N}"
  echo -e "${C}  ██║ █╗ ██║█████╗  ██████╔╝██║     ███████║█████╗  ██║     █████╔╝ ${N}"
  echo -e "${Y}  ██║███╗██║██╔══╝  ██╔══██╗██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ${N}"
  echo -e "${M}  ╚███╔███╔╝███████╗██████╔╝╚██████╗██║  ██║███████╗╚██████╗██║  ██╗${N}"
  echo -e "${M}   ╚══╝╚══╝ ╚══════╝╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝${N}"
  echo ""
  printf "  ${W}v%s${N}  ${DIM}|${N}  ${C}krypthane${N}  ${DIM}|${N}  ${Y}github.com/wavegxz-design/webcheck${N}\n" "$VERSION"
  echo -e "  ${DIM}HTTP Security Auditor — Authorized use only${N}"
  sep
}

# ─────────────────────────────────────────────────────────────────────────────
# DEPENDENCY CHECK
# ─────────────────────────────────────────────────────────────────────────────
check_deps() {
  local missing=()
  for dep in curl openssl grep awk sed; do
    command -v "$dep" &>/dev/null || missing+=("$dep")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo -e "${R}[ERROR]${N} Missing: ${missing[*]}"
    echo -e "${DIM}Install: sudo apt install ${missing[*]}${N}"
    exit 1
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# TARGET NORMALIZATION
# Strips protocol, path, port — extracts clean hostname
# Handles: example.com | https://example.com/path | http://1.2.3.4:8080/app
# ─────────────────────────────────────────────────────────────────────────────
normalize_target() {
  local raw="$1"
  local host

  # Strip protocol
  host="${raw#http://}"
  host="${host#https://}"
  # Strip path and query
  host="${host%%/*}"
  host="${host%%\?*}"
  # Strip credentials if any (user:pass@host)
  host="${host##*@}"

  # Validate — must look like a hostname or IP
  local domain_re='^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(:[0-9]+)?$'
  local ip_re='^([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]+)?$'
  local localhost_re='^localhost(:[0-9]+)?$'

  if [[ ! "$host" =~ $domain_re ]] && \
     [[ ! "$host" =~ $ip_re ]] && \
     [[ ! "$host" =~ $localhost_re ]]; then
    echo -e "${R}[ERROR]${N} Invalid target: '${raw}'"
    echo -e "${DIM}Examples: example.com | https://example.com | 192.168.1.1${N}"
    exit 1
  fi

  TARGET="${host}"
  TARGET_URL="https://${host}"
}

# ─────────────────────────────────────────────────────────────────────────────
# FETCH HEADERS — one request, stored to temp file, reused by all modules
# FIX: || true on curl — connectivity failure handled explicitly
# ─────────────────────────────────────────────────────────────────────────────
fetch_headers() {
  HEADERS_FILE=$(mktemp /tmp/webcheck_XXXXXX.txt)

  local curl_ok=false

  # Try HTTPS first
  if curl -sI \
      --max-time "$TIMEOUT" \
      --max-redirs 5 \
      -A "$UA" \
      -D "$HEADERS_FILE" \
      -o /dev/null \
      "$TARGET_URL" 2>/dev/null; then
    curl_ok=true
  # Fallback to HTTP
  elif curl -sI \
      --max-time "$TIMEOUT" \
      -A "$UA" \
      -D "$HEADERS_FILE" \
      -o /dev/null \
      "http://${TARGET}" 2>/dev/null; then
    curl_ok=true
    TARGET_URL="http://${TARGET}"
  fi

  if ! $curl_ok || [[ ! -s "$HEADERS_FILE" ]]; then
    echo -e "${R}[ERROR]${N} Cannot reach ${TARGET}"
    echo -e "${DIM}Check the URL, your connection, and that the target is online${N}"
    exit 1
  fi
}

# Header helpers — FIX: all use || true, never cause script exit
get_header() {
  grep -i "^${1}:" "$HEADERS_FILE" 2>/dev/null \
    | head -1 \
    | cut -d: -f2- \
    | sed 's/^ *//' \
    | tr -d '\r' \
    || true
}

has_header() {
  grep -qi "^${1}:" "$HEADERS_FILE" 2>/dev/null
}

get_status() {
  grep -m1 "^HTTP/" "$HEADERS_FILE" 2>/dev/null \
    | awk '{print $2}' \
    | tr -d '\r' \
    || echo "000"
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 1 — HTTP → HTTPS REDIRECT
# ─────────────────────────────────────────────────────────────────────────────
module_redirect() {
  section "HTTP → HTTPS REDIRECT"

  local tmp; tmp=$(mktemp /tmp/webcheck_redir_XXXXXX.txt)
  local http_code="000"

  # FIX: -w writes status code, || true prevents exit on connection refusal
  http_code=$(curl -sI \
    --max-time "$TIMEOUT" \
    -A "$UA" \
    -D "$tmp" \
    -o /dev/null \
    -w "%{http_code}" \
    "http://${TARGET}" 2>/dev/null || echo "000")

  local location
  location=$(grep -i "^location:" "$tmp" 2>/dev/null \
    | head -1 | cut -d: -f2- | sed 's/^ *//' | tr -d '\r' || true)

  rm -f "$tmp"

  case "$http_code" in
    301|302|307|308)
      if echo "$location" | grep -qi "^https://"; then
        finding OK "HTTP redirects to HTTPS [${http_code}]" "$location"
      else
        finding HIGH "HTTP redirects but NOT to HTTPS [${http_code}]" \
          "Location: ${location} — redirect must point to https://"
      fi
      ;;
    200)
      finding MEDIUM "HTTP responds directly without redirect" \
        "Configure: return 301 https://\$host\$request_uri;"
      ;;
    000)
      finding INFO "HTTP port unreachable (HTTPS-only or firewalled)"
      ;;
    *)
      finding LOW "Unexpected HTTP status: ${http_code}"
      ;;
  esac
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 2 — SECURITY HEADERS
# ─────────────────────────────────────────────────────────────────────────────
module_security_headers() {
  section "SECURITY HEADERS"

  # ── Strict-Transport-Security ──────────────────────────────────
  if has_header "Strict-Transport-Security"; then
    local hsts; hsts=$(get_header "Strict-Transport-Security")
    local max_age; max_age=$(echo "$hsts" | grep -oP 'max-age=\K[0-9]+' || echo "0")
    if   [[ $max_age -ge 31536000 ]]; then finding OK "Strict-Transport-Security (max-age=${max_age})"
    elif [[ $max_age -gt 0 ]];        then finding LOW "HSTS max-age too short: ${max_age}" \
                                             "Recommend: max-age=31536000; includeSubDomains; preload"
    else                                   finding MEDIUM "Strict-Transport-Security malformed" "$hsts"
    fi
  else
    finding HIGH "Strict-Transport-Security MISSING" \
      "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
  fi

  # ── Content-Security-Policy ────────────────────────────────────
  if has_header "Content-Security-Policy"; then
    local csp; csp=$(get_header "Content-Security-Policy")
    if echo "$csp" | grep -q "unsafe-inline\|unsafe-eval"; then
      finding MEDIUM "CSP contains unsafe directives" \
        "Remove 'unsafe-inline' and 'unsafe-eval' — use nonces/hashes instead"
    elif echo "$csp" | grep -q " \* "; then
      finding MEDIUM "CSP contains wildcards" "$csp"
    else
      finding OK "Content-Security-Policy present"
    fi
  else
    finding HIGH "Content-Security-Policy MISSING" \
      "Content-Security-Policy: default-src 'self'"
  fi

  # ── X-Frame-Options ────────────────────────────────────────────
  if has_header "X-Frame-Options"; then
    local xfo; xfo=$(get_header "X-Frame-Options")
    case "${xfo^^}" in
      DENY|SAMEORIGIN) finding OK "X-Frame-Options: ${xfo}" ;;
      ALLOW-FROM*)
        finding LOW "X-Frame-Options ALLOW-FROM is deprecated" \
          "Replace with CSP: frame-ancestors 'self'" ;;
      *) finding MEDIUM "X-Frame-Options value unrecognized: ${xfo}" ;;
    esac
  else
    finding MEDIUM "X-Frame-Options MISSING" \
      "X-Frame-Options: DENY"
  fi

  # ── X-Content-Type-Options ─────────────────────────────────────
  if has_header "X-Content-Type-Options"; then
    local xcto; xcto=$(get_header "X-Content-Type-Options")
    [[ "${xcto,,}" == "nosniff" ]] \
      && finding OK "X-Content-Type-Options: nosniff" \
      || finding LOW "X-Content-Type-Options unexpected value: ${xcto}"
  else
    finding MEDIUM "X-Content-Type-Options MISSING" \
      "X-Content-Type-Options: nosniff"
  fi

  # ── Referrer-Policy ────────────────────────────────────────────
  if has_header "Referrer-Policy"; then
    local rp; rp=$(get_header "Referrer-Policy")
    case "${rp,,}" in
      no-referrer|strict-origin|strict-origin-when-cross-origin|no-referrer-when-downgrade)
        finding OK "Referrer-Policy: ${rp}" ;;
      unsafe-url|origin)
        finding LOW "Referrer-Policy leaks URLs: ${rp}" ;;
      *) finding INFO "Referrer-Policy: ${rp}" ;;
    esac
  else
    finding LOW "Referrer-Policy MISSING" \
      "Referrer-Policy: strict-origin-when-cross-origin"
  fi

  # ── Permissions-Policy ─────────────────────────────────────────
  has_header "Permissions-Policy" \
    && finding OK "Permissions-Policy present" \
    || finding LOW "Permissions-Policy MISSING" \
       "Permissions-Policy: camera=(), microphone=(), geolocation=()"

  # ── X-XSS-Protection ───────────────────────────────────────────
  if has_header "X-XSS-Protection"; then
    local xxp; xxp=$(get_header "X-XSS-Protection")
    [[ "$xxp" == "0" ]] \
      && finding OK "X-XSS-Protection: 0 (correctly disabled — rely on CSP)" \
      || finding LOW "X-XSS-Protection is deprecated — set to 0, use CSP"
  else
    finding INFO "X-XSS-Protection absent (expected — ensure CSP covers XSS)"
  fi

  # ── Cross-Origin-Opener-Policy ─────────────────────────────────
  has_header "Cross-Origin-Opener-Policy" \
    && finding OK "Cross-Origin-Opener-Policy: $(get_header "Cross-Origin-Opener-Policy")" \
    || finding LOW "Cross-Origin-Opener-Policy MISSING" \
       "Cross-Origin-Opener-Policy: same-origin"

  # ── Cross-Origin-Resource-Policy ──────────────────────────────
  has_header "Cross-Origin-Resource-Policy" \
    && finding OK "Cross-Origin-Resource-Policy: $(get_header "Cross-Origin-Resource-Policy")" \
    || finding LOW "Cross-Origin-Resource-Policy MISSING" \
       "Cross-Origin-Resource-Policy: same-origin"
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 3 — INFORMATION DISCLOSURE
# ─────────────────────────────────────────────────────────────────────────────
module_disclosure() {
  section "INFORMATION DISCLOSURE"

  # ── Server header ──────────────────────────────────────────────
  if has_header "Server"; then
    local srv; srv=$(get_header "Server")
    if echo "$srv" | grep -qiP '[0-9]+\.[0-9]+|nginx/|apache/|iis/|express|php|python|ruby|jetty|tomcat'; then
      finding HIGH "Server header exposes version" \
        "Value: ${srv} — remove or replace with generic value"
    else
      finding LOW "Server header present (no version visible)" \
        "Value: ${srv} — consider removing entirely"
    fi
  else
    finding OK "Server header absent"
  fi

  # ── X-Powered-By ───────────────────────────────────────────────
  if has_header "X-Powered-By"; then
    finding HIGH "X-Powered-By exposed" \
      "Value: $(get_header "X-Powered-By") — remove this header"
  else
    finding OK "X-Powered-By absent"
  fi

  # ── .NET version headers ────────────────────────────────────────
  if has_header "X-AspNet-Version"; then
    finding HIGH "X-AspNet-Version exposed: $(get_header "X-AspNet-Version")" \
      "Add <customHeaders><remove name='X-AspNet-Version'/></customHeaders>"
  fi
  if has_header "X-AspNetMvc-Version"; then
    finding HIGH "X-AspNetMvc-Version exposed: $(get_header "X-AspNetMvc-Version")"
  fi

  # ── CMS detection headers ──────────────────────────────────────
  for hdr in "X-Generator" "X-Drupal-Cache" "X-WP-Nonce" "X-Pingback" "X-Joomla-Token"; do
    if has_header "$hdr"; then
      finding MEDIUM "${hdr} leaks CMS/platform info" \
        "Value: $(get_header "$hdr")"
    fi
  done

  # ── CORS wildcard ──────────────────────────────────────────────
  if has_header "Access-Control-Allow-Origin"; then
    local acao; acao=$(get_header "Access-Control-Allow-Origin")
    if [[ "$acao" == "*" ]]; then
      finding HIGH "CORS wildcard: Access-Control-Allow-Origin: *" \
        "Restrict to specific trusted origins"
    else
      finding OK "CORS origin restricted: ${acao}"
    fi
  fi

  # ── Proxy/CDN disclosure ───────────────────────────────────────
  if has_header "Via"; then
    finding INFO "Via header present (proxy/CDN info)" \
      "$(get_header "Via")"
  fi
  if has_header "X-Cache"; then
    finding INFO "X-Cache: $(get_header "X-Cache")"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 4 — COOKIES
# FIX: analyzed per-cookie without interfering with SCORE double-counting
# ─────────────────────────────────────────────────────────────────────────────
module_cookies() {
  section "COOKIES"

  # Collect all Set-Cookie lines
  local cookies=()
  while IFS= read -r line; do
    [[ "${line,,}" =~ ^set-cookie: ]] && cookies+=("$line")
  done < "$HEADERS_FILE"

  if [[ ${#cookies[@]} -eq 0 ]]; then
    finding INFO "No Set-Cookie headers found on this endpoint"
    return
  fi

  finding INFO "${#cookies[@]} cookie(s) detected"
  echo ""

  local idx=0
  for cookie in "${cookies[@]}"; do
    idx=$(( idx + 1 ))
    local raw; raw=$(echo "$cookie" | cut -d: -f2- | sed 's/^ *//' | tr -d '\r')
    local name; name=$(echo "$raw" | cut -d= -f1 | sed 's/^ *//')
    local cl; cl="${raw,,}"

    echo -e "  ${DIM}────── Cookie ${idx}: ${W}${name}${N}${DIM} ──────${N}"

    # Secure flag
    if echo "$cl" | grep -q "; *secure\b"; then
      echo -e "    ${G}✓${N} Secure"
    else
      echo -e "    ${R}✗${N} ${LVL_HIGH} Cookie '${name}' missing ${W}Secure${N} flag"
      SCORE=$(( SCORE - 15 ))
      FINDINGS+=("HIGH|Cookie '${name}' missing Secure flag")
    fi

    # HttpOnly
    if echo "$cl" | grep -q "; *httponly\b"; then
      echo -e "    ${G}✓${N} HttpOnly"
    else
      echo -e "    ${R}✗${N} ${LVL_HIGH} Cookie '${name}' missing ${W}HttpOnly${N} flag"
      SCORE=$(( SCORE - 15 ))
      FINDINGS+=("HIGH|Cookie '${name}' missing HttpOnly flag")
    fi

    # SameSite
    if echo "$cl" | grep -qiP "; *samesite=(strict|lax|none)"; then
      local ss; ss=$(echo "$cl" | grep -oiP "samesite=\K(strict|lax|none)" | head -1)
      if [[ "${ss,,}" == "none" ]]; then
        echo -e "    ${Y}!${N} ${LVL_MEDIUM} Cookie '${name}' SameSite=None (CSRF risk if without Secure)"
        SCORE=$(( SCORE - 8 ))
        FINDINGS+=("MEDIUM|Cookie '${name}' SameSite=None")
      else
        echo -e "    ${G}✓${N} SameSite=${ss}"
      fi
    else
      echo -e "    ${Y}!${N} ${LVL_MEDIUM} Cookie '${name}' missing ${W}SameSite${N}"
      SCORE=$(( SCORE - 8 ))
      FINDINGS+=("MEDIUM|Cookie '${name}' missing SameSite")
    fi

    # Session vs persistent
    if echo "$cl" | grep -qiP "; *(expires|max-age)"; then
      echo -e "    ${DIM}  Persistent (has expiry)${N}"
    else
      echo -e "    ${DIM}  Session cookie (no expiry)${N}"
    fi

    echo ""
  done
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 5 — TLS / SSL
# FIX: all openssl calls use || true — non-zero exit does not kill script
# FIX: grep -c replaced with grep + wc -l to avoid set -e issues
# ─────────────────────────────────────────────────────────────────────────────
module_tls() {
  section "TLS / SSL"

  # Quick connectivity check on port 443
  local cert_raw
  cert_raw=$(echo | timeout "$TIMEOUT" openssl s_client \
    -connect "${TARGET}:443" \
    -servername "$TARGET" \
    2>/dev/null || true)

  if [[ -z "$cert_raw" ]]; then
    finding CRITICAL "No TLS on port 443" \
      "HTTPS is not configured or port 443 is closed"
    return
  fi

  # Parse cert text
  local cert_text
  cert_text=$(echo "$cert_raw" \
    | openssl x509 -noout -text 2>/dev/null || true)

  if [[ -n "$cert_text" ]]; then
    local subject issuer expiry sans

    subject=$(echo "$cert_text" | grep "Subject:" | head -1 | sed 's/.*Subject: //' || true)
    issuer=$(echo  "$cert_text" | grep "Issuer:"  | head -1 | sed 's/.*Issuer: //'  || true)
    expiry=$(echo  "$cert_text" | grep "Not After" | head -1 | sed 's/.*Not After : //' || true)
    sans=$(echo    "$cert_text" | grep -A1 "Subject Alternative Name" | tail -1 \
      | sed 's/^[[:space:]]*//' || true)

    [[ -n "$subject" ]] && finding INFO "Subject : ${subject}"
    [[ -n "$issuer"  ]] && finding INFO "Issuer  : ${issuer}"
    [[ -n "$sans"    ]] && finding INFO "SANs    : ${sans}"

    # Self-signed
    if [[ -n "$subject" && -n "$issuer" && "$subject" == "$issuer" ]]; then
      finding HIGH "Self-signed certificate" \
        "Browsers will show security warnings to users"
    fi

    # Expiry countdown
    if [[ -n "$expiry" ]]; then
      local exp_ts; exp_ts=$(date -d "$expiry" +%s 2>/dev/null || echo "0")
      if [[ $exp_ts -gt 0 ]]; then
        local now_ts; now_ts=$(date +%s)
        local days=$(( (exp_ts - now_ts) / 86400 ))
        if   [[ $days -lt 0 ]];  then finding CRITICAL "Certificate EXPIRED ${days#-} days ago"
        elif [[ $days -lt 7 ]];  then finding CRITICAL "Certificate expires in ${days} days!"
        elif [[ $days -lt 30 ]]; then finding HIGH    "Certificate expires in ${days} days"
        elif [[ $days -lt 90 ]]; then finding MEDIUM  "Certificate expires in ${days} days"
        else                          finding OK      "Certificate valid for ${days} more days"
        fi
      fi
    fi
  fi

  echo ""
  echo -e "  ${DIM}Testing protocol versions...${N}"

  # FIX: test connection, use grep | wc -l — never returns non-zero that kills script
  _tls_connected() {
    local proto="$1"
    local out
    out=$(echo | timeout 5 openssl s_client \
      -connect "${TARGET}:443" \
      -servername "$TARGET" \
      "${proto}" 2>&1 || true)
    echo "$out" | grep -c "^CONNECTED" 2>/dev/null || echo "0"
  }

  # Weak protocols — should NOT be supported
  for proto_pair in "-ssl2:SSLv2" "-ssl3:SSLv3" "-tls1:TLS 1.0" "-tls1_1:TLS 1.1"; do
    local flag="${proto_pair%%:*}"
    local label="${proto_pair##*:}"
    local n; n=$(_tls_connected "$flag")
    if [[ "$n" -gt 0 ]]; then
      finding CRITICAL "Weak protocol enabled: ${label}" \
        "Disable in ssl_protocols directive"
    fi
  done

  # TLS 1.2 — should be supported
  local n12; n12=$(_tls_connected "-tls1_2")
  [[ "$n12" -gt 0 ]] \
    && finding OK  "TLS 1.2 supported" \
    || finding MEDIUM "TLS 1.2 not supported"

  # TLS 1.3 — recommended
  local n13; n13=$(_tls_connected "-tls1_3")
  [[ "$n13" -gt 0 ]] \
    && finding OK  "TLS 1.3 supported" \
    || finding LOW "TLS 1.3 not supported (recommended)"

  # Active cipher
  local cipher
  cipher=$(echo "$cert_raw" | grep "^Cipher" | awk '{print $3}' || true)
  if [[ -n "$cipher" ]]; then
    if echo "$cipher" | grep -qiP 'RC4|DES|NULL|EXPORT|anon|MD5'; then
      finding CRITICAL "Weak cipher in use: ${cipher}" \
        "Disable RC4, DES, NULL, EXPORT and anonymous ciphers"
    else
      finding OK "Active cipher: ${cipher}"
    fi
  fi

  # HSTS preload
  local hsts_val; hsts_val=$(get_header "Strict-Transport-Security")
  if echo "$hsts_val" | grep -qi "preload"; then
    finding OK "HSTS preload directive present"
  else
    finding LOW "HSTS preload missing" \
      "Add 'preload' to Strict-Transport-Security"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# SCORE & SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
render_score() {
  [[ $SCORE -lt 0 ]]   && SCORE=0
  [[ $SCORE -gt 100 ]] && SCORE=100

  local grade color filled=0 bar=""
  filled=$(( SCORE * 40 / 100 ))

  if   [[ $SCORE -ge 90 ]]; then grade="A+"; color="$G"
  elif [[ $SCORE -ge 80 ]]; then grade="A";  color="$G"
  elif [[ $SCORE -ge 70 ]]; then grade="B";  color="$C"
  elif [[ $SCORE -ge 60 ]]; then grade="C";  color="$Y"
  elif [[ $SCORE -ge 50 ]]; then grade="D";  color="$Y"
  else                            grade="F";  color="$R"
  fi

  for ((i=0; i<filled; i++));    do bar+="█"; done
  for ((i=filled; i<40; i++));   do bar+="░"; done

  echo ""
  sep
  echo -e "  ${W}${BOLD}SECURITY SCORE${N}"
  sep_thin
  printf "  ${color}[%s]${N}  ${W}${BOLD}%d/100${N}  ${DIM}Grade:${N}  ${color}${BOLD}%s${N}\n" \
    "$bar" "$SCORE" "$grade"
  echo ""
}

render_summary() {
  local end_time; end_time=$(date +%s)
  local elapsed=$(( end_time - START_TIME ))

  local n_critical=0 n_high=0 n_medium=0 n_low=0 n_ok=0 n_info=0

  for f in "${FINDINGS[@]}"; do
    case "${f%%|*}" in
      CRITICAL) n_critical=$(( n_critical+1 )) ;;
      HIGH)     n_high=$(( n_high+1 ))         ;;
      MEDIUM)   n_medium=$(( n_medium+1 ))     ;;
      LOW)      n_low=$(( n_low+1 ))           ;;
      OK)       n_ok=$(( n_ok+1 ))             ;;
      INFO)     n_info=$(( n_info+1 ))         ;;
    esac
  done

  echo -e "  ${W}FINDINGS SUMMARY${N}"
  sep_thin
  printf "  %-14s  ${R}%d${N}\n"  "CRITICAL"  "$n_critical"
  printf "  %-14s  ${R}%d${N}\n"  "HIGH"      "$n_high"
  printf "  %-14s  ${Y}%d${N}\n"  "MEDIUM"    "$n_medium"
  printf "  %-14s  ${B}%d${N}\n"  "LOW"       "$n_low"
  printf "  %-14s  ${G}%d${N}\n"  "PASSED"    "$n_ok"
  printf "  %-14s  ${DIM}%d${N}\n" "INFO"     "$n_info"
  sep_thin
  printf "  ${DIM}%-14s  %s${N}\n"   "Target"   "$TARGET_URL"
  printf "  ${DIM}%-14s  %ds${N}\n"  "Duration" "$elapsed"
  sep
  echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# USAGE
# ─────────────────────────────────────────────────────────────────────────────
usage() {
  echo -e "${W}Usage:${N}"
  echo -e "  $0 <target>"
  echo -e "  $0 -t <target>"
  echo -e "  $0 --target <target>"
  echo ""
  echo -e "${W}Target formats:${N}"
  echo -e "  example.com"
  echo -e "  https://example.com"
  echo -e "  http://192.168.1.1"
  echo -e "  http://localhost:8080"
  echo ""
  echo -e "${W}Options:${N}"
  echo -e "  -t, --target <url>   Target to scan"
  echo -e "  -h, --help           Show this help"
  echo -e "  -v, --version        Show version"
  echo ""
  echo -e "${W}Examples:${N}"
  echo -e "  $0 example.com"
  echo -e "  $0 -t https://target.com"
  echo -e "  $0 --target http://192.168.1.10"
  echo ""
  echo -e "${R}  Authorized targets only. Unauthorized use is illegal.${N}"
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
main() {
  local raw_target=""

  # FIX: proper flag parsing — supports positional, -t, and --target
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)    banner; usage; exit 0 ;;
      -v|--version) echo "webcheck v${VERSION}"; exit 0 ;;
      -t|--target)
        [[ -z "${2:-}" ]] && { echo -e "${R}[ERROR]${N} -t requires a value"; exit 1; }
        raw_target="$2"; shift 2 ;;
      -*)
        echo -e "${R}[ERROR]${N} Unknown flag: $1"
        echo -e "${DIM}Run $0 --help${N}"
        exit 1 ;;
      *)
        # Positional argument — treat as target
        [[ -n "$raw_target" ]] && { echo -e "${R}[ERROR]${N} Multiple targets specified"; exit 1; }
        raw_target="$1"; shift ;;
    esac
  done

  banner
  check_deps

  if [[ -z "$raw_target" ]]; then
    printf "  ${G}[>]${N} Target (domain or URL): "
    read -r raw_target
  fi

  normalize_target "$raw_target"

  echo -e "  ${LVL_INFO} Target  : ${W}${TARGET_URL}${N}"
  echo -e "  ${LVL_INFO} Timeout : ${W}${TIMEOUT}s${N}"
  echo ""

  echo -e "  ${DIM}Fetching headers...${N}"
  fetch_headers

  local status; status=$(get_status)
  echo -e "  ${LVL_INFO} Status  : ${W}${status}${N}"

  module_redirect
  module_security_headers
  module_disclosure
  module_cookies
  module_tls

  render_score
  render_summary
}

main "$@"
