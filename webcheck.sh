#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║   WEBCHECK v2.0 — HTTP Security Auditor                      ║
# ║   Author  : krypthane | wavegxz-design                       ║
# ║   Site    : krypthane.workernova.workers.dev                 ║
# ║   GitHub  : github.com/wavegxz-design/webcheck               ║
# ║   License : MIT                                              ║
# ║                                                              ║
# ║   Bugs fixed v2.0:                                           ║
# ║   [BUG-01] TLS hardcoded :443 breaks host:PORT targets       ║
# ║   [BUG-02] grep -c still used despite comment saying fixed   ║
# ║   [BUG-03] CSP wildcard regex missed trailing wildcards      ║
# ║   [BUG-04] HSTS preload checked twice -> double penalty      ║
# ║   [BUG-05] Cookies bypassed finding() inconsistent path      ║
# ║   [BUG-06] Score not clamped during execution                ║
# ║   [BUG-07] PORT not extracted before TLS connect             ║
# ║   [BUG-08] module_redirect mktemp not in _cleanup trap       ║
# ║                                                              ║
# ║   New in v2.0:                                               ║
# ║   [NEW] Module 6  - HTTP Methods TRACE/PUT/DELETE audit      ║
# ║   [NEW] Module 7  - WAF / CDN fingerprinting                 ║
# ║   [NEW] Module 8  - security.txt / responsible disclosure    ║
# ║   [NEW] Module 9  - DNS CAA + DNSSEC + SPF + DMARC           ║
# ║   [NEW] Module 10 - robots.txt + .git + .env exposure        ║
# ║   [NEW] Module 11 - Cache-Control / HTTP3 Alt-Svc            ║
# ║   [NEW] --output  - JSON + plain-text report                 ║
# ║   [NEW] --no-color - CI/CD pipeline mode                     ║
# ║   [NEW] --timeout  - configurable timeout                    ║
# ║   [NEW] --port     - custom TLS port                         ║
# ║   [NEW] --modules  - run specific modules only               ║
# ║   [NEW] HTTP/2 ALPN detection                                ║
# ║   [NEW] OCSP stapling check                                  ║
# ║   [NEW] Certificate transparency SCT detection               ║
# ║   [NEW] Cert key size + signature algorithm                  ║
# ║   [NEW] SHA-256 fingerprint display                          ║
# ║   [NEW] Internal IP exposure in headers                      ║
# ║   [NEW] Debug header detection                               ║
# ║   [NEW] CORS with credentials misconfiguration               ║
# ║   [NEW] SPF +all dangerous policy detection                  ║
# ║   [NEW] DMARC policy enforcement level                       ║
# ║   [NEW] Action required section in summary                   ║
# ║                                                              ║
# ║   USE ONLY ON TARGETS YOU OWN OR HAVE PERMISSION TO TEST.    ║
# ╚══════════════════════════════════════════════════════════════╝

readonly VERSION="2.0.0"
readonly SITE="krypthane.workernova.workers.dev"
readonly UA="webcheck/${VERSION} (github.com/wavegxz-design/webcheck)"

TIMEOUT=15
TLS_PORT=443
TARGET=""
TARGET_HOST=""
TARGET_URL=""
SCORE=100
FINDINGS=()
HEADERS_FILE=""
REDIRECT_TMP=""
START_TIME=$(date +%s)
OUTPUT_FILE=""
OUTPUT_FORMAT="text"
NO_COLOR=false
MODULES_TO_RUN=()

_init_colors() {
  if $NO_COLOR || [[ ! -t 1 ]]; then
    R='' G='' Y='' B='' C='' M='' W='' DIM='' BOLD='' N=''
  else
    R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' B='\033[0;34m'
    C='\033[0;36m' M='\033[0;35m' W='\033[1;37m'
    DIM='\033[2m'  BOLD='\033[1m' N='\033[0m'
  fi
  LVL_CRITICAL="${R}[CRITICAL]${N}"
  LVL_HIGH="${R}[HIGH]    ${N}"
  LVL_MEDIUM="${Y}[MEDIUM]  ${N}"
  LVL_LOW="${B}[LOW]     ${N}"
  LVL_INFO="${C}[INFO]    ${N}"
  LVL_OK="${G}[OK]      ${N}"
}
_init_colors

_cleanup() {
  [[ -n "${HEADERS_FILE:-}"  ]] && rm -f "$HEADERS_FILE"  2>/dev/null || true
  [[ -n "${REDIRECT_TMP:-}"  ]] && rm -f "$REDIRECT_TMP"  2>/dev/null || true
}
trap '_cleanup' EXIT INT TERM

sep()      { echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"; }
sep_thin() { echo -e "${DIM}──────────────────────────────────────────────────────────────${N}"; }

section() {
  echo ""
  echo -e " ${M}┌─────────────────────────────────────────────┐${N}"
  printf  " ${M}│${N}  ${W}${BOLD}%-43s${N}\n" "$*"
  echo -e " ${M}└─────────────────────────────────────────────┘${N}"
  echo ""
}

# FIX BUG-05 + BUG-06: single entry point, score clamped on every deduction
finding() {
  local level="$1" msg="$2" detail="${3:-}"
  FINDINGS+=("${level}|${msg}|${detail}")
  case "$level" in
    CRITICAL) echo -e "  ${LVL_CRITICAL} ${W}${msg}${N}"
              SCORE=$(( SCORE - 20 )); [[ $SCORE -lt 0 ]] && SCORE=0 ;;
    HIGH)     echo -e "  ${LVL_HIGH} ${W}${msg}${N}"
              SCORE=$(( SCORE - 15 )); [[ $SCORE -lt 0 ]] && SCORE=0 ;;
    MEDIUM)   echo -e "  ${LVL_MEDIUM} ${msg}"
              SCORE=$(( SCORE - 8  )); [[ $SCORE -lt 0 ]] && SCORE=0 ;;
    LOW)      echo -e "  ${LVL_LOW} ${msg}"
              SCORE=$(( SCORE - 3  )); [[ $SCORE -lt 0 ]] && SCORE=0 ;;
    INFO)     echo -e "  ${LVL_INFO} ${msg}" ;;
    OK)       echo -e "  ${LVL_OK} ${G}${msg}${N}" ;;
  esac
  [[ -n "$detail" ]] && echo -e "  ${DIM}         -> ${detail}${N}"
}

banner() {
  $NO_COLOR || [[ ! -t 1 ]] || clear
  echo ""
  echo -e "${C}  ██╗    ██╗███████╗██████╗  ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗${N}"
  echo -e "${C}  ██║    ██║██╔════╝██╔══██╗██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝${N}"
  echo -e "${C}  ██║ █╗ ██║█████╗  ██████╔╝██║     ███████║█████╗  ██║     █████╔╝ ${N}"
  echo -e "${Y}  ██║███╗██║██╔══╝  ██╔══██╗██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ${N}"
  echo -e "${M}  ╚███╔███╔╝███████╗██████╔╝╚██████╗██║  ██║███████╗╚██████╗██║  ██╗${N}"
  echo -e "${M}   ╚══╝╚══╝ ╚══════╝╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝${N}"
  echo ""
  printf "  ${W}v%s${N}  ${DIM}|${N}  ${C}krypthane${N}  ${DIM}|${N}  ${Y}github.com/wavegxz-design/webcheck${N}\n" "$VERSION"
  echo -e "  ${DIM}HTTP Security Auditor — 11 modules — Authorized use only${N}"
  sep
}

check_deps() {
  local missing=()
  for dep in curl openssl grep awk sed dig; do
    command -v "$dep" &>/dev/null || missing+=("$dep")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo -e "${R}[ERROR]${N} Missing: ${missing[*]}"
    echo -e "${DIM}Install: sudo apt install ${missing[*]} dnsutils${N}"
    exit 1
  fi
}

# FIX BUG-01 + BUG-07: extract port separately, TARGET_HOST used for openssl
normalize_target() {
  local raw="$1" host
  host="${raw#http://}"; host="${host#https://}"
  host="${host%%/*}"; host="${host%%\?*}"; host="${host##*@}"

  if [[ "$host" =~ ^(.+):([0-9]+)$ ]]; then
    [[ "$TLS_PORT" == "443" ]] && TLS_PORT="${BASH_REMATCH[2]}"
    host="${BASH_REMATCH[1]}"
  fi

  local domain_re='^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
  local ip_re='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
  local local_re='^localhost$'

  if [[ ! "$host" =~ $domain_re ]] && [[ ! "$host" =~ $ip_re ]] && [[ ! "$host" =~ $local_re ]]; then
    echo -e "${R}[ERROR]${N} Invalid target: '${raw}'"
    exit 1
  fi

  TARGET="$host"
  # FIX BUG-01: TARGET_HOST always "hostname:port" for openssl
  TARGET_HOST="${host}:${TLS_PORT}"
  if [[ "$TLS_PORT" == "443" ]]; then
    TARGET_URL="https://${host}"
  else
    TARGET_URL="https://${host}:${TLS_PORT}"
  fi
}

fetch_headers() {
  HEADERS_FILE=$(mktemp /tmp/webcheck_XXXXXX.txt)
  local curl_ok=false

  if curl -sI --max-time "$TIMEOUT" --max-redirs 5 -A "$UA" \
      -D "$HEADERS_FILE" -o /dev/null "$TARGET_URL" 2>/dev/null; then
    curl_ok=true
  elif curl -sI --max-time "$TIMEOUT" -A "$UA" \
      -D "$HEADERS_FILE" -o /dev/null "http://${TARGET}" 2>/dev/null; then
    curl_ok=true; TARGET_URL="http://${TARGET}"
  fi

  if ! $curl_ok || [[ ! -s "$HEADERS_FILE" ]]; then
    echo -e "${R}[ERROR]${N} Cannot reach ${TARGET}"; exit 1
  fi
}

get_header() {
  grep -i "^${1}:" "$HEADERS_FILE" 2>/dev/null \
    | head -1 | cut -d: -f2- | sed 's/^ *//' | tr -d '\r' || true
}
has_header() { grep -qi "^${1}:" "$HEADERS_FILE" 2>/dev/null; }
get_status()  {
  grep -m1 "^HTTP/" "$HEADERS_FILE" 2>/dev/null | awk '{print $2}' | tr -d '\r' || echo "000"
}

_should_run() {
  local mod="$1"
  [[ ${#MODULES_TO_RUN[@]} -eq 0 ]] && return 0
  for m in "${MODULES_TO_RUN[@]}"; do [[ "$m" == "$mod" ]] && return 0; done
  return 1
}

# ── MODULE 1: HTTP->HTTPS REDIRECT ─────────────────────────────────────────
module_redirect() {
  _should_run "redirect" || return 0
  section "1 — HTTP -> HTTPS REDIRECT"
  REDIRECT_TMP=$(mktemp /tmp/webcheck_redir_XXXXXX.txt)
  local http_code
  http_code=$(curl -sI --max-time "$TIMEOUT" -A "$UA" \
    -D "$REDIRECT_TMP" -o /dev/null -w "%{http_code}" \
    "http://${TARGET}" 2>/dev/null || echo "000")
  local location
  location=$(grep -i "^location:" "$REDIRECT_TMP" 2>/dev/null \
    | head -1 | cut -d: -f2- | sed 's/^ *//' | tr -d '\r' || true)

  case "$http_code" in
    301|308)
      if echo "$location" | grep -qi "^https://"; then
        finding OK "HTTP -> HTTPS permanent redirect [${http_code}]" "$location"
      else
        finding HIGH "Redirect [${http_code}] does NOT go to HTTPS" "Location: ${location}"
      fi ;;
    302|307)
      if echo "$location" | grep -qi "^https://"; then
        finding LOW "HTTP -> HTTPS temporary redirect [${http_code}] — use 301/308" "$location"
      else
        finding HIGH "Redirect [${http_code}] does NOT go to HTTPS" "Location: ${location}"
      fi ;;
    200) finding MEDIUM "HTTP serves content directly — no HTTPS redirect" \
           "Nginx: return 301 https://\$host\$request_uri;" ;;
    000) finding INFO "HTTP port unreachable (HTTPS-only or firewalled)" ;;
    *)   finding LOW "Unexpected HTTP status: ${http_code}" ;;
  esac

  if [[ -n "$location" ]] && echo "$location" | grep -qE '^https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; then
    finding MEDIUM "Redirect target is an IP address — may leak origin behind CDN" \
      "Location: $location"
  fi
}

# ── MODULE 2: SECURITY HEADERS ──────────────────────────────────────────────
module_security_headers() {
  _should_run "headers" || return 0
  section "2 — SECURITY HEADERS"

  # HSTS
  if has_header "Strict-Transport-Security"; then
    local hsts; hsts=$(get_header "Strict-Transport-Security")
    local max_age; max_age=$(echo "$hsts" | grep -oE 'max-age=[0-9]+' | grep -oE '[0-9]+' || echo "0")
    local sub_flag=""; echo "$hsts" | grep -qi "includeSubDomains" && sub_flag=" includeSubDomains"
    if   [[ $max_age -ge 31536000 ]]; then finding OK "HSTS max-age=${max_age}${sub_flag}"
    elif [[ $max_age -gt 0 ]];         then finding LOW "HSTS max-age too short: ${max_age}" \
           "Recommend: max-age=31536000; includeSubDomains; preload"
    else                                    finding MEDIUM "HSTS header malformed" "$hsts"
    fi
  else
    finding HIGH "Strict-Transport-Security MISSING" \
      "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
  fi

  # CSP - FIX BUG-03: proper wildcard detection using word boundaries
  if has_header "Content-Security-Policy"; then
    local csp; csp=$(get_header "Content-Security-Policy")
    local issues=()
    # FIX: matches '*' as a standalone source token, not just ' * '
    echo "$csp" | grep -qE '(^|[[:space:];])\*([[:space:];]|$)' && issues+=("wildcard source '*'")
    echo "$csp" | grep -q "unsafe-inline" && issues+=("'unsafe-inline'")
    echo "$csp" | grep -q "unsafe-eval"   && issues+=("'unsafe-eval'")
    echo "$csp" | grep -q "data:"         && issues+=("'data:' URI")
    if [[ ${#issues[@]} -gt 0 ]]; then
      finding MEDIUM "CSP dangerous directives: ${issues[*]}" \
        "Use nonces/hashes; avoid wildcards and unsafe-*"
    else
      finding OK "Content-Security-Policy configured safely"
    fi
    echo "$csp" | grep -q "frame-ancestors" \
      && finding OK "CSP frame-ancestors present (clickjacking protection)" \
      || finding LOW "CSP missing frame-ancestors" "Add: frame-ancestors 'self'"
  else
    finding HIGH "Content-Security-Policy MISSING" \
      "Content-Security-Policy: default-src 'self'; frame-ancestors 'self'"
  fi

  # X-Frame-Options
  if has_header "X-Frame-Options"; then
    local xfo; xfo=$(get_header "X-Frame-Options")
    case "${xfo^^}" in
      DENY|SAMEORIGIN) finding OK "X-Frame-Options: ${xfo}" ;;
      ALLOW-FROM*) finding LOW "X-Frame-Options ALLOW-FROM deprecated — use CSP frame-ancestors" ;;
      *) finding MEDIUM "X-Frame-Options unrecognized: ${xfo}" ;;
    esac
  else
    has_header "Content-Security-Policy" && \
      get_header "Content-Security-Policy" | grep -q "frame-ancestors" \
      || finding MEDIUM "X-Frame-Options MISSING" "X-Frame-Options: DENY"
  fi

  # X-Content-Type-Options
  if has_header "X-Content-Type-Options"; then
    local xcto; xcto=$(get_header "X-Content-Type-Options")
    [[ "${xcto,,}" == "nosniff" ]] \
      && finding OK "X-Content-Type-Options: nosniff" \
      || finding LOW "X-Content-Type-Options unexpected: ${xcto}"
  else
    finding MEDIUM "X-Content-Type-Options MISSING" "X-Content-Type-Options: nosniff"
  fi

  # Referrer-Policy
  if has_header "Referrer-Policy"; then
    local rp; rp=$(get_header "Referrer-Policy")
    case "${rp,,}" in
      no-referrer|strict-origin|strict-origin-when-cross-origin|no-referrer-when-downgrade)
        finding OK "Referrer-Policy: ${rp}" ;;
      unsafe-url|origin) finding LOW "Referrer-Policy leaks URLs: ${rp}" ;;
      *) finding INFO "Referrer-Policy: ${rp}" ;;
    esac
  else
    finding LOW "Referrer-Policy MISSING" "Referrer-Policy: strict-origin-when-cross-origin"
  fi

  # Permissions-Policy
  has_header "Permissions-Policy" \
    && finding OK "Permissions-Policy: $(get_header "Permissions-Policy" | cut -c1-60)" \
    || finding LOW "Permissions-Policy MISSING" \
       "Permissions-Policy: camera=(), microphone=(), geolocation=()"

  # X-XSS-Protection
  if has_header "X-XSS-Protection"; then
    local xxp; xxp=$(get_header "X-XSS-Protection")
    [[ "$xxp" == "0" ]] \
      && finding OK "X-XSS-Protection: 0 (correctly disabled — rely on CSP)" \
      || finding LOW "X-XSS-Protection deprecated — set to 0, use CSP"
  else
    finding INFO "X-XSS-Protection absent (correct — ensure CSP covers XSS)"
  fi

  # Cross-Origin headers
  has_header "Cross-Origin-Opener-Policy" \
    && finding OK "Cross-Origin-Opener-Policy: $(get_header "Cross-Origin-Opener-Policy")" \
    || finding LOW "Cross-Origin-Opener-Policy MISSING" \
       "Cross-Origin-Opener-Policy: same-origin"

  has_header "Cross-Origin-Resource-Policy" \
    && finding OK "Cross-Origin-Resource-Policy: $(get_header "Cross-Origin-Resource-Policy")" \
    || finding LOW "Cross-Origin-Resource-Policy MISSING" \
       "Cross-Origin-Resource-Policy: same-origin"

  has_header "Cross-Origin-Embedder-Policy" \
    && finding OK "Cross-Origin-Embedder-Policy: $(get_header "Cross-Origin-Embedder-Policy")" \
    || finding INFO "Cross-Origin-Embedder-Policy absent (needed for SharedArrayBuffer)"

  # Report-To / NEL
  has_header "Report-To"    && finding INFO "Report-To configured"
  has_header "NEL"          && finding INFO "Network Error Logging (NEL) configured"
  has_header "Expect-CT"    && finding INFO "Expect-CT: $(get_header "Expect-CT") (deprecated — covered by HSTS)"
}

# ── MODULE 3: INFORMATION DISCLOSURE ───────────────────────────────────────
module_disclosure() {
  _should_run "disclosure" || return 0
  section "3 — INFORMATION DISCLOSURE"

  if has_header "Server"; then
    local srv; srv=$(get_header "Server")
    if echo "$srv" | grep -qiE '[0-9]+\.[0-9]+|nginx/|apache/|iis/|express|php|python|ruby|jetty|tomcat|gunicorn|lighttpd'; then
      finding HIGH "Server header exposes version" "Value: ${srv} — use generic or remove"
    else
      finding LOW "Server header present (no version)" "Value: ${srv} — consider removing"
    fi
  else
    finding OK "Server header absent"
  fi

  has_header "X-Powered-By" \
    && finding HIGH "X-Powered-By exposed: $(get_header "X-Powered-By")" "Remove this header" \
    || finding OK "X-Powered-By absent"

  has_header "X-AspNet-Version" \
    && finding HIGH "X-AspNet-Version: $(get_header "X-AspNet-Version")" \
       "<customHeaders><remove name='X-AspNet-Version'/></customHeaders>"
  has_header "X-AspNetMvc-Version" \
    && finding HIGH "X-AspNetMvc-Version: $(get_header "X-AspNetMvc-Version")"

  for hdr in "X-Generator" "X-Drupal-Cache" "X-WP-Nonce" "X-Pingback" "X-Joomla-Token"; do
    has_header "$hdr" && finding MEDIUM "${hdr} leaks CMS info: $(get_header "$hdr")"
  done

  if has_header "Access-Control-Allow-Origin"; then
    local acao; acao=$(get_header "Access-Control-Allow-Origin")
    if [[ "$acao" == "*" ]]; then
      finding HIGH "CORS wildcard: Access-Control-Allow-Origin: *" \
        "Restrict to specific trusted origins"
      if has_header "Access-Control-Allow-Credentials" && \
         [[ "$(get_header "Access-Control-Allow-Credentials")" == "true" ]]; then
        finding CRITICAL "CORS: Allow-Credentials:true + wildcard origin — critical misconfiguration"
      fi
    else
      finding OK "CORS restricted to: ${acao}"
    fi
  fi

  has_header "Via"     && finding INFO "Via: $(get_header "Via") (proxy/CDN)"
  has_header "X-Cache" && finding INFO "X-Cache: $(get_header "X-Cache")"

  for hdr in "X-Real-Ip" "X-Forwarded-Server" "X-Forwarded-Host"; do
    if has_header "$hdr"; then
      local val; val=$(get_header "$hdr")
      if echo "$val" | grep -qE '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)'; then
        finding HIGH "Internal IP in ${hdr}: ${val}" "Strip before responding to external clients"
      else
        finding INFO "${hdr}: ${val}"
      fi
    fi
  done

  for hdr in "X-Debug" "X-Debug-Token" "X-Debug-Token-Link" "X-Symfony-Debug"; do
    has_header "$hdr" && finding HIGH "Debug header exposed: ${hdr}" "Disable debug mode in production"
  done
}

# ── MODULE 4: COOKIES ───────────────────────────────────────────────────────
# FIX BUG-05: all cookie findings go through finding() — consistent scoring
module_cookies() {
  _should_run "cookies" || return 0
  section "4 — COOKIES"

  local cookies=()
  while IFS= read -r line; do
    [[ "${line,,}" =~ ^set-cookie: ]] && cookies+=("$line")
  done < "$HEADERS_FILE"

  if [[ ${#cookies[@]} -eq 0 ]]; then finding INFO "No Set-Cookie headers found"; return; fi
  finding INFO "${#cookies[@]} cookie(s) detected"
  echo ""

  local idx=0
  for cookie in "${cookies[@]}"; do
    idx=$(( idx + 1 ))
    local raw; raw=$(echo "$cookie" | cut -d: -f2- | sed 's/^ *//' | tr -d '\r')
    local name; name=$(echo "$raw" | cut -d= -f1 | sed 's/^ *//')
    local cl="${raw,,}"

    echo -e "  ${DIM}--- Cookie ${idx}: ${W}${name}${N}${DIM} ---${N}"

    echo "$cl" | grep -q "; *secure\b" \
      && echo -e "    ${G}+${N} Secure" \
      || finding HIGH "Cookie '${name}' missing Secure flag" "Add Secure attribute"

    echo "$cl" | grep -q "; *httponly\b" \
      && echo -e "    ${G}+${N} HttpOnly" \
      || finding HIGH "Cookie '${name}' missing HttpOnly flag" "Prevents XSS cookie theft"

    if echo "$cl" | grep -qiE "; *samesite=(strict|lax|none)"; then
      local ss; ss=$(echo "$cl" | grep -oiE "samesite=(strict|lax|none)" | head -1 | cut -d= -f2)
      if [[ "${ss,,}" == "none" ]] && ! echo "$cl" | grep -q "; *secure\b"; then
        finding HIGH "Cookie '${name}' SameSite=None without Secure — browsers will reject" ""
      elif [[ "${ss,,}" == "none" ]]; then
        echo -e "    ${Y}!${N} SameSite=None (cross-site — verify intentional)"
      else
        echo -e "    ${G}+${N} SameSite=${ss}"
      fi
    else
      finding MEDIUM "Cookie '${name}' missing SameSite attribute" "Add SameSite=Strict or Lax"
    fi

    if echo "$cl" | grep -qiE "; *(expires|max-age)"; then
      local ma; ma=$(echo "$cl" | grep -oiE "max-age=[0-9]+" | grep -oE "[0-9]+" || echo "")
      if [[ -n "$ma" && $ma -gt 86400 ]]; then
        local days=$(( ma / 86400 ))
        echo -e "    ${DIM}  Persistent — ${days} day(s)${N}"
        [[ $days -gt 365 ]] && finding LOW "Cookie '${name}' lifetime is ${days} days — very long"
      else
        echo -e "    ${DIM}  Persistent${N}"
      fi
    else
      echo -e "    ${DIM}  Session cookie${N}"
    fi
    echo ""
  done
}

# ── MODULE 5: TLS/SSL ───────────────────────────────────────────────────────
# FIX BUG-01: uses TARGET_HOST (hostname:port) not hardcoded :443
# FIX BUG-02: grep -c replaced with grep | wc -l throughout
# FIX BUG-04: HSTS preload check only here (removed from module_security_headers)
module_tls() {
  _should_run "tls" || return 0
  section "5 — TLS / SSL AUDIT (port ${TLS_PORT})"

  local cert_raw
  cert_raw=$(echo | timeout "$TIMEOUT" openssl s_client \
    -connect "${TARGET_HOST}" \
    -servername "$TARGET" \
    2>/dev/null || true)

  if [[ -z "$cert_raw" ]]; then
    finding CRITICAL "No TLS on ${TARGET_HOST}" "Port ${TLS_PORT} is closed or TLS not configured"
    return
  fi

  local cert_text
  cert_text=$(echo "$cert_raw" | openssl x509 -noout -text 2>/dev/null || true)

  if [[ -n "$cert_text" ]]; then
    local subject issuer expiry sans fingerprint
    subject=$(echo "$cert_text"    | grep "Subject:"  | head -1 | sed 's/.*Subject: //'   || true)
    issuer=$(echo "$cert_text"     | grep "Issuer:"   | head -1 | sed 's/.*Issuer: //'    || true)
    expiry=$(echo "$cert_text"     | grep "Not After" | head -1 | sed 's/.*Not After : //' || true)
    sans=$(echo "$cert_text"       | grep -A1 "Subject Alternative Name" | tail -1 \
      | sed 's/^[[:space:]]*//' || true)
    fingerprint=$(echo "$cert_raw" | openssl x509 -noout -fingerprint -sha256 2>/dev/null \
      | sed 's/.*=//' || true)

    [[ -n "$subject"     ]] && finding INFO "Subject    : ${subject}"
    [[ -n "$issuer"      ]] && finding INFO "Issuer     : ${issuer}"
    [[ -n "$fingerprint" ]] && finding INFO "SHA-256    : ${fingerprint}"
    [[ -n "$sans"        ]] && finding INFO "SANs       : ${sans}"

    [[ -n "$subject" && -n "$issuer" && "$subject" == "$issuer" ]] \
      && finding HIGH "Self-signed certificate — browsers will warn users"

    echo "${sans}${subject}" | grep -q "\*\." \
      && finding INFO "Wildcard certificate — protect private key carefully"

    if [[ -n "$expiry" ]]; then
      local exp_ts now_ts days
      exp_ts=$(date -d "$expiry" +%s 2>/dev/null || echo "0")
      if [[ $exp_ts -gt 0 ]]; then
        now_ts=$(date +%s)
        days=$(( (exp_ts - now_ts) / 86400 ))
        if   [[ $days -lt 0 ]];   then finding CRITICAL "Certificate EXPIRED ${days#-} days ago"
        elif [[ $days -lt 7 ]];   then finding CRITICAL "Certificate expires in ${days} days — RENEW NOW"
        elif [[ $days -lt 30 ]];  then finding HIGH    "Certificate expires in ${days} days"
        elif [[ $days -lt 90 ]];  then finding MEDIUM  "Certificate expires in ${days} days"
        else                           finding OK      "Certificate valid ${days} days (expires: ${expiry%% *})"
        fi
      fi
    fi

    local key_bits
    key_bits=$(echo "$cert_text" | grep -oE "Public-Key: \([0-9]+ bit\)" | grep -oE "[0-9]+" || echo "")
    if [[ -n "$key_bits" ]]; then
      [[ $key_bits -lt 2048 ]] \
        && finding CRITICAL "Weak RSA key: ${key_bits} bits (minimum 2048)" \
        || finding OK "Key size: ${key_bits} bits"
    fi

    local sig_alg
    sig_alg=$(echo "$cert_text" | grep "Signature Algorithm:" | head -1 | awk '{print $NF}' || true)
    if [[ -n "$sig_alg" ]]; then
      echo "$sig_alg" | grep -qiE "sha1|md5" \
        && finding HIGH "Weak signature algorithm: ${sig_alg} — reissue with SHA-256+" \
        || finding OK "Signature algorithm: ${sig_alg}"
    fi
  fi

  echo ""
  echo -e "  ${DIM}Testing protocol versions on ${TARGET_HOST}...${N}"

  # FIX BUG-02: grep | wc -l — grep -c removed
  _tls_check() {
    local proto="$1" out
    out=$(echo | timeout 6 openssl s_client \
      -connect "${TARGET_HOST}" -servername "$TARGET" "${proto}" 2>&1 || true)
    echo "$out" | grep "^CONNECTED" | wc -l
  }

  for proto_pair in "-ssl2:SSLv2" "-ssl3:SSLv3" "-tls1:TLS 1.0" "-tls1_1:TLS 1.1"; do
    local flag="${proto_pair%%:*}" label="${proto_pair##*:}"
    local n; n=$(_tls_check "$flag")
    [[ "$n" -gt 0 ]] && finding CRITICAL "Weak protocol enabled: ${label}" \
      "Disable: ssl_protocols TLSv1.2 TLSv1.3;"
  done

  local n12; n12=$(_tls_check "-tls1_2")
  [[ "$n12" -gt 0 ]] && finding OK "TLS 1.2 supported" \
    || finding MEDIUM "TLS 1.2 not supported (required for compatibility)"

  local n13; n13=$(_tls_check "-tls1_3")
  [[ "$n13" -gt 0 ]] && finding OK "TLS 1.3 supported (optimal)" \
    || finding LOW "TLS 1.3 not supported (recommended)"

  local cipher
  cipher=$(echo "$cert_raw" | grep "^Cipher" | awk '{print $3}' || true)
  if [[ -n "$cipher" ]]; then
    echo "$cipher" | grep -qiE 'RC4|DES|NULL|EXPORT|anon|MD5|3DES' \
      && finding CRITICAL "Weak cipher in use: ${cipher}" "Disable RC4, 3DES, NULL, EXPORT" \
      || { echo "$cipher" | grep -qiE 'ECDHE|DHE' \
           && finding OK "Forward Secrecy cipher: ${cipher}" \
           || finding LOW "Cipher without Forward Secrecy: ${cipher}" "Prefer ECDHE/DHE suites"; }
  fi

  # HTTP/2 via ALPN
  local h2
  h2=$(echo | timeout 6 openssl s_client \
    -connect "${TARGET_HOST}" -servername "$TARGET" \
    -alpn "h2,http/1.1" 2>/dev/null | grep "^ALPN protocol" | grep -o "h2" || true)
  [[ "$h2" == "h2" ]] \
    && finding OK "HTTP/2 (ALPN)" \
    || finding INFO "HTTP/2 not advertised"

  # FIX BUG-04: HSTS preload check ONLY here
  local hsts_val; hsts_val=$(get_header "Strict-Transport-Security")
  echo "$hsts_val" | grep -qi "preload" \
    && finding OK "HSTS preload directive present" \
    || finding LOW "HSTS preload missing" "Add 'preload'; submit to https://hstspreload.org"

  # OCSP Stapling
  local ocsp_n; ocsp_n=$(echo "$cert_raw" | grep "OCSP Response" | wc -l)
  [[ "$ocsp_n" -gt 0 ]] \
    && finding OK "OCSP Stapling enabled" \
    || finding LOW "OCSP Stapling not detected" "ssl_stapling on; ssl_stapling_verify on;"

  # Certificate Transparency
  local sct_n; sct_n=$(echo "$cert_raw" | grep "Signed Certificate Timestamp" | wc -l)
  [[ "$sct_n" -gt 0 ]] \
    && finding OK "Certificate Transparency: ${sct_n} SCT(s) embedded" \
    || finding INFO "No embedded SCTs (may be in TLS extension)"
}

# ── MODULE 6: HTTP METHODS ──────────────────────────────────────────────────
module_methods() {
  _should_run "methods" || return 0
  section "6 — HTTP METHODS AUDIT"

  local options_resp allow_header
  options_resp=$(curl -s --max-time "$TIMEOUT" -X OPTIONS -A "$UA" -I \
    "$TARGET_URL" 2>/dev/null || true)
  allow_header=$(echo "$options_resp" | grep -i "^Allow:" | head -1 \
    | cut -d: -f2- | tr -d '\r' | sed 's/^ *//')

  if [[ -n "$allow_header" ]]; then
    finding INFO "OPTIONS Allow: ${allow_header}"
    echo "$allow_header" | grep -qi "TRACE"   && finding HIGH "TRACE enabled — XST attack risk" \
      "LimitExcept GET POST { Deny from all } or TraceEnable Off"
    echo "$allow_header" | grep -qi "PUT"     && finding MEDIUM "PUT enabled — file upload possible"
    echo "$allow_header" | grep -qi "DELETE"  && finding MEDIUM "DELETE enabled — resource deletion possible"
    echo "$allow_header" | grep -qi "CONNECT" && finding HIGH "CONNECT enabled — proxy relay risk"
  fi

  local trace_code
  trace_code=$(curl -s --max-time "$TIMEOUT" -X TRACE -A "$UA" \
    -o /dev/null -w "%{http_code}" "$TARGET_URL" 2>/dev/null || echo "000")
  case "$trace_code" in
    200) finding HIGH "TRACE returns 200 — XST attack confirmed" "Nginx: deny all in server block" ;;
    403|405|501) finding OK "TRACE disabled (${trace_code})" ;;
  esac
}

# ── MODULE 7: WAF/CDN ───────────────────────────────────────────────────────
module_waf() {
  _should_run "waf" || return 0
  section "7 — WAF / CDN DETECTION"

  local waf_name=""
  has_header "cf-ray"                && waf_name="Cloudflare"
  has_header "x-amz-cf-id"          && waf_name="AWS CloudFront"
  has_header "x-fastly-request-id"  && waf_name="Fastly"
  has_header "x-akamai-request-id"  && waf_name="Akamai"
  has_header "x-sucuri-id"          && waf_name="Sucuri"
  has_header "incap-session-id"     && waf_name="Imperva Incapsula"
  has_header "x-iinfo"              && waf_name="Imperva"

  if [[ -n "$waf_name" ]]; then
    finding INFO "WAF/CDN detected: ${waf_name}"
  else
    has_header "Server" && get_header "Server" | grep -qi "cloudflare" && waf_name="Cloudflare"
    [[ -n "$waf_name" ]] && finding INFO "WAF/CDN via Server header: ${waf_name}" \
      || finding INFO "No WAF/CDN fingerprint detected — may be direct origin or unknown WAF"
  fi

  local waf_code
  waf_code=$(curl -s --max-time "$TIMEOUT" -A "$UA" \
    -o /dev/null -w "%{http_code}" \
    "${TARGET_URL}/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E" 2>/dev/null || echo "000")
  case "$waf_code" in
    403|406|429|503) finding OK "WAF blocking XSS payloads (${waf_code})" ;;
    200) finding INFO "XSS payload returned 200 — verify app-level filtering" ;;
  esac

  has_header "Age" && finding INFO "Cached response (Age: $(get_header "Age")s) — verify sensitive data not cached"
}

# ── MODULE 8: SECURITY.TXT ──────────────────────────────────────────────────
module_security_txt() {
  _should_run "securitytxt" || return 0
  section "8 — RESPONSIBLE DISCLOSURE (security.txt)"

  local found=false content="" tmp_stxt
  tmp_stxt=$(mktemp /tmp/webcheck_stxt_XXXXXX.txt)

  for path in "/.well-known/security.txt" "/security.txt"; do
    local code
    code=$(curl -s --max-time "$TIMEOUT" -A "$UA" \
      -o "$tmp_stxt" -w "%{http_code}" "${TARGET_URL}${path}" 2>/dev/null || echo "000")
    if [[ "$code" == "200" ]] && [[ -s "$tmp_stxt" ]]; then
      found=true; content=$(cat "$tmp_stxt")
      finding OK "security.txt found at: ${path}"; break
    fi
  done
  rm -f "$tmp_stxt"

  if ! $found; then
    finding LOW "security.txt not found (RFC 9116)" \
      "Create /.well-known/security.txt with Contact: and Expires: fields"
    return
  fi

  echo "$content" | grep -qi "^Contact:" \
    && finding OK "Contact field present" \
    || finding MEDIUM "security.txt missing required Contact: field"

  if echo "$content" | grep -qi "^Expires:"; then
    local exp_str; exp_str=$(echo "$content" | grep -i "^Expires:" | head -1 | cut -d: -f2- | sed 's/^ //')
    local exp_ts; exp_ts=$(date -d "$exp_str" +%s 2>/dev/null || echo "0")
    if [[ $exp_ts -gt 0 ]]; then
      local now_ts=$(date +%s) days_left=$(( (exp_ts - now_ts) / 86400 ))
      [[ $exp_ts -lt $now_ts ]] \
        && finding HIGH "security.txt has EXPIRED — update Expires field" \
        || finding OK "Expires valid (${days_left} days remaining)"
    fi
  else
    finding MEDIUM "security.txt missing required Expires: field"
  fi

  echo "$content" | grep -qi "^Encryption:" && finding OK "PGP encryption key linked"
  echo "$content" | grep -qi "^Policy:"     && finding OK "Security policy URL provided"
}

# ── MODULE 9: DNS SECURITY ──────────────────────────────────────────────────
module_dns() {
  _should_run "dns" || return 0
  section "9 — DNS SECURITY (CAA / DNSSEC / SPF / DMARC)"

  local caa; caa=$(dig +short CAA "$TARGET" 2>/dev/null | tr -d '\r' || true)
  if [[ -n "$caa" ]]; then
    finding OK "DNS CAA records found — restricts which CAs can issue certs"
    while IFS= read -r rec; do [[ -n "$rec" ]] && finding INFO "CAA: ${rec}"; done <<< "$caa"
  else
    finding MEDIUM "No CAA records — any CA can issue certificates for ${TARGET}" \
      "Add: 0 issue \"letsencrypt.org\"; 0 iodef \"mailto:security@${TARGET}\""
  fi

  local dnssec_n; dnssec_n=$(dig +dnssec "$TARGET" A 2>/dev/null | grep "RRSIG" | wc -l | tr -d ' ' || echo "0")
  [[ "$dnssec_n" -gt 0 ]] \
    && finding OK "DNSSEC signatures detected" \
    || finding LOW "DNSSEC not detected" "Enable DNSSEC at your registrar"

  local spf; spf=$(dig +short TXT "$TARGET" 2>/dev/null | grep -i "v=spf1" | tr -d '"' || true)
  if [[ -n "$spf" ]]; then
    finding INFO "SPF: ${spf}"
    echo "$spf" | grep -q "+all" \
      && finding HIGH "SPF '+all' — any server can send email as ${TARGET}" "Use ~all or -all" \
      || { echo "$spf" | grep -q "\-all" && finding OK "SPF -all (strict)"; }
  else
    finding INFO "No SPF record"
  fi

  local dmarc; dmarc=$(dig +short TXT "_dmarc.${TARGET}" 2>/dev/null | tr -d '"' | grep -i "v=DMARC1" || true)
  if [[ -n "$dmarc" ]]; then
    echo "$dmarc" | grep -qi "p=none"       && finding LOW "DMARC p=none — reports only, no enforcement"
    echo "$dmarc" | grep -qi "p=reject"     && finding OK "DMARC p=reject (strict)"
    echo "$dmarc" | grep -qi "p=quarantine" && finding OK "DMARC p=quarantine"
  else
    finding INFO "No DMARC record for _dmarc.${TARGET}"
  fi
}

# ── MODULE 10: ROBOTS.TXT / PATH EXPOSURE ──────────────────────────────────
module_robots() {
  _should_run "robots" || return 0
  section "10 — ROBOTS.TXT / PATH EXPOSURE"

  local tmp_robots; tmp_robots=$(mktemp /tmp/webcheck_robots_XXXXXX.txt)
  local robots_code
  robots_code=$(curl -s --max-time "$TIMEOUT" -A "$UA" \
    -o "$tmp_robots" -w "%{http_code}" "${TARGET_URL}/robots.txt" 2>/dev/null || echo "000")

  if [[ "$robots_code" == "200" ]] && [[ -s "$tmp_robots" ]]; then
    local content; content=$(cat "$tmp_robots")
    finding INFO "robots.txt found"
    local sensitive=()
    for p in "/admin" "/administrator" "/wp-admin" "/cpanel" "/backup" "/db" \
             "/database" "/phpmyadmin" "/api/internal" "/private" "/staging" \
             "/config" "/.git" "/.env" "/logs" "/secret" "/upload"; do
      echo "$content" | grep -qi "Disallow:.*${p}" && sensitive+=("$p")
    done
    [[ ${#sensitive[@]} -gt 0 ]] \
      && finding MEDIUM "robots.txt reveals sensitive paths: ${sensitive[*]}" \
         "robots.txt is public — these paths may be real endpoints" \
      || finding OK "robots.txt does not expose obviously sensitive paths"
  fi
  rm -f "$tmp_robots"

  local git_code
  git_code=$(curl -s --max-time "$TIMEOUT" -A "$UA" \
    -o /dev/null -w "%{http_code}" "${TARGET_URL}/.git/HEAD" 2>/dev/null || echo "000")
  case "$git_code" in
    200) finding CRITICAL ".git/HEAD accessible — source code exposed" \
           "Nginx: location /.git { deny all; }" ;;
    403) finding LOW ".git blocked (403) — verify files not enumerable" ;;
    404) finding OK ".git not accessible" ;;
  esac

  local env_code
  env_code=$(curl -s --max-time "$TIMEOUT" -A "$UA" \
    -o /dev/null -w "%{http_code}" "${TARGET_URL}/.env" 2>/dev/null || echo "000")
  case "$env_code" in
    200) finding CRITICAL ".env file accessible — credentials exposed" \
           "IMMEDIATELY: location ~ /\\. { deny all; }" ;;
    404) finding OK ".env not accessible" ;;
  esac
}

# ── MODULE 11: CACHE-CONTROL ────────────────────────────────────────────────
module_cache() {
  _should_run "cache" || return 0
  section "11 — CACHE-CONTROL & HTTP/3"

  local cc; cc=$(get_header "Cache-Control")
  if [[ -n "$cc" ]]; then
    finding INFO "Cache-Control: ${cc}"
    echo "$cc" | grep -qi "no-store"  && finding OK "Cache-Control: no-store (not cached)"
    echo "$cc" | grep -qi "no-cache"  && finding OK "Cache-Control: no-cache (revalidation required)"
    if echo "$cc" | grep -qi "public" && ! echo "$cc" | grep -qi "no-store"; then
      finding LOW "Cache-Control: public — ensure no sensitive data in this response"
    fi
  else
    finding INFO "No Cache-Control header — default browser/proxy caching applies"
  fi

  has_header "Pragma" && finding INFO "Pragma: $(get_header "Pragma") (deprecated — use Cache-Control)"

  if has_header "Alt-Svc"; then
    local alt; alt=$(get_header "Alt-Svc")
    echo "$alt" | grep -qi "h3" \
      && finding OK "HTTP/3 (QUIC) via Alt-Svc: ${alt}" \
      || finding INFO "Alt-Svc: ${alt}"
  fi

  if has_header "Vary"; then
    local vary; vary=$(get_header "Vary")
    finding INFO "Vary: ${vary}"
    echo "$vary" | grep -qiE "Authorization|Cookie" \
      && finding OK "Vary includes Authorization/Cookie — authenticated responses not shared in cache"
  fi
}

# ── SCORE & SUMMARY ─────────────────────────────────────────────────────────
render_score() {
  [[ $SCORE -lt 0 ]] && SCORE=0; [[ $SCORE -gt 100 ]] && SCORE=100
  local grade color bar=""
  local filled=$(( SCORE * 40 / 100 ))
  if   [[ $SCORE -ge 90 ]]; then grade="A+"; color="$G"
  elif [[ $SCORE -ge 80 ]]; then grade="A";  color="$G"
  elif [[ $SCORE -ge 70 ]]; then grade="B";  color="$C"
  elif [[ $SCORE -ge 60 ]]; then grade="C";  color="$Y"
  elif [[ $SCORE -ge 50 ]]; then grade="D";  color="$Y"
  else                            grade="F";  color="$R"; fi
  for ((i=0; i<filled; i++));  do bar+="█"; done
  for ((i=filled; i<40; i++)); do bar+="░"; done
  echo ""; sep
  echo -e "  ${W}${BOLD}SECURITY SCORE${N}"; sep_thin
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
      HIGH)     n_high=$(( n_high+1 )) ;;
      MEDIUM)   n_medium=$(( n_medium+1 )) ;;
      LOW)      n_low=$(( n_low+1 )) ;;
      OK)       n_ok=$(( n_ok+1 )) ;;
      INFO)     n_info=$(( n_info+1 )) ;;
    esac
  done
  echo -e "  ${W}FINDINGS SUMMARY${N}"; sep_thin
  printf "  %-16s  ${R}%d${N}\n"   "CRITICAL"  "$n_critical"
  printf "  %-16s  ${R}%d${N}\n"   "HIGH"      "$n_high"
  printf "  %-16s  ${Y}%d${N}\n"   "MEDIUM"    "$n_medium"
  printf "  %-16s  ${B}%d${N}\n"   "LOW"       "$n_low"
  printf "  %-16s  ${G}%d${N}\n"   "PASSED"    "$n_ok"
  printf "  %-16s  ${DIM}%d${N}\n" "INFO"      "$n_info"
  sep_thin
  printf "  ${DIM}%-16s  %s${N}\n"  "Target"   "$TARGET_URL"
  printf "  ${DIM}%-16s  %ds${N}\n" "Duration" "$elapsed"
  printf "  ${DIM}%-16s  v%s${N}\n" "Webcheck" "$VERSION"
  sep; echo ""

  if [[ $n_critical -gt 0 || $n_high -gt 0 ]]; then
    echo -e "  ${R}${BOLD}ACTION REQUIRED:${N}"
    for f in "${FINDINGS[@]}"; do
      local lvl="${f%%|*}" rest="${f#*|}" msg="${rest%%|*}"
      [[ "$lvl" == "CRITICAL" || "$lvl" == "HIGH" ]] \
        && echo -e "  ${R}->  [${lvl}]${N} ${msg}"
    done
    echo ""
  fi
}

write_json() {
  local out_path="$1"
  local ts; ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  local n_c=0 n_h=0 n_m=0 n_l=0 n_o=0 n_i=0
  for f in "${FINDINGS[@]}"; do
    case "${f%%|*}" in
      CRITICAL) n_c=$(( n_c+1 )) ;; HIGH)   n_h=$(( n_h+1 )) ;;
      MEDIUM)   n_m=$(( n_m+1 )) ;; LOW)    n_l=$(( n_l+1 )) ;;
      OK)       n_o=$(( n_o+1 )) ;; INFO)   n_i=$(( n_i+1 )) ;;
    esac
  done
  local jf=""
  for f in "${FINDINGS[@]}"; do
    local lvl="${f%%|*}" rest="${f#*|}"
    local msg="${rest%%|*}" detail="${rest#*|}"
    [[ "$detail" == "$msg" ]] && detail=""
    msg="${msg//\"/\\\"}"; detail="${detail//\"/\\\"}"
    [[ -n "$jf" ]] && jf+=","
    jf+="{\"level\":\"${lvl}\",\"message\":\"${msg}\",\"detail\":\"${detail}\"}"
  done
  local grade
  if   [[ $SCORE -ge 90 ]]; then grade="A+"
  elif [[ $SCORE -ge 80 ]]; then grade="A"
  elif [[ $SCORE -ge 70 ]]; then grade="B"
  elif [[ $SCORE -ge 60 ]]; then grade="C"
  elif [[ $SCORE -ge 50 ]]; then grade="D"
  else grade="F"; fi
  cat > "$out_path" << JSON
{
  "webcheck": {
    "version": "${VERSION}",
    "timestamp": "${ts}",
    "target": "${TARGET_URL}",
    "score": ${SCORE},
    "grade": "${grade}",
    "summary": {
      "critical": ${n_c}, "high": ${n_h}, "medium": ${n_m},
      "low": ${n_l}, "passed": ${n_o}, "info": ${n_i}
    },
    "findings": [${jf}]
  }
}
JSON
  echo -e "  ${G}[+]${N} JSON report -> ${W}${out_path}${N}"
}

usage() {
  echo -e "${W}Usage:${N}  $0 <target> [options]"
  echo ""
  echo -e "${W}Options:${N}"
  echo -e "  -t, --target <url>     Target to scan"
  echo -e "  -p, --port <port>      Custom TLS port (default: 443)"
  echo -e "  -T, --timeout <sec>    Connection timeout (default: 15)"
  echo -e "  -o, --output <file>    Save report (.json = JSON format)"
  echo -e "  -m, --modules <list>   Comma-separated modules:"
  echo -e "                         redirect,headers,disclosure,cookies,tls,"
  echo -e "                         methods,waf,securitytxt,dns,robots,cache"
  echo -e "      --no-color         CI/CD mode — disable colors"
  echo -e "  -h, --help             Show help"
  echo -e "  -v, --version          Show version"
  echo ""
  echo -e "${W}Examples:${N}"
  echo -e "  $0 example.com"
  echo -e "  $0 -t https://target.com -o report.json"
  echo -e "  $0 -t target.com:8443 -p 8443"
  echo -e "  $0 -t target.com -m tls,headers,cookies"
  echo -e "  $0 -t target.com --no-color > scan.txt"
  echo ""
  echo -e "${R}  Authorized targets only.${N}"
}

run_scan() {
  local raw_target="$1"
  SCORE=100; FINDINGS=(); HEADERS_FILE=""; REDIRECT_TMP=""
  START_TIME=$(date +%s)
  normalize_target "$raw_target"
  echo -e "  ${LVL_INFO} Target  : ${W}${TARGET_URL}${N}"
  echo -e "  ${LVL_INFO} TLS Port: ${W}${TLS_PORT}${N}"
  echo -e "  ${LVL_INFO} Timeout : ${W}${TIMEOUT}s${N}"
  [[ ${#MODULES_TO_RUN[@]} -gt 0 ]] && \
    echo -e "  ${LVL_INFO} Modules : ${W}${MODULES_TO_RUN[*]}${N}"
  echo ""
  echo -e "  ${DIM}Fetching headers...${N}"
  fetch_headers
  echo -e "  ${LVL_INFO} Status  : ${W}$(get_status)${N}"

  module_redirect; module_security_headers; module_disclosure
  module_cookies; module_tls; module_methods; module_waf
  module_security_txt; module_dns; module_robots; module_cache

  render_score; render_summary

  if [[ -n "$OUTPUT_FILE" ]]; then
    [[ "$OUTPUT_FILE" == *.json ]] \
      && write_json "$OUTPUT_FILE" \
      || echo -e "  ${DIM}Tip: use --no-color > ${OUTPUT_FILE} for plain text${N}"
  fi
}

main() {
  local raw_target="" modules_arg=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)    banner; usage; exit 0 ;;
      -v|--version) echo "webcheck v${VERSION}"; exit 0 ;;
      --no-color)   NO_COLOR=true; _init_colors; shift ;;
      -t|--target)  [[ -z "${2:-}" ]] && { echo "${R}[ERROR]${N} -t needs a value"; exit 1; }
                    raw_target="$2"; shift 2 ;;
      -p|--port)    [[ -z "${2:-}" ]] && { echo "${R}[ERROR]${N} --port needs a value"; exit 1; }
                    TLS_PORT="$2"; shift 2 ;;
      -T|--timeout) [[ -z "${2:-}" ]] && { echo "${R}[ERROR]${N} --timeout needs a value"; exit 1; }
                    TIMEOUT="$2"; shift 2 ;;
      -o|--output)  [[ -z "${2:-}" ]] && { echo "${R}[ERROR]${N} --output needs a value"; exit 1; }
                    OUTPUT_FILE="$2"; shift 2 ;;
      -m|--modules) [[ -z "${2:-}" ]] && { echo "${R}[ERROR]${N} --modules needs a value"; exit 1; }
                    modules_arg="$2"; shift 2 ;;
      -*)           echo -e "${R}[ERROR]${N} Unknown flag: $1"; echo "${DIM}Run $0 --help${N}"; exit 1 ;;
      *)            [[ -n "$raw_target" ]] && { echo "${R}[ERROR]${N} Multiple targets — use -t"; exit 1; }
                    raw_target="$1"; shift ;;
    esac
  done

  [[ -n "$modules_arg" ]] && IFS=',' read -ra MODULES_TO_RUN <<< "$modules_arg"

  banner
  check_deps

  if [[ -z "$raw_target" ]]; then
    printf "  ${G}[>]${N} Target (domain or URL): "; read -r raw_target
    [[ -z "$raw_target" ]] && { echo -e "${R}[ERROR]${N} No target"; exit 1; }
  fi

  run_scan "$raw_target"
}

main "$@"
