#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║   WEBCHECK v1.0 — HTTP Security Auditor                    ║
# ║   Author  : krypthane | wavegxz-design                     ║
# ║   Site    : krypthane.workernova.workers.dev                ║
# ║   GitHub  : github.com/wavegxz-design/webcheck             ║
# ║   License : MIT                                             ║
# ║                                                              ║
# ║   USE ONLY ON TARGETS YOU OWN OR HAVE PERMISSION TO TEST.  ║
# ╚══════════════════════════════════════════════════════════════╝

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# VERSION & CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
readonly VERSION="1.0.0"
readonly SITE="krypthane.workernova.workers.dev"
readonly TIMEOUT=15
readonly UA="webcheck/${VERSION} (github.com/wavegxz-design/webcheck)"

# ─────────────────────────────────────────────────────────────────────────────
# COLORS
# ─────────────────────────────────────────────────────────────────────────────
R='\033[0;31m'    # Red
G='\033[0;32m'    # Green
Y='\033[1;33m'    # Yellow
B='\033[0;34m'    # Blue
C='\033[0;36m'    # Cyan
M='\033[0;35m'    # Magenta
W='\033[1;37m'    # White
DIM='\033[2m'
BOLD='\033[1m'
N='\033[0m'

# Risk level colors
CRITICAL="${R}[CRITICAL]${N}"
HIGH="${R}[HIGH]    ${N}"
MEDIUM="${Y}[MEDIUM]  ${N}"
LOW="${B}[LOW]     ${N}"
INFO="${C}[INFO]    ${N}"
OK="${G}[OK]      ${N}"

# ─────────────────────────────────────────────────────────────────────────────
# SCORE TRACKING
# ─────────────────────────────────────────────────────────────────────────────
SCORE=100          # starts perfect, deducted per finding
FINDINGS=()        # array of "LEVEL|message"
TARGET=""
TARGET_URL=""
HEADERS_FILE=""
CERT_FILE=""
START_TIME=$(date +%s)

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

finding() {
  local level="$1" msg="$2" detail="${3:-}"
  FINDINGS+=("${level}|${msg}")

  case "$level" in
    CRITICAL) echo -e "  ${CRITICAL} ${W}${msg}${N}"; SCORE=$((SCORE - 20)) ;;
    HIGH)     echo -e "  ${HIGH} ${W}${msg}${N}";     SCORE=$((SCORE - 15)) ;;
    MEDIUM)   echo -e "  ${MEDIUM} ${msg}";            SCORE=$((SCORE - 8))  ;;
    LOW)      echo -e "  ${LOW} ${msg}";               SCORE=$((SCORE - 3))  ;;
    INFO)     echo -e "  ${INFO} ${msg}" ;;
    OK)       echo -e "  ${OK} ${G}${msg}${N}" ;;
  esac

  [[ -n "$detail" ]] && echo -e "  ${DIM}         → ${detail}${N}"
}

banner() {
  clear
  echo -e "${C}"
cat << 'EOF'
  ██╗    ██╗███████╗██████╗  ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
  ██║    ██║██╔════╝██╔══██╗██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
  ██║ █╗ ██║█████╗  ██████╔╝██║     ███████║█████╗  ██║     █████╔╝
  ██║███╗██║██╔══╝  ██╔══██╗██║     ██╔══██║██╔══╝  ██║     ██╔═██╗
  ╚███╔███╔╝███████╗██████╔╝╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
   ╚══╝╚══╝ ╚══════╝╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝
EOF
  echo -e "${N}"
  printf "  ${W}v%s${N}  ${DIM}|${N}  ${C}krypthane${N}  ${DIM}|${N}  ${Y}%s${N}\n" "$VERSION" "github.com/wavegxz-design/webcheck"
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
    echo -e "${R}[ERROR]${N} Missing dependencies: ${missing[*]}"
    echo -e "${DIM}Install: sudo apt install ${missing[*]}${N}"
    exit 1
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# TARGET NORMALIZATION
# Accepts: example.com | http://example.com | https://example.com/path
# ─────────────────────────────────────────────────────────────────────────────
normalize_target() {
  local raw="$1"
  # Strip protocol
  local host="${raw#http://}"
  host="${host#https://}"
  # Strip path
  host="${host%%/*}"
  # Strip port for display
  TARGET="${host}"
  TARGET_URL="https://${host}"
}

# ─────────────────────────────────────────────────────────────────────────────
# FETCH HEADERS — single request, reused for all checks
# ─────────────────────────────────────────────────────────────────────────────
fetch_headers() {
  HEADERS_FILE=$(mktemp /tmp/webcheck_headers_XXXXXX.txt)

  # Follow redirects, store final headers, include HTTP/1.1 status
  if ! curl -sI \
      --max-time "$TIMEOUT" \
      --max-redirs 5 \
      -A "$UA" \
      -D "$HEADERS_FILE" \
      -o /dev/null \
      "$TARGET_URL" 2>/dev/null; then

    # Try HTTP fallback if HTTPS fails
    if ! curl -sI \
        --max-time "$TIMEOUT" \
        -A "$UA" \
        -D "$HEADERS_FILE" \
        -o /dev/null \
        "http://${TARGET}" 2>/dev/null; then
      echo -e "${R}[ERROR]${N} Cannot reach ${TARGET} — check the URL and your connection"
      rm -f "$HEADERS_FILE"
      exit 1
    fi
  fi
}

# Helper: get header value case-insensitively (returns empty if missing)
get_header() {
  local name="$1"
  grep -i "^${name}:" "$HEADERS_FILE" 2>/dev/null \
    | head -1 \
    | cut -d: -f2- \
    | sed 's/^ *//' \
    | tr -d '\r'
}

# Helper: check if header exists
has_header() {
  grep -qi "^${1}:" "$HEADERS_FILE" 2>/dev/null
}

# HTTP status code
get_status() {
  grep -m1 "^HTTP/" "$HEADERS_FILE" 2>/dev/null \
    | awk '{print $2}' \
    | tr -d '\r'
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 1 — REDIRECT HTTP → HTTPS
# ─────────────────────────────────────────────────────────────────────────────
module_redirect() {
  section "HTTP → HTTPS REDIRECT"

  local http_status
  local redirect_headers
  redirect_headers=$(mktemp /tmp/webcheck_redir_XXXXXX.txt)

  http_status=$(curl -sI \
    --max-time "$TIMEOUT" \
    -A "$UA" \
    -D "$redirect_headers" \
    -o /dev/null \
    -w "%{http_code}" \
    "http://${TARGET}" 2>/dev/null || echo "000")

  local location
  location=$(grep -i "^location:" "$redirect_headers" 2>/dev/null \
    | head -1 | cut -d: -f2- | sed 's/^ *//' | tr -d '\r' || true)

  rm -f "$redirect_headers"

  case "$http_status" in
    301|302|307|308)
      if echo "$location" | grep -qi "^https://"; then
        finding OK "HTTP redirects to HTTPS [${http_status}]" "$location"
      else
        finding HIGH "HTTP redirects but NOT to HTTPS [${http_status}]" "$location"
      fi
      ;;
    200)
      finding MEDIUM "HTTP responds directly without redirect" \
        "Configure 301 → https://${TARGET}"
      ;;
    000)
      finding INFO "HTTP port not reachable (may be intentional)"
      ;;
    *)
      finding LOW "Unexpected HTTP response: ${http_status}"
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
    if [[ $max_age -ge 31536000 ]]; then
      finding OK "Strict-Transport-Security present (max-age=${max_age})"
    elif [[ $max_age -gt 0 ]]; then
      finding LOW "Strict-Transport-Security max-age too short (${max_age})" \
        "Recommend: max-age=31536000; includeSubDomains; preload"
    else
      finding MEDIUM "Strict-Transport-Security malformed" "$hsts"
    fi
  else
    finding HIGH "Strict-Transport-Security MISSING" \
      "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
  fi

  # ── Content-Security-Policy ────────────────────────────────────
  if has_header "Content-Security-Policy"; then
    local csp; csp=$(get_header "Content-Security-Policy")
    if echo "$csp" | grep -q "unsafe-inline\|unsafe-eval"; then
      finding MEDIUM "CSP present but uses unsafe directives" \
        "Remove 'unsafe-inline' and 'unsafe-eval'"
    elif echo "$csp" | grep -q "\*"; then
      finding MEDIUM "CSP present but uses wildcards (*)" "$csp"
    else
      finding OK "Content-Security-Policy present"
    fi
  else
    finding HIGH "Content-Security-Policy MISSING" \
      "Add: Content-Security-Policy: default-src 'self'"
  fi

  # ── X-Frame-Options ────────────────────────────────────────────
  if has_header "X-Frame-Options"; then
    local xfo; xfo=$(get_header "X-Frame-Options")
    case "${xfo^^}" in
      DENY|SAMEORIGIN)
        finding OK "X-Frame-Options: ${xfo}" ;;
      ALLOW-FROM*)
        finding LOW "X-Frame-Options ALLOW-FROM is deprecated" \
          "Use CSP frame-ancestors instead" ;;
      *)
        finding MEDIUM "X-Frame-Options value unrecognized: ${xfo}" ;;
    esac
  else
    finding MEDIUM "X-Frame-Options MISSING" \
      "Add: X-Frame-Options: DENY"
  fi

  # ── X-Content-Type-Options ─────────────────────────────────────
  if has_header "X-Content-Type-Options"; then
    local xcto; xcto=$(get_header "X-Content-Type-Options")
    [[ "${xcto,,}" == "nosniff" ]] \
      && finding OK "X-Content-Type-Options: nosniff" \
      || finding LOW "X-Content-Type-Options value unexpected: ${xcto}"
  else
    finding MEDIUM "X-Content-Type-Options MISSING" \
      "Add: X-Content-Type-Options: nosniff"
  fi

  # ── Referrer-Policy ────────────────────────────────────────────
  if has_header "Referrer-Policy"; then
    local rp; rp=$(get_header "Referrer-Policy")
    case "${rp,,}" in
      no-referrer|strict-origin|strict-origin-when-cross-origin|no-referrer-when-downgrade)
        finding OK "Referrer-Policy: ${rp}" ;;
      unsafe-url|origin)
        finding LOW "Referrer-Policy leaks full URL: ${rp}" ;;
      *)
        finding INFO "Referrer-Policy: ${rp}" ;;
    esac
  else
    finding LOW "Referrer-Policy MISSING" \
      "Add: Referrer-Policy: strict-origin-when-cross-origin"
  fi

  # ── Permissions-Policy ─────────────────────────────────────────
  if has_header "Permissions-Policy"; then
    finding OK "Permissions-Policy present"
  else
    finding LOW "Permissions-Policy MISSING" \
      "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"
  fi

  # ── X-XSS-Protection (deprecated but still checked) ───────────
  if has_header "X-XSS-Protection"; then
    local xxp; xxp=$(get_header "X-XSS-Protection")
    [[ "$xxp" == "0" ]] \
      && finding OK "X-XSS-Protection: 0 (correctly disabled — use CSP instead)" \
      || finding LOW "X-XSS-Protection: ${xxp} — this header is deprecated, set to 0"
  else
    finding INFO "X-XSS-Protection absent (modern approach — ensure CSP is set)"
  fi

  # ── Cross-Origin-Opener-Policy ─────────────────────────────────
  if has_header "Cross-Origin-Opener-Policy"; then
    finding OK "Cross-Origin-Opener-Policy: $(get_header "Cross-Origin-Opener-Policy")"
  else
    finding LOW "Cross-Origin-Opener-Policy MISSING" \
      "Add: Cross-Origin-Opener-Policy: same-origin"
  fi

  # ── Cross-Origin-Resource-Policy ──────────────────────────────
  if has_header "Cross-Origin-Resource-Policy"; then
    finding OK "Cross-Origin-Resource-Policy: $(get_header "Cross-Origin-Resource-Policy")"
  else
    finding LOW "Cross-Origin-Resource-Policy MISSING" \
      "Add: Cross-Origin-Resource-Policy: same-origin"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 3 — INFORMATION DISCLOSURE
# ─────────────────────────────────────────────────────────────────────────────
module_disclosure() {
  section "INFORMATION DISCLOSURE"

  # ── Server header ──────────────────────────────────────────────
  if has_header "Server"; then
    local srv; srv=$(get_header "Server")
    # Check if it reveals version info
    if echo "$srv" | grep -qiP '[\d]+\.[\d]+|nginx/|apache/|iis/|express|php|python|ruby|jetty|tomcat'; then
      finding HIGH "Server header exposes version info" \
        "Value: ${srv} — remove or genericize"
    else
      finding LOW "Server header present (no version)" \
        "Value: ${srv} — consider removing entirely"
    fi
  else
    finding OK "Server header absent or genericized"
  fi

  # ── X-Powered-By ───────────────────────────────────────────────
  if has_header "X-Powered-By"; then
    local xpb; xpb=$(get_header "X-Powered-By")
    finding HIGH "X-Powered-By exposed" \
      "Value: ${xpb} — remove this header entirely"
  else
    finding OK "X-Powered-By absent"
  fi

  # ── X-AspNet-Version / X-AspNetMvc-Version ─────────────────────
  if has_header "X-AspNet-Version"; then
    finding HIGH "X-AspNet-Version exposed" \
      "$(get_header "X-AspNet-Version") — add <customHeaders> to remove"
  fi
  if has_header "X-AspNetMvc-Version"; then
    finding HIGH "X-AspNetMvc-Version exposed" \
      "$(get_header "X-AspNetMvc-Version")"
  fi

  # ── X-Generator / X-Drupal-Cache / X-WordPress ─────────────────
  for hdr in "X-Generator" "X-Drupal-Cache" "X-WP-Nonce" "X-Pingback"; do
    if has_header "$hdr"; then
      finding MEDIUM "${hdr} header leaks CMS info" \
        "Value: $(get_header "$hdr")"
    fi
  done

  # ── Via / X-Cache (proxy disclosure) ───────────────────────────
  if has_header "Via"; then
    finding INFO "Via header present (proxy/CDN info)" \
      "$(get_header "Via")"
  fi

  # ── Access-Control-Allow-Origin ────────────────────────────────
  if has_header "Access-Control-Allow-Origin"; then
    local acao; acao=$(get_header "Access-Control-Allow-Origin")
    if [[ "$acao" == "*" ]]; then
      finding HIGH "CORS: Access-Control-Allow-Origin: * (open to all origins)" \
        "Restrict to specific trusted origins"
    else
      finding OK "CORS: Access-Control-Allow-Origin restricted" "$acao"
    fi
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 4 — COOKIES
# ─────────────────────────────────────────────────────────────────────────────
module_cookies() {
  section "COOKIES"

  local cookies=()
  while IFS= read -r line; do
    [[ "${line,,}" =~ ^set-cookie: ]] && cookies+=("$line")
  done < "$HEADERS_FILE"

  if [[ ${#cookies[@]} -eq 0 ]]; then
    finding INFO "No Set-Cookie headers found"
    return
  fi

  finding INFO "${#cookies[@]} cookie(s) found"
  echo ""

  local idx=0
  for cookie in "${cookies[@]}"; do
    idx=$((idx+1))
    local raw; raw=$(echo "$cookie" | cut -d: -f2- | sed 's/^ *//' | tr -d '\r')
    local name; name=$(echo "$raw" | cut -d= -f1 | cut -d';' -f1)
    local cookie_lower; cookie_lower="${raw,,}"

    echo -e "  ${DIM}Cookie ${idx}: ${W}${name}${N}"

    # Secure flag
    if echo "$cookie_lower" | grep -q "; *secure"; then
      echo -e "    ${G}✓${N} Secure flag set"
    else
      finding HIGH "Cookie '${name}' missing Secure flag" \
        "Add; Secure to Set-Cookie"
      SCORE=$((SCORE + 15)) # avoid double-counting from finding()
      SCORE=$((SCORE - 15))
    fi

    # HttpOnly
    if echo "$cookie_lower" | grep -q "; *httponly"; then
      echo -e "    ${G}✓${N} HttpOnly flag set"
    else
      finding HIGH "Cookie '${name}' missing HttpOnly flag" \
        "Prevents JavaScript from accessing the cookie"
      SCORE=$((SCORE + 15))
      SCORE=$((SCORE - 15))
    fi

    # SameSite
    if echo "$cookie_lower" | grep -qP "; *samesite=(strict|lax|none)"; then
      local ss; ss=$(echo "$cookie_lower" | grep -oP "samesite=\K[^;]+" | head -1)
      if [[ "$ss" == "none" ]]; then
        finding MEDIUM "Cookie '${name}' SameSite=None (CSRF risk if not Secure)" ""
      else
        echo -e "    ${G}✓${N} SameSite=${ss}"
      fi
    else
      finding MEDIUM "Cookie '${name}' missing SameSite attribute" \
        "Add; SameSite=Strict or SameSite=Lax"
      SCORE=$((SCORE + 8))
      SCORE=$((SCORE - 8))
    fi

    # Expiry — session vs persistent
    if echo "$cookie_lower" | grep -qP "; *(expires|max-age)"; then
      echo -e "    ${DIM}→ Persistent cookie (has expiry)${N}"
    else
      echo -e "    ${DIM}→ Session cookie (no expiry)${N}"
    fi

    echo ""
  done
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 5 — TLS / SSL
# ─────────────────────────────────────────────────────────────────────────────
module_tls() {
  section "TLS / SSL"

  CERT_FILE=$(mktemp /tmp/webcheck_cert_XXXXXX.txt)

  # Fetch cert info
  echo | timeout "$TIMEOUT" openssl s_client \
    -connect "${TARGET}:443" \
    -servername "$TARGET" \
    2>/dev/null > "$CERT_FILE" || true

  if [[ ! -s "$CERT_FILE" ]]; then
    finding CRITICAL "No TLS certificate found on port 443" \
      "HTTPS is not configured"
    rm -f "$CERT_FILE"
    return
  fi

  # ── Certificate validity ────────────────────────────────────────
  local cert_text
  cert_text=$(echo | timeout "$TIMEOUT" openssl s_client \
    -connect "${TARGET}:443" \
    -servername "$TARGET" 2>/dev/null \
    | openssl x509 -noout -text 2>/dev/null) || true

  if [[ -n "$cert_text" ]]; then
    # Subject & Issuer
    local subject; subject=$(echo "$cert_text" | grep "Subject:" | head -1 | sed 's/.*Subject: //')
    local issuer;  issuer=$(echo "$cert_text"  | grep "Issuer:"  | head -1 | sed 's/.*Issuer: //')
    local expiry;  expiry=$(echo "$cert_text"  | grep "Not After" | head -1 | sed 's/.*Not After : //')

    finding INFO "Subject : ${subject}"
    finding INFO "Issuer  : ${issuer}"

    # SANs
    local sans; sans=$(echo "$cert_text" | grep -A2 "Subject Alternative Name" | tail -1 | sed 's/^[[:space:]]*//')
    [[ -n "$sans" ]] && finding INFO "SANs    : ${sans}"

    # Expiry countdown
    if [[ -n "$expiry" ]]; then
      local exp_epoch; exp_epoch=$(date -d "$expiry" +%s 2>/dev/null || echo "0")
      if [[ $exp_epoch -gt 0 ]]; then
        local now_epoch; now_epoch=$(date +%s)
        local days=$(( (exp_epoch - now_epoch) / 86400 ))
        if   [[ $days -lt 0 ]];   then finding CRITICAL "Certificate EXPIRED ${days#-} days ago"
        elif [[ $days -lt 7 ]];   then finding CRITICAL "Certificate expires in ${days} days!"
        elif [[ $days -lt 30 ]];  then finding HIGH    "Certificate expires in ${days} days"
        elif [[ $days -lt 90 ]];  then finding MEDIUM  "Certificate expires in ${days} days"
        else                           finding OK      "Certificate valid for ${days} more days"
        fi
      fi
    fi

    # Self-signed check
    if [[ "$subject" == "$issuer" ]]; then
      finding HIGH "Self-signed certificate detected" \
        "Browsers will show security warnings"
    fi
  fi

  # ── TLS version support ─────────────────────────────────────────
  echo ""
  echo -e "  ${DIM}Checking TLS protocol versions...${N}"

  # Weak protocols
  for proto in "-ssl2" "-ssl3" "-tls1" "-tls1_1"; do
    local label="${proto#-}"
    local result
    result=$(echo | timeout 5 openssl s_client \
      -connect "${TARGET}:443" \
      -servername "$TARGET" \
      "${proto}" 2>&1 | grep -c "^CONNECTED" || true)
    if [[ "$result" -gt 0 ]]; then
      finding CRITICAL "Weak protocol supported: ${label^^}" \
        "Disable ${label} in your server TLS configuration"
    fi
  done

  # TLS 1.2
  local tls12
  tls12=$(echo | timeout 5 openssl s_client \
    -connect "${TARGET}:443" \
    -servername "$TARGET" \
    -tls1_2 2>&1 | grep -c "^CONNECTED" || true)
  [[ "$tls12" -gt 0 ]] \
    && finding OK "TLS 1.2 supported" \
    || finding MEDIUM "TLS 1.2 not supported"

  # TLS 1.3
  local tls13
  tls13=$(echo | timeout 5 openssl s_client \
    -connect "${TARGET}:443" \
    -servername "$TARGET" \
    -tls1_3 2>&1 | grep -c "^CONNECTED" || true)
  [[ "$tls13" -gt 0 ]] \
    && finding OK "TLS 1.3 supported" \
    || finding LOW "TLS 1.3 not supported (recommended)"

  # ── Cipher check — look for weak ciphers ───────────────────────
  local cipher
  cipher=$(echo | timeout "$TIMEOUT" openssl s_client \
    -connect "${TARGET}:443" \
    -servername "$TARGET" 2>/dev/null \
    | grep "^Cipher" | awk '{print $3}')

  if [[ -n "$cipher" ]]; then
    if echo "$cipher" | grep -qiP 'RC4|DES|NULL|EXPORT|anon|MD5'; then
      finding CRITICAL "Weak cipher in use: ${cipher}" \
        "Disable RC4, DES, NULL, EXPORT and anonymous ciphers"
    else
      finding OK "Active cipher: ${cipher}"
    fi
  fi

  # ── HSTS preload check (redundant with headers but reported here) ──
  local hsts_val; hsts_val=$(get_header "Strict-Transport-Security")
  if echo "$hsts_val" | grep -qi "preload"; then
    finding OK "HSTS preload directive present"
  else
    finding LOW "HSTS preload directive missing" \
      "Add 'preload' to enable browser preload list"
  fi

  rm -f "$CERT_FILE"
}

# ─────────────────────────────────────────────────────────────────────────────
# SCORE RENDERER
# ─────────────────────────────────────────────────────────────────────────────
render_score() {
  # Clamp score
  [[ $SCORE -lt 0 ]]   && SCORE=0
  [[ $SCORE -gt 100 ]] && SCORE=100

  local grade color bar_char bar=""
  local filled=$(( SCORE * 40 / 100 ))

  if   [[ $SCORE -ge 90 ]]; then grade="A+"; color="$G"
  elif [[ $SCORE -ge 80 ]]; then grade="A";  color="$G"
  elif [[ $SCORE -ge 70 ]]; then grade="B";  color="$C"
  elif [[ $SCORE -ge 60 ]]; then grade="C";  color="$Y"
  elif [[ $SCORE -ge 50 ]]; then grade="D";  color="$Y"
  else                            grade="F";  color="$R"
  fi

  for ((i=0; i<filled; i++));      do bar+="█"; done
  for ((i=filled; i<40; i++));     do bar+="░"; done

  echo ""
  sep
  echo -e "  ${W}${BOLD}SECURITY SCORE${N}"
  sep_thin
  printf "  ${color}[%s]${N}  %s  ${W}${BOLD}%d/100${N}  ${DIM}Grade: ${N}${color}${BOLD}%s${N}\n" \
    "$bar" "" "$SCORE" "$grade"
  echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# FINDINGS SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
render_summary() {
  local end_time; end_time=$(date +%s)
  local elapsed=$(( end_time - START_TIME ))

  local n_critical=0 n_high=0 n_medium=0 n_low=0 n_ok=0

  for f in "${FINDINGS[@]}"; do
    case "${f%%|*}" in
      CRITICAL) n_critical=$((n_critical+1)) ;;
      HIGH)     n_high=$((n_high+1))         ;;
      MEDIUM)   n_medium=$((n_medium+1))     ;;
      LOW)      n_low=$((n_low+1))           ;;
      OK)       n_ok=$((n_ok+1))             ;;
    esac
  done

  echo -e "  ${W}FINDINGS SUMMARY${N}"
  sep_thin
  printf "  ${R}%-12s${N}  %d\n"  "CRITICAL"  "$n_critical"
  printf "  ${R}%-12s${N}  %d\n"  "HIGH"      "$n_high"
  printf "  ${Y}%-12s${N}  %d\n"  "MEDIUM"    "$n_medium"
  printf "  ${B}%-12s${N}  %d\n"  "LOW"       "$n_low"
  printf "  ${G}%-12s${N}  %d\n"  "PASSED"    "$n_ok"
  sep_thin
  printf "  ${DIM}%-12s  %ds${N}\n" "Duration" "$elapsed"
  printf "  ${DIM}%-12s  %s${N}\n"  "Target"   "$TARGET_URL"
  sep
  echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# CLEANUP
# ─────────────────────────────────────────────────────────────────────────────
cleanup() {
  rm -f "$HEADERS_FILE" "$CERT_FILE" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ─────────────────────────────────────────────────────────────────────────────
# USAGE
# ─────────────────────────────────────────────────────────────────────────────
usage() {
  echo -e "${W}Usage:${N} $0 <target> [options]"
  echo ""
  echo -e "${W}Target:${N}"
  echo -e "  example.com"
  echo -e "  https://example.com"
  echo -e "  http://192.168.1.1"
  echo ""
  echo -e "${W}Options:${N}"
  echo -e "  -h, --help     Show this help"
  echo -e "  -v, --version  Show version"
  echo ""
  echo -e "${W}Examples:${N}"
  echo -e "  $0 example.com"
  echo -e "  $0 https://target.com"
  echo ""
  echo -e "${R}  Authorized targets only.${N}"
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
main() {
  banner
  check_deps

  # Parse args
  case "${1:-}" in
    -h|--help)    usage; exit 0 ;;
    -v|--version) echo "webcheck v${VERSION}"; exit 0 ;;
    "")           usage; exit 1 ;;
    *)            normalize_target "$1" ;;
  esac

  echo -e "  ${INF} Target  : ${W}${TARGET_URL}${N}"
  echo -e "  ${INF} Timeout : ${W}${TIMEOUT}s${N}"
  echo ""

  # Fetch headers once — all modules reuse the same file
  echo -e "  ${DIM}Fetching headers...${N}"
  fetch_headers

  local status; status=$(get_status)
  echo -e "  ${INF} Status  : ${W}${status}${N}"

  # Run all modules
  module_redirect
  module_security_headers
  module_disclosure
  module_cookies
  module_tls

  # Report
  render_score
  render_summary
}

main "$@"
