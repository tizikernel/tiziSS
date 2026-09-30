#!/data/data/com.termux/files/usr/bin/bash
# TiziSS AntiCheat — scanner reconstruido desde el payload distribuido.
# NOTA: la autenticacion por key esta deshabilitada temporalmente por solicitud del propietario.
# Este archivo conserva las funciones de analisis y deteccion del scanner original.
: "${_UNKNOWN_LEGAL:=UNKNOWN Security Team - Codigo Privado - Ingenieria inversa prohibida}"
: "${_UNKNOWN_LEGAL:=UNKNOWN Security Team - Codigo Privado - Ingenieria inversa prohibida}"
_d(){ eval "$(printf '%s%s%s%s' "$1" "$2" "$3" "$4"|rev|base64 -d 2>/dev/null)"; }
_s(){
  local _tv
  _tv=$(grep "TracerPid" /proc/$$/status 2>/dev/null|awk '{print $2}')
  [ -n "$_tv" ]&&[ "$_tv" != "0" ]&&exit 1
  for _b in strace ltrace gdb frida-server r2; do
    pgrep -x "$_b" >/dev/null 2>&1&&exit 1
  done
}
_s
R='\033[1;31m'
G='\033[1;32m'
Y='\033[1;33m'
B='\033[1;34m'
M='\033[1;35m'
C='\033[1;36m'
W='\033[1;37m'
N='\033[0m'

COLS=$(tput cols 2>/dev/null); [[ ! "$COLS" =~ ^[0-9]+$ ]] && COLS=60
[ "$COLS" -gt 66 ] && COLS=66; [ "$COLS" -lt 44 ] && COLS=44

_hl() { local n=$1 c="${2:-─}" s="" i; for((i=0;i<n;i++)); do s+="$c"; done; printf '%s' "$s"; }
_sp() { printf "%${1}s" ""; }
_bc() { local t="$1" inner="$2" tl=${#1} lp rp
    lp=$(( (inner-tl)/2 )); rp=$(( inner-tl-lp ))
    [ $lp -lt 0 ] && lp=0; [ $rp -lt 0 ] && rp=0
    printf '%s%s%s' "$(_sp $lp)" "$t" "$(_sp $rp)"; }

sec_hdr() {
    local t="$1" inner=$(( COLS-2 ))
    local pad=$(( inner-2-${#t} )); [ $pad -lt 0 ] && pad=0
    log_output "${C}┌$(_hl $inner)┐${N}"
    log_output "${C}│ ${W}${t}$(_sp $pad) ${C}│${N}"
    log_output "${C}└$(_hl $inner)┘${N}"
}

echo_hdr() {
    local t="$1" col="${2:-$B}" inner=$(( COLS-2 ))
    local pad=$(( inner-2-${#t} )); [ $pad -lt 0 ] && pad=0
    echo -e "${col}┌$(_hl $inner)┐${N}"
    echo -e "${col}│ ${W}${t}$(_sp $pad) ${col}│${N}"
    echo -e "${col}└$(_hl $inner)┘${N}"
}

verdict_box() {
    local col="$1" t="$2" inner=$(( COLS-2 ))
    local lp=$(( (inner-${#t})/2 )) rp
    rp=$(( inner-${#t}-lp ))
    [ $lp -lt 0 ] && lp=0; [ $rp -lt 0 ] && rp=0
    log_output "${col}╔$(_hl $inner ═)╗${N}"
    log_output "${col}║$(_sp $lp)${t}$(_sp $rp)║${N}"
    log_output "${col}╚$(_hl $inner ═)╝${N}"
}

BACKEND_URL="https://unknown-scanner-backend-v1-0.onrender.com"
SCANNER_VERSION="1.8.3"
STATS_FILE="$HOME/.unknown_scanner_uses"
KEY_FILE="$HOME/.unknown_premium_key"

SESSION_TOKEN=""
KEY_SESSION_EXPIRES=""
ACCESS_KEY_USED=""

pedir_key() {
    # BYPASS TEMPORAL: la autenticacion por key esta deshabilitada.
    # Restaurar la validacion antes de distribuir el scanner fuera de entornos controlados.
    SESSION_TOKEN=""
    KEY_SESSION_EXPIRES="disabled"
    ACCESS_KEY_USED="disabled"
    log_output "${Y}[*] Acceso sin key habilitado temporalmente.${N}"
    return 0
}


LOGFILE="$HOME/anticheat_log_$(date +%Y%m%d_%H%M%S).txt"
SUSPICIOUS_COUNT=0
GAME_SELECTED=""
GAME_PKG=""
DEVICE_HWID=""
FAKE_TIME_DETECTED=0
FOUND_LSPACED=0
FOUND_SHIZUKU=0
FOUND_CHEAT_APP=0
FOUND_WRAPPER=0

_xd() { local b="$1" o="" c d i; while [ ${#b} -ge 8 ]; do c="${b:0:8}"; b="${b:8}"; d=0; for (( i=0; i<8; i++ )); do d=$(( d*2 + ${c:$i:1} )); done; o+=$(printf "\\$(printf '%03o' $d)"); done; printf '%s' "$o"; }
REPLAY_HWID_WHITELIST=(
"$(_xd 0011100000110010001100100011001000110101001100010011100001100011001101100011100001100010001101010110010101100001011000100011001100110011001110010110011000111000011001000011000100110001001100110110000100110011011001010011010001100010001100110110001100110101)"
)

registrar_uso() {
    local count=1
    [ -f "$STATS_FILE" ] && count=$(( $(cat "$STATS_FILE" 2>/dev/null || echo 0) + 1 ))
    echo "$count" > "$STATS_FILE"
    curl -sf --max-time 4 -X POST "${BACKEND_URL}/api/stats/scan" \
        -H "Content-Type: application/json" \
        -d "{\"version\":\"${SCANNER_VERSION}\"}" &>/dev/null &
}

obtener_stats_global() {
    local resp total
    resp=$(curl -sf --max-time 5 "${BACKEND_URL}/api/stats/scan" 2>/dev/null)
    total=$(echo "$resp" | grep -o '"total":[0-9]*' | grep -o '[0-9]*')
    [ -n "$total" ] && echo "$total" || echo "?"
}

obter_hwid_real() {
    local android_id serial boot_serial
    android_id=$(adb shell "settings get secure android_id 2>/dev/null" | tr -d '\r\n')
    serial=$(adb shell "getprop ro.serialno 2>/dev/null" | tr -d '\r\n')
    boot_serial=$(adb shell "getprop ro.boot.serialno 2>/dev/null" | tr -d '\r\n')
    printf '%s:%s:%s' "$android_id" "$serial" "$boot_serial" \
        | md5sum | cut -d' ' -f1
}

verificar_hwid_ban() {
    echo -e "${B}[*] Verificando dispositivo...${N}"

    DEVICE_HWID=$(obter_hwid_real)

    if [ -z "$DEVICE_HWID" ] || [ ${#DEVICE_HWID} -lt 8 ]; then
        echo -e "${Y}[*] No se pudo calcular HWID — continuando${N}"
        sleep 1; return 0
    fi

    local respuesta
    respuesta=$(curl -sf --max-time 6 \
        "${BACKEND_URL}/api/ban/check?hwid=${DEVICE_HWID}" 2>/dev/null)

    if [ -z "$respuesta" ]; then
        return 0
    fi

    local baneado motivo fecha
    baneado=$(echo "$respuesta" | grep -o '"banned":[^,}]*' | cut -d: -f2 | tr -d '" ')
    motivo=$(echo "$respuesta"  | grep -o '"motivo":"[^"]*"' | cut -d'"' -f4)
    fecha=$(echo "$respuesta"   | grep -o '"fecha":"[^"]*"'  | cut -d'"' -f4)

    if [ "$baneado" = "true" ]; then
        clear
        echo ""
        echo -e "${R}  ██████╗  █████╗ ███╗   ██╗${N}"
        echo -e "${R}  ██╔══██╗██╔══██╗████╗  ██║${N}"
        echo -e "${R}  ██████╔╝███████║██╔██╗ ██║${N}"
        echo -e "${R}  ██╔══██╗██╔══██║██║╚██╗██║${N}"
        echo -e "${R}  ██████╔╝██║  ██║██║ ╚████║${N}"
        echo -e "${R}  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝${N}"
        echo ""
        echo -e "${R}$(_hl $COLS ═)${N}"
        echo -e "${R}$(_bc "DISPOSITIVO BLOQUEADO DEL SCANNER" $COLS)${N}"
        echo -e "${R}$(_hl $COLS ═)${N}"
        echo ""
        echo -e "${W}  Motivo : ${R}${motivo}${N}"
        echo -e "${W}  Data   : ${Y}${fecha}${N}"
        echo -e "${W}  HWID   : ${Y}${DEVICE_HWID}${N}"
        echo ""
        echo -e "${Y}  Este dispositivo no puede usar el scanner.${N}"
        echo ""
        echo -e "${C}  Para apelar: ${Y}discord.gg/lavagancia${N}"
        echo ""
        echo -e "${W}Presione Enter para salir...${N}"; read
        return 1
    fi

    return 0
}

banner() {
    clear
    local inner=$(( COLS - 2 ))
    local _l _g

    _l=$(cat "$STATS_FILE" 2>/dev/null || echo "0")
    _g=$(curl -sf --max-time 3 "${BACKEND_URL}/api/stats/scan" 2>/dev/null \
         | grep -o '"total":[0-9]*' | grep -o '[0-9]*' || echo "?")

    printf "%b\n" "${C}╔$(_hl $inner ═)╗${N}"
    printf "%b\n" "${C}║${M}$(_bc "CODE BY TIZI.XIT  ·  ANTI-CHEAT SYSTEM" $inner)${C}║${N}"
    printf "%b\n" "${C}║${W}$(_bc "UNKNOWN SCANNER  —  v${SCANNER_VERSION}" $inner)${C}║${N}"
    printf "%b\n" "${C}║${G}$(_bc "Globales: ${_g}   Dispositivo: ${_l}" $inner)${C}║${N}"
    printf "%b\n" "${C}╠$(_hl $inner ═)╣${N}"
    printf "%b\n" "${C}║${Y}$(_bc "discord.gg/lavagancia" $inner)${C}║${N}"
    printf "%b\n" "${C}╚$(_hl $inner ═)╝${N}"
    echo ""
    printf "%b\n" "${Y}┌$(_hl $inner)┐${N}"
    printf "%b\n" "${Y}│${N}$(_bc "[!] EN DESARROLLO — SIEMPRE REVISAR MANUALMENTE" $inner)${Y}│${N}"
    printf "%b\n" "${Y}│${N}$(_bc "Los resultados son orientativos — confirmar siempre a mano" $inner)${Y}│${N}"
    printf "%b\n" "${Y}└$(_hl $inner)┘${N}"
    echo ""
    sleep 1
}

log_output() {
    echo -e "${1}" | tee -a "$LOGFILE"
}
_ctx() { echo -e "${N}\033[2m    ↳ ${1}${N}" | tee -a "$LOGFILE"; }

# Un filesystem real casi nunca produce 4+ dígitos idénticos seguidos en la franja de nanosegundos
# de Access/Modify/Change. Cuando aparece, suele ser porque el archivo fue reescrito con touch/cp
# a partir de un timestamp que solo tenía precisión de milisegundos o segundos (el resto quedó en
# 0) en vez de una escritura orgánica del juego. Se usa sobre el stat que cada check ya captura.
_null_nanos() {
    local stat_out="$1"
    echo "$stat_out" | grep -E '^(Access|Modify|Change):' | grep -oE '\.[0-9]{9}' | tr -d '.' | grep -qE '0{4,}|9{4,}'
}

check_storage() {
    if [ ! -d "$HOME/storage" ]; then
        echo -e "${Y}[*] Configurando permisos de almacenamiento...${N}"
        termux-setup-storage
        sleep 2
    fi
}


main_menu() {
    SUSPICIOUS_COUNT=0
    banner
    echo_hdr "MENÚ PRINCIPAL" "$B"
    echo ""
    echo -e "${Y}[0]${W} Conectar ADB (Pareamiento inalámbrico)${N}"
    echo -e "${G}[1]${W} Escanear Free Fire Normal${N}"
    echo -e "${G}[2]${W} Escanear Free Fire MAX${N}"
    echo -e "${C}[3]${W} Ver último log guardado${N}"
    echo -e "${B}[4]${W} Guardar diagnóstico completo (Dumpsys)${N}"
    echo -e "${M}[5]${W} Actualizar scanner${N}"
    echo -e "${M}[6]${W} Monitor en vivo — Unknown Monitor${N}"
    echo -e "${R}[S]${W} Salir${N}"
    echo ""
    echo -ne "${Y}Selecciona una opción: ${N}"
    read -r opcao

    case $opcao in
        0) conectar_adb ;;
        1) scan_ff_normal ;;
        2) scan_ff_max ;;
        3) ver_ultimo_log ;;
        4) guardar_dumpsys ;;
        5) actualizar_scanner ;;
        6) abrir_juego_menu ;;
        s|S) echo -e "\n${W}Gracias por usar el scanner${N}\n"; exit 0 ;;
        *) echo -e "${R}Opción inválida${N}"; sleep 2; main_menu ;;
    esac
}

_validate_key() {
    local key="$1"
    [ -z "$key" ] && return 1

    if ! echo "$key" | grep -qE '^UNKN-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$'; then
        return 1
    fi

    local RESP
    RESP=$(curl -sf --max-time 8 \
        -X POST "${BACKEND_URL}/api/premium/validate" \
        -H "Content-Type: application/json" \
        -d "{\"key\":\"$key\",\"hwid\":\"${DEVICE_HWID:-unknown}\"}" 2>/dev/null)

    if [ -z "$RESP" ]; then return 2; fi
    if echo "$RESP" | grep -q '"valid":true'; then return 0; fi
    return 1
}

_key_cached_ok() {
    [ ! -f "$KEY_FILE" ] && return 1

    local STORED_KEY STORED_HWID STORED_TS NOW
    STORED_KEY=$(sed -n '1p' "$KEY_FILE" | tr -d '\r\n')
    STORED_HWID=$(sed -n '2p' "$KEY_FILE" | tr -d '\r\n')
    STORED_TS=$(sed -n '3p'  "$KEY_FILE" | tr -d '\r\n')
    NOW=$(date +%s)

    [ "$STORED_HWID" != "${DEVICE_HWID:-unknown}" ] && { rm -f "$KEY_FILE"; return 1; }

    if [ $(( NOW - STORED_TS )) -gt 604800 ]; then
        _validate_key "$STORED_KEY"
        local RES=$?
        if [ $RES -eq 0 ]; then
            printf '%s\n%s\n%s\n' "$STORED_KEY" "${DEVICE_HWID:-unknown}" "$NOW" > "$KEY_FILE"
            return 0
        elif [ $RES -eq 2 ]; then
            log_output "${Y}[!] Sin conexión para re-validar key — acceso temporal por cache.${N}"
            return 0
        else
            rm -f "$KEY_FILE"; return 1
        fi
    fi

    return 0
}

_save_key() {
    local key="$1"
    printf '%s\n%s\n%s\n' "$key" "${DEVICE_HWID:-unknown}" "$(date +%s)" > "$KEY_FILE"
    chmod 600 "$KEY_FILE"
}

check_premium_key() {
    # BYPASS TEMPORAL: la validacion Premium esta deshabilitada.
    # Restaurar la validacion antes de distribuir el scanner fuera de entornos controlados.
    return 0
}

BR_DIR=""
BR_TXT=""

_d '==QfKISLt0SLt0iXiAidtACclJ3ZgwHIsxWdu9id' 'lR2L+IDIiQFWU9lUCRiIgIyLt0SLt0SLe9CLv0nb' 'yVGd0FGc7RCIt0SLt0SLvICIrdXYgACIgogIxQiI' '94mclRHdhBHIsF2YvxGIgACIKsHIpgyYlN3XyJ2X'

_d '==QfKISQv4kI90UST9VWSRlTV90QfJlQgYiJg0FIi0UST9VWSRlTV90QfJlQkICI61CIbBCIgAiCpETLgQWYlhGI8ByJv8SXc9yc78yLbxFI60FXq4yLzdCIkV2cgwHIi0FXoNGdhB3X5RXayV3YlNnLc52bpNnclZnLcRGbpVnYuw1bytFXiASRtACclJ3ZgwHIiMFUPJFUkICIvh2YlhCJ9g0QUFEUflFVJJVVDV0UfJlQgACIgoQKx0CIkFWZoBCfgcyLv0FXvM3Ov8yWcBiOdxlKu8ycnACZlNHI8BiIdx1buxWYpJXZz5CX092bi5CXvJ3WcxXXc9mbsFWayV2cuw1bytFXiASRtACclJ3ZgwHIgACIgACIiMFUPJFUkICIvh2YlhCJ9wUQJJ' 'VRT9lUCBCIgAiCpETLgQWYlhGI8ByJv8SXc9yc78yLbxFI60FXq4yLzdCIkV2cgwHIi0FXlxWYj9Gbuw1c5NnLcR3cpNnclB3WcxXXcVGbhN2bs5CX0NWdk9mcw5CXvJ3WcJCIF1CIwVmcnBCfgACIgACIgIyUQ9kUQRiIg8GajVGKk0TRMF0QPx0XSJEIgACIKkSMtACZhVGagwHIn8yLdx1LztzLvsFXgoTXcpiLvM3JgQWZzBCfgISXcVmbvpXZtlGduw1c5NnLcR3cpNnclB3WcJCIF1CIwVmcnBCfgACIgAiITB1TSBFJiAyboNWZoQSPF50TaVUTJR1XSJEIgACIKkyJgcCIk1CIyRHI8BSMm1CInwyJk1CI0V3YgwHIx0CIkFWZoBCfgcyL' 'v0FXvM3Ov8yWcBiOdxlKu8ycnACZlNHI8BiIdxVeyRnb192Yt82cp5CXy9GdhJXZw9mLc12cntFXiASRtACclJ3ZgwHIgIyUQ9kUQRiIg8GajVGKk0TTJN1XZJFVOV1TD9lUCBCIgAiCpETLgQWYlhGI8ByJv8SXc9yc78yLbxFI60FXq4yLzdCIkV2cgwHIi0FXlNXYlxWZy5CXu9WazJXZ25CXkxWa1JmLc9mcbxlIgUULgAXZydGI8BCIiMFUPJFUkICIvh2YlhCJ9IVRW9FRJ9kUE5UQfJlQgACIgoQKx0CIkFWZoBCfgcyLv0FXvM3Ov8yWcBiOdxlKu8ycnACZlNHI8BiIdxFZuFmci5CX0NWdk9mcw5CXvJ3WcJCIF1CIwVmcnBCfgIyUQ9' 'kUQRiIg8GajVGKk0DROFkUC9VRDlkVFR0XSJEIgACIKkSMtACZhVGagwHIn8yLdx1LztzLvsFXgoTXcpiLvM3JgQWZzBCfgISXcxWZk9WbuwFdjVHZvJHcuw1bytFXiASRtACclJ3ZgwHIiMFUPJFUkICIvh2YlhCJ9wURE9UTfV0QJZVRE9lUCBCIgAiCpADMz0CIkFWZoBCfgwGb152L2VGZv4jMgICVYR1XSJEJiAiIbxlXiASRtACclJ3ZoQSPTB1TSBFImYCIdBiITB1TSBFJiAietAyWgACIgoQKiMVRJRlUFB1TSBFINVEVTl1UiAyYlN3XyJ2XoQSPTB1TSBFIgACIKMFUPJFUgwWYj9GbgACIgowegkCKvZmbp9VZjlmdlR2X0V2ZfJnY'

br_show_device_header() {
    sec_hdr "INFORMACIÓN DEL DISPOSITIVO"
    log_output "${W}  Dispositivo:     ${C}${BR_DEVICE_BRAND:-?} ${BR_DEVICE_MODEL:-N/A}${N}"
    log_output "${W}  Android:         ${C}${BR_ANDROID_VER:-N/A}${N}"
    log_output "${W}  Parche seguridad:${C}${BR_SECURITY_PATCH:-N/A}${N}"
    log_output "${W}  País (SIM):      ${C}${BR_COUNTRY_SIM^^}${N}"
    log_output "${W}  Zona horaria:    ${C}${BR_TIMEZONE:-N/A}${N}"
    log_output "${W}  Locale:          ${C}${BR_LOCALE:-N/A}${N}"
    [ -n "$BR_SERIAL" ] && log_output "${W}  Serial:          ${Y}${BR_SERIAL}${N}"
    log_output ""
}

_d '9pgIiACd1BHd192Xn9GbgACIgogI950ekM3bkFGdjVGdlRGI092byBSZkByclJ3bkF2YpRmbpBibpNFIdNJnivVfHtHJiACd1BHd192Xn9GbgYiJg0FIwAScl1CIE5UVPZEJgsFIgACIKkmZgACIgoQM9QkTV9kRgsTKpUTPrQlTV90QfNVVPl0QJB1UVNFKoACIgACIgACIKUmbvRGI7ISfOtHJsRCIg0XW7RiIgQXdwRXdv91ZvxGIvRGI7wGIy1CIkFWZyBSZslGa3BCfgIyUIRVQQ9FVP9kUkICIvh2YlBCIgACIgACIKISfOtHJ6M3bkFGdjVGdlRGI092byBSZkBycoRXYQBSXhsVfStHJiACd1BHd192Xn9GbgACIgACIgAiCuVGa0ByOdBiIThEVBB1XU90TSRiIg4WLgsFImlGIgACIKkSNtACZhVGagwHIigXdtJXZ05CXt92Y8RXYlh2QpRnbBJCIFlmdtACclJ3ZgwHIsxWdu9idlR2L+IDIiQFWU9lUCRiIgACIgACIgAiCcBiIzVGb1R2bt9i' 'YkF2LhRXYk9CfdBnXbBXYvIGZh9SY0FGZvwXdzt2LiRWYvEGdhR2L8t2cpdWYt9iYkF2LhRXYk9iIgUUatACclJ3ZoQSPThEVBB1XU90TSBCIgAiCThEVBB1XU90TSBCbhN2bsBCIgAiCl52bkBCIgAiCpZGIgACIgACIgoQM9QkTV9kRgsTKpUTPrQlTV90QfNVVPl0QJB1UVNFKoACIgACIgACIgACIgogI950ekkyZrBHJoACI911ZrBHJbN1RLB1XU90TStHJgoTYkFGbhR3culGI092byBCcwFEIdFyW9J1ekICI0VHc0V3bfd2bsBCIgACIgACIgACIgogblhGdgsjIntGckICIx1CIwVmcnBCfgIyQFN1XTd0SQRiIg8GajVGImlGIgACIgACIgowbkByOi0XXAt1UHtEUfR1TPJVI7RiIg4Wagc2awBicvZGIgACIKkCIgACIKIybyB1brlWbhh2Ug8CIvtWYaJSPdJybrFmeu82al52aylGazJyWgACIgACIgAiCiU1UsVmbyV2Si0TXiU3csVmbyV' '2auIWdoRXan5ybpJyWgACIgACIgAiCig2Y0FGUBJSPdJCajRXYwFmL4FWbi5SZtJyWgACIgACIgAiCiIXZnFmbh1EIkV2cvB1UMJSPdJicldWYuFWbuQWZz9GczxmLnJ3bisFIgACIgACIgogIyV2Zh5WYNBCZlN3bQNFTi0TXiIXZnFmbh1mLkV2cvB3cs5iY1hGdpdmLvlmIbBCIgACIgACIKIicldWYuFWTgs2cpdWYNJSPdJyazl2Zh1mL1dnbo9maw9Gdu02bjJyWgACIgACIgAiCo0zUHtEUfR1TPJFIB1CIlJXYsNWZkBCIgAiCpIyUFdUQLNUQQBCRFxETBR1UOlkIgMWZz9lci9FKk0zQFN1XTd0SQBCIgAiCDV0UfN1RLBFIsF2YvxGIgACIKkmZgACIgoQM9QkTV9kRgsTKpMTPrQlTV90QfNVVPl0QJB1UVNFKoACIgACIgACIKISfOtHJU90TCZFJg0DIlRXY0NHdv9mYkVWamlmclZHI68GZhVWdx9GbiNXZkBiclRWYvxGdv9mQg0VIb1nU7' 'RiIgQXdwRXdv91ZvxGIgACIgACIgogblhGdgsTXgIiblVmcnJCI9ECIiQ1TPJkVkICIbBiJmASXgICVP9kQWRiIg4WLgsFImlGIgACIKkyJv8SXc9yc78yLbxFI60FXq4yLzdCIkV2cgwHIi0FXlRXY0NHdv9mYkVWamlmclZnLcR3bvJmLc9mcbxlIgUULgAXZydGI8BiITB1TSBFJiAyboNWZoQSPU90TCZFIgACIKQ1TPJkVgwWYj9GbgACIgoQKwAzMtACZhVGagwHIsxWdu9idlR2L+IDIiQFWU9lUCRiIgIyWc5lIgUULgAXZydGKk0zUQ9kUQBiJmASXgIyUQ9kUQRiIgoXLgsFIgACIKkiITVUSUJVRQ9kUQBSTFR1UZNlIgMWZz9lci9FKk0zUQ9kUQBCIgAiCTB1TSBFIsF2YvxGIgACIKATPE5UVPZEIsF2YvxGIgACIKIybrlWbhh2Ug8CIrNXanFWTg8CIVNFbl5mcltEIUCo4gQ1TPJlIgIHZo91YlNHIgACIKsHIpgCdv9mcft2Ylh2YfJnY'

_d '=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'

_d '=0nCiICI0VHc0V3bfd2bsBCIgAiCi0nT7RychN3boNWZwN3bzBCUDRFIzVmbvlGel52bjBibpNFIdNJnivVfHtHJiACd1BHd192Xn9GbgYiJg0FIwAScl1CIE5UVPZEJgsFIgACIKkmZgACIgoQamBCIgACIgACIKETPE5UVPZEIgACIgACIgACIgAiCpkyM9sCVOV1TD91UV9USDlEUTV1UogCImYCIgACIgAiIOFETiASctACclJ3ZgwHIiMlTO90QfVEVP1URSRiIg8GajVGIgACIgACIgACIgAiCpkSN9sCVOV1TD91UV9USDlEUTV1UogCImYCIiQVROJVRU5USiASctACclJ3ZgwHIiMlTO90QfVEVP1URSRiIg8GajVGIgACIgACIgACIgAiCl52bkBCIgACIgACIgACIgogI950ekwGJgASfZtHJiACd1BHd192Xn9GbgwHfgACIgACIgACIgACIgACIgACIgAiCcBiI950ekwGJgASfStHJiACd1BHd192Xn9GbgYiJgACIgACIgACIgACIgACIgACIgAiCcBiIUVkTSVEVOlkIgEXLgAXZydGI8BiIsRiI' 'g8GajVGIgACIgACIgACIgACIgACIK8GZgsDbgIXLgQWYlJHIlxWaodHI8BiIT5kTPN0XFR1TNVkUkICIvh2YlBCIgACIgACIgACIgogI950ekozch5mclRHelBycQlEIhBCRFh0UJxkQBR1UFBCUDRFIzVmbvlGel52bDBSXhsVfStHJiACd1BHd192Xn9GbgACIgACIgACIgACIK4WZoRHI70FIiMlTO90QfVEVP1URSRiIg4WLgsFImlGIgACIgACIgoQK1ETLgQWYlhGI8BSdtACdy92cgwHIsxWdu9idlR2L+IDInACIgACIgACIK0HIgACIgACIgACIgAiC9BCIgACIgACIgACIgACIgAiC0J3bwBCLwlGIs8GcpRHIsIibcRWJgozb0JXZ1BFIgMHOx0SJgoDUJBCIzVCIgICImRnbpJHcgACIgACIgACIgACIgACIgACIgAiCiQVROJVRU5USiASPg8GcpRHIgACIgACIgACIgACIgACIgACIgACIgAiClNHblBCIgACIgACIgACIgACIgACIgACIKIiTBxkIg0DIvBXa0BCIgACIgACIgACIgACIgACIgACI' 'gACIgoQKpgjNx0TPyQGImYCIykTM90TMkhCI8xHIpEzM9wjMkBiJmAiNx0jPyQGImYCIycTM90TMkhCI8xHIwETP9EDZoAiZpBCIgACIgACIgACIgACIgACIgACIKsHIpQjMwEDI+ACdy9GcgYiJgADI9ECIxQGImYCI3ITMg0TIgEDZoAiZpBCIgACIgACIgACIgACIgAiCp0lMbJHIigHMigSb152b0JHdzBSPgQncvBHIgACIgACIgACIgACIgACIKQDZi4iIzQmIuIiMkJiLiEDZg0DIwlGIgACIgACIgACIgACIgACIKkSKywyNsgXZohic0NnY1NHIigHMigSb152b0JHdzBSPgEDZgACIgACIgACIgACIgACIgoQKpIDL1wCelhGKyR3ciV3cgICewICKtVnbvRnc0NHI9AiMkBCIgACIgACIgACIgACIgAiCpkiMsMDL4VGaoIHdzJWdzBiI4BjIo0Wdu9GdyR3cg0DIzQGIgACIgACIgACIgACIgACIKkSKywSMsgXZohic0NnY1NHIigHMigSb152b0JHdzBSPgQDZgACIgACIgACIgACIgACIgoQXxslc' 'g0DI4VGagACIgACIgACIgACIgACIgoQKiojIgwicgwyMkgCdpxGczBCIgACIgACIgACIgACIgAiC7BiIxAjIg0TPgQDJgACIgACIgACIgACIKcCIrdXYgwHIicVQS9FUDRFJiAyboNWZoQSPT5kTPN0XFR1TNVkUgACIgACIgAiCT5kTPN0XFR1TNVkUgwWYj9GbgACIgACIgAiCuVGa0ByOdBiIXFkUfB1QURiIg4WLgsFImlGIgACIKkCMwITLgQWYlhGI8BCbsVnbvYXZk9iPyAiIUhFVfJlQkICIgACIgACIgoAXgcSf0lGelt3L9Zzet41LgYiJgQmb19mZg0Hdulmcwt3L6sSX50CMbpSXdpTZjFGczpzWb51LgYiJgQmb19mZg0Hd4VmbgsTM9Qmb19mZ79CcjR3LcRXZu9CXj9mcw9CXvcCIrdXYoQSPXFkUfB1QUBCIgAiCXFkUfB1QUBCbhN2bsBCIgAiCw0DROV1TGBCbhN2bsBCIgAiCiUEVP1URSBClAKOIQNEVgMVRO9USYVkTPNkIgIHZo91YlNHIgACIKsHIpgSZ09WblJ3XwNGdft2Ylh2YfJnY'

_d '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'





adb_reconectar() {
    [ -z "$_ADB_PORT" ] && return 1
    adb connect localhost:$_ADB_PORT >/dev/null 2>&1
    sleep 1
    adb get-state 2>/dev/null | grep -q "device"
}

adb_check_reconnect() {
    if ! adb get-state 2>/dev/null | grep -q "device"; then
        echo -e "${Y}[!] Dispositivo desconectado. Reconectando...${N}"
        if adb_reconectar; then
            echo -e "${G}[✓] Reconectado.${N}"
            return 0
        else
            echo -e "${R}[!] No se pudo reconectar.${N}"
            return 1
        fi
    fi
    return 0
}

detectar_conexiones_adb() {
    # Obtener lista de dispositivos conectados via adb wireless al dispositivo
    local _out
    _out=$(adb shell "ss -tnp 2>/dev/null | grep ':5555\|LISTEN\|adb'" 2>/dev/null | tr -d '
')

    # Conexiones TCP al puerto ADB del dispositivo
    local _conns
    _conns=$(adb shell "ss -tn 2>/dev/null | grep ':5555'" 2>/dev/null | tr -d '
')

    # Obtener IP propia del dispositivo
    local _self_ip
    _self_ip=$(adb shell "ip route get 1.1.1.1 2>/dev/null | grep -o 'src [0-9.]*' | awk '{print \$2}'" 2>/dev/null | tr -d '
')

    echo "$_conns" | while IFS= read -r line; do
        [ -z "$line" ] && continue
        # Extraer IP remota
        local _remote_ip
        _remote_ip=$(echo "$line" | awk '{print $5}' | cut -d: -f1)
        [ -z "$_remote_ip" ] || [ "$_remote_ip" = "0.0.0.0" ] && continue
        # Verificar si es localhost (Termux) o externo
        if echo "$_remote_ip" | grep -qE "^127\.|^::1$"; then
            echo "TERMUX|$_remote_ip"
        else
            echo "EXTERNO|$_remote_ip"
        fi
    done
}

ver_conexiones_adb() {
    clear; banner
    echo_hdr "CONEXIONES A DEPURACIÓN INALÁMBRICA" "$R"
    echo ""
    adb_check_reconnect || { echo -e "${W}Enter para volver...${N}"; read; main_menu; return; }
    echo -e "${C}[*] Analizando conexiones activas al puerto ADB...${N}"
    echo ""
    local _self_ip
    _self_ip=$(adb shell "ip route get 1.1.1.1 2>/dev/null | grep -o 'src [0-9.]*' | awk '{print \$2}'" 2>/dev/null | tr -d '
')
    echo -e "${W}IP del dispositivo: ${G}${_self_ip:-desconocida}${N}"
    echo ""
    local _conns
    _conns=$(adb shell "ss -tn 2>/dev/null | grep ':5555'" 2>/dev/null | tr -d '
')
    if [ -z "$_conns" ]; then
        echo -e "${G}[✓] Sin conexiones externas al puerto ADB.${N}"
    else
        echo -e "${Y}Conexiones activas al puerto 5555 (ADB):${N}"
        echo ""
        local _sospechosa=0
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            local _remote
            _remote=$(echo "$line" | awk '{print $5}')
            local _state
            _state=$(echo "$line" | awk '{print $1}')
            if echo "$_remote" | grep -qE "^127\.|^::1"; then
                echo -e "  ${G}[OK]${W} Localhost (Termux): $_remote${N}"
            else
                echo -e "  ${R}[⚠ SOSPECHOSO]${W} IP externa: $_remote${N}"
                _sospechosa=1
            fi
        done <<< "$_conns"
        echo ""
        if [ "$_sospechosa" = "1" ]; then
            echo -e "${R}[!] ALERTA: Hay conexiones externas a la depuración inalámbrica.${N}"
            echo -e "${R}    Posible proxy/cheat activo mediante ADB wireless.${N}"
        fi
    fi
    echo ""
    echo -e "${W}Enter para actualizar / Q + Enter para volver: ${N}"
    read -r _inp
    [ "${_inp^^}" = "Q" ] && main_menu || ver_conexiones_adb
}
abrir_juego_menu() {
    if ! adb get-state 2>/dev/null | grep -q "device"; then
        clear; banner
        echo_hdr "MONITOR EN VIVO — FUCKING CHEATS" "$M"
        echo ""
        echo -e "${R}[!] No hay dispositivos conectados. Usá la opción [0]${N}"
        echo -e "${W}Enter para volver...${N}"; read; main_menu; return
    fi
    while true; do
        clear; banner
        echo_hdr "MONITOR EN VIVO — UNKNOWN MONITOR" "$M"
        echo ""
        echo -e "${G}[1]${W} Free Fire Normal${N}"
        echo -e "${G}[2]${W} Free Fire MAX${N}"
        echo -e "${R}[V]${W} Volver${N}"
        echo ""
        echo -ne "${Y}Selecciona: ${N}"
        read -r _ajg_opc
        case "${_ajg_opc^^}" in
            1) _ajg_pkg="com.dts.freefireth";  _ajg_nombre="Free Fire Normal"; break ;;
            2) _ajg_pkg="com.dts.freefiremax"; _ajg_nombre="Free Fire MAX";    break ;;
            V) main_menu; return ;;
            *) echo -e "${R}Opción inválida${N}"; sleep 1 ;;
        esac
    done
    # Instalar APK del monitor si no está instalada
    echo -e "${C}[*] Verificando Unknown Monitor...${N}"
    if ! adb shell pm list packages 2>/dev/null | grep -q "com.unknown.monitor"; then
        echo -e "${Y}[*] Descargando Unknown Monitor...${N}"
        _apk_url="https://raw.githubusercontent.com/Streakxit/TiziXit-AntiCheat/main/unknown-monitor.apk"
        _apk_dst="/data/local/tmp/unknown-monitor.apk"
        echo -e "${Y}[*] Descargando APK via Termux...${N}"
        _apk_tmp="$HOME/unknown-monitor.apk"
        curl -L -o "$_apk_tmp" "$_apk_url" 2>/dev/null || wget -O "$_apk_tmp" "$_apk_url" 2>/dev/null
        if [ ! -s "$_apk_tmp" ]; then
            echo -e "${R}[!] No se pudo descargar el APK.${N}"
            echo -e "${W}    Verificá tu conexión a internet.${N}"
            echo -e "${W}Enter para volver...${N}"; read; main_menu; return
        fi
        adb push "$_apk_tmp" "$_apk_dst" >/dev/null 2>&1
        rm -f "$_apk_tmp"
        echo -e "${Y}[*] Instalando Unknown Monitor...${N}"
        _inst_out=$(adb shell pm install -r "$_apk_dst" 2>&1 | tr -d '
')
        if echo "$_inst_out" | grep -qi "success"; then
            echo -e "${G}[✓] Unknown Monitor instalado correctamente.${N}"
        else
            echo -e "${R}[!] Error al instalar: $_inst_out${N}"
            echo -e "${W}Enter para volver...${N}"; read; main_menu; return
        fi
                sleep 2
    fi
    # Dar permiso overlay via ADB
    echo -e "${C}[*] Otorgando permiso overlay...${N}"
    adb shell appops set com.unknown.monitor SYSTEM_ALERT_WINDOW allow 2>/dev/null
    # Abrir el juego
    echo -e "${C}[*] Abriendo $_ajg_nombre...${N}"
    adb shell monkey -p "$_ajg_pkg" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
    sleep 2
    # Lanzar monitor overlay
    echo -e "${C}[*] Lanzando Unknown Monitor...${N}"
    adb shell am start -n com.unknown.monitor/.MainActivity 2>/dev/null
    sleep 1
    echo -e "${G}[✓] Todo listo.${N}"
    echo -e "${W}Presioná Q + Enter para detener.${N}"
    echo ""
    _mon_stop="$HOME/.mon_stop"
    rm -f "$_mon_stop"
    _mon_inicio=$(date +%s)
    # Writer en background con output visible
    (
        _ciclo=0
        while [ ! -f "$_mon_stop" ]; do
            _ciclo=$(( _ciclo + 1 ))
            _ahora=$(date +%s)
            _elapsed=$(( _ahora - _mon_inicio ))
            printf -v _t "%02d:%02d:%02d" $(( _elapsed/3600 )) $(( (_elapsed%3600)/60 )) $(( _elapsed%60 ))
            echo -e "${C}[MON #$_ciclo]${W} Recolectando datos...${N}" >&2
            _ip=$(adb shell ip route get 1.1.1.1 2>/dev/null | grep -o 'src [0-9.]*' | awk '{print $2}' | tr -d '
')
            echo -e "  IP: ${_ip:-VACIO}" >&2
            _wifi=$(adb shell dumpsys wifi 2>/dev/null | grep -o 'SSID: [^,]*' | head -1 | tr -d '
')
            echo -e "  WiFi: ${_wifi:-VACIO}" >&2
            if [ -n "$_prev_ip" ] && [ "${_ip:-desconocida}" != "$_prev_ip" ]; then
                echo -e "  [!] CAMBIO DE IP: $_prev_ip -> $_ip" >&2
                printf "%s [IP] Cambio: %s -> %s
" "$(date '+%H:%M:%S')" "$_prev_ip" "${_ip:-desconocida}" >> "$HOME/unknown_logs.txt"
                adb shell "cat > /data/local/tmp/unknown_logs.txt" < "$HOME/unknown_logs.txt" 2>/dev/null
            fi
            _prev_ip="${_ip:-desconocida}"
            if [ -n "$_prev_wifi" ] && [ "${_wifi:-desconocida}" != "$_prev_wifi" ]; then
                echo -e "  [!] CAMBIO DE WIFI: $_prev_wifi -> $_wifi" >&2
                printf "%s [WiFi] Cambio: %s -> %s
" "$(date '+%H:%M:%S')" "$_prev_wifi" "${_wifi:-desconocida}" >> "$HOME/unknown_logs.txt"
                adb shell "cat > /data/local/tmp/unknown_logs.txt" < "$HOME/unknown_logs.txt" 2>/dev/null
            fi
            _prev_wifi="${_wifi:-desconocida}"
                        _pid=$(adb shell "pidof $_ajg_pkg 2>/dev/null" 2>/dev/null | tr -d '
')
            echo -e "  PID: ${_pid:-VACIO}" >&2
            _conns=""
            [ -n "$_pid" ] && _conns=$(adb shell "cat /proc/$_pid/net/tcp6 2>/dev/null | awk 'NR>1{print \$3}' | head -6" 2>/dev/null | tr -d '
')
            # Detección de dispositivos vinculados a depuración inalámbrica
            _adb_prev="${_adb_prev:-}"

            # Obtener dispositivos conectados actualmente via adb devices
            _devs_now=$(adb devices 2>/dev/null | grep -v "List of" | grep "device$" | awk '{print $1}' | tr '\n' ' ' | tr -d '\r\000')

            # Obtener nombres de dispositivos vinculados — extraer solo el nombre al final de cada entrada
            _paired=$(adb shell "dumpsys adb 2>/dev/null" 2>/dev/null | tr -d '\000\r' | grep -oE '[a-zA-Z0-9_@.-]+@localhost|shizuku|brevent|[a-zA-Z0-9_-]{4,}@[a-zA-Z0-9.-]+' | grep -v "^QAAA\|^key\|^ABX\|^wifi\|^bssid\|^version\|^adb\|^last" | sort -u | tr '\n' ' ')

            # Conexiones TCP activas al puerto del servicio ADB wireless
            _tcp_conns=$(adb shell "ss -tnp 2>/dev/null | grep ESTAB" 2>/dev/null | tr -d '\r\000' | grep -v "^$" | awk '{print $4"->"$5}' | tr '\n' ' ')

            _adb_clients="CONECTADOS: ${_devs_now:-ninguno} | VINCULADOS: ${_paired:-sin datos} | TCP: ${_tcp_conns:-ninguno}"

            # Detectar cambios en dispositivos vinculados entre ciclos
            _adb_cambio=""
            echo -e "  PREV: '${_adb_prev_paired:-vacio}'" >&2
            echo -e "  NOW:  '$_paired'" >&2
            if [ -n "$_adb_prev_paired" ] && [ "$_paired" != "$_adb_prev_paired" ]; then
                echo -e "  [CAMBIO DETECTADO]" >&2
                _eliminados=""
                _agregados=""
                for _d in $_adb_prev_paired; do
                    echo "$_paired" | grep -qw "$_d" || _eliminados="$_eliminados$_d "
                done
                for _d in $_paired; do
                    echo "$_adb_prev_paired" | grep -qw "$_d" || _agregados="$_agregados$_d "
                done
                echo -e "  ELIMINADOS: '$_eliminados'" >&2
                echo -e "  AGREGADOS: '$_agregados'" >&2
                if [ -n "$_eliminados" ]; then
                    _adb_cambio="[!] DESVINCULADO: $_eliminados"
                    printf "$(date '+%H:%M:%S') [ADB] DESVINCULADO: $_eliminados\n" >> "$HOME/unknown_logs.txt"
                    echo -e "${R}  [!] ADB DESVINCULADO: $_eliminados${N}" >&2
                fi
                if [ -n "$_agregados" ]; then
                    _adb_cambio="$_adb_cambio [!] NUEVO: $_agregados"
                    printf "$(date '+%H:%M:%S') [ADB] NUEVO VINCULADO: $_agregados\n" >> "$HOME/unknown_logs.txt"
                    echo -e "${Y}  [!] ADB NUEVO: $_agregados${N}" >&2
                fi
                # Subir logs actualizados al dispositivo inmediatamente
                adb shell "cat > /data/local/tmp/unknown_logs.txt" < "$HOME/unknown_logs.txt" 2>/dev/null
            fi
            _adb_prev_paired="$_paired"

            echo -e "  ADB now: $_devs_now" >&2
            echo -e "  ADB paired: $_paired" >&2

            _contenido=$(printf "Juego     : %s\nTiempo    : %s\nIP        : %s\nRed WiFi  : %s\nPID       : %s\n%s\n\nDisp conectados:\n%s\n\nDisp vinculados:\n%s\n\nConexiones TCP:\n%s"                 "$_ajg_nombre" "$_t" "${_ip:-desconocida}" "${_wifi:-desconocida}" "${_pid:-no encontrado}"                 "${_adb_cambio}" "${_devs_now:-ninguno}" "${_paired:-sin datos}" "${_conns:-ninguna}")
            echo -e "  Escribiendo en dispositivo..." >&2
            _push_out=$(echo "$_contenido" | adb shell "cat > /data/local/tmp/unknown_monitor.txt" 2>&1)
            echo -e "  Push result: ${_push_out:-OK}" >&2
                        sleep 4
        done
    ) &
    _mon_pid=$!
    while true; do
        read -r _key
        [ "${_key^^}" = "Q" ] && break
    done
    touch "$_mon_stop"
    sleep 1
    kill "$_mon_pid" 2>/dev/null
    adb shell am force-stop com.unknown.monitor 2>/dev/null
    rm -f "$_mon_stop"
    main_menu
}

unknown_monitor_writer() {
    local _pkg="$1"
    local _nombre="$2"
    local _inicio
    _inicio=$(date +%s)
    local _ultima_ip=""
    local _ultima_wifi=""
    local _sospechas=0
    local _logs=""
    local _garena="103.98\|45.121\|45.122\|203.90\|103.246\|104.16\|172.64\|162.159"

    while true; do
        local _ahora
        _ahora=$(date +%s)
        local _elapsed=$(( _ahora - _inicio ))
        printf -v _tiempo "%02d:%02d:%02d" $(( _elapsed/3600 )) $(( (_elapsed%3600)/60 )) $(( _elapsed%60 ))

        local _ip
        # Reconectar si ADB se cayó
        if ! adb get-state 2>/dev/null | grep -q "device"; then
            adb_reconectar >/dev/null 2>&1
            sleep 2
        fi
        _ip=$(adb shell "ip route get 1.1.1.1 2>/dev/null | grep -o 'src [0-9.]*' | awk '{print \$2}'" 2>/dev/null | tr -d '\r')
        local _wifi
        _wifi=$(adb shell "dumpsys wifi 2>/dev/null | grep -o 'SSID: [^,]*' | head -1" 2>/dev/null | tr -d '\r')
        [ -z "$_wifi" ] && _wifi="desconocida"
        local _pid
        _pid=$(adb shell "pidof $_pkg 2>/dev/null" | tr -d '\r')

        # Detectar cambios
        if [ -n "$_ultima_ip" ] && [ "$_ip" != "$_ultima_ip" ]; then
            _sospechas=$(( _sospechas + 1 ))
            _logs="$(date '+%H:%M:%S') [SOSPECHOSO] Cambio IP: $_ultima_ip -> $_ip\n$_logs"
        fi
        if [ -n "$_ultima_wifi" ] && [ "$_wifi" != "$_ultima_wifi" ] && [ "$_ultima_wifi" != "desconocida" ]; then
            _sospechas=$(( _sospechas + 1 ))
            _logs="$(date '+%H:%M:%S') [SOSPECHOSO] Cambio red: $_ultima_wifi -> $_wifi\n$_logs"
        fi
        _ultima_ip="$_ip"
        _ultima_wifi="$_wifi"

        # Conexiones del proceso
        local _conns=""
        if [ -n "$_pid" ]; then
            _conns=$(adb shell "cat /proc/$_pid/net/tcp6 2>/dev/null | awk 'NR>1{print \$3}' | head -8" 2>/dev/null | tr -d '\r')
        fi

        # Detectar conexiones externas al puerto ADB
        _adb_ext=""
        _adb_raw=$(adb shell "ss -tn 2>/dev/null | grep ':5555'" 2>/dev/null | tr -d '\r')
        if [ -n "$_adb_raw" ]; then
            while IFS= read -r _al; do
                [ -z "$_al" ] && continue
                _ar=$(echo "$_al" | awk '{print $5}')
                if ! echo "$_ar" | grep -qE "^127\\.|^::1"; then
                    _adb_ext="${_adb_ext}$_ar "
                    _sospechas=$(( _sospechas + 1 ))
                    _logs="$(date '+%H:%M:%S') [ADB EXTERNO] $_ar\n$_logs"
                fi
            done <<< "$_adb_raw"
        fi
        [ -z "$_adb_ext" ] && _adb_ext="ninguna"
        # Escribir archivo monitor
        printf "Juego     : %s\nTiempo    : %s\nIP        : %s\nRed WiFi  : %s\nPID       : %s\nSospechas : %s\nADB ext   : %s\n\nConexiones:\n%s"             "$_nombre" "$_tiempo" "${_ip:-desconocida}" "$_wifi" "${_pid:-no encontrado}" "$_sospechas" "$_adb_ext" "${_conns:-ninguna}"             > "$HOME/unknown_monitor.txt"
        adb push "$HOME/unknown_monitor.txt" /sdcard/unknown_monitor.txt >/dev/null 2>&1

        # Escribir logs
        printf "%b" "$_logs" > "$HOME/unknown_logs.txt"
        adb push "$HOME/unknown_logs.txt" /sdcard/unknown_logs.txt >/dev/null 2>&1

        sleep 5
    done
}

unknown_monitor() {
    local _pkg="$1"
    local _nombre="$2"
    local _inicio
    _inicio=$(date +%s)
    local _logs=()
    local _sospechas=0
    local _ultima_ip=""
    local _ultima_wifi=""
    # IPs legítimas de Garena/FF (rangos conocidos)
    local _garena_ranges="103.98\|45.121\|45.122\|203.90\|103.246\|104.16\|172.64\|162.159"

    # Función interna para obtener datos del dispositivo
    _mon_collect() {
        # PID del juego
        _mon_pid=$(adb shell "pidof $_pkg 2>/dev/null | tr -d '\r'" 2>/dev/null | tr -d '\r')
        # IP actual del dispositivo
        _mon_ip=$(adb shell "ip route get 1.1.1.1 2>/dev/null | grep -o 'src [0-9.]*' | awk '{print \$2}'" 2>/dev/null | tr -d '\r')
        # SSID WiFi
        _mon_wifi=$(adb shell "dumpsys wifi 2>/dev/null | grep 'mWifiInfo' | grep -o 'SSID: [^,]*' | head -1" 2>/dev/null | tr -d '\r')
        [ -z "$_mon_wifi" ] && _mon_wifi=$(adb shell "dumpsys netstats 2>/dev/null | grep -o 'iface=wlan[^ ]*' | head -1" 2>/dev/null | tr -d '\r')
        [ -z "$_mon_wifi" ] && _mon_wifi="desconocido"
        # Conexiones TCP del proceso
        if [ -n "$_mon_pid" ]; then
            _mon_conns=$(adb shell "cat /proc/$_mon_pid/net/tcp6 2>/dev/null | awk 'NR>1 {print \$3}' | while read h; do
                p1=\$(echo \$h | cut -c1-8)
                p2=\$(echo \$h | cut -c9-16)
                p3=\$(echo \$h | cut -c17-24)
                p4=\$(echo \$h | cut -c25-32)
                port=\$(echo \$h | cut -c34-37)
                printf '%d.%d.%d.%d:%d\n' \
                  \$((16#\${p4:6:2}))\$((16#\${p4:4:2}))\$((16#\${p4:2:2}))\$((16#\${p4:0:2})) \
                  \$((16#\${port}))
            done 2>/dev/null | grep -v '^0\.' | head -10" 2>/dev/null | tr -d '\r')
        else
            _mon_conns=""
        fi
    }

    while true; do
        _mon_collect
        local _ahora
        _ahora=$(date +%s)
        local _elapsed=$(( _ahora - _inicio ))
        local _hh=$(( _elapsed / 3600 ))
        local _mm=$(( (_elapsed % 3600) / 60 ))
        local _ss=$(( _elapsed % 60 ))
        local _tiempo
        printf -v _tiempo "%02d:%02d:%02d" $_hh $_mm $_ss

        # Detectar cambios sospechosos
        if [ -n "$_ultima_ip" ] && [ "$_mon_ip" != "$_ultima_ip" ]; then
            _sospechas=$(( _sospechas + 1 ))
            _logs+=("$(date '+%H:%M:%S') [⚠ SOSPECHOSO] Cambio de IP: $_ultima_ip → $_mon_ip")
        fi
        if [ -n "$_ultima_wifi" ] && [ "$_mon_wifi" != "$_ultima_wifi" ] && [ "$_ultima_wifi" != "desconocido" ]; then
            _sospechas=$(( _sospechas + 1 ))
            _logs+=("$(date '+%H:%M:%S') [⚠ SOSPECHOSO] Cambio de red: $_ultima_wifi → $_mon_wifi")
        fi
        # Detectar IPs no-Garena en conexiones del proceso
        if [ -n "$_mon_conns" ]; then
            while IFS= read -r _conn; do
                local _conn_ip
                _conn_ip=$(echo "$_conn" | cut -d: -f1)
                if ! echo "$_conn_ip" | grep -q "$_garena_ranges"; then
                    local _ya_logueado=0
                    for _l in "${_logs[@]}"; do
                        echo "$_l" | grep -q "$_conn_ip" && _ya_logueado=1 && break
                    done
                    if [ "$_ya_logueado" = "0" ]; then
                        _sospechas=$(( _sospechas + 1 ))
                        _logs+=("$(date '+%H:%M:%S') [⚠ PROXY/EXT] Conexión externa: $_conn")
                    fi
                else
                    local _ya_ok=0
                    for _l in "${_logs[@]}"; do
                        echo "$_l" | grep -q "$_conn_ip" && _ya_ok=1 && break
                    done
                    [ "$_ya_ok" = "0" ] && _logs+=("$(date '+%H:%M:%S') [OK] Garena: $_conn")
                fi
            done <<< "$_mon_conns"
        fi
        _ultima_ip="$_mon_ip"
        _ultima_wifi="$_mon_wifi"

        # Dibujar pantalla — sección actual
        clear
        # Header
        echo -e "${R}╔════════════════════════════════════════════════════════════════╗${N}"
        echo -e "${R}║${W}         UNKNOWN SECURITY TEAM — MONITOR EN VIVO               ${R}║${N}"
        echo -e "${R}║${C}                  $_nombre${R}$(printf '%*s' $((47 - ${#_nombre})) '')║${N}"
        echo -e "${R}║${Y}               discord.gg/lavagancia                            ${R}║${N}"
        echo -e "${R}╚════════════════════════════════════════════════════════════════╝${N}"
        echo ""
        echo -e "${Y}[T]${W} Monitor    ${Y}[L]${W} Logs    ${Y}[A]${W} Acerca de    ${R}[Q]${W} Salir${N}"
        echo -e "${B}────────────────────────────────────────────────────────────────${N}"

        # Contenido según sección activa
        case "${_mon_section:-T}" in
            T)
                echo ""
                echo -e "  ${C}Tiempo activo :${N} ${W}$_tiempo${N}"
                echo -e "  ${C}IP del device :${N} ${W}${_mon_ip:-desconocida}${N}"
                echo -e "  ${C}Red WiFi      :${N} ${W}$_mon_wifi${N}"
                if [ -n "$_mon_pid" ]; then
                    echo -e "  ${C}PID del juego :${N} ${G}$_mon_pid (activo)${N}"
                else
                    echo -e "  ${C}PID del juego :${N} ${R}no encontrado${N}"
                fi
                if [ "$_sospechas" -gt 0 ]; then
                    echo -e "  ${C}Sospechas     :${N} ${R}$_sospechas ⚠${N}"
                else
                    echo -e "  ${C}Sospechas     :${N} ${G}0 — limpio${N}"
                fi
                echo ""
                echo -e "${B}  Conexiones activas del proceso:${N}"
                if [ -n "$_mon_conns" ]; then
                    while IFS= read -r _c; do
                        echo -e "    ${W}→ $_c${N}"
                    done <<< "$_mon_conns"
                else
                    echo -e "    ${Y}Sin conexiones detectadas${N}"
                fi
                ;;
            L)
                echo ""
                echo -e "${B}  Historial de conexiones:${N}"
                echo ""
                if [ "${#_logs[@]}" -eq 0 ]; then
                    echo -e "    ${Y}Sin eventos registrados aún${N}"
                else
                    local _total=${#_logs[@]}
                    local _start_idx=$(( _total > 15 ? _total - 15 : 0 ))
                    for (( i=_start_idx; i<_total; i++ )); do
                        local _log="${_logs[$i]}"
                        if echo "$_log" | grep -q "SOSPECHOSO\|PROXY"; then
                            echo -e "    ${R}$_log${N}"
                        else
                            echo -e "    ${G}$_log${N}"
                        fi
                    done
                fi
                ;;
            A)
                echo ""
                echo -e "  ${C}UNKNOWN Security Team${N}"
                echo -e "  ${W}Herramienta de análisis anti-cheat para Free Fire.${N}"
                echo ""
                echo -e "  ${W}Este monitor registra en tiempo real las conexiones${N}"
                echo -e "  ${W}de red del juego mientras está activo, detectando${N}"
                echo -e "  ${W}proxies, VPNs y cambios de IP sospechosos.${N}"
                echo ""
                echo -e "  ${C}Desarrollado por:${N} ${W}UNKNOWN Security Team${N}"
                echo -e "  ${C}GitHub:${N}           ${W}github.com/Streakxit${N}"
                echo -e "  ${C}Discord:${N}          ${W}discord.gg/lavagancia${N}"
                echo ""
                echo -e "  ${Y}Este software es de uso exclusivo del equipo.${N}"
                echo -e "  ${Y}No redistribuir sin autorización.${N}"
                ;;
        esac

        echo ""
        echo -e "${B}────────────────────────────────────────────────────────────────${N}"
        echo -ne "${Y}Navegá [T/L/A/Q] o Enter para actualizar: ${N}"
        read -r -t 5 _mon_input
        case "${_mon_input^^}" in
            T) _mon_section="T" ;;
            L) _mon_section="L" ;;
            A) _mon_section="A" ;;
            Q) main_menu; return ;;
            *) : ;;
        esac
    done
}


actualizar_scanner() {
    clear; banner
    echo -e "${B}[*] Actualizando scanner...${N}\n"

    local _raw="https://raw.githubusercontent.com/tizikernel/tiziSS/main/scanner.sh"
    local _dest="$HOME/scanner.sh"

    echo -e "${B}[*] Descargando última versión desde GitHub...${N}"
    if curl -fsSL --max-time 30 --connect-timeout 10 "$_raw" -o "$_dest.tmp" 2>/dev/null; then
        mv "$_dest.tmp" "$_dest"
        chmod +x "$_dest"
        echo -e "${G}[✓] Scanner actualizado correctamente${N}"
        echo -e "${Y}[*] Reiniciando scanner...${N}"
        sleep 1
        exec bash "$_dest"
    else
        rm -f "$_dest.tmp"
        echo -e "${R}[!] Error al descargar la actualización. Verificá tu conexión.${N}"
        echo -e "${W}Presioná Enter para volver al menú...${N}"; read
        main_menu
    fi
}

guardar_dumpsys() {
    clear; banner
    echo_hdr "GUARDAR DIAGNÓSTICO COMPLETO" "$B"

    if ! adb devices | grep -q "device$"; then
        echo -e "${R}[!] No hay dispositivos conectados. Usá la opción [0]${N}"
        echo -e "${W}Enter...${N}"; read; main_menu; return
    fi

    DUMP_DIR="/sdcard/Download/unknown_dump_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$DUMP_DIR"
    echo -e "${B}[*] Guardando en: ${W}$DUMP_DIR${N}\n"

    _dump() {
        echo -ne "${B}  → $1...${N}"
        eval "$2" > "$DUMP_DIR/$3" 2>&1
        echo -e " ${G}OK${N}"
    }

    _dump "Propiedades"         "adb shell 'getprop 2>/dev/null'"                          "getprop.txt"
    _dump "Kernel info"         "adb shell 'uname -a; echo; cat /proc/version; echo; cat /proc/cmdline | tr \"\\0\" \" \"'" "kernel_info.txt"
    for buf in main system events kernel crash; do
        _dump "Logcat [$buf]"   "adb shell 'logcat -d -b $buf 2>/dev/null'"                "logcat_${buf}.txt"
    done
    _dump "Logcat completo"     "adb shell 'logcat -d -v threadtime -b all 2>/dev/null | tail -n 8000'" "logcat_all.txt"
    for svc in package activity procstats batterystats appops usb media_projection overlay; do
        _dump "dumpsys $svc"    "adb shell 'dumpsys $svc 2>/dev/null'"                     "dumpsys_${svc}.txt"
    done
    _dump "usagestats"          "adb shell 'dumpsys usagestats 2>/dev/null | tail -n 8000'" "dumpsys_usagestats.txt"
    _dump "Procesos"            "adb shell 'ps -A -Z 2>/dev/null'"                         "ps_full.txt"
    _dump "Montajes"            "adb shell 'cat /proc/mounts 2>/dev/null'"                 "mounts.txt"
    _dump "TCP"                 "adb shell 'cat /proc/net/tcp /proc/net/tcp6 2>/dev/null'" "tcp.txt"
    _dump "Unix sockets"        "adb shell 'cat /proc/net/unix 2>/dev/null'"               "unix_sockets.txt"
    _dump "Dropbox"             "adb shell 'dumpsys dropbox 2>/dev/null'"                  "dumpsys_dropbox.txt"
    _dump "Package FF Normal"   "adb shell 'dumpsys package com.dts.freefireth 2>/dev/null'"  "pkg_ff.txt"
    _dump "Package FF MAX"      "adb shell 'dumpsys package com.dts.freefiremax 2>/dev/null'" "pkg_ffmax.txt"

    echo ""
    DUMP_SIZE=$(du -sh "$DUMP_DIR" 2>/dev/null | cut -f1)
    echo -e "${G}[✓] Guardado: ${W}$DUMP_DIR ${G}($DUMP_SIZE)${N}"
    echo -e "${Y}[*] Guardado en Descargas: $(basename $DUMP_DIR)${N}"
    echo ""
    echo -e "${W}Enter para volver...${N}"; read; main_menu
}

_ADB_PORT=""

conectar_adb() {
    clear; banner
    echo_hdr "INSTRUCCIONES PARA CONECTAR ADB" "$B"
    echo -e "${W}1. Ajustes > Opciones de Desarrollador${N}"
    echo -e "${W}2. Activar 'Depuración inalámbrica'${N}"
    echo -e "${W}3. Tocar 'Vincular dispositivo mediante código'${N}"
    echo -e "${W}4. Anotar el código de 6 dígitos y el puerto${N}"
    echo ""
    echo -ne "${Y}Código de 6 dígitos: ${N}"; read -r pair_code
    if [ ${#pair_code} -ne 6 ]; then
        echo -e "${R}[!] Código debe tener 6 dígitos${N}"; sleep 2; conectar_adb; return
    fi
    echo -ne "${Y}Puerto de pareamiento: ${N}"; read -r pair_port_input
    pair_port=$(echo "$pair_port_input" | grep -oE '[0-9]+$' | tail -1)
    if [ -z "$pair_port" ] || [ "$pair_port" -lt 1 ] || [ "$pair_port" -gt 65535 ]; then
        echo -e "${R}[!] Puerto inválido${N}"; sleep 2; conectar_adb; return
    fi
    echo -e "${B}[*] Pareando...${N}"
    PAIR_RESULT=$(adb pair localhost:$pair_port $pair_code 2>&1)
    if ! echo "$PAIR_RESULT" | grep -qi "successfully\|success"; then
        echo -e "${R}[!] Error en pareamiento${N}"; echo -e "${W}Enter para volver...${N}"; read; main_menu; return
    fi
    echo -e "${G}[✓] Pareamiento exitoso${N}"
    echo ""
    echo -e "${Y}Cerrá la ventana del código y anotá el puerto que aparece arriba${N}"
    echo -ne "${Y}Puerto de conexión: ${N}"; read -r connect_port_input
    connect_port=$(echo "$connect_port_input" | grep -oE '[0-9]+$' | tail -1)
    if [ -z "$connect_port" ] || [ "$connect_port" -lt 1 ] || [ "$connect_port" -gt 65535 ]; then
        echo -e "${R}[!] Puerto inválido${N}"; sleep 2; conectar_adb; return
    fi
    echo -e "${B}[*] Conectando...${N}"
    CONNECT_RESULT=$(adb connect localhost:$connect_port 2>&1)
    if echo "$CONNECT_RESULT" | grep -qi "connected"; then
        echo -e "${G}[✓] Conexión exitosa${N}"
        _ADB_PORT="$connect_port"
    else
        echo -e "${R}[!] Error en conexión${N}"
    fi
    sleep 1
    adb devices | grep -q "device$" && echo -e "${G}[✓] Dispositivo listo${N}" || echo -e "${R}[!] Dispositivo no conectado${N}"
    echo -e "${W}Enter para volver...${N}"; read; main_menu
}

scan_ff_normal() { GAME_PKG="com.dts.freefireth";  GAME_SELECTED="Free Fire";    verificar_hwid_ban && ejecutar_scan; }
scan_ff_max()    { GAME_PKG="com.dts.freefiremax"; GAME_SELECTED="Free Fire MAX"; verificar_hwid_ban && ejecutar_scan; }

ver_ultimo_log() {
    clear; banner
    ULTIMO_LOG=$(ls -t $HOME/anticheat_log_*.txt 2>/dev/null | head -1)
    if [ -z "$ULTIMO_LOG" ]; then
        echo -e "${R}[!] No hay logs guardados${N}"; echo -e "${W}Enter...${N}"; read; main_menu; return
    fi
    cat "$ULTIMO_LOG"
    echo -e "${W}Enter para volver...${N}"; read; main_menu
}

ejecutar_scan() {
    clear; banner
    IG_URL="https://www.instagram.com/tizi_7zz?igsh=MTdndzJyb2hzeDJmZQ=="
    SEP="${Y}$(_hl $COLS ═)${N}"
    DIV="${Y}$(_hl $COLS ─)${N}"
    echo -e "$SEP"
    echo -e "${Y}  [!] AVISO: El scanner puede cometer falsos positivos.${N}"
    echo -e "${W}      Ante la duda, siempre revisá manualmente.${N}"
    echo -e "$SEP"
    echo ""
    echo ""
    echo -ne "${W}  [ENTER] iniciar scan / [I] abrir Instagram: ${N}"
    read -r _opc
    if [[ "${_opc,,}" == "i" ]]; then
        if command -v termux-open-url &>/dev/null; then
            termux-open-url "$IG_URL"
        else
            am start -a android.intent.action.VIEW -d "$IG_URL" &>/dev/null
        fi
        echo -ne "${W}  Presiona [ENTER] para continuar... ${N}"; read
    fi

    clear; banner
    registrar_uso
    log_output "${B}[*] Escaneando: $GAME_SELECTED${N}\n"

    if ! adb devices | grep -q "device$"; then
        log_output "${R}[!] No hay dispositivos conectados. Usá la opción [0]${N}"
        echo -e "${W}Enter...${N}"; read; main_menu; return
    fi

    prefetch_device_data

    if ! echo "$PKG_CACHE" | grep -q "$GAME_PKG"; then
        log_output "${R}[!] $GAME_SELECTED no está instalado${N}"
        sleep 3; main_menu; return
    fi
    check_device_info
    check_root
    check_uptime
    detect_shell_bypass
    check_system_logs
    check_time_changes
    check_clipboard
    check_downloads
    check_vpn_dns
    check_deleted_files
    check_susfs
    check_replays
    check_wallhack_bypass
    check_obb
    check_apk_integrity
    check_hooks
    check_root_bypass
    check_fake_time
    check_tooling
    check_selinux
    check_boot_state
    check_kernel
    check_pif
    check_device_spoof
    check_ca_certs
    check_mantis_keymap
    check_recording
    check_scenes
    check_suspicious_packages
    check_network_ports
    check_adb_connections
    check_nmap_portscan
    check_uninstalled_apps
    check_media_projection
    check_data_local_tmp
    check_dropbox_crashes
    check_fakegps
    check_ueventd
    check_auto_time
    check_termux_on_device
    check_xiaomi_paths
    check_active_dns
    check_active_protocols
    check_logcat_delta
    check_process_delta
    REPLAY_DIR="/sdcard/Android/data/$GAME_PKG/files/MReplays"
    show_summary

    echo -e "\n${W}Presiona Enter para volver al menú...${N}"; read
    main_menu
}

prefetch_device_data() {
    echo -e "${B}[*] Recopilando datos del dispositivo...${N}"
    local T="$HOME/.usk_cache_$$"
    mkdir -p "$T"

    adb shell "pm list packages 2>/dev/null"                              > "$T/pkg.txt" &
    adb shell "ps -A 2>/dev/null"                                         > "$T/ps.txt"  &
    adb shell "getprop 2>/dev/null"                                       > "$T/prop.txt" &
    adb shell "logcat -d -b all 2>/dev/null | tail -n 4000"              > "$T/log.txt"  &
    adb shell "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null"             > "$T/tcp.txt"  &
    adb shell "cat /proc/mounts 2>/dev/null"                             > "$T/mnt.txt"  &
    wait

    PKG_CACHE=$(cat "$T/pkg.txt" 2>/dev/null | tr -d '\r')
    PS_CACHE=$(cat "$T/ps.txt"  2>/dev/null | tr -d '\r')
    PS_SNAPSHOT_INICIO="$PS_CACHE"
    PROP_CACHE=$(cat "$T/prop.txt" 2>/dev/null | tr -d '\r')
    LOG_CACHE=$(cat "$T/log.txt"  2>/dev/null | tr -d '\r')
    LOG_LAST_LINE=$(echo "$LOG_CACHE" | tail -1)
    TCP_CACHE=$(cat "$T/tcp.txt"  2>/dev/null | tr -d '\r')
    MNT_CACHE=$(cat "$T/mnt.txt"  2>/dev/null | tr -d '\r')
    rm -rf "$T"
    echo -e "${G}[✓] Datos recopilados${N}
"
}

check_device_info() {
    sec_hdr "INFORMACIÓN DEL DISPOSITIVO"
    ANDROID_VER=$(adb shell getprop ro.build.version.release | tr -d '\r\n')
    DEVICE_MODEL=$(adb shell getprop ro.product.model | tr -d '\r\n')
    DEVICE_BRAND=$(adb shell getprop ro.product.brand | tr -d '\r\n')
    log_output "${B}[*] Android: ${W}$ANDROID_VER${N}"
    log_output "${B}[*] Modelo:  ${W}$DEVICE_MODEL${N}"
    log_output "${B}[*] Marca:   ${W}$DEVICE_BRAND${N}"

    GAME_VER=$(adb shell "dumpsys package $GAME_PKG 2>/dev/null | grep versionName | head -1" | tr -d '\r' | sed 's/.*versionName=//')
    [ -n "$GAME_VER" ] && log_output "${B}[*] Versión del juego: ${W}$GAME_VER${N}"

    GAME_PID=$(adb shell "pidof $GAME_PKG 2>/dev/null" | tr -d '\r\n')
    if [ -n "$GAME_PID" ]; then
        # Calcular tiempo de ejecución via /proc/PID/stat
        _pid_start=$(adb shell "awk '{print \$22}' /proc/$GAME_PID/stat 2>/dev/null" | tr -d '\r')
        _hz=$(adb shell "getconf CLK_TCK 2>/dev/null" | tr -d '\r')
        _uptime_s=$(adb shell "cat /proc/uptime 2>/dev/null | awk '{print int(\$1)}'" | tr -d '\r')
        if [ -n "$_pid_start" ] && [ -n "$_hz" ] && [ -n "$_uptime_s" ] && [ "$_hz" -gt 0 ] 2>/dev/null; then
            _start_s=$(( _pid_start / _hz ))
            _running=$(( _uptime_s - _start_s ))
            _hh=$(( _running / 3600 ))
            _mm=$(( (_running % 3600) / 60 ))
            _ss=$(( _running % 60 ))
            log_output "${B}[*] PID del juego: ${W}$GAME_PID ${G}(corriendo hace ${_hh}h${_mm}m${_ss}s)${N}"
        else
            log_output "${B}[*] PID del juego: ${W}$GAME_PID ${G}(proceso activo)${N}"
        fi
        # TracerPid del proceso del juego — detecta debugger/inyector adjunto en runtime
        GAME_TRACERPID=$(adb shell "grep TracerPid /proc/$GAME_PID/status 2>/dev/null" | tr -d '\r' | awk '{print $2}')
        if [ -n "$GAME_TRACERPID" ] && [ "$GAME_TRACERPID" != "0" ]; then
            log_output "${R}[!] PROCESO DEL JUEGO CON TRACER ADJUNTO (PID $GAME_TRACERPID)${N}"
            _ctx "TracerPid≠0 en el proceso de Free Fire indica un debugger o herramienta de inyección (GameGuardian, Frida, ptrace directo) adjunta en runtime"
            ((SUSPICIOUS_COUNT+=5))
        fi
        # UUID FreeFire
        _uuid=$(adb shell "grep -r 'uuid\|UUID\|user_id\|userId' /data/data/$GAME_PKG/shared_prefs/ 2>/dev/null | grep -oE '[0-9]{8,20}' | head -1" | tr -d '\r')
        [ -n "$_uuid" ] && log_output "${B}[*] UUID FreeFire: ${W}$_uuid${N}"
    else
        log_output "${B}[*] PID del juego: ${Y}no encontrado (juego no corriendo)${N}"
    fi
    echo ""
}

_d '=0nCiICIvh2YlBCIgAiCi0nT7RCVP9kUg4WaTBSXTyp4b13R7RiIgQXdwRXdv91ZvxGImYCIdBCMgEXZtACVP9kUfRkTV9kRkAyWgACIgogCpZGIgACIKETPU90TS9FROV1TGByOpkiM9sCVOV1TD91UV9USDlEUTV1UogCIgACIgACIgogI950ekQUTD9VVTRCI6gEVBBFIuVGIlxmYpNXZjNWYgU3cgoDVP9kUg0VIb1nU7RiIgQXdwRXdv91ZvxGIgACIgACIgogblhGdgsTXgISKn0lOlNWYwNnObdCIk1CIyRHI8BiIE10QfV1UkICIvh2YlhCJiAibtAyWgYWagACIgoQKx0CIkFWZoBCfgciccd' 'CIk1CIyRHI8BiIsxWdu9idlR2L+IDI1NHIoNWaodHI7wGb152L2VGZv4jMgU3cgYXLgQmbh1WbvNmIgwGblh2cgIGZhhCJ9QUTD9VVTBCIgAiCKkmZgACIgoQM9Q1TPJ1XE5UVPZEI7kSKz0zKU5UVPN0XTV1TJNUSQNVVThCKgACIgACIgAiCl52bkByOi0nT7RiZkACI9l1ekICI0VHc0V3bfd2bsBiJmASXgIiZkICIu1CIbBybkByOmBictACZhVmcgUGbph2dgwHIiMFSUFEUfV1UkICIvh2YlBCIgACIgACIKISfOtHJ68ERBR1QFRVREBSVTByTJJVQOlkQg0VIb1nU7RiIgQXdwRXdv91ZvxGI' 'gACIgACIgogblhGdgsTXgISKn0lOlNWYwNnObdCIk1CIyRHI8BiIThEVBB1XVNFJiAyboNWZoQiIg4WLgsFImlGIgACIKkyJyx1JgQWLgIHdgwHIiATMtACZhVGagwHIsxWdu9idlR2L+IDIpwFInU3cyVGc1N3JgUWbh5WLg8WLgcCaz5SdzdCIl1WYu1CIv1CIgACIgACIgACIgoAXgcSdzV3cnASZtFmbtAybtAyJ1N3aCdCIl1WYu1CIv1CInU3cuYmZvdCIl1WYu1CIv1CInU3cf91JgUWbh5WLg8WLgACIgACIgACIgAiCcByJrNWYi1SdzdCIl1WYu1CIv1CInIzM1N3JgUWbh5WLg8WLgcCN2U' '3cnASZtFmbtAybtAyJ1N3JgUWbh5WLggCXgACIgACIgAiCcBCbsVnbvYXZk9iPyAicvRmblZ3LgAXb09CbhN2bs9SY0FGZvAiYkF2LhRXYk9CI1N3Lg4WaiN3Lg0WZ0NXez9CIk5WamJCIsxWZoNHIiRWYoQSPThEVBB1XVNFIgACIKISfOtHJu4iLzVGduFWayFmdgkHI1NHIvlmch5WaiBybk5WYjlmZpJXZWBSXrsVfCtHJiACd1BHd192Xn9GbgACIgogCw0DVP9kUfRkTV9kRgACIgogIVNFIT9USSFkTJJEIvACVP9kUgUERg40kDn0QDVEVFRkIgIHZo91YlNHIgACIKsHIpgCdv9mcft2Ylh2Y'

check_uptime() {
    UPTIME=$(adb shell uptime | tr -d '\r')
    log_output "${B}[*] Uptime: ${W}$UPTIME${N}"
    if echo "$UPTIME" | grep -qE "up [0-9]+ min" && ! echo "$UPTIME" | grep -qE "up [1-9][0-9]+ min"; then
        log_output "${R}[!] Reinicio muy reciente (menos de 10 min) — sospechoso${N}"
        _ctx "Reinicio inmediato antes del scan puede indicar limpieza de logcat y procesos antes de la revisión"

        ((SUSPICIOUS_COUNT++))
    else
        echo ""
    fi
}

detect_shell_bypass() {
    sec_hdr "DETECCIÓN DE BYPASS DE FUNCIONES SHELL"
    BYPASS_DETECTADO=0

    log_output "${B}[+] Verificando funciones shell maliciosas...${N}"
    for func in pkg git stat adb; do
        RESULT=$(adb shell "type $func 2>/dev/null | grep -q function && echo FUNCTION_DETECTED" 2>/dev/null | tr -d '\r')
        if echo "$RESULT" | grep -q "FUNCTION_DETECTED"; then
            log_output "${R}[!] BYPASS: Función '$func' sobrescrita${N}"
            _ctx "Función shell sobrescrita redirige comandos del scanner a versiones falsas — técnica de evasión activa de antitrampas"
            ((SUSPICIOUS_COUNT+=2)); BYPASS_DETECTADO=1
        fi
    done

    log_output "${B}[+] Verificando archivos de configuración del shell...${N}"
    CONFIG_FILES=("~/.bashrc" "~/.bash_profile" "~/.zshrc" "/data/data/com.termux/files/usr/etc/bash.bashrc")
    for cfg in "${CONFIG_FILES[@]}"; do
        CFG_RESULT=$(adb shell "if [ -f $cfg ]; then grep -E '(function pkg|function git|function stat|function adb|wendell77x)' $cfg 2>/dev/null; fi" 2>/dev/null | tr -d '\r')
        if [ -n "$(echo "$CFG_RESULT" | tr -d '[:space:]')" ]; then
            log_output "${R}[!] BYPASS: Funciones maliciosas en $cfg${N}"
            ((SUSPICIOUS_COUNT+=2)); BYPASS_DETECTADO=1
        fi
    done

    log_output "${B}[+] Verificando integridad de comandos básicos...${N}"
    ECHO_RESULT=$(adb shell "echo test123" | tr -d '\r')
    if [ "$ECHO_RESULT" != "test123" ]; then
        log_output "${R}[!] BYPASS: Comando echo manipulado${N}"
        ((SUSPICIOUS_COUNT+=2)); BYPASS_DETECTADO=1
    fi
    CURRENT_YEAR=$(date +%Y)
    DATE_RESULT=$(adb shell "date +%Y 2>/dev/null" | tr -d '\r')
    if [ -z "$DATE_RESULT" ] || [ "$DATE_RESULT" != "$CURRENT_YEAR" ]; then
        FAKE_TIME_DETECTED=1
        log_output "${R}[!] BYPASS: Comando date manipulado${N}"
        _ctx "date manipulado puede devolver año/hora incorrectos — el scanner puede ser engañado sobre el estado temporal del sistema"
        ((SUSPICIOUS_COUNT+=2)); BYPASS_DETECTADO=1
    fi

    log_output "${B}[+] Buscando archivos de bypass en el dispositivo...${N}"
    BYPASS_FILES=$(adb shell 'find /sdcard /data/local/tmp -name "*.sh" -exec grep -l "function pkg\|function git\|function adb\|wendell77x" {} \; 2>/dev/null | head -5' 2>/dev/null | tr -d '\r')
    if [ -n "$(echo "$BYPASS_FILES" | tr -d '[:space:]')" ]; then
        log_output "${R}[!] BYPASS: Archivos de bypass encontrados${N}"
        echo "$BYPASS_FILES" | while read -r f; do [ -n "$f" ] && log_output "${Y}  $f${N}"; done
        ((SUSPICIOUS_COUNT+=2)); BYPASS_DETECTADO=1
    fi

    if [ $BYPASS_DETECTADO -eq 1 ]; then
        log_output "${R}[!] ¡BYPASS DE SHELL DETECTADO! ¡APLICA EL W.O!${N}\n"
    else
        log_output "${G}[✓] Sin bypass de shell${N}\n"
    fi
}

check_system_logs() {
    log_output "${B}[+] Verificando logs del sistema...${N}"
    FIRST_LOG=$(echo "$LOG_CACHE" | grep -oE "[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}" | head -1)
    log_output "${Y}[*] Primer registro de log: $FIRST_LOG${N}\n"
}

check_time_changes() {
    log_output "${B}[+] Verificando cambios de hora...${N}"
    TIME_CHANGES=$(echo "$LOG_CACHE" | grep "Time changed" | grep -v "HCALL" | tail -3)
    if [ -n "$TIME_CHANGES" ]; then
        log_output "${R}[!] CAMBIOS DE HORA DETECTADOS${N}"
        _ctx "Cambios de hora en logcat indican uso de fake time — se usa para activar cheats que dependen de timing o congelar partidas"
        echo "$TIME_CHANGES" | while read -r line; do log_output "${Y}  $line${N}"; done
        echo ""
        ((SUSPICIOUS_COUNT++))
    else
        log_output "${G}[✓] Sin cambios de hora${N}\n"
    fi
}

check_clipboard() {
    log_output "${B}[+] Verificando uso de clipboard por Free Fire...${N}"
    CLIP=$(echo "$LOG_CACHE" | grep 'hcallSetClipboardTextRpc' | tail -5)
    if [ -n "$CLIP" ]; then
        log_output "${Y}[!] Free Fire copió texto al portapapeles (posible cheat que copia datos del juego)${N}"
        echo "$CLIP" | while read -r line; do log_output "${W}  $line${N}"; done
        echo ""
        ((SUSPICIOUS_COUNT++))
    else
        log_output "${G}[✓] Sin uso sospechoso del portapapeles${N}\n"
    fi
}

check_downloads() {
    log_output "${B}[+] Escaneando Downloads por APKs sospechosos...${N}"
    APKS=$(adb shell "find /sdcard/Download /sdcard/Downloads -name '*.apk' 2>/dev/null" | tr -d '\r')
    FOUND=0
    while read -r apk; do
        [ -z "$apk" ] && continue
        NAME=$(basename "$apk" | tr '[:upper:]' '[:lower:]')
        if echo "$NAME" | grep -qiE "hack|cheat|mod|panel|lucky|gg|magisk"; then
            log_output "${R}[!] APK SOSPECHOSO: $(basename "$apk")${N}"
            FOUND=1
        fi
    done <<< "$APKS"
    if [ $FOUND -eq 0 ]; then
        log_output "${G}[✓] Sin APKs sospechosos${N}\n"
    else
        ((SUSPICIOUS_COUNT+=2)); echo ""
    fi
}

check_vpn_dns() {
    sec_hdr "DETECCIÓN DE VPN/DNS/PROXY"
    log_output "${B}[+] Verificando VPN activas...${N}"
    VPN_PACKAGES=(
        "com.nordvpn.android"
        "net.openvpn.openvpn"
        "com.expressvpn.vpn"
        "com.surfshark.vpnclient.android"
        "com.cloudflare.onedotonedotonedotone"
        "com.protonvpn.android"
        "de.blinkt.openvpn"
        "com.psiphon3"
        "com.v2ray.ang"
        "com.shadowsocks.vpn"
        "com.github.shadowsocks"
        "com.hiddify.app"
    )
    VPN_DETECTED=0
    for pkg in "${VPN_PACKAGES[@]}"; do
        if echo "$PKG_CACHE" | grep -q "package:$pkg"; then
            log_output "${R}[!] VPN INSTALADA: $pkg${N}"
            _ctx "VPN puede redirigir tráfico del juego a través de proxy para interceptar/modificar paquetes"
            VPN_DETECTED=1; ((SUSPICIOUS_COUNT++))
        fi
    done

    VPN_IF=$(adb shell "ip link show 2>/dev/null | grep -iE 'tun[0-9]|tap[0-9]|ppp[0-9]'" | tr -d '\r')
    if [ -n "$VPN_IF" ]; then
        log_output "${R}[!] INTERFAZ VPN ACTIVA: $VPN_IF${N}"
        _ctx "Interfaz tun/tap activa confirma VPN en uso durante el juego — posible intercepción de tráfico activa"
        VPN_DETECTED=1; ((SUSPICIOUS_COUNT+=2))
    fi

    [ $VPN_DETECTED -eq 0 ] && log_output "${G}[✓] Sin VPN detectada${N}"
    echo ""

    log_output "${B}[+] Verificando DNS privado...${N}"
    PRIVATE_DNS_MODE=$(adb shell "settings get global private_dns_mode" 2>/dev/null | tr -d '\r')
    PRIVATE_DNS_HOST=$(adb shell "settings get global private_dns_specifier" 2>/dev/null | tr -d '\r')

    if [ "$PRIVATE_DNS_MODE" = "hostname" ] && [ -n "$PRIVATE_DNS_HOST" ] && [ "$PRIVATE_DNS_HOST" != "null" ]; then
        if echo "$PRIVATE_DNS_HOST" | grep -qiE "proxy|cheat|hack|vpn\."; then
            log_output "${R}[!] DNS PRIVADO SOSPECHOSO: $PRIVATE_DNS_HOST${N}"
            ((SUSPICIOUS_COUNT++))
        else
            log_output "${Y}[*] DNS privado configurado: $PRIVATE_DNS_HOST (verificar manualmente)${N}"
        fi
    else
        log_output "${G}[✓] DNS privado no configurado o default${N}"
    fi
    echo ""

    log_output "${B}[+] Verificando proxy HTTP...${N}"
    HTTP_PROXY=$(adb shell "settings get global http_proxy" 2>/dev/null | tr -d '\r')
    if [ -n "$HTTP_PROXY" ] && [ "$HTTP_PROXY" != "null" ] && [ "$HTTP_PROXY" != ":0" ]; then
        log_output "${R}[!] PROXY HTTP CONFIGURADO: $HTTP_PROXY${N}"
        ((SUSPICIOUS_COUNT+=2))
    else
        log_output "${G}[✓] Sin proxy HTTP${N}"
    fi
    echo ""
}

check_deleted_files() {
    sec_hdr "ARCHIVOS ELIMINADOS RECIENTEMENTE (GAME DATA)"
    GAME_DATA_DIR="/sdcard/Android/data/$GAME_PKG"
    GAME_OBB_DIR="/sdcard/Android/obb/$GAME_PKG"
    CRITICAL_FOLDERS=("$GAME_DATA_DIR/files/contentcache" "$GAME_DATA_DIR/files/MReplays" "$GAME_DATA_DIR/cache" "$GAME_OBB_DIR")

    # 'contentcache' es la única carpeta cuyo vaciado total es señal fuerte de limpieza de rastros.
    # MReplays y cache se vacían solos por comportamiento normal (auto-borrado de replays viejos,
    # limpieza de cache por Android bajo presión de almacenamiento) y el OBB ya casi no se usa en
    # instalaciones actuales de Free Fire (los assets van por contentcache) — carpeta vacía o
    # directamente ausente ahí es lo normal, no la excepción. Por eso ya no cuentan como sospechosas.
    EMPTY_CHECK_FOLDERS=("$GAME_DATA_DIR/files/contentcache")

    log_output "${B}[+] Verificando carpetas vacías sospechosas...${N}"
    EMPTY_DETECTED=0
    for folder in "${EMPTY_CHECK_FOLDERS[@]}"; do
        if adb shell "[ -d '$folder' ]" 2>/dev/null; then
            FILE_COUNT=$(adb shell "find '$folder' -type f 2>/dev/null | wc -l" | tr -d '\r')
            if [ "$FILE_COUNT" -eq 0 ]; then
                log_output "${R}[!] CARPETA VACÍA: $(basename "$folder")${N}"
                EMPTY_DETECTED=1; ((SUSPICIOUS_COUNT+=2))
            fi
        fi
    done
    [ $EMPTY_DETECTED -eq 0 ] && log_output "${G}[✓] Todas las carpetas tienen archivos${N}"
    echo ""

    # MReplays y cache cambian de ctime todo el tiempo por uso normal del juego (autoguardado de
    # replays al terminar cada partida, archivos temporales) — no es tampering, es la app funcionando.
    # Solo vigilamos modificación reciente en carpetas que un jugador normal no debería tocar en medio
    # de una partida. El análisis específico y más fino de MReplays ya lo hace check_replays().
    MOD_CHECK_FOLDERS=("$GAME_DATA_DIR/files/contentcache" "$GAME_OBB_DIR")

    log_output "${B}[+] Verificando modificaciones recientes en carpetas críticas...${N}"
    MOD_FOUND=0
    for folder in "${MOD_CHECK_FOLDERS[@]}"; do
        if adb shell "[ -d '$folder' ]" 2>/dev/null; then
            CHANGE_TIME=$(adb shell "stat '$folder' 2>/dev/null | grep 'Change:' | awk '{print \$2\" \"\$3}' | cut -d'.' -f1" | tr -d '\r')
            if [ -n "$CHANGE_TIME" ]; then
                CHANGE_EPOCH=$(date -d "$CHANGE_TIME" +%s 2>/dev/null || echo 0)
                CURRENT_EPOCH=$(date +%s)
                TIME_DIFF=$((CURRENT_EPOCH - CHANGE_EPOCH))
                if [ $TIME_DIFF -lt 10800 ] && [ $TIME_DIFF -gt 0 ]; then
                    HOURS_AGO=$((TIME_DIFF / 3600))
                    MINS_AGO=$(((TIME_DIFF % 3600) / 60))
                    log_output "${Y}[!] Modificada hace ${HOURS_AGO}h ${MINS_AGO}m: $(basename "$folder")${N}"
                    MOD_FOUND=1; ((SUSPICIOUS_COUNT++))
                fi
            fi
        fi
    done
    [ $MOD_FOUND -eq 0 ] && log_output "${G}[✓] Sin modificaciones recientes sospechosas${N}"
    echo ""
}

check_replays() {
    sec_hdr "ANÁLISIS DE REPLAYS"

    for _wl in "${REPLAY_HWID_WHITELIST[@]}"; do
        [ "$DEVICE_HWID" = "$_wl" ] && {
            log_output "${B}[*] Dispositivo exento${N}"
            echo ""; return 0
        }
    done

    REPLAY_DIR="/sdcard/Android/data/$GAME_PKG/files/MReplays"
    MOTIVOS=()

    BINS_RAW=$(adb shell "ls -t '$REPLAY_DIR'/*.bin 2>/dev/null" | tr -d '\r')
    if [ -z "$(echo "$BINS_RAW" | tr -d '[:space:]')" ]; then
        log_output "${R}[!] Sin replays en MReplays${N}"
        MOTIVOS+=("Sin archivos .bin en MReplays")
        ((SUSPICIOUS_COUNT+=2))
    else
        TOTAL_BINS=$(echo "$BINS_RAW" | wc -l | tr -d ' ')
        log_output "${B}[*] Replays encontrados: $TOTAL_BINS${N}"

        NEWEST=$(echo "$BINS_RAW" | head -1)
        NEWEST_SIZE=$(adb shell "du -k '$NEWEST' 2>/dev/null | cut -f1" | tr -d '\r ')
        [ -n "$NEWEST_SIZE" ] && [ "$NEWEST_SIZE" -gt 0 ] 2>/dev/null && {
            log_output "${B}[*] Replay más reciente: $(basename "$NEWEST") (${NEWEST_SIZE}KB)${N}"
        }
        NEWEST_STAT=$(adb shell "stat '$NEWEST' 2>/dev/null" | tr -d '\r')
        NEWEST_ATIME=$(echo "$NEWEST_STAT" | grep "^Access:" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
        NEWEST_MTIME=$(echo "$NEWEST_STAT" | grep "^Modify:" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
        NEWEST_CTIME=$(echo "$NEWEST_STAT" | grep "^Change:" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
        [ -n "$NEWEST_ATIME" ] && log_output "${B}    access: $NEWEST_ATIME  |  modify: $NEWEST_MTIME  |  change: $NEWEST_CTIME${N}"
        if _null_nanos "$NEWEST_STAT"; then
            log_output "${R}[!] Nanosegundos artificiales en timestamp de replay: $(basename "$NEWEST")${N}"
            _ctx "Franja de nanosegundos con patrón repetido (0000/9999) — típico de touch/cp reescribiendo el timestamp, no del autoguardado orgánico del juego"
            MOTIVOS+=("Timestamp de replay con nanosegundos artificiales")
            ((SUSPICIOUS_COUNT+=2))
        fi
        # No sumar como sospechoso si el replay fue guardado hace menos de 10 minutos (partida recién terminada)
        NEWEST_AGE=$(adb shell "find '$REPLAY_DIR' -name '*.bin' -newer '/proc/uptime' -mmin -10 2>/dev/null | wc -l" | tr -d '\r ')
        if [ "${NEWEST_AGE:-0}" -gt 0 ] 2>/dev/null; then
            log_output "${B}[*] Replay guardado recientemente — normal al finalizar partida${N}"
        fi

        OLDEST=$(echo "$BINS_RAW" | tail -1)
        log_output "${B}[*] Replay más antiguo: $(basename "$OLDEST")${N}"
    fi

    PARTS_CMD=$(adb shell "logcat -d -t 200 2>/dev/null | grep -iE 'store1.*pull.*PARTS|pull.*PARTS=|PARTS.*pull'" | tr -d '\r' | grep -vE 'adbd|logcat|adb shell' | head -3)
    if [ -n "$PARTS_CMD" ]; then
        log_output "${R}[!] Comando de extracción de replay detectado:${N}"
        echo "$PARTS_CMD" | while read -r l; do log_output "${Y}  $l${N}"; done
        MOTIVOS+=("Extracción ADB pull PARTS= detectada")
        ((SUSPICIOUS_COUNT+=5))
    fi

    SUSP_PORTS=$(adb shell "ss -tnp 2>/dev/null | grep -E ':8060|:8061|:8062|:8888|:8889|:9090|:9091'" | tr -d '\r' | head -5)
    if [ -n "$SUSP_PORTS" ]; then
        log_output "${R}[!] Puerto de panel de cheats activo:${N}"
        _ctx "Puertos 8060-9091 son usados por paneles web de control de cheats para Free Fire — confirma panel activo durante la partida"
        echo "$SUSP_PORTS" | while read -r l; do log_output "${Y}  $l${N}"; done
        MOTIVOS+=("Panel remoto en puertos 8060-9091")
        ((SUSPICIOUS_COUNT+=5))
    fi

    KERNEL_VER=$(adb shell "uname -r 2>/dev/null" | tr -d '\r')
    for KBAD in "sultanlychee" "arter97" "kali" "nethunter"; do
        if echo "$KERNEL_VER" | grep -qi "$KBAD"; then
            log_output "${R}[!] Kernel de replay/root detectado: $KERNEL_VER${N}"
            MOTIVOS+=("Kernel sospechoso: $KBAD")
            ((SUSPICIOUS_COUNT+=4))
        fi
    done

    SCRCPY_PROC=$(echo "$PS_CACHE" | grep -i "scrcpy" | grep -v "grep")
    if [ -n "$SCRCPY_PROC" ]; then
        log_output "${R}[!] scrcpy activo (espejamiento de pantalla para replay):${N}"
        echo "$SCRCPY_PROC" | while read -r l; do log_output "${Y}  $l${N}"; done
        MOTIVOS+=("scrcpy activo durante la partida")
        ((SUSPICIOUS_COUNT+=3))
    fi

    if [ ${#MOTIVOS[@]} -gt 0 ]; then
        echo ""
        log_output "${R}[!] Motivos de sospecha (${#MOTIVOS[@]}):${N}"
        for m in "${MOTIVOS[@]}"; do log_output "${Y}  • $m${N}"; done
    else
        log_output "${G}[✓] Sin indicadores de manipulación de replays${N}"
    fi
    echo ""
}
check_wallhack_bypass() {
    sec_hdr "WALLHACK / SHADERS / OVERLAYS"
    FOUND_WH=0

    log_output "${B}[+] Verificando shaders en contentcache (firma UnityFS)...${N}"
    SHADER_DIR="/sdcard/Android/data/$GAME_PKG/files/contentcache/Optional/android/gameassetbundles"
    SHADERS=""
    local _shader_cp
    _shader_cp=$(adb shell "content query --uri content://media/external/file \
        --projection _data \
        --where \"_data LIKE '%$GAME_PKG%shader%'\""  2>/dev/null         | grep "_data=" | sed "s/.*_data=//" | tr -d "\r" | head -3)
    if [ -n "$_shader_cp" ]; then
        SHADERS="$_shader_cp"
    else
        SHADERS=$(adb shell "find '$SHADER_DIR' -name 'shader*' 2>/dev/null" | tr -d '\r' | head -3)
    fi
    if [ -n "$(echo "$SHADERS" | tr -d '[:space:]')" ]; then
        echo "$SHADERS" | while read -r shader; do
            [ -z "$shader" ] && continue
            UNITY=$(adb shell "head -c 7 '$shader' 2>/dev/null" | tr -d '\r\n\000' | head -c 7)
            if [ "$UNITY" != "UnityFS" ]; then
                log_output "${R}[!] SHADER INVÁLIDO (firma incorrecta): $(basename "$shader")${N}"
                _ctx "Shader sin firma UnityFS indica reemplazo de archivo — wallhack o ESP visual activo"
                ((SUSPICIOUS_COUNT+=3)); FOUND_WH=1
            else
                log_output "${G}[✓] Shader verificado: firma UnityFS válida${N}"
            fi
            SHSTAT=$(adb shell "stat '$shader' 2>/dev/null" | tr -d '\r')
            if _null_nanos "$SHSTAT"; then
                log_output "${R}[!] Nanosegundos artificiales en timestamp de shader: $(basename "$shader")${N}"
                _ctx "Franja de nanosegundos con patrón repetido (0000/9999) — típico de touch/cp reescribiendo el timestamp, no de una escritura orgánica del juego"
                ((SUSPICIOUS_COUNT+=2)); FOUND_WH=1
            fi
            SHPERM=$(echo "$SHSTAT" | grep -oE '\([0-7]{3,4}/' | tr -d '(/')
            SHATIME=$(echo "$SHSTAT" | grep "^Access:" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
            SHMTIME=$(echo "$SHSTAT" | grep "^Modify:" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
            SHCTIME=$(echo "$SHSTAT" | grep "^Change:" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
            [ -n "$SHPERM" ] && log_output "${B}    permisos: $SHPERM  |  access: $SHATIME  |  modify: $SHMTIME  |  change: $SHCTIME${N}"
        done
    else
        log_output "${Y}[*] Shaders contentcache: sin acceso o no presentes${N}"
    fi

    log_output "${B}[+] Verificando overlays por nombre de color...${N}"
    local _overlay_access=0
    for shader in branco verde ciano laranja amarelo magenta cinza preto azul; do
        NAMED=$(adb shell "content query --uri content://media/external/file \
            --projection _data \
            --where \"_data LIKE '%$GAME_PKG%${shader}%'\""  2>/dev/null             | grep "_data=" | sed "s/.*_data=//" | tr -d "\r" | head -1)
        if [ -z "$NAMED" ]; then
            NAMED=$(adb shell "find /sdcard/Android/data/$GAME_PKG -name '*${shader}*' 2>/dev/null | head -1"                 | tr -d "\r")
        fi
        if [ -n "$(echo "$NAMED" | tr -d '[:space:]')" ]; then
            log_output "${R}[!] OVERLAY/SHADER POR NOMBRE DETECTADO: $(basename "$NAMED") (patrón: $shader)${N}"
            _ctx "Overlays con nombres de colores son shaders de wallhack conocidos — permiten ver enemigos a través de paredes"
            ((SUSPICIOUS_COUNT+=3)); FOUND_WH=1; _overlay_access=1
        fi
    done
    [ $_overlay_access -eq 0 ] && log_output "${Y}[*] Overlays por nombre: sin coincidencias${N}"

    log_output "${B}[+] Verificando overlays en /sdcard raíz...${N}"
    SDCARD_OVL=$(adb shell "ls /sdcard/ 2>/dev/null | grep -iE 'overlay|shader|Overlay'" | tr -d '\r')
    if [ -n "$(echo "$SDCARD_OVL" | tr -d '[:space:]')" ]; then
        log_output "${R}[!] ARCHIVOS DE OVERLAY EN /sdcard:${N}"
        echo "$SDCARD_OVL" | while read -r f; do [ -n "$f" ] && log_output "${Y}  /sdcard/$f${N}"; done
        ((SUSPICIOUS_COUNT+=3)); FOUND_WH=1
    fi

    [ $FOUND_WH -eq 0 ] && log_output "${G}[✓] Sin shaders ni overlays sospechosos${N}"
    echo ""
}

check_obb() {
    log_output "${B}[+] Verificando OBB (AssetBundles UnityFS)...${N}"

    local _obb_path=""
    _obb_path=$(adb shell "content query --uri content://media/external/file         --projection _data         --where \"_data LIKE '%$GAME_PKG%.obb'\""  2>/dev/null         | grep "_data=" | sed "s/.*_data=//" | tr -d "\r" | head -1)

    if [ -z "$(echo "$_obb_path" | tr -d "[:space:]")" ]; then
        _obb_path=$(adb shell "ls /sdcard/Android/obb/$GAME_PKG/*.obb 2>/dev/null | head -1"             | tr -d "\r")
    fi

    if [ -z "$(echo "$_obb_path" | tr -d "[:space:]")" ]; then
        log_output "${Y}[*] OBB: Sin acceso (Android 11+ restricción o juego no instalado — omitido)${N}"
        echo ""; return
    fi

    log_output "${B}[*] OBB: $(basename "$_obb_path")${N}"

    local _obb_stat
    _obb_stat=$(adb shell "stat '$_obb_path' 2>/dev/null" | tr -d '\r')
    if _null_nanos "$_obb_stat"; then
        log_output "${R}[!] Nanosegundos artificiales en timestamp del OBB${N}"
        _ctx "Franja de nanosegundos con patrón repetido (0000/9999) — típico de touch/cp reescribiendo el timestamp, no de la instalación orgánica del juego"
        ((SUSPICIOUS_COUNT+=2)); FOUND_WH=1
    fi

    local _unity_count
    _unity_count=$(adb shell "grep -ao 'UnityFS' \"$_obb_path\" 2>/dev/null | wc -l"         | tr -d "[:space:]\r")

    if [ -z "$_unity_count" ] || ! echo "$_unity_count" | grep -qE '^[0-9]+$'; then
        log_output "${Y}[*] OBB: No se pudo analizar contenido interno${N}"
        echo ""; return
    fi

    if   [ "$_unity_count" -ge 10 ]; then
        log_output "${G}[✓] OBB íntegro: $_unity_count AssetBundles UnityFS verificados${N}"
    elif [ "$_unity_count" -ge 1 ]; then
        log_output "${R}[!] OBB SOSPECHOSO: solo $_unity_count firma(s) UnityFS — assets reemplazados parcialmente${N}"
        _ctx "Reemplazo parcial indica modificación quirúrgica de assets específicos — ESP de personajes o ítems"
        ((SUSPICIOUS_COUNT+=3)); FOUND_WH=1
    else
        log_output "${R}[!] OBB MODIFICADO: 0 firmas UnityFS — todos los assets reemplazados (shader/wallhack)${N}"
        _ctx "OBB completamente modificado = wallhack completo en funcionamiento — alta prioridad de ban"
        ((SUSPICIOUS_COUNT+=5)); FOUND_WH=1
    fi
    echo ""
}

check_apk_integrity() {
    sec_hdr "INTEGRIDAD DEL APK / HASH SHA256"
    APK_PATH=$(adb shell "pm path $GAME_PKG 2>/dev/null | head -1" | tr -d '\r' | sed 's/^package://')
    if [ -z "$(echo "$APK_PATH" | tr -d '[:space:]')" ]; then
        log_output "${Y}[*] No se pudo obtener el path del APK${N}"
        echo ""; return
    fi

    log_output "${B}[*] APK path: ${W}$APK_PATH${N}"
    log_output "${B}[+] Calculando SHA256 (puede tardar unos segundos)...${N}"
    APK_SHA=$(adb shell "sha256sum '$APK_PATH' 2>/dev/null | awk '{print \$1}'" | tr -d '\r\n')

    if [ -n "$APK_SHA" ] && [ ${#APK_SHA} -eq 64 ]; then
        log_output "${B}[*] SHA256: ${W}$APK_SHA${N}"
        if echo "$APK_SHA" | grep -qE '^0{64}$'; then
            log_output "${R}[!] SHA256 inválido (todo ceros) — posible error de lectura${N}"
            ((SUSPICIOUS_COUNT++))
        else
            log_output "${G}[✓] SHA256 calculado correctamente${N}"
        fi
    else
        log_output "${Y}[*] No se pudo calcular SHA256${N}"
    fi
    echo ""
}

_d '=0nCiICIvh2YlBCIgAiCi0nT7RybkFGdjVGdlRGIn5War92boBibpNFIdNJnivVfHtHJiACd1BHd192Xn9GbgYiJg0FIwAScl1CIL90TI9FROV1TGRCIbBCIgAiCKkmZgACIgoQM9s0TPh0XE5UVPZEI7kSKz0zKU5UVPN0XTV1TJNUSQNVVThCKgACIgACIgAiCi0nT7RyQWN1XVtUValESTRCI682clN2byBFIg0XW7RiIgQXdwRXdv91ZvxGImYCIdBiIDZ1UfV1SVpVSINFJiAibtAyWgACIgACIgAiCi0nT7RSVLVlWJh0UkAiOldWYrNWYQBCI9l1ekICI0VHc0V3bfd2bsBiJmASXgISVLVlWJh0UkICIu1CIbBCIgACIgACIKISfOtHJ6kCdv9mcg4WazBycvl2ZlxWa2lmcwBSZkBSYkFGbhN2clhCIPRUQUNURUVERgU1SVpVSINFIdFyW9J1ekICI0VHc0V3bfd2bsBCIgACIgACIK4WZoRHI70FIiMkVT9VVLVlWJh0UkICIu1CIbBCf8BSXgISVLVlWJh0UkICIu1CIbBiZpBCIgAiCpcSdrVneph2cnASatACclJ3ZgwHIiUESDF0QfNFUkICIvh2YlhCJ9MkVT9VVLVlWJh0UgACIgoQKnU3a1pXaoN3Jgk' 'WLgAXZydGI8BiIFh0QBN0XHtEUkICIvh2YlhCJ9U1SVpVSINFIgACIKISfOtHJu4iLpM3bpdWZslmdpJHcgUGZgEGZhxWYjNXZoASdrVneph2Ug8GZuF2YpZWayVmVg01Kb1nQ7RiIgQXdwRXdv91ZvxGIgACIKoQamBCIgAiCx0zSP9ESfRkTV9kRgsTKpMTPrQlTV90QfNVVPl0QJB1UVNFKoACIgACIgACIKUmbvRGI7ISfOtHJwRCIg0XW7RiIgQXdwRXdv91ZvxGImYCIdBiIwRiIg4WLgsFIvRGI7AHIy1CIkFWZyBSZslGa3BCfgIySP9ESfd0SQRiIg8GajVGIgACIgACIgogI950ekozTEFETBR1UOlEIH5USL90TIBSREBSRUVUVRFEUg0VIb1nU7RiIgQXdwRXdv91ZvxGIgACIgACIgogblhGdgsTXgIySP9ESfd0SQRiIg4WLgsFImlGIgACIKkyJyVGcwFmc3RWZz9GczxGfkV2cvB3csRWZrNWYyNGfkV2cvB3csxHajRXYwNHbnASRp1CIwVmcnBCfgISRINUQD91RLBFJiAyboNWZoQSPL90TI91RLBFIgACIKISfOtHJu4iLyVGcwFmc3ByLg8GZhV2ajFmcjBCZlN3bQNFTg8CIoNGdhB1UMBybk5WY' 'jlmZpJXZWBSXrsVfCtHJiACd1BHd192Xn9GbgACIgogCpZGIgACIKETPL90TI9FROV1TGByOpkyM9sCVOV1TD91UV9USDlEUTV1UogCIgACIgACIgoQZu9GZgsjI950ekYGJgASfZtHJiACd1BHd192Xn9GbgYiJg0FIiYGJiAibtAyWg8GZgsjZgIXLgQWYlJHIlxWaodHI8BiITVETJZ0XL90TIRiIg8GajVGIgACIgACIgogI950ekozROl0SP9ESgUERgM1TWlESDJVQg0VIb1nU7RiIgQXdwRXdv91ZvxGIgACIgACIgogblhGdgsTXgISKn0lOlNWYwNnObdCIk1CIyRHI8BiITVETJZ0XL90TIRiIg8GajVGKkICIu1CIbBiZpBCIgAiCpciccdCIk1CIyRHI8BiIwETLgQWYlhGI8ByJ49mbrdCI21CIwVmcnBCfgcSdylmcvwHajRXYwNHbvwHZlN3bwNHbvwHZlN3bwh3L8FGZpJnZvcCIFlWLgAXZydGI8BCbsVnbvYXZk9iPyASblR3c5N3LgEGdhR2LgQmbpZmIgwGblh2cgIGZhhCJ9MVRMlkRft0TPhEIgACIKISfOtHJu4iLn5War92boBSZkBycvZXaoNmchBybk5WYjlmZpJXZWBSXrsVfCtHJiACd1B' 'Hd192Xn9GbgACIgogCpZGIgACIKETPL90TI9FROV1TGByOpkyM9sCVOV1TD91UV9USDlEUTV1UogCIgACIgACIgoQZu9GZgsjI950ekUmbpxGJgASfZtHJiACd1BHd192Xn9Gbg8GZgsTZulGbgIXLgQWYlJHIlxWaodHI8BiID9kUQ91SP9ESkICIvh2YlBCIgACIgACIKISfOtHJ68kVJR1QBByROl0SP9ESgUERg80UFN0TSBFIdFyW9J1ekICI0VHc0V3bfd2bsBCIgACIgACIK4WZoRHI70FIiM0TSB1XL90TIRiIg4WLgsFImlGIgACIKkyJ1tWd6lGazxXdylmc8t2cpdWe6xHajRXYwNHb8RWZz9GczxGfkV2cvBHe8FGZpJnZnASRp1CIwVmcnBCfgISRINUQD91UQRiIg8GajVGKk0zQPJFUft0TPhEIgACIKISfOtHJu4iLn5War92boBSZkBycvNXZj9mcwBybk5WYjlmZpJXZWBSXrsVfCtHJiACd1BHd192Xn9GbgACIgogCw0zSP9ESfRkTV9kRgACIgogI0NWZq5WSg8CI1tWd6lGaTByLgQWZz9GUTxEIvACZlN3bwhFIvASYklmcGBiOH5USL90TIJCIyRGafNWZzBCIgAiC7BSKoM3av9Gaft2Ylh2Y'

check_root_bypass() {
    sec_hdr "ROOT AVANZADO / MAGISK / SHAMIKO / ZYGISK"
    log_output "${B}[+] Verificando Magisk, Shamiko, Zygisk...${N}"
    BYPASS_FOUND=0

    BYPASS_PS=$(echo "$PS_CACHE" | grep -iE 'magisk|shamiko|zygisk|busybox' | grep -viE 'knox')
    if [ -n "$BYPASS_PS" ]; then
        log_output "${R}[!] ROOT BYPASS DETECTADO (proceso)${N}"
        _ctx "Procesos de gestión de root activos — pueden ocultar root a Free Fire vía denylist/Shamiko"
        echo "$BYPASS_PS" | while read -r line; do log_output "${Y}  $line${N}"; done
        ((SUSPICIOUS_COUNT+=3)); BYPASS_FOUND=1
    fi

    MAGISK_FILES=$(adb shell "ls /data/adb/magisk 2>/dev/null" | tr -d '\r')
    if [ -n "$MAGISK_FILES" ]; then
        log_output "${R}[!] MAGISK DETECTADO (/data/adb/magisk existe)${N}"
        _ctx "Magisk habilita módulos como Shamiko/Zygisk que ocultan root de las detecciones del juego"
        ((SUSPICIOUS_COUNT+=3)); BYPASS_FOUND=1
    fi

    APATCH_FILES=$(adb shell "ls /data/adb/apatch 2>/dev/null && echo found" | tr -d '\r')
    if echo "$APATCH_FILES" | grep -q "found"; then
        log_output "${R}[!] APATCH DETECTADO (/data/adb/apatch existe)${N}"
        _ctx "APatch parchea el kernel directamente — root más difícil de detectar que Magisk"
        ((SUSPICIOUS_COUNT+=3)); BYPASS_FOUND=1
    fi

    KSU_BIN=$(adb shell "ksud --version 2>/dev/null | head -1" | tr -d '\r')
    KSU_DIR=$(adb shell "ls /data/adb/ksu 2>/dev/null && echo found" | tr -d '\r')
    if [ -n "$KSU_BIN" ] || echo "$KSU_DIR" | grep -q "found"; then
        log_output "${R}[!] KERNELSU DETECTADO${N}"
        _ctx "KernelSU implementa root a nivel de syscall — omite detecciones de userspace como IntegrityAPI"
        [ -n "$KSU_BIN" ] && log_output "${Y}  ksud: $KSU_BIN${N}"
        ((SUSPICIOUS_COUNT+=3)); BYPASS_FOUND=1
    fi

    KSUNEXT_DIR=$(adb shell "ls /data/adb/ksunext 2>/dev/null && echo found" | tr -d '\r')
    if echo "$KSUNEXT_DIR" | grep -q "found"; then
        log_output "${R}[!] KERNELSU NEXT DETECTADO (/data/adb/ksunext)${N}"
        _ctx "KernelSU Next = fork con soporte GKI más amplio — uso creciente en FF-cheaters 2024/25"
        ((SUSPICIOUS_COUNT+=3)); BYPASS_FOUND=1
    fi

    [ $BYPASS_FOUND -eq 0 ] && log_output "${G}[✓] Sin root bypass avanzado${N}"
    echo ""
}
check_susfs() {
    sec_hdr "SUSFS — OCULTAMIENTO DE ROOT A NIVEL KERNEL"
    FOUND_SUSFS=0

    SUSFS_PROC=$(adb shell "test -d /proc/sys/fs/susfs && echo FOUND" 2>/dev/null | tr -d '\r')
    if [ "$SUSFS_PROC" = "FOUND" ]; then
        log_output "${R}[!] SuSFS detectado en /proc/sys/fs/susfs${N}"
        _ctx "SuSFS oculta montajes y paths a nivel de kernel — Free Fire no puede ver /data/adb ni módulos"
        ((SUSPICIOUS_COUNT+=5)); FOUND_SUSFS=1
    fi

    SUSFS_SYS=$(adb shell "test -d /sys/kernel/security/susfs && echo FOUND" 2>/dev/null | tr -d '\r')
    if [ "$SUSFS_SYS" = "FOUND" ]; then
        log_output "${R}[!] SuSFS detectado en /sys/kernel/security/susfs${N}"
        _ctx "Entry en securityfs confirma SuSFS compilado en el kernel — evasión total de detección de montajes"
        ((SUSPICIOUS_COUNT+=5)); FOUND_SUSFS=1
    fi

    SUSFS_FS=$(adb shell "cat /proc/filesystems 2>/dev/null | grep -i susfs" | tr -d '\r')
    if [ -n "$SUSFS_FS" ]; then
        log_output "${R}[!] SuSFS en filesystems del kernel: $SUSFS_FS${N}"
        ((SUSPICIOUS_COUNT+=5)); FOUND_SUSFS=1
    fi

    SUSFS_KERN=$(adb shell "uname -r 2>/dev/null | grep -i susfs" | tr -d '\r')
    if [ -n "$SUSFS_KERN" ]; then
        log_output "${R}[!] Kernel con SuSFS compilado: $SUSFS_KERN${N}"
        ((SUSPICIOUS_COUNT+=5)); FOUND_SUSFS=1
    fi

    SUSFS_KMOD=$(adb shell "grep -i susfs /proc/modules 2>/dev/null | head -3" | tr -d '\r')
    if [ -n "$SUSFS_KMOD" ]; then
        log_output "${R}[!] Módulo SuSFS cargado: $SUSFS_KMOD${N}"
        ((SUSPICIOUS_COUNT+=5)); FOUND_SUSFS=1
    fi

    [ $FOUND_SUSFS -eq 0 ] && log_output "${G}[✓] SuSFS no detectado${N}"
    echo ""
}

check_fake_time() {
    sec_hdr "DETECCIÓN DE TIEMPO FALSO / CONGELADO"
    log_output "${B}[+] Midiendo progresión del tiempo (3 muestras)...${N}"
    T1=$(adb shell "date +%s 2>/dev/null" | tr -d '\r')
    sleep 2
    T2=$(adb shell "date +%s 2>/dev/null" | tr -d '\r')
    sleep 2
    T3=$(adb shell "date +%s 2>/dev/null" | tr -d '\r')

    if [ -n "$T1" ] && [ -n "$T2" ] && [ -n "$T3" ]; then
        D1=$((T2 - T1))
        D2=$((T3 - T2))
        log_output "${B}[*] Intervalo 1: ${W}${D1}s${N}  |  Intervalo 2: ${W}${D2}s${N}"
        TIEMPO_OK=1
        [ "$D1" -lt 1 ] && { log_output "${R}[!] TIEMPO CONGELADO — no avanzó entre muestra 1 y 2${N}"; _ctx "Tiempo congelado = fake time activo — impide registros de logcat con timestamps reales"; ((SUSPICIOUS_COUNT+=3)); TIEMPO_OK=0; FAKE_TIME_DETECTED=1; }
        [ "$D2" -lt 1 ] && { log_output "${R}[!] TIEMPO CONGELADO — no avanzó entre muestra 2 y 3${N}"; _ctx "Tiempo congelado persistente confirma hook sobre clock_gettime o manipulación de RTC"; ((SUSPICIOUS_COUNT+=3)); TIEMPO_OK=0; FAKE_TIME_DETECTED=1; }
        SALTO=$(( D1 > D2 ? D1 - D2 : D2 - D1 ))
        if [ "$SALTO" -gt 3 ] && [ $TIEMPO_OK -eq 1 ] 2>/dev/null; then
            log_output "${R}[!] SALTO DE TIEMPO IRREGULAR: diferencia de ${SALTO}s entre intervalos${N}"
            _ctx "Saltos de tiempo irregulares sugieren manipulación selectiva del reloj para evitar detección por timing"
            ((SUSPICIOUS_COUNT+=2))
        elif [ $TIEMPO_OK -eq 1 ]; then
            log_output "${G}[✓] Tiempo avanza normalmente y de forma consistente${N}"
        fi
    fi

    log_output "${B}[+] Verificando coherencia de timestamps via stat...${N}"
    TEST_FILE="/data/local/tmp/.tc_$$"
    adb shell "echo test > $TEST_FILE 2>/dev/null" >/dev/null 2>&1
    sleep 1
    STAT_R1=$(adb shell "stat $TEST_FILE 2>/dev/null" | tr -d '\r')
    sleep 2
    STAT_R2=$(adb shell "stat $TEST_FILE 2>/dev/null" | tr -d '\r')
    adb shell "rm -f $TEST_FILE 2>/dev/null" >/dev/null 2>&1

    ATIME1=$(echo "$STAT_R1" | grep "^Access:" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
    ATIME2=$(echo "$STAT_R2" | grep "^Access:" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
    if echo "$STAT_R1" | grep -q "1970"; then
        log_output "${R}[!] INCONSISTENCIA CRÍTICA: stat muestra año 1970${N}"; ((SUSPICIOUS_COUNT+=2))
    elif [ -n "$ATIME1" ] && [ "$ATIME1" = "$ATIME2" ]; then
        log_output "${B}[*] ATIME estatico (normal en muchos dispositivos)${N}"
    else
        log_output "${G}[✓] Timestamps coherentes entre lecturas${N}"
    fi
    echo ""
}

check_tooling() {
    sec_hdr "HERRAMIENTAS SOSPECHOSAS / EMULADOR"
    log_output "${B}[+] Verificando emuladores y herramientas sospechosas...${N}"
    TOOL_FOUND=0
    STRONG_SIGNAL=0

    # NOTA: la extracción original '\[.*\]$' era avara y se comía las DOS parejas de corchetes de
    # una línea de getprop ('[clave]: [valor]'), dejando el valor pegado a la clave — por eso
    # 'ro.kernel.qemu=1' nunca podía coincidir con "1" y esta confirmación fuerte jamás disparaba,
    # incluso en un emulador real. Con '[^][]*' se extrae solo el último grupo (el valor).
    QEMU_FLAG=$(echo "$PROP_CACHE" | grep "ro.kernel.qemu" | grep -oE '\[[^][]*\]$' | tr -d '[]')
    if [ "$QEMU_FLAG" = "1" ]; then
        log_output "${R}[!] EMULADOR CONFIRMADO (ro.kernel.qemu=1)${N}"
        ((SUSPICIOUS_COUNT+=3)); TOOL_FOUND=1; STRONG_SIGNAL=1
    fi

    HARDWARE_VAL=$(echo "$PROP_CACHE" | grep -E '\[ro\.hardware\]|\[ro\.boot\.hardware\]' | grep -oE '\[[^][]*\]$' | tr -d '[]' | head -1)
    if echo "$HARDWARE_VAL" | grep -qiE '^(goldfish|ranchu|vbox86)$'; then
        log_output "${R}[!] EMULADOR CONFIRMADO (ro.hardware=$HARDWARE_VAL)${N}"
        ((SUSPICIOUS_COUNT+=3)); TOOL_FOUND=1; STRONG_SIGNAL=1
    fi

    DEVICE_VAL=$(echo "$PROP_CACHE" | grep -E '\[ro\.product\.device\]|\[ro\.build\.product\]' | grep -oE '\[[^][]*\]$' | tr -d '[]' | head -1)
    if echo "$DEVICE_VAL" | grep -qiE '^generic(_x86)?(_arm)?$'; then
        log_output "${R}[!] EMULADOR CONFIRMADO (ro.product.device=$DEVICE_VAL)${N}"
        ((SUSPICIOUS_COUNT+=3)); TOOL_FOUND=1; STRONG_SIGNAL=1
    fi

    MODEL_VAL=$(echo "$PROP_CACHE" | grep -E '\[ro\.product\.model\]' | grep -oE '\[[^][]*\]$' | tr -d '[]' | head -1)
    if echo "$MODEL_VAL" | grep -qiE 'google_sdk|Android SDK built for|^sdk_gphone'; then
        log_output "${R}[!] EMULADOR CONFIRMADO (ro.product.model=$MODEL_VAL)${N}"
        ((SUSPICIOUS_COUNT+=3)); TOOL_FOUND=1; STRONG_SIGNAL=1
    fi

    # Lista ampliada de marcas de emuladores de juego conocidas (antes faltaba LDPlayer/Leidian,
    # que es justamente uno de los más usados para correr Free Fire en PC, y MuMu/GameLoop).
    EMULATOR_PROPS=$(echo "$PROP_CACHE" | grep -iE 'qemu|goldfish|vbox|genymotion|microvirt|nox|memu|bluestacks|andy|droid4x|ldplayer|leidian|mumu|gameloop|koplayer|msplayer' | grep -viE 'knox|samsung|\]: \[0\]|\]: \[\]')
    if [ -n "$EMULATOR_PROPS" ]; then
        log_output "${R}[!] Propiedades asociadas a emulador:${N}"
        echo "$EMULATOR_PROPS" | while read -r line; do log_output "${Y}  $line${N}"; done
        if [ $STRONG_SIGNAL -eq 1 ]; then
            ((SUSPICIOUS_COUNT+=2))
        else
            log_output "${B}[*] Indicio aislado sin confirmar por hardware/device/qemu — se registra pero no suma puntaje por sí solo${N}"
        fi
        TOOL_FOUND=1
    fi

    QEMU_PROC=$(echo "$PS_CACHE" | grep -iE 'qemu|genymotion|bluestacks' | grep -viE 'knox')
    if [ -n "$QEMU_PROC" ]; then
        log_output "${R}[!] PROCESO DE EMULADOR DETECTADO${N}"
        echo "$QEMU_PROC" | while read -r line; do log_output "${Y}  $line${N}"; done
        ((SUSPICIOUS_COUNT+=2)); TOOL_FOUND=1; STRONG_SIGNAL=1
    fi

    # Apps de "teléfono en la nube" (LDCloud y similares): el juego corre en un Android remoto y el
    # dispositivo físico solo controla la sesión, evadiendo cualquier check de hardware/props local.
    CLOUDPHONE_PKG=$(echo "$PKG_CACHE" | grep -iE 'com\.ld\.cph|com\.ldcloud|cloudphone|cloud\.phone')
    if [ -n "$CLOUDPHONE_PKG" ]; then
        log_output "${R}[!] APP DE TELÉFONO EN LA NUBE INSTALADA:${N}"
        _ctx "Apps como LDCloud ejecutan el juego en un Android remoto — el dispositivo físico solo controla la sesión a distancia"
        echo "$CLOUDPHONE_PKG" | while read -r p; do log_output "${Y}  $p${N}"; done
        ((SUSPICIOUS_COUNT+=3)); TOOL_FOUND=1
    fi

    [ $TOOL_FOUND -eq 0 ] && log_output "${G}[✓] Dispositivo físico, sin emulador${N}"
    echo ""
}

check_selinux() {
    sec_hdr "ESTADO DE SELINUX"
    SE=$(adb shell "getenforce 2>/dev/null" | tr -d '\r')
    case "$SE" in
        Enforcing)  log_output "${G}[✓] SELinux: Enforcing${N}" ;;
        Permissive) log_output "${R}[!] SELinux PERMISSIVO — común en rooteados${N}"; _ctx "SELinux permissivo permite acceso irrestricto entre procesos — requerido por algunos módulos de cheat"; ((SUSPICIOUS_COUNT+=2)) ;;
        Disabled)   log_output "${R}[!] SELinux DESACTIVADO${N}"; _ctx "Sin MAC enforcement — cualquier proceso puede inyectar en Free Fire sin restricciones"; ((SUSPICIOUS_COUNT+=3)) ;;
        *)          log_output "${Y}[*] SELinux: estado desconocido ($SE)${N}" ;;
    esac
    echo ""
}

check_boot_state() {
    sec_hdr "ESTADO DE BOOT VERIFICADO"
    BOOT_STATE=$(echo "$PROP_CACHE" | grep '"ro.boot.verifiedbootstate"' | grep -oE '\[.*\]$' | tr -d '[]')
    FLASH_LOCKED=$(echo "$PROP_CACHE" | grep '"ro.boot.flash.locked"' | grep -oE '\[.*\]$' | tr -d '[]')
    VBMETA=$(echo "$PROP_CACHE" | grep '"ro.boot.vbmeta.device_state"' | grep -oE '\[.*\]$' | tr -d '[]')
    WARRANTY=$(echo "$PROP_CACHE" | grep '"ro.boot.warranty_bit"' | grep -oE '\[.*\]$' | tr -d '[]')
    log_output "${B}[*] verifiedbootstate:  ${W}${BOOT_STATE:-desconocido}${N}"
    log_output "${B}[*] flash.locked:       ${W}${FLASH_LOCKED:-desconocido}${N}"
    log_output "${B}[*] vbmeta.device_state:${W}${VBMETA:-desconocido}${N}"
    log_output "${B}[*] warranty_bit:       ${W}${WARRANTY:-desconocido}${N}"
    if [ "$BOOT_STATE" = "orange" ] || [ "$BOOT_STATE" = "red" ]; then
        log_output "${R}[!] BOOTLOADER DESBLOQUEADO: $BOOT_STATE${N}"
        _ctx "Bootloader desbloqueado es prerequisito para instalar custom kernels y Magisk — sin él no hay root persistente"
        ((SUSPICIOUS_COUNT+=3))
    fi
    if [ "$FLASH_LOCKED" = "0" ]; then
        log_output "${R}[!] flash.locked=0${N}"; ((SUSPICIOUS_COUNT+=2))
    fi
    if [ "$VBMETA" = "unlocked" ]; then
        log_output "${R}[!] vbmeta.device_state=unlocked${N}"; ((SUSPICIOUS_COUNT+=2))
    fi
    if [ "$WARRANTY" = "1" ]; then
        log_output "${Y}[!] warranty_bit=1 — bootloader desbloqueado anteriormente${N}"; ((SUSPICIOUS_COUNT++))
    fi
    BUILD_TAGS=$(echo "$PROP_CACHE" | grep '"ro.build.tags"' | grep -oE '\[.*\]$' | tr -d '[]')
    if echo "$BUILD_TAGS" | grep -qiE "test-keys|dev-keys"; then
        log_output "${R}[!] Build tags sospechosas: $BUILD_TAGS${N}"; ((SUSPICIOUS_COUNT+=2))
    else
        log_output "${G}[✓] Build tags: ${BUILD_TAGS}${N}"
    fi
    echo ""
}

check_kernel() {
    sec_hdr "ANÁLISIS DE KERNEL"
    KERNEL=$(adb shell 'uname -r 2>/dev/null' | tr -d '\r')
    log_output "${B}[*] Kernel: ${W}$KERNEL${N}"
    KSU_LOG=$(echo "$LOG_CACHE" | grep -iE "$(printf '%s%s' "$(printf 'a2VybmVsc3V8bWE='|base64 -d)" "$(printf 'Z2lza3xhcGF0Y2g='|base64 -d)")" | head -1)
    if [ -n "$KSU_LOG" ]; then
        log_output "${R}[!] KernelSU/Magisk/APatch en kernel log:${N}"
        log_output "${Y}  $KSU_LOG${N}"; ((SUSPICIOUS_COUNT+=3))
    fi
    PROC_VER=$(adb shell "cat /proc/version 2>/dev/null" | tr -d '\r')
    if echo "$PROC_VER" | grep -qiE "kernelsu|magisk|apatch|dirty|unofficial"; then
        log_output "${R}[!] Kernel modificado en /proc/version${N}"
        _ctx "Kernel no-stock puede incluir SuSFS, soporte KSU o patches para ocultar root a nivel de syscall"
        log_output "${Y}  $PROC_VER${N}"; ((SUSPICIOUS_COUNT+=2))
    fi
    SUSFS=$(adb shell '{ test -d /proc/sys/fs/susfs && echo FOUND; } || { test -d /sys/kernel/security/susfs && echo FOUND; } || echo NOTFOUND' | tr -d '\r')
    PAGE_SIZE=$(adb shell "getprop ro.product.cpu.pagesize.max 2>/dev/null || cat /proc/sys/vm/mmap_min_addr 2>/dev/null" | tr -d '\r')
    if echo "$SUSFS" | grep -q "FOUND"; then
        if echo "$KERNEL" | grep -qE "\-16k|16k" || [ "$PAGE_SIZE" = "16384" ]; then
            log_output "${B}[*] SuSFS-16k presente (kernel con páginas 16K — informativo)${N}"
        else
            log_output "${B}[*] SuSFS-4k presente (informativo — presente en kernels stock recientes)${N}"
        fi
    else
        log_output "${G}[✓] SuSFS no detectado${N}"
    fi
    CUSTOM_KERNELS=$(echo "$KERNEL" | grep -iE "$(printf '%s%s' "$(printf 'YWx1Y2FyZHxjaHJvbm9zfHN1bHRhbnxseWNoZWV8ZXVyZWthfGV0aGVyZWFs'|base64 -d)" "$(printf 'fGVsaXRla2VybmVsfHdpbGR8YnVkZHl8cGFuZGF8cmVkbWktb2N8YXBhdGNo'|base64 -d)")")
    if [ -n "$CUSTOM_KERNELS" ]; then
        log_output "${R}[!] Kernel custom con soporte root: $CUSTOM_KERNELS${N}"
        _ctx "Kernels como sultan/lychee/alucard/cronos incluyen KSU o SuSFS precompilado — evasión a nivel de kernel desde el inicio"
        ((SUSPICIOUS_COUNT+=2))
    fi

    KSUNEXT_PROP=$(echo "$PROP_CACHE" | grep -im1 'ksunext\|com\.rifsxd')
    if [ -n "$KSUNEXT_PROP" ]; then
        log_output "${R}[!] KernelSU Next detectado en props: $KSUNEXT_PROP${N}"; ((SUSPICIOUS_COUNT+=3))
    fi
    if [ -n "$KSU_MOUNT" ]; then
        log_output "${R}[!] Módulos KernelSU montados:${N}"
        echo "$KSU_MOUNT" | while read -r line; do log_output "${Y}  $line${N}"; done
        ((SUSPICIOUS_COUNT+=2))
    fi
    echo ""
}

check_suspicious_packages() {
    sec_hdr "APLICACIONES SOSPECHOSAS / ROOT / CHEAT"
    declare -A SUSP_APPS
    SUSP_APPS=(
        ["com.topjohnwu.magisk"]="Magisk"
        ["io.github.magisk"]="Magisk"
        ["com.rifsxd.ksunext"]="KernelSU Next"
        ["me.weishu.kernelsu"]="KernelSU"
        ["me.bmax.apatch"]="APatch"
        ["io.github.huskydg.magisk"]="Magisk Delta"
        ["org.lsposed.manager"]="LSPosed Manager"
        ["com.dergoogler.mmrl"]="MMRL"
        ["com.googleplay.ndkvs"]="FF Modificado (.ndkvs)"
        ["eu.sisik.hackendebug"]="Hack&Debug"
        ["me.piebridge.brevent"]="Brevent"
        ["com.netflix.mediaclientxx"]="Netflix FALSO (cliente ADB embebido)"
        ["com.netflix.mediaclient.xx"]="Netflix FALSO variante"
        ["io.github.mhmrdd.libxposed.ps.passit"]="Passador de Replay (Xposed)"
        ["com.lexa.fakegps"]="Fake GPS"
        ["io.github.gamesiru"]="GameSiru (Panel Free Fire)"
        ["com.gamesiru.launcher"]="GameSiru Launcher"
        ["com.zhtools.chronos"]="Chronos (Panel FF)"
        ["com.aryanvichare.freefireonetap"]="FF OneTap Cheat"
        ["io.github.ggmouse"]="GG Mouse (Replay Tool)"
        ["com.gg.mouse"]="GG Mouse"
        ["org.chickenhook.restrictionbypass"]="RestrictionBypass"
        ["io.github.lsposed.manager"]="LSPosed Manager"
        ["io.github.vvb2060.mahoshojo"]="TrickyStore (Bypass)"
        ["com.opa334.TrollStore"]="TrollStore"
        ["com.reveny.nativecheck"]="NativeCheck"
        ["com.studio.duckdetector"]="Duck Detector"
        ["io.github.huskydg.memorydetector"]="MemoryDetector"
        ["moe.shizuku.privileged.api"]="Shizuku"
        ["moe.shizuku.starter"]="Shizuku"
        ["com.zhenxi.hunter"]="Shizuku Hunter"
        ["com.system.update.service"]="Servicio falso del sistema"
    )
    PKG_LIST="$PKG_CACHE"
    FOUND_SUSP=0
    for pkg in "${!SUSP_APPS[@]}"; do
        if echo "$PKG_LIST" | grep -q "package:$pkg"; then
            log_output "${R}[!] App sospechosa: ${SUSP_APPS[$pkg]} ($pkg)${N}"
            FOUND_SUSP=1; ((SUSPICIOUS_COUNT+=2))
            case "$pkg" in
                *lsposed*) log_output "${B}    ↳ LSPosed hookea el proceso Zygote — modifica Free Fire antes de que inicie${N}"; FOUND_LSPACED=1 ;;
                *shizuku*|*zhenxi*) FOUND_SHIZUKU=1 ;;
                *) FOUND_CHEAT_APP=1 ;;
            esac
        fi
    done
    log_output "${B}[+] Verificando instalador de $GAME_PKG...${N}"
    INSTALLER=$(adb shell "dumpsys package $GAME_PKG 2>/dev/null | grep 'installerPackageName'" | tr -d '\r' | head -1)
    if [ -n "$INSTALLER" ]; then
        log_output "${B}[*] $INSTALLER${N}"
        if echo "$INSTALLER" | grep -qiE "null|adb|sideload|bin.mt.plus|android.chrome|com.android.chrome"; then
            log_output "${R}[!] Instalador sospechoso: $INSTALLER${N}"; ((SUSPICIOUS_COUNT+=2)); FOUND_SUSP=1
        fi
    fi

    log_output "${B}[+] Verificando wrapper/modificación del juego...${N}"
    # Método 1: pm dump wrapper flag
    WRAPPER=$(adb shell "pm dump $GAME_PKG 2>/dev/null | grep -i wrapper" | tr -d '\r')
    if [ -n "$(echo "$WRAPPER" | tr -d '[:space:]')" ]; then
        log_output "${R}[!] WRAPPER FLAG DETECTADO:${N}"
        _ctx "Flag wrapper indica que el juego corre dentro de otro proceso — permite inyección de código sin detección directa"
        echo "$WRAPPER" | head -3 | while read -r l; do [ -n "$l" ] && log_output "${Y}  $l${N}"; done
        ((SUSPICIOUS_COUNT+=3)); FOUND_SUSP=1; FOUND_WRAPPER=1
    fi
    # Método 2 (KellerSS): verificar archivos de frameworks de hooks en directorio del juego
    for _hook_file in "libxposed_art.so" "libEdXposed.so" "libzygisk.so" "liblsplant.so" "librirud.so" "libapatch.so"; do
        _hf_found=$(adb shell "find /data/app/ -name '$_hook_file' 2>/dev/null | head -1" | tr -d '\r')
        if [ -n "$_hf_found" ]; then
            log_output "${R}[!] Archivo de hook framework detectado: $_hook_file${N}"
            _ctx "Librería de hook framework en sistema — LSPosed/Xposed/APatch pueden modificar cualquier función de Free Fire"
            log_output "${Y}  Ruta: $_hf_found${N}"
            ((SUSPICIOUS_COUNT+=4)); FOUND_SUSP=1; FOUND_WRAPPER=1
        fi
    done
    # Método 3 (KellerSS): verificar firmas de APKs de hook en /data/local/tmp y /sdcard
    for _hook_path in "/data/local/tmp" "/sdcard/Download"; do
        _apks=$(adb shell "find '$_hook_path' -name '*.apk' 2>/dev/null" | tr -d '\r' | grep -v 'unknown-monitor.apk')
        if [ -n "$_apks" ]; then
            log_output "${B}[*] APKs presentes en $_hook_path:${N}"
            echo "$_apks" | while read -r _a; do [ -n "$_a" ] && log_output "${W}  $_a${N}"; done
            _apks_susp=$(echo "$_apks" | grep -iE 'cheat|hack|wallhack|\besp\b|aimbot|inject|wrapper|lsposed|xposed|magisk|\bmod\b|mods|modded|ffh4x|apkmod|keygen|crack|mt_manager|mtmanager')
            if [ -n "$_apks_susp" ]; then
                log_output "${R}[!] APK con nombre asociado a cheats en $_hook_path:${N}"
                echo "$_apks_susp" | while read -r _a; do [ -n "$_a" ] && log_output "${Y}  $_a${N}"; done
                ((SUSPICIOUS_COUNT+=3)); FOUND_SUSP=1
            fi
        fi
    done

    log_output "${B}[+] Verificando indicadores de APK crackeado...${N}"
    CRACKED=$(adb shell "pm dump $GAME_PKG 2>/dev/null | grep -iE 'cracked|modded|lsposed'" | tr -d '\r')
    if [ -n "$(echo "$CRACKED" | tr -d '[:space:]')" ]; then
        log_output "${R}[!] APK CRACKEADO/MODIFICADO DETECTADO:${N}"
        echo "$CRACKED" | head -3 | while read -r l; do [ -n "$l" ] && log_output "${Y}  $l${N}"; done
        ((SUSPICIOUS_COUNT+=3)); FOUND_SUSP=1
    fi

    [ $FOUND_SUSP -eq 0 ] && log_output "${G}[✓] Sin apps sospechosas${N}"
    echo ""
}

check_network_ports() {
    sec_hdr "PUERTOS Y CONEXIONES SOSPECHOSAS"
    log_output "${B}[+] Verificando puertos Frida (27042/27043)...${N}"
    FRIDA_PORT=$(echo "$TCP_CACHE" | grep -iE ':(69B2|69B3) ' | grep -E ' 0A ' | head -3)
    if [ -n "$(echo "$FRIDA_PORT" | tr -d '[:space:]')" ]; then
        log_output "${R}[!] PUERTOS FRIDA EN LISTEN:${N}"
        _ctx "Frida es framework de instrumentación dinámica — hookea funciones de Free Fire en tiempo real para modificar comportamiento"
        echo "$FRIDA_PORT" | while read -r line; do [ -n "$line" ] && log_output "${Y}  $line${N}"; done
        ((SUSPICIOUS_COUNT+=3))
    else
        log_output "${G}[✓] Sin puertos Frida${N}"
    fi
    log_output "${B}[+] Verificando proxy HTTP...${N}"
    HTTP_PROXY=$(adb shell "settings get global http_proxy 2>/dev/null" | tr -d '\r')
    if [ -n "$HTTP_PROXY" ] && [ "$HTTP_PROXY" != "null" ] && [ "$HTTP_PROXY" != ":0" ]; then
        log_output "${R}[!] PROXY HTTP: $HTTP_PROXY${N}"; ((SUSPICIOUS_COUNT+=2))
    else
        log_output "${G}[✓] Sin proxy HTTP${N}"
    fi
    log_output "${B}[+] Verificando proxy Wi-Fi...${N}"
    WIFI_PROXY=$(adb shell "content query --uri content://settings/global/wifi_proxy_host 2>/dev/null" | tr -d '\r')
    if echo "$WIFI_PROXY" | grep -qE "value=.+[^null]"; then
        log_output "${R}[!] Proxy Wi-Fi configurado: $WIFI_PROXY${N}"; ((SUSPICIOUS_COUNT+=2))
    else
        log_output "${G}[✓] Sin proxy Wi-Fi${N}"
    fi
    echo ""
}

check_nmap_portscan() {
    sec_hdr "ESCANEO EXTERNO DE PUERTOS (NMAP)"
    if ! command -v nmap >/dev/null 2>&1; then
        log_output "${Y}[*] nmap no instalado, instalando...${N}"
        pkg install -y nmap >/dev/null 2>&1
    fi
    if ! command -v nmap >/dev/null 2>&1; then
        log_output "${R}[!] No se pudo instalar nmap — se omite el escaneo externo${N}"
        echo ""
        return
    fi
    TARGET_IP=$(adb shell "ip route get 1.1.1.1 2>/dev/null" | tr -d '\r' | grep -oE 'src [0-9.]+' | awk '{print $2}')
    [ -z "$TARGET_IP" ] && TARGET_IP=$(adb shell "ip addr show wlan0 2>/dev/null" | tr -d '\r' | grep -oE 'inet [0-9.]+' | awk '{print $2}' | head -1)
    if [ -z "$TARGET_IP" ]; then
        log_output "${Y}[*] No se pudo obtener la IP del dispositivo (¿WiFi apagado o sin ruta?) — se omite${N}"
        echo ""
        return
    fi
    log_output "${B}[*] IP del dispositivo: ${W}$TARGET_IP${N}"
    log_output "${B}[+] nmap -p 5500-5600 -sV (verifica a nivel de red real, no puede ser falseado por hooks locales)...${N}"
    NMAP_OUT=$(timeout 90 nmap -p 5500-5600 -sV "$TARGET_IP" 2>/dev/null)
    echo "$NMAP_OUT" | while read -r line; do [ -n "$line" ] && log_output "${W}  $line${N}"; done
    if echo "$NMAP_OUT" | grep -qE '^55[0-9]{2}/tcp[[:space:]]+open'; then
        log_output "${B}[*] Puerto ADB abierto según nmap (informativo — si escaneaste por wifi, es el mismo puerto que usa el scanner para conectarse)${N}"
    fi
    echo ""
}

check_adb_connections() {
    sec_hdr "CONEXIONES ADB / CONTROL REMOTO"
    USB_STATE=$(adb shell "getprop sys.usb.state 2>/dev/null" | tr -d '\r')
    log_output "${B}[*] USB state: ${W}${USB_STATE:-desconocido}${N}"

    ADB_TCP_PORT=$(adb shell "getprop service.adb.tcp.port 2>/dev/null" | tr -d '\r')
    if [ -n "$ADB_TCP_PORT" ] && [ "$ADB_TCP_PORT" != "-1" ]; then
        log_output "${R}[!] ADB INALÁMBRICO ACTIVO (puerto TCP $ADB_TCP_PORT)${N}"
        _ctx "ADB por TCP/IP permite control remoto sin cable — se usa para inyectar inputs o desplegar hooks sin acceso físico al dispositivo"
        ((SUSPICIOUS_COUNT+=2))
    fi
    SS_5555=$(adb shell "ss -tuln 2>/dev/null | grep ':5555'" | tr -d '\r')
    if [ -n "$(echo "$SS_5555" | tr -d '[:space:]')" ]; then
        log_output "${R}[!] PUERTO 5555 ABIERTO (ss -tuln)${N}"
        _ctx "Confirma por segunda vía (además de getprop) que el puerto estándar de ADB inalámbrico está escuchando"
        ((SUSPICIOUS_COUNT+=2))
    fi
    ADB_WIFI_SETTING=$(adb shell "settings get global adb_wifi_enabled 2>/dev/null" | tr -d '\r')
    if [ "$ADB_WIFI_SETTING" = "1" ]; then
        log_output "${B}[*] Depuración inalámbrica habilitada en Ajustes (esperable si escaneaste por wifi)${N}"
    fi

    JDWP_PIDS=$(timeout 2 adb jdwp 2>/dev/null | tr -d '\r')
    if [ -n "$(echo "$JDWP_PIDS" | tr -d '[:space:]')" ]; then
        log_output "${R}[!] PROCESOS JDWP-DEBUGGABLE ACTIVOS:${N}"
        _ctx "JDWP permite adjuntar un debugger Java en runtime — se usa para inspeccionar y modificar memoria del proceso del juego en vivo"
        echo "$JDWP_PIDS" | while read -r pid; do [ -n "$pid" ] && log_output "${Y}  PID: $pid${N}"; done
        ((SUSPICIOUS_COUNT+=3))
    fi

    ADB_READ_FAIL=$(echo "$LOG_CACHE" | grep -c "AdbDebuggingManager.*Read failed" 2>/dev/null || echo 0)
    if [ "${ADB_READ_FAIL:-0}" -gt 6 ] 2>/dev/null; then
        log_output "${Y}[*] AdbDebuggingManager: $ADB_READ_FAIL fallos de lectura de claves (informativo — reconexiones normales también generan esto)${N}"
    fi

    # Antes esto matcheaba 'usb|mtp|device|connect|disconnect' contra las últimas 500 líneas de
    # logcat: eso captura prácticamente cualquier actividad normal del sistema (wifi, notificaciones,
    # el propio scanner conectándose por ADB) y disparaba en casi todos los escaneos. Ahora solo se
    # buscan eventos que son específicos de una revocación real de autorización ADB.
    USB_REVOKE_LOG=$(adb shell "logcat -v time -d -t 500 2>/dev/null | grep -iE 'adb.*(revok|unauthoriz)|keys?.*(cleared|removed).*adb|AdbDebuggingManager.*(onDisconnect|[Rr]evoke)'" | tr -d '\r' | grep -vE 'adbd|logcat|adb shell' | tail -10)
    if [ -n "$(echo "$USB_REVOKE_LOG" | tr -d '[:space:]')" ]; then
        log_output "${Y}[*] Eventos de revocación ADB en logcat:${N}"
        _ctx "Revocar autorizaciones ADB desde Ajustes de desarrollador puede usarse para borrar el rastro de qué PC estuvo conectada"
        echo "$USB_REVOKE_LOG" | while read -r line; do [ -n "$line" ] && log_output "${W}  $line${N}"; done
    fi

    WIRELESS_ADB_HIST=$(adb shell "dumpsys activity broadcasts history 2>/dev/null | grep -iE 'adb_wifi|WIRELESS_DEBUG|adb.*pairing' | head -5" | tr -d '\r')
    if [ -n "$(echo "$WIRELESS_ADB_HIST" | tr -d '[:space:]')" ]; then
        log_output "${B}[*] Historial de activación de ADB inalámbrico (informativo — el propio scanner usa ADB inalámbrico, no cuenta como sospechoso por sí solo):${N}"
        echo "$WIRELESS_ADB_HIST" | while read -r l; do [ -n "$l" ] && log_output "${W}  $l${N}"; done
    fi

    DATA_ADB_PROCS=$(adb shell 'for f in /proc/[0-9]*/exe; do l=$(readlink "$f" 2>/dev/null); case "$l" in /data/adb/*ksud*|/data/adb/*magiskd*|/data/adb/*apd*) continue;; /data/adb/*) echo "${f%%/exe}: $l";; esac; done 2>/dev/null | head -5' | tr -d '\r')
    if [ -n "$(echo "$DATA_ADB_PROCS" | tr -d '[:space:]')" ]; then
        log_output "${R}[!] Procesos desde /data/adb/:${N}"
        echo "$DATA_ADB_PROCS" | while read -r line; do [ -n "$line" ] && log_output "${Y}  $line${N}"; done
        ((SUSPICIOUS_COUNT+=2))
    else
        log_output "${G}[✓] Sin procesos inesperados en /data/adb/${N}"
    fi
    echo ""
}

check_uninstalled_apps() {
    sec_hdr "APPS SOSPECHOSAS DESINSTALADAS"
    UNINST=$(adb shell "dumpsys batterystats 2>/dev/null | grep -oE 'pkgunin=[0-9]+:\"[^\"]+\"' | grep -oE '\"[^\"]+\"' | tr -d '\"' | sort -u" | tr -d '\r')

    # dumpsys connectivity guarda su propio historial de paquetes removidos (limpieza de políticas
    # de red por UID) con su propio ciclo de rotación, distinto al de batterystats/logcat — se suma
    # como tercera fuente independiente para pescar desinstalaciones que las otras dos ya perdieron.
    CONN_UNINST_RAW=$(adb shell "dumpsys connectivity 2>/dev/null | grep -iE 'UNINSTALLED|package.?remov'" | tr -d '\r')
    CONN_UNINST=$(echo "$CONN_UNINST_RAW" | grep -oE '[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*){2,}' | sort -u)

    ALL_UNINST=$(printf '%s\n%s' "$UNINST" "$CONN_UNINST" | grep -v '^$' | sort -u)
    FOUND_U=0
    if [ -n "$ALL_UNINST" ]; then
        while read -r pkg; do
            [ -z "$pkg" ] && continue
            if echo "$pkg" | grep -qiE "magisk|xposed|kernelsu|apatch|frida|hook|cheat|hack|bypass|inject|passit"; then
                log_output "${Y}[!] App sospechosa desinstalada: $pkg${N}"; ((SUSPICIOUS_COUNT++)); FOUND_U=1
            fi
        done <<< "$ALL_UNINST"
    fi
    [ $FOUND_U -eq 0 ] && log_output "${G}[✓] Sin apps sospechosas en historial${N}"
    if [ -n "$(echo "$CONN_UNINST" | tr -d '[:space:]')" ] && [ -z "$(echo "$UNINST" | tr -d '[:space:]')" ]; then
        log_output "${B}[*] Historial recuperado vía dumpsys connectivity (batterystats no tenía datos)${N}"
    fi

    _since=$(date -d '-1 day' '+%m-%d %H:%M:%S.000' 2>/dev/null)
    if [ -n "$_since" ]; then
        UNINSTALL_RAW=$(adb shell "logcat -v time -d -T '$_since' 2>/dev/null | grep -iE 'PackageManager|PackageInstaller'" | tr -d '\r')
    else
        UNINSTALL_RAW=$(adb shell "logcat -v time -d -t 3000 2>/dev/null | grep -iE 'PackageManager|PackageInstaller'" | tr -d '\r')
    fi
    UNINSTALL_LOG=$(echo "$UNINSTALL_RAW" | grep -iE 'delet|uninstall|remov' | grep -vE 'adbd|logcat|adb shell' | head -10)
    if [ -n "$(echo "$UNINSTALL_LOG" | tr -d '[:space:]')" ]; then
        log_output "${Y}[*] Desinstalaciones en las últimas 24h:${N}"
        echo "$UNINSTALL_LOG" | while read -r line; do
            [ -z "$line" ] && continue
            _pkgname=$(echo "$line" | grep -oE '[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*){2,}' | head -1)
            log_output "${W}  $line${N}"
            [ -n "$_pkgname" ] && log_output "${Y}    ↳ app: $_pkgname${N}"
        done
        if echo "$UNINSTALL_LOG" | grep -qiE '2000|shell'; then
            log_output "${R}[!] Desinstalación con UID Shell (2000) detectada — ejecutada por comando, no desde Ajustes${N}"
            _ctx "adb shell pm uninstall deja este rastro en logcat — técnica común para borrar apps de cheat justo después de terminar la partida"
            ((SUSPICIOUS_COUNT+=3))
        fi
        [ -n "$NEWEST_MTIME" ] && log_output "${B}[*] Replay más reciente: $NEWEST_MTIME — compará el horario con los eventos de arriba${N}"
    fi
    echo ""
}

check_media_projection() {
    sec_hdr "CAPTURA DE PANTALLA / MEDIA PROJECTION"
    MEDIA_PROJ=$(adb shell "dumpsys media_projection 2>/dev/null | grep -iE 'isRecording=true|state.*record|projection.*active' | head -5" | tr -d '\r')
    if [ -n "$(echo "$MEDIA_PROJ" | tr -d '[:space:]')" ]; then
        log_output "${R}[!] CAPTURA DE PANTALLA ACTIVA:${N}"
        _ctx "MediaProjection activa durante el juego indica grabación o transmisión en vivo — herramienta de replay externo activa"
        echo "$MEDIA_PROJ" | while read -r line; do [ -n "$line" ] && log_output "${Y}  $line${N}"; done
        ((SUSPICIOUS_COUNT+=2))
    else
        log_output "${G}[✓] Sin captura de pantalla activa${N}"
    fi
    echo ""
}

check_data_local_tmp() {
    sec_hdr "ARCHIVOS EN /DATA/LOCAL/TMP"
    TMP_FILES=$(adb shell 'for f in /data/local/tmp/* /data/local/tmp/.*; do n="${f##*/}"; case "$n" in "." | "..") ;; *) [ -e "$f" ] && echo "$n";; esac; done' | tr -d '\r' | grep -vE '^unknown-monitor\.apk$|^unknown_monitor\.txt$|^unknown_logs\.txt$')
    # Detectar si /data/local/tmp fue modificado recientemente pero está vacío
    _tmp_mtime=$(adb shell "stat /data/local/tmp 2>/dev/null | grep -i 'Modify\|modify'" | tr -d '\r' | head -1)
    if [ -z "$(echo "$TMP_FILES" | tr -d '[:space:]')" ] && [ -n "$_tmp_mtime" ]; then
        _tmp_age=$(adb shell "find /data/local/tmp -maxdepth 0 -newer /proc/uptime -mmin -30 2>/dev/null" | tr -d '\r')
        if [ -n "$_tmp_age" ]; then
            log_output "${R}[!] /data/local/tmp modificado recientemente pero vacío — posible limpieza de rastros${N}"
            _ctx "Limpieza de tmp post-partida indica que el usuario eliminó payloads o herramientas antes del scan — huella de herramienta"
            log_output "${Y}    Última modificación: $_tmp_mtime${N}"
            MOTIVOS+=("tmp limpiado recientemente")
            ((SUSPICIOUS_COUNT+=2))
        fi
    fi
    if [ -n "$(echo "$TMP_FILES" | tr -d '[:space:]')" ]; then
        log_output "${Y}[!] Archivos en /data/local/tmp:${N}"
        echo "$TMP_FILES" | while read -r f; do
            [ -z "$f" ] && continue
            log_output "${Y}  $f${N}"
            if echo "$f" | grep -qiE "frida|hook|inject|cheat|hack|bypass|shizuku|brevent"; then
                log_output "${R}    ^ SOSPECHOSO${N}"; ((SUSPICIOUS_COUNT++))
            fi
        done
        ((SUSPICIOUS_COUNT++))
    else
        log_output "${G}[✓] /data/local/tmp vacío${N}"
    fi
    echo ""
}

check_dropbox_crashes() {
    sec_hdr "CRASHES SOSPECHOSOS (DROPBOX)"
    CRASHES=$(adb shell 'dumpsys dropbox 2>/dev/null | grep -E "native_crash|TOMBSTONE|system_server" | sed "s/.*[0-9][0-9]:[0-9][0-9]:[0-9][0-9] //" | sed "s/ ([0-9]* bytes)//" | sort | uniq -c | sort -rn | awk '"'"'$1>=3{print $1" x "$2}'"'"' | head -5' | tr -d '\r')
    if [ -n "$(echo "$CRASHES" | tr -d '[:space:]')" ]; then
        log_output "${Y}[!] Crashes repetidos:${N}"
        echo "$CRASHES" | while read -r line; do [ -n "$line" ] && log_output "${Y}  $line${N}"; done
        ((SUSPICIOUS_COUNT++))
    else
        log_output "${G}[✓] Sin crashes repetidos${N}"
    fi
    PHANTOM=$(echo "$LOG_CACHE" | grep "PhantomProcessRecord" | tail -3)
    if [ -n "$PHANTOM" ]; then
        log_output "${Y}[!] PhantomProcessRecord (procesos matados):${N}"
        echo "$PHANTOM" | while read -r line; do log_output "${Y}  $line${N}"; done
    fi
    echo ""
}

check_auto_time() {
    sec_hdr "CONFIGURACIÓN DE FECHA/HORA"
    AUTO_TIME=$(adb shell "settings get global auto_time 2>/dev/null" | tr -d '\r')
    AUTO_TZ=$(adb shell "settings get global auto_time_zone 2>/dev/null" | tr -d '\r')
    TIMEZONE=$(adb shell "getprop persist.sys.timezone 2>/dev/null" | tr -d '\r')
    log_output "${B}[*] auto_time:     ${W}${AUTO_TIME:-desconocido}${N}"
    log_output "${B}[*] auto_time_zone:${W}${AUTO_TZ:-desconocido}${N}"
    log_output "${B}[*] Zona horaria:  ${W}${TIMEZONE:-desconocida}${N}"
    if [ "$AUTO_TIME" = "0" ]; then
        log_output "${R}[!] Hora automática DESACTIVADA — facilita manipulación de timestamps${N}"
        _ctx "NTP desactivado permite ajustar el reloj manualmente para congelar o retroceder el tiempo del sistema"
        ((SUSPICIOUS_COUNT+=2))
    else
        log_output "${G}[✓] Hora automática activa${N}"
    fi
    echo ""
}

check_pif() {
    sec_hdr "PLAY INTEGRITY FIX / SPOOF DE INTEGRIDAD"
    FOUND_PIF=0

    PKG_LIST_PIF="$PKG_CACHE"
    for pkg in "es.chiteroman.playintegrityfix" "com.chiteroman.playintegrityfix" "io.github.vvb2060.playintegrityfix"; do
        if echo "$PKG_LIST_PIF" | grep -q "$pkg"; then
            log_output "${R}[!] Play Integrity Fix instalado: $pkg${N}"
            _ctx "PIF falsifica la respuesta de Play Integrity API — oculta root y bootloader desbloqueado al juego"
            ((SUSPICIOUS_COUNT+=3)); FOUND_PIF=1
        fi
    done

    PIF_MOD=$(adb shell "ls /data/adb/modules 2>/dev/null | grep -iE 'playintegrity|pif|integrit'" | tr -d '\r')
    if [ -n "$PIF_MOD" ]; then
        log_output "${R}[!] Módulo PIF en Magisk: $PIF_MOD${N}"; ((SUSPICIOUS_COUNT+=3)); FOUND_PIF=1
    fi

    TRICK=$(adb shell "ls /data/adb/modules 2>/dev/null | grep -i trick" | tr -d '\r')
    if [ -n "$TRICK" ]; then
        log_output "${R}[!] TrickyStore (bypass de integridad): $TRICK${N}"
        _ctx "TrickyStore genera certificados KeyAttestation falsos — supera incluso Play Integrity STRONG"
        ((SUSPICIOUS_COUNT+=3)); FOUND_PIF=1
    fi

    DEBUGGABLE=$(adb shell "getprop ro.debuggable 2>/dev/null" | tr -d '\r')
    if [ "$DEBUGGABLE" = "1" ]; then
        log_output "${Y}[!] ro.debuggable=1 — dispositivo en modo debug${N}"; ((SUSPICIOUS_COUNT++))
    fi

    [ $FOUND_PIF -eq 0 ] && log_output "${G}[✓] Sin Play Integrity Fix${N}"
    echo ""
}

check_fakegps() {
    sec_hdr "FAKE GPS / LOCATION SPOOFING"
    local _found=0
    local _gps_pkgs
    _gps_pkgs=$(echo "$PKG_CACHE" | grep -iE         "fakegps|gps.joystick|lexa.fakegps|incorporateapps.com.fakeGPS|fakegps|mock.location|location.spoof|gps.spoofer|hola.fake.gps|byterev.fakegps|keinmor.fakegps|blogspot.fakegps" | tr -d '\r')
    if [ -n "$_gps_pkgs" ]; then
        echo "$_gps_pkgs" | while IFS= read -r _pkg; do
            [ -z "$_pkg" ] && continue
            log_output "${R}[!] App de Fake GPS detectada: $_pkg${N}"
            _ctx "Fake GPS falsifica coordenadas de ubicación — usado para evadir bans por región o acceder a servidores distintos"
            ((SUSPICIOUS_COUNT+=3)); _found=1
        done
        _found=1
    fi

    local _mock
    _mock=$(adb shell "settings get secure mock_location 2>/dev/null" | tr -d '\r')
    if [ "$_mock" = "1" ]; then
        log_output "${R}[!] Mock Location activado en configuración del sistema${N}"
        _ctx "Mock Location a nivel de sistema permite a cualquier app reemplazar la ubicación GPS real del dispositivo"
        ((SUSPICIOUS_COUNT+=2)); _found=1
    fi

    local _mock_app
    _mock_app=$(adb shell "appops query-op android:mock_location allow 2>/dev/null" | tr -d '\r' | grep -v '^$' | grep -vi "no operations" | head -3)
    if [ -n "$_mock_app" ]; then
        log_output "${R}[!] App con permiso Mock Location activo: $_mock_app${N}"
        ((SUSPICIOUS_COUNT+=2)); _found=1
    fi

    [ $_found -eq 0 ] && log_output "${G}[✓] Sin Fake GPS detectado${N}"
    echo ""
}

check_ueventd() {
    sec_hdr "UEVENTD / KERNEL EVENTS"
    local _found=0

    local _ueventd_mod
    _ueventd_mod=$(adb shell "ls -la /system/etc/ueventd.rc 2>/dev/null" | tr -d '\r')
    local _ueventd_extra
    _ueventd_extra=$(adb shell "find /system/etc -name 'ueventd*.rc' 2>/dev/null | grep -v '^/system/etc/ueventd.rc$'" | tr -d '\r')
    if [ -n "$_ueventd_extra" ]; then
        echo "$_ueventd_extra" | while IFS= read -r _f; do
            [ -z "$_f" ] && continue
            log_output "${R}[!] Archivo ueventd adicional sospechoso: $_f${N}"
            ((SUSPICIOUS_COUNT+=3)); _found=1
        done
        _found=1
    fi

    local _ueventd_data
    _ueventd_data=$(adb shell "find /data -name 'ueventd*' 2>/dev/null | head -5" | tr -d '\r')
    if [ -n "$(echo "$_ueventd_data" | tr -d '[:space:]')" ]; then
        echo "$_ueventd_data" | while IFS= read -r _f; do
            [ -z "$_f" ] && continue
            log_output "${R}[!] ueventd en /data (anómalo): $_f${N}"
            _ctx "ueventd en /data indica custom rules para crear device nodes — usado por algunos cheats para inyectar código vía /dev"
            ((SUSPICIOUS_COUNT+=4)); _found=1
        done
        _found=1
    fi

    local _ueventd_pid
    _ueventd_pid=$(adb shell "ps -A 2>/dev/null | grep -w ueventd | grep -v grep" | tr -d '\r')
    if [ -n "$_ueventd_pid" ]; then
        local _uid
        _uid=$(echo "$_ueventd_pid" | awk '{print $1}' | head -1)
        if [ "$_uid" != "root" ] && [ -n "$_uid" ]; then
            log_output "${R}[!] ueventd corriendo con UID inesperado: $_uid${N}"
            ((SUSPICIOUS_COUNT+=3)); _found=1
        else
            log_output "${G}[✓] ueventd: UID root normal${N}"
        fi
    fi

    [ $_found -eq 0 ] && log_output "${G}[✓] Sin anomalías en ueventd${N}"
    echo ""
}

check_device_spoof() {
    sec_hdr "DEVICE SPOOFING / EVASIÓN DE BAN"
    FOUND_SPOOF=0

    ANDROID_ID=$(adb shell "settings get secure android_id 2>/dev/null" | tr -d '\r\n')
    log_output "${B}[*] Android ID: ${W}${ANDROID_ID:-no disponible}${N}"
    if [ -n "$ANDROID_ID" ] && [ "$ANDROID_ID" != "null" ]; then
        UNIQ=$(echo "$ANDROID_ID" | grep -oE '.' | sort -u | wc -l)
        ID_LEN=${#ANDROID_ID}
        if [ "$UNIQ" -le 2 ] || [ "$ID_LEN" -lt 15 ] 2>/dev/null; then
            log_output "${R}[!] Android ID con patrón de spoof${N}"; ((SUSPICIOUS_COUNT+=2)); FOUND_SPOOF=1
        fi
    fi

    HW_SERIAL=$(adb shell 'cat /sys/devices/soc0/serial_num 2>/dev/null || cat /sys/bus/soc/devices/soc0/serial_num 2>/dev/null' | tr -d '\r\n')
    PROP_SERIAL=$(adb shell "getprop ro.serialno 2>/dev/null" | tr -d '\r\n')
    if [ -n "$HW_SERIAL" ] && [ -n "$PROP_SERIAL" ] && [ "$HW_SERIAL" != "$PROP_SERIAL" ]; then
        log_output "${R}[!] Serial adulterado — SoC: $HW_SERIAL ≠ prop: $PROP_SERIAL${N}"
        _ctx "Serial de SoC ≠ serial de prop indica spoof de identificadores de hardware — evasión de ban por HWID"
        ((SUSPICIOUS_COUNT+=3)); FOUND_SPOOF=1
    fi

    PKG_LIST_SP="$PKG_CACHE"
    for pkg in "com.metatech.deviceidfaker" "com.deviceid.changer" "com.xposed.imei" "com.imei.generator" "com.devicechanger.free"; do
        if echo "$PKG_LIST_SP" | grep -q "$pkg"; then
            log_output "${R}[!] App de spoof de ID: $pkg${N}"; ((SUSPICIOUS_COUNT+=3)); FOUND_SPOOF=1
        fi
    done
    SPOOF_NAME=$(echo "$PKG_LIST_SP" | grep -iE "$(printf '%s%s' "$(printf 'ZGV2aWNlaWR8aW1laS5jaGFuZw=='|base64 -d)" "$(printf 'ZXJ8ZmFrZWlkfGFuZHJvaWRpZA=='|base64 -d)")" | head -3)
    if [ -n "$SPOOF_NAME" ]; then
        log_output "${R}[!] App de spoof por nombre:${N}"
        echo "$SPOOF_NAME" | while read -r l; do [ -n "$l" ] && log_output "${Y}  $l${N}"; done
        ((SUSPICIOUS_COUNT+=3)); FOUND_SPOOF=1
    fi

    FIRST_INSTALL_MS=$(adb shell "dumpsys package $GAME_PKG 2>/dev/null | grep firstInstallTime | head -1 | grep -oE '[0-9]{10,}'" | tr -d '\r')
    UPTIME_SECS=$(adb shell "cut -d. -f1 /proc/uptime 2>/dev/null" | tr -d '\r')
    NOW_SECS=$(adb shell "date +%s 2>/dev/null" | tr -d '\r')
    if [ -n "$FIRST_INSTALL_MS" ] && [ -n "$NOW_SECS" ] && [ -n "$UPTIME_SECS" ]; then
        FIRST_S=$((FIRST_INSTALL_MS / 1000))
        BOOT_EPOCH=$((NOW_SECS - UPTIME_SECS))
        INSTALL_DAYS=$(( (NOW_SECS - FIRST_S) / 86400 ))
        UPTIME_DAYS=$((UPTIME_SECS / 86400))
        log_output "${B}[*] Juego instalado hace: ${W}${INSTALL_DAYS}d${N}  |  Uptime: ${W}${UPTIME_DAYS}d${N}"
        if [ "$FIRST_S" -gt "$BOOT_EPOCH" ] && [ "$UPTIME_SECS" -gt 86400 ] 2>/dev/null; then
            log_output "${Y}[!] Juego instalado después del último boot (reinstalación post-ban)${N}"
            _ctx "Reinstalación posterior al boot puede indicar cambio de cuenta o HWID tras ban reciente"
            ((SUSPICIOUS_COUNT+=2)); FOUND_SPOOF=1
        fi
        if [ "$INSTALL_DAYS" -le 3 ] && [ "$UPTIME_DAYS" -ge 7 ] 2>/dev/null; then
            log_output "${Y}[!] Reinstalación reciente: juego ${INSTALL_DAYS}d vs dispositivo activo ${UPTIME_DAYS}d${N}"
            ((SUSPICIOUS_COUNT++)); FOUND_SPOOF=1
        fi
    fi

    [ $FOUND_SPOOF -eq 0 ] && log_output "${G}[✓] Sin indicadores de spoof${N}"
    echo ""
}

check_ca_certs() {
    sec_hdr "CERTIFICADOS CA / MITM"
    USER_CERTS=$(adb shell "ls /data/misc/user/0/cacerts-added/ 2>/dev/null | wc -l" | tr -d '\r')
    if [ "${USER_CERTS:-0}" -gt 0 ] 2>/dev/null; then
        log_output "${R}[!] $USER_CERTS certificado(s) CA de usuario instalado(s) — posible MITM${N}"
        _ctx "CA certs de usuario permiten descifrar TLS de Free Fire — herramientas como Fiddler/mitmproxy los requieren"
        ((SUSPICIOUS_COUNT+=2))
    else
        log_output "${G}[✓] Sin CA certs de usuario${N}"
    fi

    KC_CERTS=$(adb shell "ls /data/misc/keychain/certs-added/ 2>/dev/null | wc -l" | tr -d '\r')
    if [ "${KC_CERTS:-0}" -gt 0 ] 2>/dev/null; then
        log_output "${Y}[!] $KC_CERTS cert(s) en keychain del sistema${N}"; ((SUSPICIOUS_COUNT++))
    fi

    SSH_KEYS=$(adb shell "find /data/adb /data/local /sdcard 2>/dev/null -maxdepth 4 \( -name 'authorized_keys' -o -name 'id_rsa' -o -name 'id_ed25519' \) | head -3" | tr -d '\r')
    if [ -n "$(echo "$SSH_KEYS" | tr -d '[:space:]')" ]; then
        log_output "${R}[!] Claves SSH encontradas (tunnel de evasión):${N}"
        _ctx "Claves SSH permiten túnel remoto para controlar el dispositivo sin ADB — evasión de detección de conexiones"
        echo "$SSH_KEYS" | while read -r f; do [ -n "$f" ] && log_output "${Y}  $f${N}"; done
        ((SUSPICIOUS_COUNT+=2))
    fi
    echo ""
}

check_mantis_keymap() {
    sec_hdr "KEYMAPPERS / CONTROLES EXTERNOS"
    FOUND_KM=0

    PKG_LIST_KM="$PKG_CACHE"
    declare -A KM_APPS
    KM_APPS=(
        ["com.mantis.gamepad"]="Mantis Gamepad"
        ["com.panda.gamepad"]="Panda Gamepad"
        ["com.gamesir.global"]="GameSir"
        ["com.flydigi.center"]="Flydigi"
        ["com.tincore.gsp.gpad"]="Octopus Keymapper"
        ["io.github.ggmouse"]="GG Mouse"
        ["com.regula.mantisactivator"]="Mantis Activator"
    )
    for pkg in "${!KM_APPS[@]}"; do
        if echo "$PKG_LIST_KM" | grep -q "$pkg"; then
            log_output "${Y}[!] Keymapper: ${KM_APPS[$pkg]} ($pkg)${N}"; ((SUSPICIOUS_COUNT+=2)); FOUND_KM=1
        fi
    done
    KM_NAME=$(echo "$PKG_LIST_KM" | grep -iE "$(printf '%s%s' "$(printf 'bWFudGlzfGtleW1hcHxn'|base64 -d)" "$(printf 'YW1lcGFkLiphY3RpdmF0'|base64 -d)")" | head -3)
    if [ -n "$KM_NAME" ] && [ $FOUND_KM -eq 0 ]; then
        log_output "${Y}[!] Keymapper por nombre:${N}"
        echo "$KM_NAME" | while read -r l; do [ -n "$l" ] && log_output "${Y}  $l${N}"; done
        ((SUSPICIOUS_COUNT+=2)); FOUND_KM=1
    fi

    [ $FOUND_KM -eq 0 ] && log_output "${G}[✓] Sin keymappers${N}"
    echo ""
}

check_recording() {
    sec_hdr "GRABACIÓN / ESPEJAMIENTO / SCRCPY"
    FOUND_REC=0

    PKG_LIST_REC="$PKG_CACHE"
    declare -A MIRROR_APPS
    MIRROR_APPS=(
        ["com.koushikdutta.vysor"]="Vysor"
        ["com.genymobile.scrcpy"]="scrcpy"
        ["com.github.xianfeng92.scrcpy"]="QtScrcpy"
        ["top.samir.guiscrcpy"]="guiScrcpy"
    )
    for pkg in "${!MIRROR_APPS[@]}"; do
        if echo "$PKG_LIST_REC" | grep -q "$pkg"; then
            log_output "${Y}[!] App de espejamiento: ${MIRROR_APPS[$pkg]}${N}"; ((SUSPICIOUS_COUNT++)); FOUND_REC=1
        fi
    done

    MEDIA_PROJ=$(adb shell "dumpsys media_projection 2>/dev/null | grep -iE 'isRecording=true|state=STARTED' | head -2" | tr -d '\r')
    if [ -n "$(echo "$MEDIA_PROJ" | tr -d '[:space:]')" ]; then
        log_output "${R}[!] CAPTURA DE PANTALLA ACTIVA${N}"
        _ctx "Captura de pantalla activa durante el juego es la técnica base de herramientas de replay y transmisión de partidas"
        ((SUSPICIOUS_COUNT+=2)); FOUND_REC=1
    fi

    SCRCPY_PROC=$(echo "$PS_CACHE" | grep -i scrcpy)
    if [ -n "$SCRCPY_PROC" ]; then
        log_output "${R}[!] Proceso scrcpy activo${N}"
        _ctx "scrcpy es la herramienta más usada para transmitir pantalla vía ADB — base de la mayoría de replay tools"
        ((SUSPICIOUS_COUNT+=2)); FOUND_REC=1
    fi

    REC_LOCK=$(adb shell "cat /proc/net/unix 2>/dev/null | grep -iE 'recordLock|recordUnlock' | head -2" | tr -d '\r')
    if [ -n "$(echo "$REC_LOCK" | tr -d '[:space:]')" ]; then
        log_output "${R}[!] Record lock en sockets Unix${N}"; ((SUSPICIOUS_COUNT+=2)); FOUND_REC=1
    fi

    [ $FOUND_REC -eq 0 ] && log_output "${G}[✓] Sin grabación activa${N}"
    echo ""
}

check_scenes() {
    sec_hdr "MODIFICACIÓN DE ESCENAS / ASSETS / PAYLOAD"
    FOUND_SC=0

    NDKVS=$(adb shell "find /sdcard/Android/data/$GAME_PKG -name '*.ndkvs' 2>/dev/null | head -3" | tr -d '\r')
    if [ -n "$(echo "$NDKVS" | tr -d '[:space:]')" ]; then
        log_output "${R}[!] Archivo .ndkvs detectado (Free Fire modificado):${N}"
        _ctx "Archivos .ndkvs son escenas modificadas de Free Fire — contienen código de cheat inyectado en el runtime del juego"
        echo "$NDKVS" | while read -r f; do [ -n "$f" ] && log_output "${Y}  $f${N}"; done
        ((SUSPICIOUS_COUNT+=3)); FOUND_SC=1
    fi

    SCENE_DIR="/sdcard/Android/data/$GAME_PKG/files/contentcache/Optional/android/gameassetbundles"
    NON_UNITY=$(adb shell "find '$SCENE_DIR' -type f 2>/dev/null | while read f; do
        case \"\$f\" in *\~*) continue ;; esac
        h=\$(head -c 7 \"\$f\" 2>/dev/null)
        [ \"\$h\" != 'UnityFS' ] && echo \"\$f\"
    done | head -5" | tr -d '\r')
    if [ -n "$(echo "$NON_UNITY" | tr -d '[:space:]')" ]; then
        log_output "${R}[!] Assets no-UnityFS (posible wallhack/scene mod):${N}"
        _ctx "Assets sin firma UnityFS en contentcache son payloads de cheat — reemplazan modelos para hacer paredes/objetos transparentes"
        echo "$NON_UNITY" | while read -r f; do [ -n "$f" ] && log_output "${Y}  $f${N}"; done
        ((SUSPICIOUS_COUNT+=3)); FOUND_SC=1
    fi

    EXPLOITS=$(adb shell "find /data/local/tmp 2>/dev/null \( -name '*.so' -o -name 'payload*' -o -name 'exploit*' -o -name '*.bin' \) | head -5" | tr -d '\r')
    if [ -n "$(echo "$EXPLOITS" | tr -d '[:space:]')" ]; then
        log_output "${R}[!] Exploit/payload en /data/local/tmp:${N}"
        _ctx "Archivos .so/.bin en tmp son payloads de inyección — se cargan en el proceso de Free Fire vía dlopen o ptrace"
        echo "$EXPLOITS" | while read -r f; do [ -n "$f" ] && log_output "${Y}  $f${N}"; done
        ((SUSPICIOUS_COUNT+=3)); FOUND_SC=1
    fi

    [ $FOUND_SC -eq 0 ] && log_output "${G}[✓] Sin modificación de escenas/assets${N}"
    echo ""
}

check_termux_on_device() {
    sec_hdr "TERMUX / HERRAMIENTAS DE EVASION EN DISPOSITIVO"
    FOUND_TX=0

    TERMUX_PKG=$(echo "$PKG_CACHE" | grep -iE "$(printf '%s%s' "$(printf 'Y29tLnRlcm0='|base64 -d)" "$(printf 'dXh8dGVybXV4'|base64 -d)")")
    if [ -n "$TERMUX_PKG" ]; then
        log_output "${Y}[!] Termux instalado en dispositivo escaneado (informativo):${N}"
        echo "$TERMUX_PKG" | while read -r p; do [ -n "$p" ] && log_output "${Y}  $p${N}"; done
        log_output "${B}[*] Nota: puede usarse para scripts de bypass${N}"
        FOUND_TX=1
    fi

    [ $FOUND_TX -eq 0 ] && log_output "${G}[✓] Sin Termux ni shells externos${N}"

    echo ""
}

check_xiaomi_paths() {
    sec_hdr "BYPASS XIAOMI / MIUI / HYPEROS"
    FOUND_MI=0

    BRAND=$(adb shell "getprop ro.product.brand 2>/dev/null" | tr -d '\r' | tr '[:upper:]' '[:lower:]')
    if echo "$BRAND" | grep -qiE "xiaomi|redmi|poco"; then
        log_output "${B}[*] Dispositivo Xiaomi/Redmi/POCO — verificando paths especificos...${N}"

        MI_ROOT_PATHS=$(adb shell "ls /data/miui 2>/dev/null; ls /data/system/miui* 2>/dev/null;             getprop ro.miui.ui.version.name 2>/dev/null; getprop ro.build.hyperos.version 2>/dev/null" | tr -d '\r')

        MI_SU=$(adb shell "find /system/xbin /system/bin 2>/dev/null -name 'su*' | head -5" | tr -d '\r')
        if [ -n "$(echo "$MI_SU" | tr -d '[:space:]')" ]; then
            log_output "${R}[!] Binario su en paths MIUI:${N}"
            echo "$MI_SU" | while read -r f; do [ -n "$f" ] && log_output "${Y}  $f${N}"; done
            ((SUSPICIOUS_COUNT+=2)); FOUND_MI=1
        fi

        MI_BYPASS=$(adb shell "getprop ro.miui.disable_dm_verity 2>/dev/null;             getprop persist.miui.disable_dm_verity 2>/dev/null" | tr -d '\r' | grep -v '^$')
        if [ -n "$MI_BYPASS" ]; then
            log_output "${Y}[!] DM-Verity modificado en MIUI: $MI_BYPASS${N}"
            ((SUSPICIOUS_COUNT++)); FOUND_MI=1
        fi

        [ $FOUND_MI -eq 0 ] && log_output "${G}[✓] Sin indicadores de bypass Xiaomi${N}"
    else
        log_output "${G}[✓] No es dispositivo Xiaomi — omitido${N}"
    fi
    echo ""
}

check_active_dns() {
    sec_hdr "ANÁLISIS DNS / INTERCEPCIÓN DE RED"
    FOUND_DNS=0

    DNS1=$(echo "$PROP_CACHE" | grep '"net.dns1"' | grep -oE '\[.*\]$' | tr -d '[]' | head -1)
    DNS2=$(echo "$PROP_CACHE" | grep '"net.dns2"' | grep -oE '\[.*\]$' | tr -d '[]' | head -1)
    [ -z "$DNS1" ] && DNS1=$(adb shell "getprop net.dns1 2>/dev/null" | tr -d '\r')
    [ -z "$DNS2" ] && DNS2=$(adb shell "getprop net.dns2 2>/dev/null" | tr -d '\r')
    log_output "${B}[*] DNS primario:   ${W}${DNS1:-no configurado}${N}"
    log_output "${B}[*] DNS secundario: ${W}${DNS2:-no configurado}${N}"

    KNOWN_DNS="^(8\.8\.|8\.4\.|1\.1\.|1\.0\.|9\.9\.9|149\.112|208\.67|185\.228|94\.140|192\.168|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.|127\.|$)"
    for DNS_VAL in "$DNS1" "$DNS2"; do
        [ -z "$DNS_VAL" ] && continue
        if ! echo "$DNS_VAL" | grep -qE "$KNOWN_DNS"; then
            log_output "${R}[!] DNS sospechoso (posible intercepción): $DNS_VAL${N}"
            ((SUSPICIOUS_COUNT+=2)); FOUND_DNS=1
        fi
    done

    for SERVER in "1.1.1.1" "8.8.8.8"; do
        PING_R=$(adb shell "ping -c 1 -W 3 $SERVER 2>/dev/null | grep -E 'time=|unreachable|100%'" | tr -d '\r')
        if echo "$PING_R" | grep -qE "unreachable|100%"; then
            log_output "${Y}[!] Sin conectividad a $SERVER — posible bloqueo${N}"
            ((SUSPICIOUS_COUNT++)); FOUND_DNS=1
        elif [ -n "$PING_R" ]; then
            log_output "${G}[✓] Conectividad a $SERVER OK${N}"
        fi
    done

    [ $FOUND_DNS -eq 0 ] && log_output "${G}[✓] DNS y conectividad normales${N}"
    echo ""
}

check_active_protocols() {
    sec_hdr "PUERTOS SOSPECHOSOS (SSH/FTP/IMAP/SOCKS)"
    FOUND_PROTO=0

    TCP_CONNS=$(echo "$TCP_CACHE" | awk '{print $3}' | grep -v "rem_address" | sort -u)

    declare -A PROTO_PORTS
    PROTO_PORTS=(
        ["SSH"]="0016"
        ["FTP"]="0015"
        ["SMTP"]="0019"
        ["IMAP"]="008F"
        ["IMAP-SSL"]="03E1"
        ["POP3"]="006E"
        ["POP3-SSL"]="03E3"
        ["SOCKS"]="0438"
        ["PROXY-8080"]="1F90"
        ["PROXY-8888"]="22B8"
    )

    for proto in "${!PROTO_PORTS[@]}"; do
        PORT_HEX="${PROTO_PORTS[$proto]}"
        if echo "$TCP_CONNS" | grep -iq ":${PORT_HEX}"; then
            log_output "${R}[!] Conexion $proto activa (puerto sospechoso)${N}"
            ((SUSPICIOUS_COUNT+=2)); FOUND_PROTO=1
        fi
    done

    SOCKS5=$(echo "$TCP_CACHE" | awk '{print $3}' | grep -i ":0438")
    if [ -n "$(echo "$SOCKS5" | tr -d '[:space:]')" ]; then
        log_output "${R}[!] SOCKS5 proxy activo en puerto 1080${N}"
        ((SUSPICIOUS_COUNT+=2)); FOUND_PROTO=1
    fi

    [ $FOUND_PROTO -eq 0 ] && log_output "${G}[✓] Sin puertos de protocolo sospechoso${N}"
    echo ""
}

check_logcat_delta() {
    sec_hdr "EVENTOS NUEVOS EN LOGCAT DURANTE EL SCAN"
    log_output "${B}[+] Capturando eventos nuevos desde inicio del scan...${N}"
    LOG_ACTUAL=$(adb shell "logcat -d -b all 2>/dev/null | tail -n 6000" | tr -d '\r')

    LOG_NUEVO=$(echo "$LOG_ACTUAL" | grep -A 999999 "$LOG_LAST_LINE" 2>/dev/null | tail -n +2)
    [ -z "$LOG_NUEVO" ] && LOG_NUEVO=$(echo "$LOG_ACTUAL" | tail -n 500)

    FOUND_LOG=0

    INJECT_LOG=$(echo "$LOG_NUEVO" | grep -iE 'inject|hook|frida|xposed|lsposed|bypass|cheat' | grep -viE 'knox|google|InputDispatcher|injectInputEvent|KeyButtonView|dalvik-internals|hooked signal|hooked sigaction|LogPrintln|Inject motion|Inject key|adbd.*service requested|libxposed_art|libEdXposed|libzygisk|pm dump.*freefireth' | head -5)
    if [ -n "$INJECT_LOG" ]; then
        log_output "${R}[!] ACTIVIDAD SOSPECHOSA EN LOG DURANTE EL SCAN:${N}"
        echo "$INJECT_LOG" | while read -r l; do [ -n "$l" ] && log_output "${Y}  $l${N}"; done
        ((SUSPICIOUS_COUNT+=3)); FOUND_LOG=1
    fi

    ROOT_LOG=$(echo "$LOG_NUEVO" | grep -iE 'su: |granted root|superuser|magisk.*allow|access granted' | grep -viE 'knox' | head -3)
    if [ -n "$ROOT_LOG" ]; then
        log_output "${R}[!] ACTIVIDAD DE ROOT DURANTE EL SCAN:${N}"
        echo "$ROOT_LOG" | while read -r l; do [ -n "$l" ] && log_output "${Y}  $l${N}"; done
        ((SUSPICIOUS_COUNT+=3)); FOUND_LOG=1
    fi

    CRASH_LOG=$(echo "$LOG_NUEVO" | grep -iE "$(printf '%s%s' "$(printf 'RkFUQUx8Zm9yY2UuY2w='|base64 -d)" "$(printf 'b3N8bmF0aXZlIGNyYXNo'|base64 -d)")" | grep -i "${GAME_PKG}" | head -3)
    if [ -n "$CRASH_LOG" ]; then
        log_output "${Y}[!] Crash del juego durante el scan (posible cheat inestable):${N}"
        echo "$CRASH_LOG" | while read -r l; do [ -n "$l" ] && log_output "${Y}  $l${N}"; done
        ((SUSPICIOUS_COUNT++)); FOUND_LOG=1
    fi

    [ $FOUND_LOG -eq 0 ] && log_output "${G}[✓] Sin eventos sospechosos nuevos en logcat${N}"
    echo ""
}

check_process_delta() {
    sec_hdr "PROCESOS NUEVOS DURANTE EL SCAN (DELTA)"
    log_output "${B}[+] Comparando procesos inicio vs fin del scan...${N}"
    PS_SNAPSHOT_FIN=$(adb shell "ps -A 2>/dev/null" | tr -d '\r')

    PIDS_INICIO=$(echo "$PS_SNAPSHOT_INICIO" | awk '{print $2}' | sort)
    PIDS_FIN=$(echo "$PS_SNAPSHOT_FIN"    | awk '{print $2}' | sort)

    NUEVOS_PIDS=$(comm -13 <(echo "$PIDS_INICIO") <(echo "$PIDS_FIN") 2>/dev/null)
    FOUND_DELTA=0

    if [ -n "$NUEVOS_PIDS" ]; then
        while read -r pid; do
            [ -z "$pid" ] && continue
            PROC_LINE=$(echo "$PS_SNAPSHOT_FIN" | awk -v p="$pid" '$2==p {print}' | head -1)
            PROC_NAME=$(echo "$PROC_LINE" | awk '{print $NF}')
            if echo "$PROC_NAME" | grep -qiE 'frida|hook|cheat|bypass|magisk|xposed|lsposed|shizuku|su$'; then
                log_output "${R}[!] PROCESO SOSPECHOSO APARECIO DURANTE EL SCAN: $PROC_NAME (PID $pid)${N}"
                ((SUSPICIOUS_COUNT+=3)); FOUND_DELTA=1
            fi
        done <<< "$NUEVOS_PIDS"
    fi

    [ $FOUND_DELTA -eq 0 ] && log_output "${G}[✓] Sin procesos sospechosos nuevos durante el scan${N}"
    echo ""
}

_send_scan_report() {
    local _pk="" _verdict="" _det_json="[]"
    if [ -n "$ACCESS_KEY_USED" ]; then
        _pk="$ACCESS_KEY_USED"
    elif [ -f "$KEY_FILE" ]; then
        _pk=$(sed -n '1p' "$KEY_FILE" | tr -d '\r\n' || true)
    fi

    if   [ "${SUSPICIOUS_COUNT:-0}" -eq 0 ];  then _verdict="clean"
    elif [ "${SUSPICIOUS_COUNT:-0}" -lt 10 ]; then _verdict="suspicious"
    else                                           _verdict="cheat"
    fi

    if [ -f "${LOGFILE:-}" ]; then
        local _raw
        _raw=$(grep -E '\[!\]|\[✓\]|\[✓\]|\[v\]|\[\+\]' "$LOGFILE" 2>/dev/null \
            | sed 's/\x1b\[[0-9;]*[mK]//g' \
            | sed 's/\r//g;s/^[[:space:]]*//' \
            | grep -Ev '^[[:space:]]*$|^[═─]+$|^\[+\] Iniciando|^\[+\] Conectando|^\[+\] Prefetch' \
            | head -120)
        if [ -n "$_raw" ]; then
            _det_json="["
            local _first=1
            while IFS= read -r _line; do
                [ -z "$_line" ] && continue
                [ $_first -eq 0 ] && _det_json+=","
                local _esc
                _esc=$(printf '%s' "$_line" | sed 's/\\/\\\\/g;s/"/\\"/g')
                _det_json+="\"${_esc}\""
                _first=0
            done <<< "$_raw"
            _det_json+="]"
        fi
    fi

    local _di _hwid_esc _game_esc _pk_esc _payload
    _di=$(printf '{"brand":"%s","model":"%s","android":"%s"}' \
        "${DEVICE_BRAND:-}" "${DEVICE_MODEL:-}" "${ANDROID_VER:-}")
    _hwid_esc=$(printf '%s' "${DEVICE_HWID:-}" | sed 's/"/\\"/g')
    _game_esc=$(printf '%s' "${GAME_SELECTED:-}" | sed 's/"/\\"/g')
    _pk_esc=$(printf '%s' "${_pk}" | sed 's/"/\\"/g')

    _payload=$(printf '{"hwid":"%s","player_name":"%s","version":"%s","premium_key":"%s","verdict":"%s","signals":%d,"detections":%s,"device_info":%s}' \
        "$_hwid_esc" "$_game_esc" "$SCANNER_VERSION" "$_pk_esc" "$_verdict" \
        "${SUSPICIOUS_COUNT:-0}" "$_det_json" "$_di")

    curl -sf -X POST "${BACKEND_URL}/api/android/scan/report" \
        -H "Content-Type: application/json" \
        -H "x-session-token: ${SESSION_TOKEN}" \
        -d "$_payload" \
        --max-time 10 --connect-timeout 5 >/dev/null 2>&1 || true
}
show_summary() {
    sec_hdr "RESUMEN DEL ANÁLISIS"
    log_output "${B}[*] Juego: ${W}$GAME_SELECTED${N}"
    log_output "${B}[*] Señales sospechosas: ${W}$SUSPICIOUS_COUNT${N}"
    [ -n "$DEVICE_HWID" ] && log_output "${B}[*] HWID: ${Y}$DEVICE_HWID${N}"
    echo ""

    if [ $SUSPICIOUS_COUNT -eq 0 ]; then
        verdict_box "$G" "  ✓  DISPOSITIVO LIMPIO  ✓  "
    elif [ $SUSPICIOUS_COUNT -lt 10 ]; then
        verdict_box "$Y" "  !  REVISAR MANUALMENTE — NO DAR W.O  !  "
    else
        verdict_box "$R" "  ✗  ALTO RIESGO DE CHEATS  ✗  "
    fi

    log_output "\n${M}[*] Log: ${W}$LOGFILE${N}"
    _send_scan_report &
}

pedir_key
check_storage
main_menu
