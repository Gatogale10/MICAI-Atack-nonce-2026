#!/usr/bin/env bash
# =============================================================================
# capture.sh
# Captura tráfico TLS y genera conexiones al servidor vulnerable.
#
# Uso: bash capture.sh [--interface IFACE] [--port PORT]
#                      [--connections N] [--output FILE]
# =============================================================================

set -euo pipefail

IFACE="lo"
PORT=4433
N_CONNECTIONS=200
OUTPUT="data/capture.pcap"
SERVER="192.168.100.149"

while [[ $# -gt 0 ]]; do
    case $1 in
        --interface)  IFACE="$2";         shift 2 ;;
        --port)       PORT="$2";           shift 2 ;;
        --connections) N_CONNECTIONS="$2"; shift 2 ;;
        --output)     OUTPUT="$2";         shift 2 ;;
        --server)     SERVER="$2";         shift 2 ;;
        *) echo "Argumento desconocido: $1"; exit 1 ;;
    esac
done

mkdir -p "$(dirname "$OUTPUT")"

echo "============================================="
echo " Captura TLS"
echo " Interfaz: ${IFACE} | Puerto: ${PORT}"
echo " Conexiones a generar: ${N_CONNECTIONS}"
echo " Output: ${OUTPUT}"
echo "============================================="

# Limpiar captura previa si existe
rm -f "$OUTPUT"

# Arrancar tshark en background
echo "[1/3] Iniciando captura con tshark..."
sudo tshark \
    -i "${IFACE}" \
    -f "tcp port ${PORT}" \
    -w "${OUTPUT}" \
    -a duration:180 \
    -q &
TSHARK_PID=$!
sleep 2  # dar tiempo a tshark para arrancar

echo "[2/3] Generando ${N_CONNECTIONS} conexiones TLS..."
SUCCESS=0
FAIL=0
for i in $(seq 1 "$N_CONNECTIONS"); do
    if curl -sk \
            --tlsv1.2 \
            --tls-max 1.2 \
            --connect-timeout 3 \
            "https://${SERVER}:${PORT}/" \
            > /dev/null 2>&1; then
        SUCCESS=$((SUCCESS + 1))
    else
        FAIL=$((FAIL + 1))
    fi

    # Mostrar progreso cada 20 conexiones
    if (( i % 20 == 0 )); then
        echo "  Conexiones: ${i}/${N_CONNECTIONS} (ok=${SUCCESS}, fail=${FAIL})"
    fi
    sleep 0.05  # pequeña pausa para separar paquetes
done

echo "[3/3] Deteniendo captura..."
sudo kill "$TSHARK_PID" 2>/dev/null || true
wait "$TSHARK_PID" 2>/dev/null || true

PCAP_SIZE=$(du -sh "$OUTPUT" 2>/dev/null | cut -f1 || echo "?")
echo ""
echo "Captura terminada: ${OUTPUT} (${PCAP_SIZE})"
echo "Conexiones exitosas: ${SUCCESS}/${N_CONNECTIONS}"
echo ""
echo "Siguiente paso:"
echo "  python3 capture/parser_pcap.py --pcap ${OUTPUT}"