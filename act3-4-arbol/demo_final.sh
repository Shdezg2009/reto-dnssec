#!/bin/bash
set -e
cd ~/dnslab-act3
LOG="demo_final_$(date +%Y%m%d_%H%M%S).log"

echo "=== Corrida final del laboratorio DNSSEC ===" | tee "$LOG"
date -u | tee -a "$LOG"

echo -e "\n--- 1. Levantando/asegurando todos los contenedores ---" | tee -a "$LOG"
docker compose up -d 2>&1 | tee -a "$LOG"
sleep 2

echo -e "\n--- 2. Estado de los 15 contenedores ---" | tee -a "$LOG"
docker compose ps --format 'table {{.Name}}\t{{.Status}}' | tee -a "$LOG"

echo -e "\n--- 3. Limpiando cache de recursive2 ---" | tee -a "$LOG"
docker exec recursive2 rndc flush 2>&1 | tee -a "$LOG" || true

echo -e "\n--- 4. Control rapido: valida vs no valida ---" | tee -a "$LOG"
for d in www.beta.signed. www.delta.signed. www.expired.test. www.nods.test. www.badalg.test.; do
  echo -n "$d -> " | tee -a "$LOG"
  dig @172.30.0.150 "$d" A +dnssec | grep -o 'status: [A-Z]*\|flags: [a-z ]*' | tr '\n' ' ' | tee -a "$LOG"
  echo "" | tee -a "$LOG"
done

echo -e "\n--- 5. Herramienta de verificacion + CSV ---" | tee -a "$LOG"
python3 verificar_dnssec.py | tee -a "$LOG"

echo -e "\n--- 6. Zone walking: NSEC en beta.signed ---" | tee -a "$LOG"
./walk_nsec.sh beta.signed. 172.30.0.50 | tee -a "$LOG"

echo -e "\n--- 7. Contraste: NSEC3 en delta.signed (solo hashes) ---" | tee -a "$LOG"
dig @172.30.0.80 delta.signed. NSEC3PARAM +short | tee -a "$LOG"
dig @172.30.0.80 zzz-inexistente.delta.signed. A +dnssec | grep NSEC3 | head -1 | tee -a "$LOG"

echo -e "\n--- 8. Arbol final del laboratorio ---" | tee -a "$LOG"
tree -L 3 --dirsfirst | tee -a "$LOG"
docker compose ps --format 'table {{.Name}}\t{{.Status}}' | tee -a "$LOG"

echo -e "\n=== Corrida completa. Log guardado en $LOG ===" | tee -a "$LOG"
echo "=== CSV en verificacion_dnssec.csv ===" | tee -a "$LOG"
