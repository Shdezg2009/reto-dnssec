#!/bin/bash
# Zone walking con NSEC: sigue la cadena "next domain name" registro por registro.
ZONA="$1"
SERVIDOR="$2"
ACTUAL="$ZONA"
echo "Iniciando zone walking en $ZONA via $SERVIDOR"
for i in $(seq 1 20); do
    SALIDA=$(dig @"$SERVIDOR" "$ACTUAL" NSEC +dnssec +noall +answer)
    SIGUIENTE=$(echo "$SALIDA" | awk '$4=="NSEC" {print $5}')
    if [ -z "$SIGUIENTE" ]; then
        echo "Fin de la cadena (sin mas NSEC)."
        break
    fi
    echo "$ACTUAL  ->  siguiente: $SIGUIENTE"
    if [ "$SIGUIENTE" = "$ZONA" ]; then
        echo "Cadena cerrada, ciclo completo."
        break
    fi
    ACTUAL="$SIGUIENTE"
done
