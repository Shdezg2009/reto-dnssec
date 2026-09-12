#!/usr/bin/env bash
# ============================================================
# Reconstruye el arbol DNSSEC completo desde cero.
# Idempotente: borra lo anterior y regenera llaves + firmas frescas.
# Uso:  ./construir.sh
# ============================================================
set -euo pipefail

IMG="internetsystemsconsortium/bind9:9.18"
LAB="$(cd "$(dirname "$0")" && pwd)/lab"
NET="dnslab"
SUBNET="172.30.0.0/24"

echo ">>> [1/7] Limpiando entorno anterior..."
docker rm -f root unsigned alpha signed beta gamma delta test expired nods badalg recursive1 recursive2 2>/dev/null || true
docker network rm $NET 2>/dev/null || true
# Borrar cualquier red que ocupe el rango 172.30 (redes viejas de compose)
for n in $(docker network ls -q); do
  if docker network inspect "$n" --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null | grep -q '172.30'; then
    for c in $(docker network inspect "$n" --format '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null); do docker rm -f "$c" 2>/dev/null || true; done
    docker network rm "$n" 2>/dev/null || true
  fi
done
sudo rm -rf "$LAB" 2>/dev/null || true
mkdir -p "$LAB"
cd "$LAB"

echo ">>> [2/7] Creando red $NET ($SUBNET)..."
docker network create --subnet $SUBNET $NET >/dev/null

# ---------- helper: crear carpetas de una zona ----------
mkzone() { mkdir -p "$LAB/$1/zones"; }
for s in root unsigned alpha signed beta gamma delta test expired nods badalg recursive1 recursive2; do mkzone $s; done

echo ">>> [3/7] Escribiendo named.conf y zonas planas..."

# ---- named.conf autoritativos (recursion no) ----
auth_conf() { # $1=carpeta $2=ip $3=zona $4=archivo
cat > "$LAB/$1/named.conf" <<EOF
options {
    directory "/var/cache/bind";
    listen-on { $2; };
    listen-on-v6 { none; };
    recursion no;
    allow-query { any; };
};
zone "$3" {
    type primary;
    file "/var/lib/bind/$4";
};
EOF
}

auth_conf root     172.30.0.10 "."             db.root.signed
auth_conf unsigned 172.30.0.20 "unsigned"      db.unsigned
auth_conf alpha    172.30.0.21 "alpha.unsigned" db.alpha.unsigned
auth_conf signed   172.30.0.40 "signed"        db.signed.signed
auth_conf beta     172.30.0.50 "beta.signed"   db.beta.signed
auth_conf gamma    172.30.0.60 "gamma.signed"  db.gamma
auth_conf delta    172.30.0.80 "delta.signed"  db.delta.signed
auth_conf test     172.30.0.70 "test"          db.test.signed
auth_conf expired  172.30.0.71 "expired.test"  db.expired.signed
auth_conf nods     172.30.0.72 "nods.test"     db.nods.signed
auth_conf badalg   172.30.0.73 "badalg.test"   db.badalg.signed

# ---- recursive1 (SIN validacion) ----
cat > "$LAB/recursive1/named.conf" <<EOF
options {
    directory "/var/cache/bind";
    listen-on { 172.30.0.100; };
    listen-on-v6 { none; };
    recursion yes;
    allow-recursion { 172.30.0.0/24; };
    allow-query { 172.30.0.0/24; };
    dnssec-validation no;
};
zone "." { type hint; file "/var/lib/bind/db.root.hints"; };
EOF

# recursive2 provisional (se sobrescribe con el trust anchor en el paso 6)
cat > "$LAB/recursive2/named.conf" <<EOF
options {
    directory "/var/cache/bind";
    listen-on { 172.30.0.150; };
    listen-on-v6 { none; };
    recursion yes;
    allow-recursion { 172.30.0.0/24; };
    allow-query { any; };
    dnssec-validation no;
};
zone "." { type hint; file "/var/lib/bind/db.root.hints"; };
EOF

# hints (para ambos recursivos)
printf '.\t86400 IN NS ns.root.\nns.root.\t86400 IN A 172.30.0.10\n' \
  | tee "$LAB/recursive1/zones/db.root.hints" > "$LAB/recursive2/zones/db.root.hints"

# ---- zonas planas ----
cat > "$LAB/root/zones/db.root" <<'EOF'
$TTL 86400
@   IN  SOA ns.root. admin.root. ( 2026090101 3600 900 604800 86400 )
@            IN  NS  ns.root.
ns.root.     IN  A   172.30.0.10
unsigned.    IN  NS  ns.unsigned.
ns.unsigned. IN  A   172.30.0.20
signed.      IN  NS  ns.signed.
ns.signed.   IN  A   172.30.0.40
test.        IN  NS  ns.test.
ns.test.     IN  A   172.30.0.70
EOF

cat > "$LAB/unsigned/zones/db.unsigned" <<'EOF'
$TTL 86400
@   IN  SOA ns.unsigned. admin.unsigned. ( 2026090101 3600 900 604800 86400 )
@                  IN  NS  ns.unsigned.
ns.unsigned.       IN  A   172.30.0.20
alpha              IN  NS  ns.alpha.unsigned.
ns.alpha.unsigned. IN  A   172.30.0.21
EOF

cat > "$LAB/alpha/zones/db.alpha.unsigned" <<'EOF'
$TTL 86400
@   IN  SOA ns.alpha.unsigned. admin.alpha.unsigned. ( 2026090101 3600 900 604800 86400 )
@   IN  NS  ns.alpha.unsigned.
ns  IN  A   172.30.0.21
www IN  A   172.30.0.21
EOF

cat > "$LAB/signed/zones/db.signed" <<'EOF'
$TTL 86400
@   IN  SOA ns.signed. admin.signed. ( 2026090101 3600 900 604800 86400 )
@                 IN  NS  ns.signed.
ns.signed.        IN  A   172.30.0.40
beta              IN  NS  ns.beta.signed.
ns.beta.signed.   IN  A   172.30.0.50
gamma             IN  NS  ns.gamma.signed.
ns.gamma.signed.  IN  A   172.30.0.60
delta             IN  NS  ns.delta.signed.
ns.delta.signed.  IN  A   172.30.0.80
EOF

zone_www() { # $1=carpeta $2=zona-origen $3=ip
cat > "$LAB/$1/zones/db.$1" <<EOF
\$TTL 86400
@   IN  SOA ns.$2. admin.$2. ( 2026090101 3600 900 604800 86400 )
@   IN  NS  ns.$2.
ns  IN  A   $3
www IN  A   $3
EOF
}
zone_www beta   beta.signed   172.30.0.50
zone_www gamma  gamma.signed  172.30.0.60
zone_www delta  delta.signed  172.30.0.80
zone_www expired expired.test 172.30.0.71
zone_www nods    nods.test    172.30.0.72
zone_www badalg  badalg.test  172.30.0.73

cat > "$LAB/test/zones/db.test" <<'EOF'
$TTL 86400
@   IN  SOA ns.test. admin.test. ( 2026090101 3600 900 604800 86400 )
@                IN  NS  ns.test.
ns.test.         IN  A   172.30.0.70
expired          IN  NS  ns.expired.test.
ns.expired.test. IN  A   172.30.0.71
nods             IN  NS  ns.nods.test.
ns.nods.test.    IN  A   172.30.0.72
badalg           IN  NS  ns.badalg.test.
ns.badalg.test.  IN  A   172.30.0.73
EOF

echo ">>> [4/7] Generando docker-compose.yml..."
{
echo "services:"
svc() { # $1=nombre $2=ip
cat <<EOF
  $1:
    image: $IMG
    container_name: $1
    command: ["-g","-c","/etc/bind/named.conf"]
    volumes:
      - ./$1/named.conf:/etc/bind/named.conf:ro
      - ./$1/zones:/var/lib/bind
    networks:
      dnslab:
        ipv4_address: $2
EOF
}
svc root 172.30.0.10;   svc unsigned 172.30.0.20; svc alpha 172.30.0.21
svc signed 172.30.0.40; svc beta 172.30.0.50;     svc gamma 172.30.0.60
svc delta 172.30.0.80;  svc test 172.30.0.70;     svc expired 172.30.0.71
svc nods 172.30.0.72;   svc badalg 172.30.0.73
svc recursive1 172.30.0.100; svc recursive2 172.30.0.150
echo "networks:"
echo "  dnslab:"
echo "    external: true"
} > "$LAB/docker-compose.yml"

echo ">>> [5/7] Levantando contenedores..."
cd "$LAB"
docker compose up -d >/dev/null
sleep 3

# ---------- helpers de firmado ----------
sign()    { docker exec -w /var/lib/bind "$1" dnssec-signzone -S -o "$2" "$3" >/dev/null; }
sign3()   { docker exec -w /var/lib/bind "$1" dnssec-signzone -3 "$2" -S -o "$3" "$4" >/dev/null; }
keygen()  { docker exec -w /var/lib/bind "$1" dnssec-keygen -a "$2" ${5:+-b $5} -n ZONE $3 "$4" >/dev/null; }
dsof()    { docker exec -w /var/lib/bind "$1" cat "$2"; }

echo ">>> [6/7] Firmando zonas y armando la cadena DS..."

# --- beta: ECDSA + NSEC ---
keygen beta ECDSAP256SHA256 "-f KSK" beta.signed
keygen beta ECDSAP256SHA256 ""       beta.signed
sign   beta beta.signed db.beta

# --- delta: RSA + NSEC3 ---
SALT=$(head -c 4 /dev/urandom | xxd -p)
keygen delta RSASHA256 "-f KSK" delta.signed 2048
keygen delta RSASHA256 ""       delta.signed 2048
sign3  delta "$SALT" delta.signed db.delta

# --- gamma: NO se firma (control) ---

# --- DS de beta y delta -> signed (gamma sin DS a proposito) ---
dsof beta  dsset-beta.signed.  >> signed/zones/db.signed
dsof delta dsset-delta.signed. >> signed/zones/db.signed

# --- signed: ECDSA ---
keygen signed ECDSAP256SHA256 "-f KSK" signed
keygen signed ECDSAP256SHA256 ""       signed
sign   signed signed db.signed

# --- expired: firma CADUCADA (fecha en el pasado, calculada en el host) ---
keygen expired ECDSAP256SHA256 "-f KSK" expired.test
keygen expired ECDSAP256SHA256 ""       expired.test
INI=$(date -u -d "30 days ago" +%Y%m%d%H%M%S); FIN=$(date -u -d "1 day ago" +%Y%m%d%H%M%S)
docker exec -w /var/lib/bind expired dnssec-signzone -P -s "$INI" -e "$FIN" -S -o expired.test db.expired >/dev/null

# --- nods: firmado bien pero SIN DS en test ---
keygen nods ECDSAP256SHA256 "-f KSK" nods.test
keygen nods ECDSAP256SHA256 ""       nods.test
sign   nods nods.test db.nods

# --- badalg: firmado bien, DS CORRUPTO en test ---
keygen badalg ECDSAP256SHA256 "-f KSK" badalg.test
keygen badalg ECDSAP256SHA256 ""       badalg.test
sign   badalg badalg.test db.badalg

# DS de expired (valido) al padre test
dsof expired dsset-expired.test. >> test/zones/db.test
# DS de badalg pero corrompiendo el hash (primer byte -> FF)
DSBAD=$(dsof badalg dsset-badalg.test. | awk '{h=$NF; c=substr(h,1,1); nc=(c=="1"?"2":"1"); $NF=nc substr(h,2); print}')
# nods NO recibe DS (defecto)
echo "$DSBAD" >> test/zones/db.test

# --- test: ECDSA ---
keygen test ECDSAP256SHA256 "-f KSK" test
keygen test ECDSAP256SHA256 ""       test
sign   test test db.test

# --- DS de signed y test -> raiz ---
dsof signed dsset-signed. >> root/zones/db.root
dsof test   dsset-test.   >> root/zones/db.root

# --- raiz: ECDSA ---
keygen root ECDSAP256SHA256 "-f KSK" .
keygen root ECDSAP256SHA256 ""       .
sign   root . db.root

# --- trust anchor de la raiz -> recursive2 ---
KSK=$(docker exec -w /var/lib/bind root sh -c 'grep -h "IN DNSKEY 257" K.+*.key | head -1' | sed 's/.*IN DNSKEY //')
read F P A K <<< "$KSK"
cat > "$LAB/recursive2/named.conf" <<EOF
options {
    directory "/var/cache/bind";
    listen-on { 172.30.0.150; };
    listen-on-v6 { none; };
    recursion yes;
    allow-recursion { 172.30.0.0/24; };
    allow-query { any; };
    dnssec-validation yes;
};
trust-anchors { "." initial-key $F $P $A "$K"; };
zone "." { type hint; file "/var/lib/bind/db.root.hints"; };
EOF

echo ">>> [7/7] Reiniciando para aplicar firmas..."
sudo chown -R "$USER":"$USER" "$LAB" 2>/dev/null || true
docker compose restart >/dev/null
sleep 4

echo ""
echo "============================================"
echo " Laboratorio DNSSEC listo."
echo " Verificacion rapida:"
docker exec recursive2 rndc flush 2>/dev/null || true
echo -n "  beta (debe validar, flag ad): "; dig @172.30.0.150 www.beta.signed. A +dnssec 2>/dev/null | grep -o 'flags:[a-z ]*ad' || echo "sin ad"
echo -n "  delta NSEC3PARAM:             "; dig @172.30.0.80 delta.signed. NSEC3PARAM +short 2>/dev/null
echo -n "  gamma (sin firmar, resuelve): "; dig @172.30.0.150 www.gamma.signed. A +short 2>/dev/null
echo "============================================"
