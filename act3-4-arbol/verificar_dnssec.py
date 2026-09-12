#!/usr/bin/env python3
"""
Herramienta de verificacion DNSSEC para el laboratorio del Reto (Act. 4, punto 5).
"""
import subprocess, csv, re
from datetime import datetime, timezone

RECURSIVO_VALIDADOR = "172.30.0.150"

# (zona, ip_zona_o_None, ip_padre, padre, target_validacion, tipo_validacion)
DOMINIOS = [
    ("unsigned.",       None,          "172.30.0.10", ".",         None, None),
    ("alpha.unsigned.", None,          "172.30.0.20", "unsigned.", None, None),
    ("epsilon.unsigned.", None,          "172.30.0.20", "unsigned.", None, None),
    ("zeta.unsigned.",    None,          "172.30.0.20", "unsigned.", None, None),
    ("signed.",         "172.30.0.40", "172.30.0.10", ".",         "signed.", "DNSKEY"),
    ("beta.signed.",    "172.30.0.50", "172.30.0.40", "signed.",   "www.beta.signed.", "A"),
    ("gamma.signed.",   None,          "172.30.0.40", "signed.",   None, None),
    ("delta.signed.",   "172.30.0.80", "172.30.0.40", "signed.",   "www.delta.signed.", "A"),
    ("test.",           "172.30.0.70", "172.30.0.10", ".",         "test.", "DNSKEY"),
    ("expired.test.",   "172.30.0.71", "172.30.0.70", "test.",     "www.expired.test.", "A"),
    ("nods.test.",      "172.30.0.72", "172.30.0.70", "test.",     "www.nods.test.", "A"),
    ("badalg.test.",    "172.30.0.73", "172.30.0.70", "test.",     "www.badalg.test.", "A"),
]

ALGS_AUTORIZADOS = {"8": "RSASHA256", "10": "RSASHA512", "13": "ECDSAP256SHA256", "14": "ECDSAP384SHA384"}

def correr(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=8)
        return r.stdout
    except Exception:
        return ""

def lineas_rr(salida):
    """Devuelve solo lineas de registro real: name ttl IN tipo resto..."""
    for linea in salida.splitlines():
        partes = linea.split()
        if len(partes) >= 4 and partes[2] == "IN":
            yield partes

def obtener_dnskey(dominio, servidor):
    if not servidor:
        return []
    salida = correr(f"dig @{servidor} {dominio} DNSKEY +dnssec +noall +answer")
    claves = []
    for p in lineas_rr(salida):
        if p[3] == "DNSKEY":               # filtro estricto: tipo exacto, no dentro de un RRSIG
            flags, protocolo, algoritmo = p[4], p[5], p[6]
            clave_b64 = "".join(p[7:])
            tam_aprox = (len(clave_b64) * 3 // 4) * 8
            claves.append({"flags": flags, "algoritmo": algoritmo, "keysize_aprox": tam_aprox})
    return claves

def obtener_rrsig_soa(dominio, servidor):
    if not servidor:
        return None
    salida = correr(f"dig @{servidor} {dominio} SOA +dnssec +noall +answer")
    for p in lineas_rr(salida):
        if p[3] == "RRSIG":
            # RRSIG: tipo-cubierto algoritmo labels ttl-orig expira inicia keytag firmante...
            expira, inicia = p[8], p[9]
            fmt = "%Y%m%d%H%M%S"
            try:
                exp = datetime.strptime(expira, fmt).replace(tzinfo=timezone.utc)
                ini = datetime.strptime(inicia, fmt).replace(tzinfo=timezone.utc)
                vigente = ini <= datetime.now(timezone.utc) <= exp
            except ValueError:
                vigente = None
            return {"vigente": vigente}
    return None

def obtener_nsec_tipo(dominio, servidor):
    if not servidor:
        return "na"
    salida = correr(f"dig @{servidor} {dominio} NSEC3PARAM +dnssec +noall +answer")
    for p in lineas_rr(salida):
        if p[3] == "NSEC3PARAM":
            return "NSEC3"
    salida2 = correr(f"dig @{servidor} zzz-inexistente.{dominio} A +dnssec")
    if "NSEC3" in salida2:
        return "NSEC3"
    if re.search(r"\bNSEC\b", salida2):
        return "NSEC"
    return "na"

def obtener_ds_en_padre(dominio, servidor_padre):
    if not servidor_padre:
        return False
    salida = correr(f"dig @{servidor_padre} {dominio} DS +dnssec +noall +answer")
    return any(p[3] == "DS" for p in lineas_rr(salida))

def dig_status_flags(target, tipo):
    salida = correr(f"dig @{RECURSIVO_VALIDADOR} {target} {tipo} +dnssec")
    status_m = re.search(r"status:\s*(\w+)", salida)
    flags_m = re.search(r"flags:\s*([a-z ]+);", salida)
    status = status_m.group(1) if status_m else "?"
    flags = flags_m.group(1).split() if flags_m else []
    return status, "ad" in flags

def motivo_por_delv(target, tipo):
    salida = correr(f"delv @{RECURSIVO_VALIDADOR} {target} {tipo} 2>&1").lower()
    if "expired" in salida or "no valid rrsig" in salida or "no valid signature" in salida:
        return "RRSIG expirada / sin firma valida"
    if "broken trust chain" in salida or "no matching ds" in salida:
        return "DS no coincide con DNSKEY (algoritmo/hash desalineado)"
    return "SERVFAIL (ver delv para detalle exacto)"

def main():
    filas = []
    for zona, srv_zona, srv_padre, padre, target, tipo in DOMINIOS:
        claves = obtener_dnskey(zona, srv_zona)
        activo = len(claves) > 0
        rrsig = obtener_rrsig_soa(zona, srv_zona) if activo else None
        nsec_tipo = obtener_nsec_tipo(zona, srv_zona) if activo else "na"
        ds_ok = obtener_ds_en_padre(zona, srv_padre)

        if not activo:
            valida, motivo = "n/a", "DNSSEC no activo en la zona"
        else:
            status, tiene_ad = dig_status_flags(target, tipo)
            if status == "NOERROR" and tiene_ad:
                valida, motivo = "si", ""
            elif status == "SERVFAIL":
                if rrsig and rrsig["vigente"] is False:
                    valida, motivo = "no", "RRSIG fuera de vigencia (expirada)"
                elif ds_ok:
                    valida, motivo = "no", "DS no coincide con DNSKEY (algoritmo/hash desalineado)"
                else:
                    valida, motivo = "no", motivo_por_delv(target, tipo)
            elif status == "NOERROR" and not tiene_ad:
                valida, motivo = "n/a", "Zona insecure (sin DS en el padre)" if not ds_ok else "Resuelve sin AD (revisar)"
            else:
                valida, motivo = "n/a", f"status {status}"

        algoritmos = sorted({c["algoritmo"] for c in claves})
        tam_bits = max([c["keysize_aprox"] for c in claves], default=0)
        alg_autorizado = all(a in ALGS_AUTORIZADOS for a in algoritmos) if algoritmos else None

        observaciones = []
        if activo and not ds_ok:
            observaciones.append("Sin DS en zona padre -> cadena rota (insecure)")
        if rrsig and rrsig["vigente"] is False:
            observaciones.append("RRSIG fuera de vigencia (expirada)")
        if algoritmos and alg_autorizado is False:
            observaciones.append("Algoritmo no autorizado detectado")

        filas.append({
            "dominio": zona,
            "dnssec_activo": "si" if activo else "no",
            "valida": valida,
            "motivo_fallo": motivo if valida != "si" else "",
            "nsec": nsec_tipo,
            "algoritmo": ",".join(algoritmos) if algoritmos else "na",
            "keysize_bits_aprox": tam_bits if tam_bits else "na",
            "rrset_firmadas": "si" if rrsig else "no",
            "ds_en_padre": "si" if ds_ok else "no",
            "observaciones": "; ".join(observaciones) if observaciones else "ninguna",
        })

    columnas = ["dominio","dnssec_activo","valida","motivo_fallo","nsec","algoritmo",
                "keysize_bits_aprox","rrset_firmadas","ds_en_padre","observaciones"]
    with open("verificacion_dnssec.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=columnas)
        w.writeheader()
        w.writerows(filas)

    ancho = {c: max(len(c), max((len(str(f[c])) for f in filas), default=0)) for c in columnas}
    print("  ".join(c.ljust(ancho[c]) for c in columnas))
    for f in filas:
        print("  ".join(str(f[c]).ljust(ancho[c]) for c in columnas))
    print("\nCSV -> verificacion_dnssec.csv")

if __name__ == "__main__":
    main()
