#!/usr/bin/env python3
"""Extrae registros SOA/NS/A/AAAA (con TTL) de una captura DNS -> CSV."""
import sys, csv
from scapy.all import rdpcap, DNS

TYPES = {1: "A", 2: "NS", 6: "SOA", 28: "AAAA"}
path = sys.argv[1] if len(sys.argv) > 1 else "captura_act2.pcap"

filas = []
for p in rdpcap(path):
    if DNS not in p or p[DNS].qr != 1:      # solo respuestas
        continue
    dns = p[DNS]
    for seccion, registros in (("ANSWER", dns.an), ("AUTHORITY", dns.ns), ("ADDITIONAL", dns.ar)):
        for rr in (registros or []):
            t = TYPES.get(getattr(rr, "type", None))
            if t is None:
                continue
            nombre = rr.rrname.decode(errors="replace").rstrip(".")
            if t == "SOA":
                datos = f"mname={rr.mname.decode(errors='replace')} serial={rr.serial}"
            else:
                d = rr.rdata
                datos = d.decode(errors="replace").rstrip(".") if isinstance(d, bytes) else str(d)
            filas.append([seccion, nombre, t, rr.ttl, datos])

print(f"{'SECCION':11}{'DOMINIO':26}{'TIPO':6}{'TTL':8}DATOS")
print("-" * 90)
for f in filas:
    print(f"{f[0]:11}{f[1]:26}{f[2]:6}{str(f[3]):8}{f[4]}")

with open("registros_act2.csv", "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["seccion", "dominio", "tipo", "ttl", "datos"])
    w.writerows(filas)
print(f"\n{len(filas)} registros -> registros_act2.csv")
