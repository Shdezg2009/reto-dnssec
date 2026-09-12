from scapy.all import rdpcap, DNS

pcap_file = "dns_lab_traza.pcapng"

try:
    packets = rdpcap(pcap_file)
    print(f"\n[*] Analizando {len(packets)} paquetes de la traza '{pcap_file}'...")
    print("=" * 95)
    print(f"{'DOMINIO':<32} | {'TIPO':<6} | {'TTL':<8} | {'VALOR / RDATA'}")
    print("=" * 95)
    
    registros_vistos = set()
    
    for pkt in packets:
        if pkt.haslayer(DNS):
            dns = pkt.getlayer(DNS)
            # Revisar todas las secciones donde viajan registros (Answer, Authority, Additional)
            sections = [dns.an, dns.ns, dns.ar]
            counts = [dns.ancount, dns.nscount, dns.arcount]
            
            for section, count in zip(sections, counts):
                if section and count:
                    for i in range(count):
                        try:
                            rr = section[i]
                            if hasattr(rr, 'type') and rr.type in [1, 2, 6]: # A=1, NS=2, SOA=6
                                tipo_str = "A" if rr.type == 1 else ("NS" if rr.type == 2 else "SOA")
                                dominio = rr.rrname.decode() if isinstance(rr.rrname, bytes) else str(rr.rrname)
                                ttl = rr.ttl
                                rdata = str(rr.rdata)
                                
                                identificador = (dominio, tipo_str, ttl, rdata)
                                if identificador not in registros_vistos:
                                    registros_vistos.add(identificador)
                                    print(f"{dominio:<32} | {tipo_str:<6} | {ttl:<8} | {rdata}")
                        except Exception:
                            continue
    print("=" * 95)
    print("[*] Análisis finalizado con éxito.\n")
except FileNotFoundError:
    print(f"[!] No se encontró el archivo '{pcap_file}'. Asegúrate de que esté guardado en esta misma carpeta.")
