# Reto DNSSEC — Laboratorio de pruebas con BIND

Laboratorio de DNSSEC en un entorno completamente aislado (sandbox) con Docker,
para el curso **Aplicación de Criptografía y Seguridad (MA2005B)** del
Tecnológico de Monterrey, en colaboración con **NIC México**.

El objetivo es aplicar criptografía de clave pública a un problema real de la
industria —la autenticidad en el DNS— construyendo un árbol de nombres firmado,
enlazando su cadena de confianza, e introduciendo fallas controladas para
observar cómo un servidor validador las detecta.

---

## 1. Contexto técnico

El DNS original (RFC 1034/1035, 1987) no incluye mecanismos de autenticidad, lo
que permite ataques de suplantación como el envenenamiento de caché (Kaminsky,
2008). **DNSSEC** (RFC 4033/4034/4035) mitiga esto firmando criptográficamente
cada conjunto de registros (RRset) y encadenando la confianza desde la raíz
mediante registros **DS** (Delegation Signer).

Este laboratorio implementa esa cadena de extremo a extremo y demuestra, de
forma medible, la diferencia entre un dominio protegido y uno que no lo está.

## 2. Topología (subred 172.30.0.0/24)

Cada servidor es un contenedor BIND 9 independiente con su propia IP, emulando
la delegación jerárquica real del DNS.

| Servidor | IP | Rol | DNSSEC |
|---|---|---|---|
| root | .10 | Autoritativo raíz | Firmado (alg 13, ECDSA) |
| unsigned | .20 | gTLD sin firmar | No |
| signed | .40 | gTLD firmado | Firmado (alg 13) |
| test | .70 | gTLD para malas configuraciones | Firmado (alg 13) |
| alpha.unsigned | .21 | 2º nivel bajo unsigned | No |
| beta.signed | .50 | 2º nivel, **NSEC** | Firmado (alg 13, ECDSA) |
| delta.signed | .80 | 2º nivel, **NSEC3** | Firmado (alg 8, RSA) |
| gamma.signed | .60 | 2º nivel de control | No (a propósito) |
| expired.test | .71 | Falla: RRSIG caducada | Firmado, firma vencida |
| nods.test | .72 | Falla: sin DS en el padre | Firmado, cadena rota |
| badalg.test | .73 | Falla: DS desalineado | Firmado, DS no coincide |
| recursive1 | .100 | Recursivo sin validación | dnssec-validation no |
| recursive2 | .150 | Recursivo validador | dnssec-validation yes + trust anchor |

## 3. Cadena de confianza

La validacion parte del **trust anchor** (la KSK publica de la raiz, instalada
manualmente en recursive2, ya que en un sandbox no aplica la raiz real de
Internet) y desciende nivel por nivel. En cada delegacion, la zona padre publica
un registro **DS** que es el hash de la KSK del hijo.

```text
raiz  (KSK = trust anchor en recursive2)
|
+-- DS(signed) --> signed  [KSK/ZSK propias, alg 13]
|                   |
|                   +-- DS(beta)  --> beta.signed   [NSEC,  ECDSA]  OK
|                   +-- DS(delta) --> delta.signed  [NSEC3, RSA]    OK
|                   +-- (sin DS)  --> gamma.signed  [insecure]
|
+-- DS(test)   --> test    [KSK/ZSK propias, alg 13]
                    |
                    +-- DS(expired)  --> expired.test  [firma vencida]  FALLA
                    +-- (sin DS)     --> nods.test     [cadena rota]    INSECURE
                    +-- DS'(badalg)  --> badalg.test   [DS desalineado] FALLA
```

Cada firma se realiza con `dnssec-keygen` (genera KSK y ZSK) y `dnssec-signzone`
(produce los RRSIG, el registro NSEC/NSEC3 y el `dsset` con el DS para el padre).

## 4. Escenarios de mala configuración

El gTLD `test` alberga tres dominios que fallan de maneras distintas, cada uno
ilustrando un modo de fallo real que un auditor debe distinguir:

| Dominio | Defecto introducido | Respuesta del validador | RFC relacionado |
|---|---|---|---|
| expired.test | RRSIG firmada con vigencia en el pasado | **SERVFAIL** (firma expirada) | 4034 §3.1.5 |
| nods.test | Zona firmada pero sin DS en el padre | **NOERROR sin AD** (insecure) | 4035 §5 |
| badalg.test | DS en el padre con hash alterado | **SERVFAIL** (DS ≠ DNSKEY) | 4035 §5.2 |

La distinción clave: **expired y badalg producen fallo duro (SERVFAIL)** porque
la firma o el enlace criptográfico son inválidos, mientras que **nods produce
fallo suave (insecure)** porque, al no haber DS, el validador la trata como zona
legítimamente no firmada (compatibilidad con DNS plano durante la transición).

## 5. NSEC vs NSEC3 (prueba de no existencia y zone walking)

- **beta.signed** usa **NSEC**: los registros de no existencia enlazan nombres en
  texto claro, lo que permite enumerar toda la zona ("zone walking").
- **delta.signed** usa **NSEC3** (RFC 5155): los nombres se publican como hashes,
  mitigando la enumeración.

El script `herramientas/walk_nsec.sh` demuestra el zone walking sobre beta
siguiendo la cadena NSEC. El mismo intento sobre delta solo revela hashes.

## 6. Estructura del repositorio

construir.sh Reconstruye TODO el árbol desde cero (idempotente)
limpiar.sh Borra contenedores, red y archivos generados
herramientas/
verificar_dnssec.py Audita cada zona y genera el CSV de entregables
walk_nsec.sh Demuestra zone walking (NSEC vs NSEC3)
extraer_dns.py Extrae registros (SOA/NS/A/AAAA + TTL) de capturas
evidencias/
verificacion_dnssec.csv Salida de la auditoría (resultado real)
arbol_dnslab.txt Árbol de directorios del laboratorio
capturas/ Trazas de Wireshark (.pcapng)
reporte/ Reporte técnico y ejecutivo


## 7. Reproducir el laboratorio

Requisitos: Docker y la imagen `internetsystemsconsortium/bind9:9.18`.

```bash
./construir.sh                       # levanta y firma el árbol completo (~30s)
python3 herramientas/verificar_dnssec.py   # audita y regenera el CSV
./herramientas/walk_nsec.sh beta.signed. 172.30.0.50   # zone walking NSEC
./limpiar.sh                         # resetea el entorno
```

El script genera **llaves y firmas nuevas en cada corrida**, por lo que el
laboratorio no depende de material criptográfico versionado ni de firmas
caducadas: siempre produce un árbol válido y consistente.

### Verificación manual con dig

```bash
# Dominio válido -> debe traer la bandera 'ad' (Authentic Data)
dig @172.30.0.150 www.beta.signed. A +dnssec

# Dominio con firma vencida -> SERVFAIL
dig @172.30.0.150 www.expired.test. A +dnssec

# Comparación: el recursivo sin validación NUNCA marca 'ad'
dig @172.30.0.100 www.beta.signed. A +dnssec
```

## 8. Nota de seguridad

Las llaves privadas DNSSEC (`*.private`) están **excluidas** del repositorio
mediante `.gitignore`. Solo se versiona material público por diseño (llaves
públicas, registros DS y zonas firmadas). El laboratorio opera en aislamiento
total (sandbox), sin contacto con la raíz real de Internet.

## 9. Marco normativo (RFCs)

- **4033 / 4034 / 4035** — Especificación base de DNSSEC.
- **5155** — NSEC3 (prueba de no existencia con hash, mitiga zone walking).
- **6605** — Uso de curvas elípticas (ECDSA) en DNSSEC.
- **5011** — Automatización del manejo de trust anchors (rollover de claves).
- **9364** — Documento consolidado de DNSSEC (BCP).
