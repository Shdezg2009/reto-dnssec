# Reto DNSSEC — Laboratorio de pruebas con BIND

Laboratorio de DNSSEC en entorno aislado (sandbox) con Docker, para
Aplicación de Criptografía y Seguridad (MA2005B), Tecnológico de Monterrey.

## Estructura
- `act3-4-arbol/` — árbol DNSSEC completo (raíz firmada; TLDs signed/unsigned/test;
  ramas NSEC, NSEC3 y sin firmar; dominios mal configurados) y `docker-compose.yml`.
- `act2-base/` — laboratorio base de la Actividad 2 (DNS sin DNSSEC).
- `lab-anterior/` — respaldo de la versión previa.
- `reporte/` — reporte técnico y ejecutivo.
- `capturas/` — trazas de Wireshark (.pcapng).

## Topología (subred 172.30.0.0/24)
| Servidor | IP | Rol |
|---|---|---|
| root | .10 | Raíz firmada (ECDSAP256SHA256) |
| unsigned | .20 | TLD sin firmar |
| signed | .40 | TLD firmado |
| test | .70 | TLD firmado (dominios mal configurados) |
| beta.signed | .50 | Firmado con NSEC (ECDSA, alg 13) |
| delta.signed | .80 | Firmado con NSEC3 (RSA, alg 8) |
| gamma.signed | .60 | Control sin firmar |
| expired.test | .71 | Falla: firma RRSIG caducada |
| nods.test | .72 | Falla: sin registro DS en el padre |
| badalg.test | .73 | Falla: DS desalineado con la KSK |
| recursive1 | .100 | Recursivo sin validación DNSSEC |
| recursive2 | .150 | Recursivo con validación (trust anchor local) |

## Nota de seguridad
Las llaves privadas DNSSEC (`*.private`) están excluidas mediante `.gitignore`.
Solo se versiona material público (llaves públicas, DS, zonas firmadas).

## Uso
```bash
cd act3-4-arbol
docker compose up -d
```
