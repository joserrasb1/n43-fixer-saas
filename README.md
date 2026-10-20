# Norma 43 Validator & Converter (Secure MVP)

SaaS MVP para gestorías en España: sube ficheros bancarios **Norma 43 (AEB)** en `.txt`/`.n43` para:

1. **Validar** estructura (cabeceras, movimientos, registros finales) y detectar descuadres de saldo.
2. **Reparar** automáticamente fallos de codificación/formato (UTF-8/Latin-1/CP1252, BOM, CRLF, tabuladores).
3. **Convertir** a JSON / CSV / Excel listo para pre-asentamientos contables.

Versión endurecida con saneado de entradas, límites estrictos, cabeceras de seguridad y suite de **123 tests** (cobertura 93%).

## Características de seguridad

- Límite de subida: 10 MB · máx. 50.000 líneas · 4.096 caracteres/línea
- Bloqueo de path traversal, null bytes, CRLF en nombres, extensiones no permitidas
- Detección de payloads: XSS, template injection, `eval`/`exec`, SQLi
- Cabeceras: CSP, HSTS, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`
- `Content-Disposition` con nombre saneado (sin caracteres no ASCII)
- Errores genéricos sin exposición de stacktraces

## Arranque local

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
```

- App: http://localhost:8000
- Docs OpenAPI: http://localhost:8000/docs

## Tests

```bash
pytest -v
pytest --cov=parser_engine --cov=security_utils --cov=main --cov-report=term-missing
```

## API

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/` | UI web con arrastrar/soltar |
| POST | `/api/parse-n43` | Sube `.txt`/`.n43`, devuelve resumen JSON (movimientos, saldos, errores, warnings, reparaciones) |
| GET | `/api/export-csv` | Descarga movimientos en CSV (`;`, UTF-8 BOM) |
| GET | `/api/export-xlsx` | Descarga movimientos en Excel |

## Despliegue en Render

El repositorio ya incluye `render.yaml` (plan gratis, región Frankfurt,
health check en `/health` y `autoDeploy` activo), así que desplegar es
conectar el repo:

1. En Render: **New → Web Service** → conecta `joserrasb1/n43-fixer-saas`.
2. Render detecta `render.yaml` y arranca
   `uvicorn main:app --host 0.0.0.0 --port $PORT`.
3. Tras el build, abre la URL pública asignada y comprueba
   `curl -s https://<tu-servicio>.onrender.com/health`
   → `{"status":"ok","service":"n43-fixer",...}`.

### POC en plan gratuito (0 $, sin tarjeta)

- El servicio **se duerme a los 15 min** sin tráfico: al volver a visitarlo
  aparece la página «Application loading...» (~1 min de despertar).
- 750 h de instancia al mes por workspace, compartidas entre todos los
  servicios gratis (los servicios dormidos no consumen horas).
- El disco es efímero y el estado en memoria (`app.state.last` que usan los
  exports) se pierde al dormirse o al redeplegar: si el cliente ya no tiene
  el fichero original a mano, hay que volver a subirlo.

### Producción siempre encendida (7 $/mes)

Cuando el producto empiece a facturar, **sin migrar nada** (mismo servicio,
misma URL, mismo código):

1. Añade tarjeta en **Billing** (verificación de 1 $, reembolsada).
2. Servicio → **Settings ▸ Compute Plan** → `0.5c-512mb`
   (0.5 CPU / 512 MB, **7 $/mes**, prorrateado al segundo) → **Apply**.
3. Cambia en `render.yaml` `plan: free` → `plan: 0.5c-512mb` y pushea:
   el blueprint tiene `autoDeploy: true`, y mientras el fichero diga
   `free`, un sync volvería a bajar el servicio al plan gratuito.
4. Listo: **nunca se duerme** y no hay página de carga (tampoco en los
   deploys: el zero-downtime está incluido en el plan Hobby).

Se puede volver a `free` en cualquier momento desde el mismo sitio.
Con un plan Starter de 29 €/mes del SaaS, los 7 $/mes de hosting son
marginalidad.

## Notas

- POC orientado a pruebas internas. Para producción se recomienda rate-limiting (Redis + SlowAPI), logging estructurado, validación por esquema N43 específico de cada banco y WAF.
- El parser es **estricto**: lee cada campo en su posición fija del estándar AEB 43 (registros 11/22/33 y cierre 88/99) sin interpretación heurística. Los registros de otros tipos se ignoran con un aviso, y un saldo o importe ilegible se reporta en lugar de inventarse.
- **Modo tolerante de cuadre:** los descuadres del registro 33 (contadores, totales al debe/haber o saldo final) se reportan como **avisos** y no impiden el parseo ni la exportación de los movimientos. El campo `saldos.cuadra` lo resume (`true` cuadra / `false` descuadre / `null` sin datos de cierre) y la web lo muestra como «Válido con descuadre».
