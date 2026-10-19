# -*- coding: utf-8 -*-
"""
main.py
-------
FastAPI app endurecida para Norma 43.

Seguridad aplicada:
- Middleware de límite de tamaño de request/body
- Cabeceras de seguridad globales
- Validación filename + extensión + contenido
- Saneado de filename
- Límite de lectura
- Manejo de errores genérico (sin exponer stacktrace)
- Content-Disposition con nombre seguro
"""

from __future__ import annotations

import io
import json
import time
from typing import Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from starlette.middleware.base import BaseHTTPMiddleware

from parser_engine import N43Parser, ParseResult
from security_utils import (
    ALLOWED_EXTENSIONS,
    MAX_UPLOAD_BYTES,
    check_content_security,
    check_filename_security,
    secure_filename,
    secure_http_headers,
)

# UI básica (Tailwind CDN) con drag & drop
HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Norma 43 - Validador / Conversor MVP (Seguro)</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
  <style>body{font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial}</style>
</head>
<body class="bg-slate-50 text-slate-900">
  <div class="max-w-5xl mx-auto px-4 py-8">
    <header class="mb-8">
      <h1 class="text-2xl sm:text-3xl font-semibold">Validador, Reparador y Conversor de ficheros Norma 43 (AEB) – Versión segura</h1>
      <p class="text-slate-600 mt-1">Con límites, saneado, validación y cabeceras de seguridad.</p>
    </header>
    <section class="bg-white border border-slate-200 rounded-xl shadow-sm p-6">
      <form id="form" enctype="multipart/form-data">
        <div id="drop" class="border-2 border-dashed border-slate-300 rounded-lg p-8 text-center hover:border-slate-400 transition">
          <input id="file" name="file" type="file" accept=".txt,.TXT,.n43,.N43" class="hidden" required>
          <div class="flex flex-col items-center gap-2">
            <p class="text-slate-700"><span class="font-medium">Arrastra aquí</span> o <button type="button" id="pick" class="text-indigo-600 hover:underline">selecciona un fichero</button></p>
            <p class="text-xs text-slate-500">Máx 10MB • .txt / .n43 • Sin null bytes ni patrones sospechosos</p>
            <p id="name" class="text-xs text-slate-500 mt-1"></p>
          </div>
        </div>
        <div class="mt-4 flex items-center gap-3">
          <button type="submit" class="inline-flex items-center gap-2 bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-lg text-sm font-medium shadow-sm">Analizar fichero</button>
          <span id="spin" class="hidden text-slate-500 text-sm">Procesando...</span>
        </div>
      </form>
    </section>
    <section id="result" class="hidden mt-6 bg-white border border-slate-200 rounded-xl shadow-sm overflow-hidden">
      <div class="px-6 py-4 border-b border-slate-200 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 class="text-lg font-semibold">Resultado del análisis</h2>
          <p class="text-xs text-slate-500 mt-0.5">Resumen + seguridad + saldos</p>
        </div>
        <div class="flex flex-wrap gap-2">
          <a id="dl-json" class="inline-flex items-center gap-1.5 text-sm px-3 py-1.5 rounded-lg border border-slate-200 hover:bg-slate-50" download>JSON</a>
          <a id="dl-csv" class="inline-flex items-center gap-1.5 text-sm px-3 py-1.5 rounded-lg border border-slate-200 hover:bg-slate-50" download>CSV</a>
          <a id="dl-xlsx" class="inline-flex items-center gap-1.5 text-sm px-3 py-1.5 rounded-lg border border-slate-200 hover:bg-slate-50" download>XLSX</a>
        </div>
      </div>
      <div class="grid md:grid-cols-2 gap-6 px-6 py-6">
        <div>
          <h3 class="text-sm font-semibold mb-2">Estado</h3>
          <div id="status" class="text-sm text-slate-700 space-y-1"></div>
          <h3 class="text-sm font-semibold mt-4 mb-2">Reparaciones</h3>
          <ul id="rep" class="text-sm text-slate-600 list-disc pl-5 space-y-0.5"></ul>
          <h3 class="text-sm font-semibold mt-4 mb-2">Warnings</h3>
          <ul id="warn" class="text-sm text-amber-700 list-disc pl-5 space-y-0.5"></ul>
          <h3 class="text-sm font-semibold mt-4 mb-2">Errores</h3>
          <ul id="err" class="text-sm text-red-700 list-disc pl-5 space-y-0.5"></ul>
        </div>
        <div>
          <h3 class="text-sm font-semibold mb-2">Saldos, Resumen & Seguridad</h3>
          <pre id="saldos" class="text-xs bg-slate-50 border border-slate-200 rounded-lg p-3 overflow-auto max-h-[460px]"></pre>
        </div>
      </div>
    </section>
  </div>
<script>
const form=document.getElementById('form'), file=document.getElementById('file'), pick=document.getElementById('pick'), drop=document.getElementById('drop'), name=document.getElementById('name'), spin=document.getElementById('spin'), result=document.getElementById('result');
pick.addEventListener('click',()=>file.click());
['dragenter','dragover'].forEach(e=>drop.addEventListener(e,ev=>{ev.preventDefault();ev.stopPropagation();drop.classList.add('border-indigo-400')}));
['dragleave','drop'].forEach(e=>drop.addEventListener(e,ev=>{ev.preventDefault();ev.stopPropagation();drop.classList.remove('border-indigo-400')}));
drop.addEventListener('drop',ev=>{const f=ev.dataTransfer.files[0]; if(f){file.files=ev.dataTransfer.files; name.textContent='Fichero: '+f.name;}});
file.addEventListener('change',ev=>{const f=ev.target.files[0]; name.textContent=f?'Fichero: '+f.name:''});
form.addEventListener('submit',async ev=>{
  ev.preventDefault();
  const fd=new FormData(); const f=file.files[0]; if(!f)return;
  fd.append('file',f);
  spin.classList.remove('hidden');
  try{
    const r=await fetch('/api/parse-n43',{method:'POST',body:fd});
    const j=await r.json();
    render(j);
    document.getElementById('dl-json').href='data:application/json;charset=utf-8,'+encodeURIComponent(JSON.stringify(j,null,2));
    document.getElementById('dl-csv').href='/api/export-csv?ts='+Date.now();
    document.getElementById('dl-xlsx').href='/api/export-xlsx?ts='+Date.now();
    result.classList.remove('hidden'); window.scrollTo({top:result.offsetTop-16,behavior:'smooth'});
  }catch(e){alert('Error al procesar');}
  finally{spin.classList.add('hidden');}
});
function render(j){
  const st=document.getElementById('status'); st.innerHTML='';
  st.insertAdjacentHTML('beforeend','<div><span class="font-medium">OK:</span> '+j.ok+'</div>');
  st.insertAdjacentHTML('beforeend','<div><span class="font-medium">Fichero:</span> '+(j.filename||'-')+'</div>');
  st.insertAdjacentHTML('beforeend','<div><span class="font-medium">Fichero seguro:</span> '+(j.filename_safe||'-')+'</div>');
  st.insertAdjacentHTML('beforeend','<div><span class="font-medium">Encoding detectado:</span> '+(j.encoding_detected||'-')+'</div>');
  st.insertAdjacentHTML('beforeend','<div><span class="font-medium">Encoding usado:</span> '+(j.encoding_used||'-')+'</div>');
  function list(id,arr){const el=document.getElementById(id); el.innerHTML=''; (arr||[]).forEach(x=>{const li=document.createElement('li'); li.textContent=x; el.appendChild(li);});}
  list('rep',j.reparado); list('warn',j.warnings); list('err',j.errores);
  document.getElementById('saldos').textContent=JSON.stringify({saldos:j.saldos,resumen:j.resumen,security:j.security,cabecera:j.cabecera,trailer:j.trailer},null,2);
}
</script>
</body>
</html>
"""


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Rechaza requests con Content-Length superior al límite permitido."""

    async def dispatch(self, request, call_next):
        cl = request.headers.get("content-length")
        if cl:
            try:
                if int(cl) > MAX_UPLOAD_BYTES:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "detail": "Payload demasiado grande (máx %d bytes)" % MAX_UPLOAD_BYTES
                        },
                    )
            except ValueError:
                pass
        response = await call_next(request)
        for k, v in secure_http_headers():
            response.headers[k] = v
        return response


app = FastAPI(
    title="Norma 43 Validator & Converter (Secure MVP)",
    description="Validación, reparación ligera y conversión segura de extractos Norma 43 AEB.",
    version="1.0.0-secure",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(BodySizeLimitMiddleware)


@app.on_event("startup")
def _startup() -> None:
    app.state.last = {}  # type: ignore


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    """Sirve página estática para subir fichero Norma 43"""
    return HTML


@app.post("/api/parse-n43")
async def parse_n43(file: UploadFile = File(...)) -> JSONResponse:
    """Recibe fichero bancario (.txt/.n43), valida, repara y devuelve resumen JSON."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="Fichero sin nombre")

    fn_check = check_filename_security(file.filename)
    if not fn_check.safe:
        raise HTTPException(status_code=400, detail="; ".join(fn_check.blocked_reasons))

    ext = file.filename.lower().rsplit(".", 1)[-1] if "." in file.filename else ""
    if "." + ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Extensión no permitida. Usa .txt o .n43")

    try:
        data = await file.read(MAX_UPLOAD_BYTES + 1)
        if len(data) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413, detail="Tamaño excede límite (%d bytes)" % MAX_UPLOAD_BYTES
            )
        if len(data) == 0:
            raise HTTPException(status_code=400, detail="Fichero vacío")

        cc = check_content_security(data)
        if not cc.safe:
            raise HTTPException(status_code=400, detail="; ".join(cc.blocked_reasons))

        p = N43Parser(filename=file.filename)
        res = p.parse_bytes(data, filename=file.filename)  # type: ParseResult

        app.state.last["json"] = p.to_json(res)  # type: ignore
        app.state.last["res"] = res  # type: ignore
        app.state.last["ts"] = time.time()  # type: ignore

        j = json.loads(p.to_json(res))
        return JSONResponse(content=j)
    except HTTPException:
        raise
    except Exception:
        # No exponer stacktrace ni detalles internos al cliente
        raise HTTPException(status_code=500, detail="Error inesperado al parsear")


@app.get("/api/export-csv")
async def export_csv() -> Response:
    """Descarga movimientos en CSV con punto y coma, UTF-8 BOM para Excel ES"""
    res = app.state.last.get("res")  # type: Optional[ParseResult]  # type: ignore
    if res is None:
        raise HTTPException(
            status_code=404, detail="No hay ningún parseo reciente. Sube primero un fichero."
        )
    p = N43Parser()
    csvb = p.to_csv_bytes(res)
    fname = secure_filename(res.filename_safe or res.filename or "n43_movimientos.txt")
    fname_csv = fname.rsplit(".", 1)[0] + ".csv"
    return Response(
        content=csvb,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="%s"' % fname_csv},
    )


@app.get("/api/export-xlsx")
async def export_xlsx() -> StreamingResponse:
    """Descarga movimientos en Excel (.XLSX)"""
    res = app.state.last.get("res")  # type: Optional[ParseResult]  # type: ignore
    if res is None:
        raise HTTPException(
            status_code=404, detail="No hay ningún parseo reciente. Sube primero un fichero."
        )
    p = N43Parser()
    xlsb = p.to_excel_bytes(res)
    buf = io.BytesIO(xlsb)
    buf.seek(0)
    fname = secure_filename(res.filename_safe or res.filename or "n43_movimientos.txt")
    fname_xlsx = fname.rsplit(".", 1)[0] + ".xlsx"
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": 'attachment; filename="%s"' % fname_xlsx},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
