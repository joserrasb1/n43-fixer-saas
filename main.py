# -*- coding: utf-8 -*-
"""
main.py
-------
FastAPI app endurecida para Norma 43 con interfaz SaaS profesional.

Seguridad aplicada:
- Middleware de límite de tamaño de request/body
- Cabeceras de seguridad globales (CSP, HSTS, nosniff, X-Frame...)
- Validación filename + extensión + contenido
- Saneado de filename en Content-Disposition
- Manejo de errores genérico (sin exponer stacktrace)
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

# Interfaz pública (landing + demo funcional en un único documento)
HTML = r"""
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>N43 Fixer — Valida, repara y convierte ficheros Norma 43</title>
<meta name="description" content="Sube tu fichero Norma 43 (AEB), valida estructura y saldos, repara codificación y descarga un Excel o CSV limpio en segundos.">
<script src="https://cdn.tailwindcss.com"></script>
<script>
tailwind.config = {
  theme: { extend: { fontFamily: { sans: ['Inter','system-ui','sans-serif'] } } }
};
</script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  html { scroll-behavior: smooth; }
  body { font-family: Inter, system-ui, sans-serif; }
  @keyframes fadeUp { from { opacity:0; transform:translateY(14px); } to { opacity:1; transform:none; } }
  .fade-in { animation: fadeUp .45s ease both; }
  @keyframes blob { 0%,100% { transform: translate(0,0) scale(1); } 50% { transform: translate(30px,-20px) scale(1.08); } }
  .blob { animation: blob 14s ease-in-out infinite; }
  .table-scroll::-webkit-scrollbar { height:8px; width:8px; }
  .table-scroll::-webkit-scrollbar-thumb { background:#cbd5e1; border-radius:8px; }
</style>
</head>
<body class="bg-slate-50 text-slate-900 antialiased">

<!-- ============ HEADER ============ -->
<header class="sticky top-0 z-40 border-b border-slate-200 bg-white/85 backdrop-blur">
  <div class="mx-auto flex h-16 max-w-6xl items-center justify-between px-4 sm:px-6">
    <a href="#" class="flex items-center gap-2.5">
      <span class="flex h-9 w-9 items-center justify-center rounded-xl bg-indigo-600 shadow-sm shadow-indigo-600/30">
        <svg class="h-5 w-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m-7 5h8a2 2 0 002-2V7a2 2 0 00-2-2h-1.586a1 1 0 01-.707-.293l-1.414-1.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg>
      </span>
      <span class="text-lg font-bold tracking-tight">N43&nbsp;Fixer</span>
      <span class="hidden rounded-full border border-indigo-200 bg-indigo-50 px-2 py-0.5 text-[11px] font-semibold text-indigo-700 sm:inline">BETA</span>
    </a>
    <nav class="hidden items-center gap-7 text-sm font-medium text-slate-600 md:flex">
      <a href="#como-funciona" class="hover:text-indigo-600">Cómo funciona</a>
      <a href="#demo" class="hover:text-indigo-600">Demo</a>
      <a href="#compatibilidad" class="hover:text-indigo-600">Compatibilidad</a>
      <a href="#precios" class="hover:text-indigo-600">Precios</a>
    </nav>
    <a href="#demo" class="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-700">Probar gratis</a>
  </div>
</header>

<!-- ============ HERO + DEMO ============ -->
<section class="relative overflow-hidden bg-slate-900 text-white">
  <div class="blob pointer-events-none absolute -left-24 -top-24 h-96 w-96 rounded-full bg-indigo-600/25 blur-3xl"></div>
  <div class="blob pointer-events-none absolute -bottom-32 right-0 h-96 w-96 rounded-full bg-emerald-500/15 blur-3xl" style="animation-delay:-7s"></div>

  <div class="mx-auto grid max-w-6xl items-center gap-12 px-4 py-16 sm:px-6 lg:grid-cols-2 lg:py-24">
    <!-- Copy -->
    <div class="fade-in">
      <span class="inline-flex items-center gap-2 rounded-full border border-emerald-400/30 bg-emerald-400/10 px-3 py-1 text-xs font-semibold text-emerald-300">
        <span class="h-1.5 w-1.5 rounded-full bg-emerald-400"></span>
        Prueba gratuita · Sin registro · Sin tarjeta
      </span>
      <h1 class="mt-5 text-4xl font-extrabold leading-tight tracking-tight sm:text-5xl">
        Arrastra tu <span class="bg-gradient-to-r from-indigo-400 to-sky-400 bg-clip-text text-transparent">Norma&nbsp;43</span>
        y descárgalo arreglado en segundos.
      </h1>
      <p class="mt-4 max-w-xl text-lg text-slate-300">
        Valida la estructura, detecta descuadres de saldo, repara la codificación y convierte tu extracto bancario a <strong class="text-white">Excel, CSV o JSON</strong> listo para pre-asentamiento. Sin picar datos a mano.
      </p>
      <ul class="mt-6 space-y-2.5 text-sm text-slate-300">
        <li class="flex items-start gap-2.5"><svg class="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/></svg>Validación de cabeceras, movimientos y registros finales</li>
        <li class="flex items-start gap-2.5"><svg class="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/></svg>Reparación automática de UTF-8 / Latin-1 / CP1252, BOM y saltos de línea</li>
        <li class="flex items-start gap-2.5"><svg class="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/></svg>Comprobación de cuadre: saldo inicial + movimientos = saldo final</li>
      </ul>
      <div class="mt-8 flex flex-wrap gap-3">
        <a href="#demo" class="rounded-lg bg-indigo-500 px-5 py-3 text-sm font-semibold text-white shadow-lg shadow-indigo-500/25 transition hover:bg-indigo-400">Analizar mi fichero</a>
        <a href="#como-funciona" class="rounded-lg border border-slate-600 px-5 py-3 text-sm font-semibold text-slate-200 transition hover:border-slate-400 hover:bg-slate-800">Ver cómo funciona</a>
      </div>
      <p class="mt-6 text-xs text-slate-400">Tu fichero se procesa en el servidor y no se almacena: se olvida al terminar la petición.</p>
    </div>

    <!-- Dropzone card -->
    <div id="demo" class="fade-in scroll-mt-20 rounded-2xl border border-slate-200 bg-white p-6 shadow-2xl shadow-black/40">
      <div class="flex items-center justify-between">
        <h2 class="text-base font-bold text-slate-900">Demo en vivo</h2>
        <span class="rounded-full bg-emerald-50 px-2.5 py-1 text-[11px] font-semibold text-emerald-700 ring-1 ring-emerald-200">Gratis</span>
      </div>

      <form id="form" enctype="multipart/form-data" class="mt-4">
        <div id="drop" class="cursor-pointer rounded-xl border-2 border-dashed border-slate-300 bg-slate-50 px-5 py-8 text-center transition hover:border-indigo-400 hover:bg-indigo-50/40">
          <input id="file" name="file" type="file" accept=".txt,.n43,.TXT,.N43" class="hidden" required>
          <span class="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-indigo-100 text-indigo-600">
            <svg class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8"><path stroke-linecap="round" stroke-linejoin="round" d="M12 16V4m0 0L8 8m4-4l4 4M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2"/></svg>
          </span>
          <p class="mt-3 text-sm font-semibold text-slate-800">Arrastra aquí tu fichero bancario</p>
          <p class="mt-1 text-xs text-slate-500">o <span class="font-semibold text-indigo-600 underline decoration-indigo-300 underline-offset-2">selecciónalo</span> · .txt o .n43 · máx. 10&nbsp;MB</p>
          <p id="name" class="mt-2 hidden truncate rounded-md bg-white px-2 py-1 text-xs font-medium text-slate-600 ring-1 ring-slate-200"></p>
        </div>

        <!-- Instrucciones en 3 pasos -->
        <ol class="mt-4 grid grid-cols-3 gap-2 text-center text-[11px] leading-tight text-slate-500">
          <li class="rounded-lg bg-slate-50 px-1.5 py-2 ring-1 ring-slate-100"><span class="block text-xs font-bold text-slate-800">1</span>Arrastra el .n43</li>
          <li class="rounded-lg bg-slate-50 px-1.5 py-2 ring-1 ring-slate-100"><span class="block text-xs font-bold text-slate-800">2</span>Revisa la validación</li>
          <li class="rounded-lg bg-slate-50 px-1.5 py-2 ring-1 ring-slate-100"><span class="block text-xs font-bold text-slate-800">3</span>Descarga el Excel</li>
        </ol>

        <button id="submit" type="submit" class="mt-4 flex w-full items-center justify-center gap-2 rounded-lg bg-indigo-600 px-4 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60">
          <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
          <span id="submit-txt">Analizar fichero</span>
        </button>
        <p id="form-err" class="mt-3 hidden rounded-lg bg-red-50 px-3 py-2 text-xs font-medium text-red-700 ring-1 ring-red-200"></p>
      </form>
    </div>
  </div>
</section>

<!-- ============ RESULTADO ============ -->
<section id="resultado" class="mx-auto hidden max-w-6xl scroll-mt-20 px-4 py-14 sm:px-6">
  <div class="fade-in rounded-2xl border border-slate-200 bg-white shadow-xl shadow-slate-200/60">
    <!-- Cabecera resultado -->
    <div class="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 px-6 py-5">
      <div>
        <div class="flex flex-wrap items-center gap-3">
          <h2 class="text-lg font-bold text-slate-900">Resultado del análisis</h2>
          <span id="estado" class="rounded-full px-3 py-1 text-xs font-semibold ring-1">—</span>
        </div>
        <p id="meta" class="mt-1 text-xs text-slate-500"></p>
      </div>
      <div class="flex flex-wrap gap-2">
        <a id="dl-csv" class="inline-flex cursor-pointer items-center gap-1.5 rounded-lg bg-emerald-600 px-3.5 py-2 text-xs font-semibold text-white shadow-sm transition hover:bg-emerald-700" download>
          <svg class="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2M12 4v12m0 0l-4-4m4 4l4-4"/></svg>CSV</a>
        <a id="dl-xlsx" class="inline-flex cursor-pointer items-center gap-1.5 rounded-lg bg-indigo-600 px-3.5 py-2 text-xs font-semibold text-white shadow-sm transition hover:bg-indigo-700" download>
          <svg class="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2M12 4v12m0 0l-4-4m4 4l4-4"/></svg>Excel</a>
        <a id="dl-json" class="inline-flex cursor-pointer items-center gap-1.5 rounded-lg border border-slate-200 px-3.5 py-2 text-xs font-semibold text-slate-700 transition hover:bg-slate-50" download>
          <svg class="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2M12 4v12m0 0l-4-4m4 4l4-4"/></svg>JSON</a>
      </div>
    </div>

    <div class="px-6 py-6">
      <!-- KPIs -->
      <div class="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <div class="rounded-xl bg-slate-50 p-4 ring-1 ring-slate-100">
          <p class="text-[11px] font-semibold uppercase tracking-wide text-slate-500">Líneas</p>
          <p id="kpi-lineas" class="mt-1 text-2xl font-bold text-slate-900">0</p>
        </div>
        <div class="rounded-xl bg-slate-50 p-4 ring-1 ring-slate-100">
          <p class="text-[11px] font-semibold uppercase tracking-wide text-slate-500">Movimientos</p>
          <p id="kpi-movs" class="mt-1 text-2xl font-bold text-slate-900">0</p>
        </div>
        <div class="rounded-xl bg-slate-50 p-4 ring-1 ring-slate-100">
          <p class="text-[11px] font-semibold uppercase tracking-wide text-slate-500">Saldo inicial (est.)</p>
          <p id="kpi-inicial" class="mt-1 text-2xl font-bold text-slate-900">0,00 €</p>
        </div>
        <div id="kpi-cuadre-card" class="rounded-xl bg-slate-50 p-4 ring-1 ring-slate-100">
          <p class="text-[11px] font-semibold uppercase tracking-wide text-slate-500">Cuadre de saldo</p>
          <p id="kpi-cuadre" class="mt-1 text-2xl font-bold text-slate-900">—</p>
          <p id="kpi-cuadre-det" class="mt-0.5 text-[11px] text-slate-500"></p>
        </div>
      </div>

      <div class="mt-5 grid gap-5 lg:grid-cols-2">
        <!-- Incidencias -->
        <div class="rounded-xl border border-slate-200 p-4">
          <h3 class="text-sm font-bold text-slate-900">Incidencias</h3>
          <div class="mt-3 space-y-3 text-xs">
            <div>
              <p class="mb-1.5 flex items-center gap-1.5 font-semibold text-red-700">
                <span class="h-2 w-2 rounded-full bg-red-500"></span>Errores <span id="err-n" class="font-normal text-slate-400">(0)</span>
              </p>
              <ul id="err" class="space-y-1 text-slate-600"></ul>
            </div>
            <div>
              <p class="mb-1.5 flex items-center gap-1.5 font-semibold text-amber-700">
                <span class="h-2 w-2 rounded-full bg-amber-500"></span>Avisos <span id="warn-n" class="font-normal text-slate-400">(0)</span>
              </p>
              <ul id="warn" class="space-y-1 text-slate-600"></ul>
            </div>
            <div>
              <p class="mb-1.5 flex items-center gap-1.5 font-semibold text-indigo-700">
                <span class="h-2 w-2 rounded-full bg-indigo-500"></span>Reparaciones aplicadas <span id="rep-n" class="font-normal text-slate-400">(0)</span>
              </p>
              <ul id="rep" class="space-y-1 text-slate-600"></ul>
            </div>
          </div>
        </div>

        <!-- Saldos / detalle técnico -->
        <div class="rounded-xl border border-slate-200 p-4">
          <h3 class="text-sm font-bold text-slate-900">Saldos y estructura</h3>
          <pre id="saldos" class="table-scroll mt-3 max-h-72 overflow-auto rounded-lg bg-slate-950 p-3 text-[11px] leading-relaxed text-emerald-300"></pre>
        </div>
      </div>

      <!-- Tabla movimientos -->
      <div class="mt-5">
        <div class="mb-2 flex items-center justify-between">
          <h3 class="text-sm font-bold text-slate-900">Movimientos</h3>
          <span id="mv-note" class="text-[11px] text-slate-400"></span>
        </div>
        <div class="table-scroll max-h-96 overflow-auto rounded-xl border border-slate-200">
          <table class="min-w-full divide-y divide-slate-200 text-xs">
            <thead class="sticky top-0 bg-slate-50">
              <tr id="mv-head" class="text-left text-[11px] uppercase tracking-wide text-slate-500"></tr>
            </thead>
            <tbody id="mv-body" class="divide-y divide-slate-100 bg-white text-slate-700"></tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</section>

<!-- ============ CÓMO FUNCIONA ============ -->
<section id="como-funciona" class="mx-auto max-w-6xl scroll-mt-20 px-4 py-16 sm:px-6">
  <div class="mx-auto max-w-2xl text-center">
    <p class="text-xs font-bold uppercase tracking-widest text-indigo-600">Cómo funciona</p>
    <h2 class="mt-2 text-3xl font-bold tracking-tight text-slate-900">Tres pasos, cero complicaciones</h2>
    <p class="mt-3 text-slate-600">Sin instalar nada y sin cambiar tu software contable.</p>
  </div>
  <div class="mt-10 grid gap-5 md:grid-cols-3">
    <div class="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
      <span class="flex h-10 w-10 items-center justify-center rounded-lg bg-indigo-100 text-sm font-extrabold text-indigo-700">1</span>
      <h3 class="mt-4 font-bold text-slate-900">Sube tu fichero</h3>
      <p class="mt-1.5 text-sm text-slate-600">Arrastra el <code class="rounded bg-slate-100 px-1 py-0.5 text-xs">.txt</code> o <code class="rounded bg-slate-100 px-1 py-0.5 text-xs">.n43</code> que te da tu banco. Nada de registro.</p>
    </div>
    <div class="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
      <span class="flex h-10 w-10 items-center justify-center rounded-lg bg-indigo-100 text-sm font-extrabold text-indigo-700">2</span>
      <h3 class="mt-4 font-bold text-slate-900">Validamos y reparamos</h3>
      <p class="mt-1.5 text-sm text-slate-600">Comprobamos cabeceras y saldos, corregimos codificación y te señalamos cualquier descuadre.</p>
    </div>
    <div class="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
      <span class="flex h-10 w-10 items-center justify-center rounded-lg bg-indigo-100 text-sm font-extrabold text-indigo-700">3</span>
      <h3 class="mt-4 font-bold text-slate-900">Descarga limpio</h3>
      <p class="mt-1.5 text-sm text-slate-600">Exporta a Excel, CSV o JSON listo para importar como pre-asentamiento en tu contabilidad.</p>
    </div>
  </div>
</section>

<!-- ============ COMPATIBILIDAD ============ -->
<section id="compatibilidad" class="border-y border-slate-200 bg-white py-14">
  <div class="mx-auto max-w-6xl px-4 text-center sm:px-6">
    <p class="text-xs font-bold uppercase tracking-widest text-slate-400">Compatible con tu software actual</p>
    <p class="mx-auto mt-3 max-w-2xl text-sm text-slate-600">
      No sustituimos a tu programa contable: preparamos el fichero para que entre a la primera en el que ya usas.
    </p>
    <div class="mt-7 flex flex-wrap items-center justify-center gap-3">
      <span class="rounded-xl border border-slate-200 bg-slate-50 px-5 py-2.5 text-sm font-bold text-slate-500">A3 Contabilidad</span>
      <span class="rounded-xl border border-slate-200 bg-slate-50 px-5 py-2.5 text-sm font-bold text-slate-500">Sage 50</span>
      <span class="rounded-xl border border-slate-200 bg-slate-50 px-5 py-2.5 text-sm font-bold text-slate-500">Contasol</span>
      <span class="rounded-xl border border-slate-200 bg-slate-50 px-5 py-2.5 text-sm font-bold text-slate-500">Holded</span>
      <span class="rounded-xl border border-slate-200 bg-slate-50 px-5 py-2.5 text-sm font-bold text-slate-500">Cegid</span>
      <span class="rounded-xl border border-slate-200 bg-slate-50 px-5 py-2.5 text-sm font-bold text-slate-500">Axesor</span>
    </div>
  </div>
</section>

<!-- ============ PRECIOS ============ -->
<section id="precios" class="mx-auto max-w-6xl scroll-mt-20 px-4 py-16 sm:px-6">
  <div class="mx-auto max-w-2xl text-center">
    <p class="text-xs font-bold uppercase tracking-widest text-indigo-600">Precios</p>
    <h2 class="mt-2 text-3xl font-bold tracking-tight text-slate-900">Empieza gratis, paga cuando te convenza</h2>
    <p class="mt-3 text-slate-600">Prueba con tus ficheros reales: <strong>los primeros 10 ficheros son gratis</strong>, sin tarjeta.</p>
  </div>
  <div class="mx-auto mt-10 grid max-w-3xl gap-5 md:grid-cols-2">
    <div class="rounded-2xl border border-slate-200 bg-white p-7 shadow-sm">
      <h3 class="text-sm font-bold uppercase tracking-wide text-slate-500">Starter</h3>
      <p class="mt-3"><span class="text-4xl font-extrabold text-slate-900">29&nbsp;€</span><span class="text-sm text-slate-500">/mes</span></p>
      <ul class="mt-5 space-y-2.5 text-sm text-slate-600">
        <li class="flex gap-2"><span class="font-bold text-emerald-500">✓</span>Hasta 50 ficheros o 2.500 líneas al mes</li>
        <li class="flex gap-2"><span class="font-bold text-emerald-500">✓</span>Exportación Excel, CSV y JSON</li>
        <li class="flex gap-2"><span class="font-bold text-emerald-500">✓</span>Validación y reparación completa</li>
      </ul>
      <a href="#demo" class="mt-6 block rounded-lg border border-slate-300 py-2.5 text-center text-sm font-semibold text-slate-700 transition hover:bg-slate-50">Probar gratis</a>
    </div>
    <div class="relative rounded-2xl border-2 border-indigo-600 bg-white p-7 shadow-xl shadow-indigo-600/10">
      <span class="absolute -top-3 left-1/2 -translate-x-1/2 rounded-full bg-indigo-600 px-3 py-1 text-[11px] font-bold text-white">MÁS ELEGIDO</span>
      <h3 class="text-sm font-bold uppercase tracking-wide text-indigo-600">Pro</h3>
      <p class="mt-3"><span class="text-4xl font-extrabold text-slate-900">69&nbsp;€</span><span class="text-sm text-slate-500">/mes</span></p>
      <ul class="mt-5 space-y-2.5 text-sm text-slate-600">
        <li class="flex gap-2"><span class="font-bold text-emerald-500">✓</span>Ficheros ilimitados</li>
        <li class="flex gap-2"><span class="font-bold text-emerald-500">✓</span>Soporte prioritario</li>
        <li class="flex gap-2"><span class="font-bold text-emerald-500">✓</span>Nuevos formatos de banco primero</li>
      </ul>
      <a href="#demo" class="mt-6 block rounded-lg bg-indigo-600 py-2.5 text-center text-sm font-semibold text-white transition hover:bg-indigo-700">Probar gratis</a>
    </div>
  </div>
</section>

<!-- ============ FOOTER ============ -->
<footer class="border-t border-slate-200 bg-white">
  <div class="mx-auto flex max-w-6xl flex-col items-center justify-between gap-3 px-4 py-8 sm:flex-row sm:px-6">
    <p class="text-xs text-slate-500">© 2026 N43 Fixer · Herramienta para gestorías · Ficheros Norma 43 (AEB)</p>
    <div class="flex gap-5 text-xs text-slate-500">
      <a href="#demo" class="hover:text-indigo-600">Demo</a>
      <a href="#precios" class="hover:text-indigo-600">Precios</a>
      <a href="/docs" class="hover:text-indigo-600">API</a>
    </div>
  </div>
</footer>

<!-- Toast -->
<div id="toast" class="pointer-events-none fixed bottom-5 right-5 z-50 hidden max-w-sm rounded-xl px-4 py-3 text-sm font-medium shadow-2xl ring-1"></div>

<script>
(function () {
  var form = document.getElementById('form'),
      file = document.getElementById('file'),
      drop = document.getElementById('drop'),
      nameEl = document.getElementById('name'),
      submit = document.getElementById('submit'),
      submitTxt = document.getElementById('submit-txt'),
      formErr = document.getElementById('form-err'),
      result = document.getElementById('resultado'),
      toast = document.getElementById('toast'),
      toastTimer = null;

  function showToast(msg, type) {
    var colors = type === 'error'
      ? 'bg-red-600 text-white ring-red-700'
      : 'bg-slate-900 text-white ring-slate-700';
    toast.className = 'pointer-events-none fixed bottom-5 right-5 z-50 max-w-sm rounded-xl px-4 py-3 text-sm font-medium shadow-2xl ring-1 ' + colors;
    toast.textContent = msg;   // textContent: seguro frente a XSS
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { toast.classList.add('hidden'); }, 5000);
  }

  function showFormErr(msg) {
    formErr.textContent = msg;
    formErr.classList.remove('hidden');
  }

  function hideFormErr() { formErr.classList.add('hidden'); }

  drop.addEventListener('click', function () { file.click(); });
  ['dragenter', 'dragover'].forEach(function (e) {
    drop.addEventListener(e, function (ev) {
      ev.preventDefault(); ev.stopPropagation();
      drop.classList.add('border-indigo-500', 'bg-indigo-50');
    });
  });
  ['dragleave', 'drop'].forEach(function (e) {
    drop.addEventListener(e, function (ev) {
      ev.preventDefault(); ev.stopPropagation();
      drop.classList.remove('border-indigo-500', 'bg-indigo-50');
    });
  });
  drop.addEventListener('drop', function (ev) {
    if (ev.dataTransfer && ev.dataTransfer.files.length) {
      file.files = ev.dataTransfer.files;
      setName();
    }
  });
  file.addEventListener('change', setName);

  function setName() {
    if (file.files.length) {
      nameEl.textContent = 'Fichero: ' + file.files[0].name;
      nameEl.classList.remove('hidden');
      hideFormErr();
    }
  }

  function eur(v) {
    if (v === null || v === undefined || isNaN(v)) return '—';
    return Number(v).toLocaleString('es-ES', { minimumFractionDigits: 2, maximumFractionDigits: 2 }) + ' €';
  }

  function fillList(id, nId, arr) {
    var el = document.getElementById(id);
    el.innerHTML = '';
    arr = arr || [];
    document.getElementById(nId).textContent = '(' + arr.length + ')';
    if (!arr.length) {
      var li = document.createElement('li');
      li.className = 'italic text-slate-400';
      li.textContent = 'Ninguna';
      el.appendChild(li);
      return;
    }
    arr.forEach(function (x) {
      var li = document.createElement('li');
      li.className = 'flex gap-1.5';
      var span = document.createElement('span');
      span.textContent = '•';
      var txt = document.createElement('span');
      txt.textContent = x;
      li.appendChild(span); li.appendChild(txt);
      el.appendChild(li);
    });
  }

  function render(j) {
    // Estado
    var estado = document.getElementById('estado');
    var cls, txt;
    if (!j.ok) { txt = 'Con errores'; cls = 'bg-red-50 text-red-700 ring-red-200'; }
    else if ((j.saldos || {}).cuadra === false) { txt = 'Válido con descuadre'; cls = 'bg-orange-50 text-orange-700 ring-orange-200'; }
    else if ((j.warnings || []).length) { txt = 'Válido con avisos'; cls = 'bg-amber-50 text-amber-700 ring-amber-200'; }
    else { txt = 'Válido · todo cuadra'; cls = 'bg-emerald-50 text-emerald-700 ring-emerald-200'; }
    estado.textContent = txt;
    estado.className = 'rounded-full px-3 py-1 text-xs font-semibold ring-1 ' + cls;

    // Meta línea
    var r = j.resumen || {}, s = j.saldos || {};
    document.getElementById('meta').textContent =
      (j.filename || 'fichero') +
      ' · codificación ' + (j.encoding_used || '—') +
      ' · ' + (r.total_lineas || 0) + ' líneas' +
      ' · ' + ((j.reparado || []).length) + ' reparación(es)';

    // KPIs
    document.getElementById('kpi-lineas').textContent = r.total_lineas || 0;
    document.getElementById('kpi-movs').textContent = r.lineas_movimiento || 0;
    document.getElementById('kpi-inicial').textContent = eur(s.saldo_inicial_estimado);

    var cuadre = document.getElementById('kpi-cuadre'),
        det = document.getElementById('kpi-cuadre-det'),
        card = document.getElementById('kpi-cuadre-card');
    if (s.diferencia_saldo_final !== undefined && s.diferencia_saldo_final !== null) {
      var d = s.diferencia_saldo_final;
      if (Math.abs(d) < 0.01) {
        cuadre.textContent = 'Cuadra ✓';
        cuadre.className = 'mt-1 text-2xl font-bold text-emerald-600';
        det.textContent = 'Declarado: ' + eur(s.saldo_final_declarado_trailer);
      } else {
        cuadre.textContent = eur(d);
        cuadre.className = 'mt-1 text-2xl font-bold text-red-600';
        det.textContent = 'Descuadre vs. ' + eur(s.saldo_final_declarado_trailer) + ' declarado';
      }
      card.className = 'rounded-xl p-4 ring-1 ' + (Math.abs(d) < 0.01 ? 'bg-emerald-50 ring-emerald-100' : 'bg-red-50 ring-red-100');
    } else if (s.cuadra === false) {
      // El saldo final no se pudo leer, pero sí hay descuadres en el cierre
      // (totales o contadores del registro 33): avisamos en ámbar.
      cuadre.textContent = 'No cuadra';
      cuadre.className = 'mt-1 text-2xl font-bold text-orange-600';
      det.textContent = 'Saldo final ilegible · revisa los avisos';
      card.className = 'rounded-xl p-4 ring-1 bg-orange-50 ring-orange-100';
    } else {
      cuadre.textContent = 'Sin dato';
      cuadre.className = 'mt-1 text-2xl font-bold text-slate-400';
      det.textContent = 'No se pudo contrastar con el registro final';
      card.className = 'rounded-xl bg-slate-50 p-4 ring-1 ring-slate-100';
    }

    fillList('err', 'err-n', j.errores);
    fillList('warn', 'warn-n', j.warnings);
    fillList('rep', 'rep-n', j.reparado);

    document.getElementById('saldos').textContent = JSON.stringify({
      saldos: s, resumen: r, cabecera: j.cabecera, trailer: j.trailer
    }, null, 2);

    // Tabla de movimientos (máx. 100 filas visibles)
    var mv = j.movimientos || [];
    var head = document.getElementById('mv-head'), body = document.getElementById('mv-body');
    head.innerHTML = ''; body.innerHTML = '';
    var cols = [['linea', '#'], ['fecha_operacion', 'Fecha'], ['concepto', 'Concepto'], ['importe', 'Importe'], ['signo', 'Signo'], ['referencia', 'Referencia']];
    cols.forEach(function (c) {
      var th = document.createElement('th');
      th.className = 'px-3 py-2.5 font-semibold';
      th.textContent = c[1];
      head.appendChild(th);
    });
    mv.slice(0, 100).forEach(function (row) {
      var tr = document.createElement('tr');
      cols.forEach(function (c) {
        var td = document.createElement('td');
        td.className = 'px-3 py-2';
        var v = row[c[0]];
        if (c[0] === 'importe') {
          td.textContent = v === null || v === undefined ? '—' : eur(v);
          if (v < 0) td.className += ' font-semibold text-red-600';
          else td.className += ' text-emerald-700';
        } else {
          td.textContent = (v === null || v === undefined) ? '—' : String(v);
          if (c[0] === 'concepto') td.className += ' max-w-[24rem] truncate';
        }
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
    document.getElementById('mv-note').textContent =
      mv.length > 100 ? 'Mostrando 100 de ' + mv.length + ' (descarga el CSV/Excel para verlos todos)' : (mv.length + ' movimiento(s)');

    // Descargas
    document.getElementById('dl-json').href = 'data:application/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(j, null, 2));
    document.getElementById('dl-csv').href = '/api/export-csv?ts=' + Date.now();
    document.getElementById('dl-xlsx').href = '/api/export-xlsx?ts=' + Date.now();

    result.classList.remove('hidden');
    result.classList.add('fade-in');
  }

  form.addEventListener('submit', async function (ev) {
    ev.preventDefault();
    hideFormErr();
    if (!file.files.length) { showFormErr('Selecciona primero un fichero .txt o .n43.'); return; }

    submit.disabled = true;
    submitTxt.textContent = 'Analizando…';
    try {
      var fd = new FormData();
      fd.append('file', file.files[0]);
      var resp = await fetch('/api/parse-n43', { method: 'POST', body: fd });
      var data = await resp.json();
      if (!resp.ok) {
        showFormErr(data.detail || 'No se pudo procesar el fichero.');
        showToast('No se pudo procesar el fichero', 'error');
        return;
      }
      render(data);
      showToast('Análisis completado');
      setTimeout(function () {
        result.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }, 120);
    } catch (e) {
      showFormErr('Error de conexión con el servidor.');
      showToast('Error de conexión', 'error');
    } finally {
      submit.disabled = false;
      submitTxt.textContent = 'Analizar fichero';
    }
  });
})();
</script>
</body>
</html>
"""


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Rechaza requests con Content-Length superior al límite permitido y añade cabeceras seguras."""

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
    title="N43 Fixer — Norma 43 Validator & Converter",
    description="Validación, reparación ligera y conversión segura de extractos Norma 43 AEB.",
    version="1.1.0-secure",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(BodySizeLimitMiddleware)


@app.on_event("startup")
def _startup() -> None:
    app.state.last = {}  # type: ignore


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    """Landing + demo funcional"""
    return HTML


@app.get("/health")
async def health() -> JSONResponse:
    """Health check ligero para sondas de despliegue y monitores (Render, UptimeRobot...)."""
    return JSONResponse(
        content={"status": "ok", "service": "n43-fixer", "version": "1.1.0-secure"}
    )


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
