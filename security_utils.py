# -*- coding: utf-8 -*-
"""
security_utils.py
-----------------
Utilidades de seguridad para el validador de ficheros Norma 43.

Incluye:
- Límites de tamaño, líneas, longitud por línea
- Saneado de filename (prevención path traversal)
- Detección de patrones de inyección / payloads sospechosos
- Validación estricta de contenido
- Generación de cabeceras HTTP seguras
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import List, Tuple

# Límites conservadores para un POC SaaS gratuito
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_LINES = 50000
MAX_LINE_LEN = 4096
ALLOWED_EXTENSIONS = {".txt", ".n43"}

# Patrones sospechosos comunes en intentos de inyección
SUSPICIOUS_PATTERNS = [
    # HTML/JS
    r"<\s*script",
    r"onerror\s*=",
    r"onload\s*=",
    r"javascript\s*:",
    r"data\s*:\s*text/html",
    # Plantillas/SSRF/Command-like
    r"\{\{.*\}\}",
    r"\$\{.*\}",
    r"<%.*%>",
    r"eval\s*\(",
    r"exec\s*\(",
    r"__import__",
    r"system\s*\(",
    r"passthru\s*\(",
    r"shell_exec",
    # Traversal / null byte
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%00",
    r"\x00",
    # SQL-like (por si se llegara a loggear mal)
    r"union\s+select",
    r"drop\s+table",
    r"insert\s+into",
    r"update\s+\S+\s+set",
    r"delete\s+from",
    r";\s*--",
]

# Compilados con flags estrictas
SUSPICIOUS_RE = re.compile(
    "|".join(f"(?:{p})" for p in SUSPICIOUS_PATTERNS), re.IGNORECASE | re.DOTALL
)

WINDOWS_RESERVED_NAMES = {
    "con", "prn", "aux", "nul",
    "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
    "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
}


@dataclass
class SecurityCheckResult:
    """Resultado de las validaciones de seguridad"""
    safe: bool
    blocked_reasons: List[str]
    warnings: List[str]


def secure_filename(filename):
    # type: (str | None) -> str
    """
    Genera un nombre de fichero seguro, eliminando path traversal, espacios
    y caracteres potencialmente peligrosos para cabeceras HTTP.
    """
    if not filename:
        return "upload.txt"

    # Obtener basename
    name = os.path.basename(filename)

    # Eliminar cualquier componente de ruta residual
    name = name.replace("\\", "/")
    name = os.path.basename(name)

    # Normalizar
    name = name.strip().strip(".")

    # Permitir solo alfanuméricos, guion, guion bajo, punto
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)

    # Evitar nombres reservados/windows-like (raíz sin extensión)
    root = os.path.splitext(name)[0].lower()
    if root in WINDOWS_RESERVED_NAMES:
        name = "safe_" + name

    # Asegurar extensión válida
    ext = os.path.splitext(name)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        root = os.path.splitext(name)[0]
        root = root or "upload"
        name = root + ".txt"

    # Longitud razonable
    if len(name) > 150:
        ext = os.path.splitext(name)[1]
        name = name[:140] + ext

    # No permitir nombres que empiecen con punto oculto
    if name.startswith("."):
        name = "upload" + name

    return name


def check_filename_security(filename):
    # type: (str | None) -> SecurityCheckResult
    """Valida el nombre del fichero subido"""
    res = SecurityCheckResult(safe=True, blocked_reasons=[], warnings=[])

    if not filename:
        res.safe = False
        res.blocked_reasons.append("Nombre de fichero vacío o no válido")
        return res

    name = filename

    # Path traversal directo
    if ".." in name or name.count("/") > 3 or name.count("\\") > 3:
        res.safe = False
        res.blocked_reasons.append("Nombre de fichero con ruta sospechosa (path traversal)")

    # Null byte
    if "\x00" in name:
        res.safe = False
        res.blocked_reasons.append("Nombre de fichero contiene byte nulo")

    # Caracteres de control
    if re.search(r"[\x01-\x1F\x7F]", name):
        res.safe = False
        res.blocked_reasons.append("Nombre de fichero contiene caracteres de control")

    # Extensión
    ext = os.path.splitext(name)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        res.safe = False
        res.blocked_reasons.append(
            "Extensión no permitida. Solo " + ", ".join(sorted(ALLOWED_EXTENSIONS))
        )

    # CRLF injection en header
    if "\r" in name or "\n" in name:
        res.safe = False
        res.blocked_reasons.append(
            "Nombre de fichero con salto de línea (CRLF injection riesgo en headers)"
        )

    return res


def check_content_security(data):
    # type: (bytes) -> SecurityCheckResult
    """
    Analiza bytes crudos en busca de patrones claramente maliciosos.
    No decodifica forzadamente: busca patrones en bytes y en intentos UTF-8.
    """
    res = SecurityCheckResult(safe=True, blocked_reasons=[], warnings=[])

    if len(data) == 0:
        res.safe = False
        res.blocked_reasons.append("Contenido vacío")
        return res

    if len(data) > MAX_UPLOAD_BYTES:
        res.safe = False
        res.blocked_reasons.append("Tamaño excede límite (%d bytes)" % MAX_UPLOAD_BYTES)

    # Buscar null byte
    if b"\x00" in data:
        res.safe = False
        res.blocked_reasons.append("Contenido contiene byte nulo (potencial exploit)")

    # Intentar inspeccionar como texto con reemplazo para detectar patrones
    try:
        preview = data[:8192].decode("latin-1", errors="replace")
    except Exception:
        preview = ""

    if SUSPICIOUS_RE.search(preview):
        res.safe = False
        res.blocked_reasons.append(
            "Contenido contiene patrones sospechosos (inyección/script/traversal)"
        )

    # Detección de binario muy atípico: ratio de bytes imprimibles bajo
    if preview:
        printable = sum(1 for c in preview if c.isprintable() or c in "\n\r\t")
        ratio = printable / len(preview) if preview else 0
        if ratio < 0.70:
            res.warnings.append(
                "Ratio de caracteres imprimibles bajo (<70%). Verificar que sea un TXT Norma 43 válido"
            )

    return res


def check_text_security(text):
    # type: (str) -> SecurityCheckResult
    """Validaciones tras decodificación y normalización"""
    res = SecurityCheckResult(safe=True, blocked_reasons=[], warnings=[])

    if not text:
        res.safe = False
        res.blocked_reasons.append("Texto normalizado vacío")
        return res

    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        res.safe = False
        res.blocked_reasons.append("Demasiadas líneas (%d > %d)" % (len(lines), MAX_LINES))

    # Validar longitud por línea
    long_lines = 0
    for l in lines[:1000]:  # muestreo razonable para no penalizar
        if len(l) > MAX_LINE_LEN:
            long_lines += 1
    if long_lines > 0:
        res.warnings.append(
            "Se detectan %d línea(s) con longitud > %d caracteres" % (long_lines, MAX_LINE_LEN)
        )

    # Re-chequeo de patrones tras normalización
    if SUSPICIOUS_RE.search(text[:16384]):
        res.safe = False
        res.blocked_reasons.append("Texto contiene patrones sospechosos tras normalización")

    return res


def secure_http_headers():
    # type: () -> List[Tuple[str, str]]
    """Cabeceras HTTP seguras recomendadas para respuestas"""
    return [
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
        ("Permissions-Policy", "geolocation=(), microphone=(), camera=()"),
        (
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'",
        ),
        ("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload"),
        ("Cross-Origin-Resource-Policy", "same-origin"),
        ("Cross-Origin-Embedder-Policy", "require-corp"),
    ]
