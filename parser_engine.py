# -*- coding: utf-8 -*-
"""
parser_engine.py
----------------
Motor determinista y seguro para ficheros Norma 43 (AEB).

Mejoras de seguridad/resistencia:
- Validación con security_utils
- Límites: MAX_LINES, MAX_LINE_LEN
- Normalización controlada
- Extracción numérica estricta
- Detección de líneas vacías excesivas
- Prevención de DoS por líneas gigantes
- Exportación con nombres/bytes controlados
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP, localcontext
from typing import Any, Dict, List, Optional, Tuple

try:
    import chardet  # type: ignore
except Exception:  # pragma: no cover
    chardet = None  # type: ignore

try:
    import pandas as pd  # type: ignore
except Exception:  # pragma: no cover
    pd = None  # type: ignore

from security_utils import (
    MAX_LINE_LEN,
    MAX_LINES,
    check_content_security,
    check_filename_security,
    check_text_security,
    secure_filename,
)

# ----------------------------- UTILIDADES -----------------------------

NUMERIC_CLEAN_RE = re.compile(r"[^0-9+\-\.]")
DATE_DDMMYY_RE = re.compile(r"^\d{6}$")
AMOUNT_RE = re.compile(r"[-+]?\d{1,10}[.,]\d{2}")


def _to_decimal(val):
    # type: (Any) -> Optional[Decimal]
    """Convierte un string/valor a Decimal con precisión razonable para importes EUR."""
    if val is None:
        return None
    s = str(val).strip()
    if s == "":
        return None
    s = s.replace(" ", "")
    if "," in s and "." not in s:
        s = s.replace(",", ".")
    elif "," in s and "." in s:
        # Asumimos coma decimal: quita puntos miles
        if s.rfind(",") > s.rfind("."):
            s = s.replace(".", "").replace(",", ".")
        else:
            s = s.replace(",", "")
    s2 = NUMERIC_CLEAN_RE.sub("", s)
    if s2 in ("", "+", "-", "."):
        return None
    try:
        with localcontext() as ctx:
            ctx.prec = 200  # evita InvalidOperation con números de muchos dígitos
            d = Decimal(s2)
            return d.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except (InvalidOperation, ValueError):
        return None


def _parse_date_ddmmyy(s):
    # type: (str) -> Optional[str]
    """Intenta parsear fecha AEB tipo DDMMYY a ISO 8601 YYYY-MM-DD."""
    s = s.strip()
    if not DATE_DDMMYY_RE.match(s):
        return None
    dd, mm, yy = int(s[0:2]), int(s[2:4]), int(s[4:6])
    yyyy = 1900 + yy if yy >= 80 else 2000 + yy
    try:
        dt = datetime(yyyy, mm, dd)
        return dt.strftime("%Y-%m-%d")
    except ValueError:
        return None


# ----------------------------- DATACLASSES -----------------------------

@dataclass
class LineInfo:
    """Información por línea cruda"""
    raw: str
    normalized: str
    lineno: int
    length: int
    record_hint: Optional[str] = None  # HEADER|MOV|TRAILER|OTHER|EMPTY
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


@dataclass
class Movement:
    """Movimiento limpio listo para exportar/pre-asentamiento"""
    linea: int
    fecha_operacion: Optional[str] = None
    fecha_valor: Optional[str] = None
    concepto: Optional[str] = None
    importe: Optional[float] = None
    signo: Optional[str] = None
    saldo_post: Optional[float] = None
    referencia: Optional[str] = None
    codigo_cuenta: Optional[str] = None
    codigo_oficina: Optional[str] = None
    iban: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ParseResult:
    """Resultado global del parseo"""
    ok: bool
    filename: Optional[str] = None
    filename_safe: Optional[str] = None
    encoding_detected: Optional[str] = None
    encoding_used: Optional[str] = None
    reparado: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errores: List[str] = field(default_factory=list)
    security: Dict[str, Any] = field(default_factory=dict)
    lineas: List[LineInfo] = field(default_factory=list)
    movimientos: List[Movement] = field(default_factory=list)
    cabecera: Dict[str, Any] = field(default_factory=dict)
    trailer: Dict[str, Any] = field(default_factory=dict)
    saldos: Dict[str, Any] = field(default_factory=dict)
    resumen: Dict[str, Any] = field(default_factory=dict)


# ----------------------------- PARSER PRINCIPAL -----------------------------

class N43Parser:
    """
    Parser determinista para ficheros Norma 43 AEB.

    Estructura orientativa:
    - Registro cabecera: suele empezar por '1'
    - Registros de movimiento: suelen empezar por '2'
    - Registro final/totales: suele empezar por '9'
    """

    def __init__(self, filename=None):
        # type: (Optional[str]) -> None
        self.filename = filename
        self.filename_safe = secure_filename(filename)

    def _detect_encoding(self, data):
        # type: (bytes) -> Tuple[Optional[str], str]
        """Detecta codificación con chardet y elige la más segura."""
        enc = None
        if chardet is not None:
            try:
                res = chardet.detect(data) or {}
                enc = res.get("encoding")
            except Exception:
                enc = None
        candidates = []
        if enc:
            candidates.append(enc.lower())
        candidates.extend(["utf-8", "latin-1", "cp1252", "iso-8859-1"])
        seen = set()
        for c in candidates:
            if c in seen:
                continue
            seen.add(c)
            try:
                data.decode(c)
                return (enc, c)
            except UnicodeError:
                continue
        return (enc, "latin-1")

    def _normalize_text(self, text):
        # type: (str) -> Tuple[str, List[str], List[str]]
        """Normaliza saltos de línea, espacios y caracteres problemáticos menores."""
        reparado = []  # type: List[str]
        warnings = []  # type: List[str]
        if "\r\n" in text:
            text2 = text.replace("\r\n", "\n")
            reparado.append("Convertidos CRLF a LF")
        elif "\r" in text:
            text2 = text.replace("\r", "\n")
            reparado.append("Convertidos CR a LF")
        else:
            text2 = text
        if text2.startswith("\ufeff"):
            text2 = text2.lstrip("\ufeff")
            reparado.append("Eliminado BOM UTF-8")
        if "\t" in text2:
            text2 = text2.replace("\t", " ")
            reparado.append("Sustituidos tabuladores por espacios")
        # Colapsar espacios y caracteres de control restantes
        text2 = re.sub(r"[ \x00-\x08\x0B\x0C\x0E-\x1F\x7F]+", " ", text2)
        lines_fixed = []  # type: List[str]
        changed_trim = False
        for l in text2.splitlines():
            nl = l.rstrip()
            if len(nl) > MAX_LINE_LEN:
                nl = nl[:MAX_LINE_LEN]
                warnings.append("Línea truncada por exceder MAX_LINE_LEN en normalización")
            if nl != l.rstrip("\n\r"):
                changed_trim = True
            lines_fixed.append(nl)
        if changed_trim:
            reparado.append("Recortados espacios finales por línea")
        text3 = "\n".join(lines_fixed)
        if len(text3.strip()) == 0:
            warnings.append("Fichero vacío tras normalización")
        return text3, reparado, warnings

    def parse_bytes(self, data, filename=None):
        # type: (bytes, Optional[str]) -> ParseResult
        """Parsea contenido binario con todas las validaciones de seguridad."""
        fn = filename or self.filename
        res = ParseResult(ok=False, filename=fn, filename_safe=secure_filename(fn))
        sc = check_filename_security(fn)
        res.security["filename_check"] = {
            "safe": sc.safe,
            "blocked_reasons": sc.blocked_reasons,
            "warnings": sc.warnings,
        }
        if not sc.safe:
            res.errores.extend(sc.blocked_reasons)
            return res

        cc = check_content_security(data)
        res.security["content_check"] = {
            "safe": cc.safe,
            "blocked_reasons": cc.blocked_reasons,
            "warnings": cc.warnings,
        }
        res.warnings.extend(cc.warnings)
        if not cc.safe:
            res.errores.extend(cc.blocked_reasons)
            return res

        enc_det, enc_use = self._detect_encoding(data)
        res.encoding_detected = enc_det
        res.encoding_used = enc_use
        try:
            text = data.decode(enc_use, errors="replace")
        except Exception as e:
            res.errores.append("Error decodificando con %s: %s" % (enc_use, e))
            return res

        if enc_use not in ("utf-8",):
            res.reparado.append("Decodificado con %s (fallback/conservador)" % enc_use)

        text_n, rep_n, warn_n = self._normalize_text(text)
        res.reparado.extend(rep_n)
        res.warnings.extend(warn_n)

        tc = check_text_security(text_n)
        res.security["text_check"] = {
            "safe": tc.safe,
            "blocked_reasons": tc.blocked_reasons,
            "warnings": tc.warnings,
        }
        res.warnings.extend(tc.warnings)
        if not tc.safe:
            res.errores.extend(tc.blocked_reasons)
            return res

        return self._parse_text(text_n, filename=fn, res=res)

    def _parse_text(self, text, filename=None, res=None):
        # type: (str, Optional[str], Optional[ParseResult]) -> ParseResult
        """Parsea texto ya normalizado (usado directamente por tests unitarios)."""
        fn = filename or self.filename
        if res is None:
            res = ParseResult(ok=False, filename=fn, filename_safe=secure_filename(fn))
        res.filename = fn
        res.filename_safe = secure_filename(fn)
        if text.strip() == "":
            res.errores.append("Fichero sin contenido útil")
            return res
        raw_lines = text.splitlines()
        if len(raw_lines) > MAX_LINES:
            res.errores.append("Demasiadas líneas (%d > %d)" % (len(raw_lines), MAX_LINES))
            return res
        res.lineas = []
        empty_cnt = 0
        for i, rl in enumerate(raw_lines, 1):
            if rl.strip() == "":
                empty_cnt += 1
            li = LineInfo(raw=rl, normalized=rl, lineno=i, length=len(rl))
            res.lineas.append(li)
        if empty_cnt > len(res.lineas) * 0.8:
            res.warnings.append("Más del 80% de líneas parecen vacías tras normalización")
        self._infer_record_types(res)
        self._extract_header_trailer(res)
        self._extract_movements(res)
        self._validate_lengths(res)
        self._validate_balances(res)
        self._build_summary(res)
        res.ok = len(res.errores) == 0
        return res

    def _infer_record_types(self, res):
        # type: (ParseResult) -> None
        for li in res.lineas:
            s = li.normalized.strip()
            if s == "":
                li.record_hint = "EMPTY"
                continue
            c0 = s[0]
            if c0 == "1":
                li.record_hint = "HEADER"
            elif c0 == "2":
                li.record_hint = "MOV"
            elif c0 == "9":
                li.record_hint = "TRAILER"
            else:
                li.record_hint = "OTHER"
                li.warnings.append(
                    "Carácter inicial no estándar Norma 43 (esperado 1/2/9)"
                )

    def _extract_header_trailer(self, res):
        # type: (ParseResult) -> None
        headers = [l for l in res.lineas if l.record_hint == "HEADER"]
        trailers = [l for l in res.lineas if l.record_hint == "TRAILER"]
        if len(headers) == 0:
            res.errores.append("Falta registro de CABECERA (tipo 1)")
        elif len(headers) > 1:
            res.warnings.append(
                "Se detectan %d cabeceras: se usa la primera" % len(headers)
            )
        if headers:
            h = headers[0].normalized
            res.cabecera = {
                "linea": headers[0].lineno,
                "raw10": h[:60] if len(h) >= 60 else h,
                "longitud": len(h),
            }
            if len(h) < 20:
                res.errores.append("Cabecera demasiado corta (<20)")
        if len(trailers) == 0:
            res.warnings.append(
                "No se detecta registro FINAL/TOTALES (tipo 9). "
                "Se intentará cuadrar por movimientos"
            )
        else:
            t = trailers[-1].normalized
            res.trailer = {
                "linea": trailers[-1].lineno,
                "raw10": t[:60] if len(t) >= 60 else t,
                "longitud": len(t),
            }
            if len(t) < 10:
                res.errores.append("Trailer demasiado corto (<10)")

    def _extract_movements(self, res):
        # type: (ParseResult) -> None
        movs = [l for l in res.lineas if l.record_hint == "MOV"]
        if len(movs) == 0:
            res.warnings.append("No se detectan registros de MOVIMIENTO (tipo 2)")
        for ml in movs:
            s = ml.normalized
            m = Movement(linea=ml.lineno)
            # Fecha DDMMYY orientativa
            for i in range(0, min(len(s) - 5, MAX_LINE_LEN)):
                cand = s[i:i + 6]
                if cand.isdigit():
                    iso = _parse_date_ddmmyy(cand)
                    if iso and m.fecha_operacion is None:
                        m.fecha_operacion = iso
                        break
            # Importe: último número con decimales (convención orientativa)
            nums = AMOUNT_RE.findall(s)
            if nums:
                imp = _to_decimal(nums[-1])
                if imp is not None:
                    m.importe = float(imp)
                    m.signo = "-" if imp < 0 else "+"
            if len(s) > 6:
                m.concepto = s[6:42].strip()
            if len(s) > 42:
                m.referencia = s[42:62].strip() or None
            res.movimientos.append(m)

    def _validate_lengths(self, res):
        # type: (ParseResult) -> None
        for li in res.lineas:
            if li.record_hint == "HEADER" and li.length < 20:
                li.errors.append("Longitud cabecera < 20")
                res.errores.append(
                    "Línea %d: longitud cabecera insuficiente" % li.lineno
                )
            if li.record_hint == "TRAILER" and li.length < 10:
                li.errors.append("Longitud trailer < 10")
                res.errores.append(
                    "Línea %d: longitud trailer insuficiente" % li.lineno
                )
            if li.record_hint == "MOV" and li.length < 30:
                li.errors.append("Longitud movimiento < 30 (posible truncado)")
                res.warnings.append("Línea %d: movimiento corto <30" % li.lineno)

    def _validate_balances(self, res):
        # type: (ParseResult) -> None
        with localcontext() as ctx:
            ctx.prec = 200
            sum_imp = Decimal("0.00")
            for m in res.movimientos:
                d = _to_decimal(m.importe) if m.importe is not None else None
                if d is None:
                    res.warnings.append(
                        "Línea %d: importe no identificable para cuadratura" % m.linea
                    )
                    continue
                sum_imp += d
            sum_q = sum_imp.quantize(Decimal("0.01"))
        res.saldos = {
            "num_movimientos": len(res.movimientos),
            "suma_importes": float(sum_q),
            "saldo_inicial_estimado": 0.0,
            "saldo_final_estimado": float(sum_q),
        }
        t = res.trailer.get("raw10", "")
        nums_t = AMOUNT_RE.findall(t)
        if nums_t:
            sf = _to_decimal(nums_t[-1])
            if sf is not None:
                diff = (sf - sum_q).quantize(Decimal("0.01"))
                res.saldos.update(
                    {
                        "saldo_inicial_candidato_trailer": float(
                            (sf - sum_q).quantize(Decimal("0.01"))
                        ),
                        "saldo_final_declarado_trailer": float(sf),
                        "diferencia_saldo_final": float(diff),
                    }
                )
                if abs(diff) >= Decimal("0.01"):
                    res.errores.append(
                        "Descuadre de saldo detectado: diferencia %s EUR "
                        "(suma movimientos vs saldo final declarado)" % diff
                    )
                else:
                    res.warnings.append(
                        "Saldos parecen cuadrar con totales del trailer (aprox.)"
                    )
        else:
            res.warnings.append(
                "Trailer sin importes detectables: no se pudo contrastar saldo final"
            )

    def _build_summary(self, res):
        # type: (ParseResult) -> None
        res.resumen = {
            "total_lineas": len(res.lineas),
            "lineas_movimiento": len([l for l in res.lineas if l.record_hint == "MOV"]),
            "lineas_vacias": len([l for l in res.lineas if l.record_hint == "EMPTY"]),
            "tiene_cabecera": any(l.record_hint == "HEADER" for l in res.lineas),
            "tiene_trailer": any(l.record_hint == "TRAILER" for l in res.lineas),
            "con_errores": len(res.errores) > 0,
            "num_errores": len(res.errores),
            "num_warnings": len(res.warnings),
            "num_reparados": len(res.reparado),
        }

    def to_json(self, res):
        # type: (ParseResult) -> str
        """Serializa el resultado completo a JSON seguro."""
        def _default(obj):
            if isinstance(obj, Decimal):
                return float(obj)
            if hasattr(obj, "__dataclass_fields__"):
                return asdict(obj)
            return str(obj)
        return json.dumps(res, ensure_ascii=False, indent=2, default=_default)

    def to_csv_bytes(self, res):
        # type: (ParseResult) -> bytes
        """Exporta movimientos a CSV (UTF-8 BOM, ;)"""
        if pd is not None:
            try:
                df = pd.json_normalize(asdict(res)["movimientos"])
                buf = io.StringIO()
                df.to_csv(
                    buf, index=False, sep=";",
                    quoting=csv.QUOTE_NONNUMERIC, encoding="utf-8-sig",
                )
                return buf.getvalue().encode("utf-8-sig")
            except Exception:
                pass
        buf = io.StringIO(newline="")
        fieldnames = list(Movement.__dataclass_fields__.keys())
        w = csv.DictWriter(buf, fieldnames=fieldnames, delimiter=";")
        w.writeheader()
        for m in res.movimientos:
            w.writerow({k: getattr(m, k) for k in fieldnames})
        return buf.getvalue().encode("utf-8")

    def to_excel_bytes(self, res):
        # type: (ParseResult) -> bytes
        """Exporta movimientos a Excel (XLSX)"""
        if pd is not None:
            try:
                df = pd.json_normalize(asdict(res)["movimientos"])
                buf = io.BytesIO()
                with pd.ExcelWriter(buf, engine="openpyxl") as writer:
                    df.to_excel(writer, index=False, sheet_name="N43_MOVIMIENTOS")
                return buf.getvalue()
            except Exception:
                pass
        return self.to_csv_bytes(res)
