# -*- coding: utf-8 -*-
"""
parser_engine.py
----------------
Motor determinista y seguro para ficheros Norma 43 (AEB 43).

Parseo ESTRICTO del estándar AEB 43 (posiciones fijas, índices 0-based). No
hay modo heurístico ni interpretación aproximada: cada campo se lee de su
posición exacta y, si no contiene datos válidos, se emite un aviso o un error.

Normalización y registros reconocidos (índices 0-based):
   - Cada línea se normaliza a EXACTAMENTE 80 caracteres:
     * si es más corta -> se completa con espacios a la derecha (.ljust(80))
     * si es más larga  -> se recorta a los primeros 80 (linea[:80])
   - Registro 11 (cabecera de cuenta): entidad 2:6, oficina 6:10, cuenta
     10:20, fecha inicial 20:26 (AAMMDD), fecha final 26:32 (AAMMDD), clave
     de saldo inicial en el índice 32 ('1' deudor = negativo, '2' acreedor =
     positivo), saldo inicial en 33:47 (14 dígitos, 2 decimales) y divisa en
     47:50 (fuera del saldo).
   - Registro 22 (movimiento): fecha de operación en 10:16 (AAMMDD), fecha
     valor en 16:22 (AAMMDD), clave de debe/haber en el índice 27 ('1' =
     cargo = negativo, '2' = abono = positivo; nunca '0'), importe en 28:42
     (14 dígitos, 2 decimales implícitos) y concepto en 52:80.
   - Registro 33 (final de cuenta): núm. movimientos al debe 20:25, total
     debe 25:39 (14 dígitos), núm. movimientos al haber 39:44, total haber
     44:58 (14 dígitos), clave de saldo final en el índice 58 ('1'/'2'),
     saldo final 59:73 (14 dígitos) y divisa 73:76 para verificar el cuadre.
   - Todos los importes usan 14 dígitos con 2 decimales implícitos
     (int(campo) / 100.0); nunca se añaden ceros de más.
   - Registro 88/99 (fin de archivo): reconocidos como tráiler de cierre
     (tiene_trailer = true).
   - Cualquier otro tipo de registro (13, 23, 34...) se ignora con un aviso:
     el parser solo extrae datos de 11/22/33 y detecta el cierre con 88/99.

Notas de seguridad/robustez (igual que versiones anteriores):
- Validación con security_utils (filename, contenido, texto)
- Límites: MAX_LINES, MAX_LINE_LEN, MAX_UPLOAD_BYTES
- Detección de payload malicioso antes de parsear
- Sin "reparación" de espacios finales: la Norma 43 REQUIERE el relleno de
  espacios hasta 80 caracteres, así que se conservan y se completa/recorta.
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

# Longitud fija de los registros Norma 43 (AEB)
LON_ESTRUCTURA = 80

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


def _parse_date_aammdd(s):
    # type: (str) -> Optional[str]
    """Parsea fecha AEB tipo AAMMDD (AAño, MMes, DDía) a ISO YYYY-MM-DD."""
    s = s.strip()
    if not DATE_DDMMYY_RE.match(s):  # mismo patrón: 6 dígitos
        return None
    aa, mm, dd = int(s[0:2]), int(s[2:4]), int(s[4:6])
    yyyy = 1900 + aa if aa >= 80 else 2000 + aa
    try:
        dt = datetime(yyyy, mm, dd)
        return dt.strftime("%Y-%m-%d")
    except ValueError:
        return None


# ----------------------------- DATACLASSES -----------------------------

@dataclass
class LineInfo:
    """Información por línea cruda"""
    raw: str                       # línea original (sin tocar)
    normalized: str                # línea normalizada a 80 posiciones (estándar AEB)
    lineno: int
    length: int                    # longitud ORIGINAL de la línea
    record_hint: Optional[str] = None  # HEADER|MOV|TRAILER|FINAL_CUENTA|OTHER|EMPTY
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

    Estructura AEB 43 (posiciones fijas, 80 caracteres por línea, índices 0-based):
    - 11: cabecera de cuenta (entidad 2:6, oficina 6:10, cuenta 10:20,
      fecha inicial 20:26 AAMMDD, fecha final 26:32 AAMMDD, clave saldo 32,
      saldo inicial 33:47, divisa 47:50)
    - 22: movimiento (fecha operación 10:16 AAMMDD, fecha valor 16:22 AAMMDD,
      debe/haber índice 27, importe 28:42, concepto 52:80)
    - 33: final de cuenta (núm. debe 20:25, total debe 25:39, núm. haber
      39:44, total haber 44:58, clave saldo final 58, saldo final 59:73,
      divisa 73:76)
    - 88/99: fin de archivo (tráiler de cierre)

    El parseo es siempre estricto: no hay fallback heurístico. Los registros
    de tipos distintos a 11/22/33/88/99 se ignoran con un aviso.
    """

    def __init__(self, filename=None):
        # type: (Optional[str]) -> None
        self.filename = filename
        self.filename_safe = secure_filename(filename)

    # ------------------------- CAMPOS DE POSICIÓN FIJA -------------------------

    @staticmethod
    def _importe_14(campo):
        # type: (str) -> Optional[Decimal]
        """Convierte un campo de importe/saldo de 14 dígitos a Decimal.

        El estándar AEB 43 usa SIEMPRE 14 dígitos con 2 decimales implícitos
        (int(campo) / 100.0). No se añaden ceros: si el campo (una vez quitados
        los espacios de relleno) no tiene exactamente 14 dígitos, devuelve None.
        """
        s = campo.replace(" ", "")
        if len(s) != 14 or not s.isdigit():
            return None
        with localcontext() as ctx:
            ctx.prec = 200
            try:
                return Decimal(int(s)) / Decimal(100)
            except (InvalidOperation, ValueError):
                return None

    @staticmethod
    def _entero(campo):
        # type: (str) -> Optional[int]
        """Convierte un contador posicional (p.ej. número de movimientos)."""
        s = campo.replace(" ", "")
        if not s or not s.isdigit():
            return None
        try:
            return int(s)
        except ValueError:  # pragma: no cover - isdigit lo garantiza
            return None

    # ------------------------- NORMALIZACIÓN / BYTES -------------------------

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
        """Normaliza saltos de línea y caracteres de control.

        NOTA: NO se recortan ni alteran los espacios finales de cada línea:
        la Norma 43 exige el relleno con espacios hasta 80 caracteres. El
        ajuste exacto a 80 posiciones (relleno/recorte) se aplica después,
        por línea, en _parse_text.
        """
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
        # Sustituye caracteres de control individuales por espacio, SIN alterar
        # las carreras de espacios de relleno (posiciones fijas del estándar)
        text2 = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", " ", text2)
        lines_fixed = []  # type: List[str]
        for l in text2.splitlines():
            if len(l) > MAX_LINE_LEN:
                l = l[:MAX_LINE_LEN]
                warnings.append("Línea truncada por exceder MAX_LINE_LEN en normalización")
            lines_fixed.append(l)
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
        """Parsea texto ya normalizado (usado directamente por tests unitarios).

        Normaliza cada línea a 80 posiciones (rellena con espacios a la derecha
        o recorta a 80) antes de analizar posiciones absolutas del estándar.
        """
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
            # Normalización a 80 posiciones: rellena a la derecha o recorta
            norm = rl.ljust(LON_ESTRUCTURA)[:LON_ESTRUCTURA]
            li = LineInfo(raw=rl, normalized=norm, lineno=i, length=len(rl))
            res.lineas.append(li)
        if empty_cnt > len(res.lineas) * 0.8:
            res.warnings.append("Más del 80% de líneas parecen vacías tras normalización")
        self._infer_record_types(res)
        self._extract_cabecera(res)
        self._extract_movimientos(res)
        self._extract_final(res)
        self._validate_balances(res)
        self._validate_lengths(res)
        self._build_summary(res)
        res.ok = len(res.errores) == 0
        return res

    # ------------------------- CLASIFICACIÓN DE REGISTROS -------------------------

    def _infer_record_types(self, res):
        # type: (ParseResult) -> None
        """Clasifica cada línea por su tipo de registro en los índices 0:2.

        Tipos reconocidos: 11 (cabecera), 22 (movimiento), 33 (final de
        cuenta) y 88/99 (fin de archivo). Los demás tipos se marcan como OTHER
        y se ignoran con un aviso: no se intenta interpretarlos.
        """
        for li in res.lineas:
            if li.normalized.strip() == "":
                li.record_hint = "EMPTY"
                continue
            tipo = li.normalized[0:2]
            if tipo == "11":
                li.record_hint = "HEADER"
            elif tipo == "22":
                li.record_hint = "MOV"
            elif tipo == "33":
                li.record_hint = "FINAL_CUENTA"
            elif tipo in ("88", "99"):
                li.record_hint = "TRAILER"
            else:
                li.record_hint = "OTHER"
                msg = (
                    "Tipo de registro %r no reconocido (esperado 11/22/33/88/99): "
                    "línea ignorada" % tipo
                )
                li.warnings.append(msg)
                res.warnings.append(msg)

    # --------------------- EXTRACCIÓN ESTRICTA (POSICIONES FIJAS) ---------------------

    def _extract_cabecera(self, res):
        # type: (ParseResult) -> None
        """Registro 11 (cabecera de cuenta): entidad 2:6, oficina 6:10, cuenta
        10:20, fecha inicial 20:26 (AAMMDD), fecha final 26:32 (AAMMDD), clave
        de saldo inicial en el índice 32 ('1' deudor = negativo, '2' acreedor =
        positivo), saldo inicial 33:47 (14 dígitos) y divisa 47:50 (fuera del
        saldo: no puede interferir en su lectura)."""
        cab = [l for l in res.lineas if l.normalized.startswith("11")]
        if not cab:
            res.errores.append("Falta registro de CABECERA (tipo 11)")
            return
        if len(cab) > 1:
            res.warnings.append(
                "Se detectan %d registros tipo 11: se usa el primero" % len(cab)
            )
        li = cab[0]
        l = li.normalized
        clave_saldo = l[32]
        saldo_dec = self._importe_14(l[33:47])
        mult = None
        if clave_saldo == "1":
            mult = Decimal("-1")
        elif clave_saldo == "2":
            mult = Decimal("1")
        else:
            res.warnings.append(
                "Registro 11: clave de saldo inicial %r no válida (esperada 1 o 2)"
                % clave_saldo
            )
        saldo_inicial = None
        if saldo_dec is not None:
            saldo_inicial = float(saldo_dec * (mult if mult is not None else Decimal("1")))
        else:
            res.warnings.append(
                "Registro 11: saldo inicial no identificable en índices 33:47"
            )
        res.cabecera = {
            "linea": li.lineno,
            "registro": "11",
            "entidad": l[2:6].strip(),
            "oficina": l[6:10].strip(),
            "cuenta": l[10:20].strip(),
            "fecha_inicial": _parse_date_aammdd(l[20:26]),
            "fecha_final": _parse_date_aammdd(l[26:32]),
            "clave_saldo": clave_saldo,
            "saldo_inicial": saldo_inicial,
            "divisa": l[47:50].strip(),
            "longitud": li.length,
        }

    def _extract_movimientos(self, res):
        # type: (ParseResult) -> None
        """Registro 22: fecha de operación (índices 10:16, formato AAMMDD),
        fecha valor (índices 16:22, AAMMDD), clave de debe/haber (índice 27,
        '1' = cargo = negativo/gasto, '2' = abono = positivo/ingreso; nunca
        '0'), importe (índices 28:42, 14 dígitos con 2 decimales implícitos) y
        concepto (índices 52:80)."""
        movs = [l for l in res.lineas if l.normalized.startswith("22")]
        if not movs:
            res.warnings.append("No se detectan registros de MOVIMIENTO (tipo 22)")
        for ml in movs:
            l = ml.normalized
            m = Movement(linea=ml.lineno)
            fop = l[10:16]
            m.fecha_operacion = _parse_date_aammdd(fop)
            if fop.strip() and m.fecha_operacion is None:
                res.warnings.append(
                    "Línea %d: fecha de operación %r no válida en registro 22"
                    % (ml.lineno, fop.strip())
                )
            fval = l[16:22]
            m.fecha_valor = _parse_date_aammdd(fval)
            if fval.strip() and m.fecha_valor is None:
                res.warnings.append(
                    "Línea %d: fecha valor %r no válida en registro 22"
                    % (ml.lineno, fval.strip())
                )
            m.concepto = l[52:80].strip() or None
            clave_op = l[2:4].strip()
            clave_dh = l[27]
            importe = self._importe_14(l[28:42])
            mult = None
            if clave_dh == "1":
                mult = Decimal("-1")   # debe/cargo: negativo / gasto
            elif clave_dh == "2":
                mult = Decimal("1")    # haber/abono: positivo / ingreso
            else:
                res.warnings.append(
                    "Línea %d: clave de debe/haber %r no válida en registro 22 "
                    "(esperada '1' cargo o '2' abono)" % (ml.lineno, clave_dh)
                )
            if importe is not None:
                valor = importe * (mult if mult is not None else Decimal("1"))
                m.importe = float(valor)
                m.signo = "-" if valor < 0 else "+"
            else:
                res.warnings.append(
                    "Línea %d: importe no identificable para cuadratura" % ml.lineno
                )
            m.extra = {"clave_operacion": clave_op, "clave_debe_haber": clave_dh}
            res.movimientos.append(m)

    def _extract_final(self, res):
        # type: (ParseResult) -> None
        """Registro 33 (final de cuenta): núm. movimientos al debe 20:25, total
        debe 25:39 (14 dígitos), núm. movimientos al haber 39:44, total haber
        44:58 (14 dígitos), clave de saldo final en el índice 58 ('1' deudor =
        negativo, '2' acreedor = positivo), saldo final 59:73 (14 dígitos) y
        divisa 73:76. Registro 88/99: fin de archivo, tráiler de cierre."""
        fin_cuenta = [l for l in res.lineas if l.record_hint == "FINAL_CUENTA"]
        fin_fichero = [l for l in res.lineas if l.record_hint == "TRAILER"]
        if not fin_cuenta:
            res.warnings.append(
                "No se detecta registro FINAL DE CUENTA (tipo 33). "
                "No se podrá verificar el cuadre contra saldos declarados"
            )
        elif len(fin_cuenta) > 1:
            res.warnings.append(
                "Se detectan %d registros tipo 33: se usa el último" % len(fin_cuenta)
            )
        if fin_cuenta:
            li = fin_cuenta[-1]
            l = li.normalized
            num_debe = self._entero(l[20:25])          # núm. movimientos debe
            total_debe = self._importe_14(l[25:39])    # total debe (14 dígitos)
            num_haber = self._entero(l[39:44])         # núm. movimientos haber
            total_haber = self._importe_14(l[44:58])   # total haber (14 dígitos)
            clave_sf = l[58]                           # clave de saldo final
            saldo_decl = self._importe_14(l[59:73])    # saldo final (14 dígitos)
            if saldo_decl is None:
                res.warnings.append(
                    "Registro 33: saldo final no identificable en índices 59:73"
                )
            # Signo del saldo final según su clave ('1' negativo, '2' positivo)
            if clave_sf == "1":
                saldo_mult = Decimal("-1")
            elif clave_sf == "2":
                saldo_mult = Decimal("1")
            else:
                saldo_mult = Decimal("1")
                if clave_sf.strip():
                    res.warnings.append(
                        "Registro 33: clave de saldo final %r no válida "
                        "(esperada 1 o 2)" % clave_sf
                    )
            if saldo_decl is not None:
                saldo_decl = saldo_decl * saldo_mult
            res.trailer = {
                "linea": li.lineno,
                "registro": "33",
                "num_movimientos_debe": num_debe,
                "total_debe": float(total_debe) if total_debe is not None else None,
                "num_movimientos_haber": num_haber,
                "total_haber": float(total_haber) if total_haber is not None else None,
                "clave_saldo_final": clave_sf,
                "saldo_final": float(saldo_decl) if saldo_decl is not None else None,
                "divisa": l[73:76].strip(),
                "longitud": li.length,
            }
        if not fin_fichero:
            res.warnings.append(
                "No se detecta registro de FIN DE ARCHIVO (tipo 88/99)"
            )
        if fin_fichero:
            li = fin_fichero[-1]
            if not res.trailer:
                res.trailer = {}
            res.trailer["fin_fichero"] = {
                "linea": li.lineno,
                "registro": li.normalized[:2],
            }

    def _validate_balances(self, res):
        # type: (ParseResult) -> None
        """Comprobación de cuadre AEB 43 (modo tolerante):
        - saldo inicial (reg. 11) + movimientos firmados (reg. 22) = saldo
          final declarado (reg. 33);
        - número de movimientos y totales al debe/haber declarados en el
          registro 33 frente a lo parseado (si están presentes).

        Los descuadres se registran como AVISOS (no bloquean el parseo): así un
        fichero con el cierre incoherente o ilegible sigue mostrando y pudiendo
        exportar sus movimientos. `res.saldos["cuadra"]` resume el resultado
        (True cuadra / False descuadre / None sin datos de cierre).
        """
        with localcontext() as ctx:
            ctx.prec = 200
            suma = Decimal("0.00")
            suma_debe = Decimal("0.00")
            suma_haber = Decimal("0.00")
            num_debe = 0
            num_haber = 0
            for m in res.movimientos:
                d = _to_decimal(m.importe) if m.importe is not None else None
                if d is None:
                    continue
                suma += d
                if d < 0:
                    suma_debe += -d
                    num_debe += 1
                elif d > 0:
                    suma_haber += d
                    num_haber += 1
            suma_q = suma.quantize(Decimal("0.01"))
            debe_q = suma_debe.quantize(Decimal("0.01"))
            haber_q = suma_haber.quantize(Decimal("0.01"))

        cab = res.cabecera or {}
        tr = res.trailer or {}
        inicial = cab.get("saldo_inicial")
        declarado = tr.get("saldo_final")
        decl_ndebe = tr.get("num_movimientos_debe")
        decl_tdebe = tr.get("total_debe")
        decl_nhaber = tr.get("num_movimientos_haber")
        decl_thaber = tr.get("total_haber")

        res.saldos = {
            "num_movimientos": len(res.movimientos),
            "suma_importes": float(suma_q),
            "saldo_inicial_estimado": inicial if inicial is not None else 0.0,
            "saldo_final_declarado_trailer": declarado,
            "saldo_final_estimado": (
                float((_to_decimal(inicial) + suma_q).quantize(Decimal("0.01")))
                if inicial is not None
                else float(suma_q)
            ),
            "num_movimientos_debe": num_debe,
            "total_debe": float(debe_q),
            "num_movimientos_haber": num_haber,
            "total_haber": float(haber_q),
        }
        if decl_ndebe is not None:
            res.saldos["num_movimientos_debe_declarado"] = decl_ndebe
        if decl_tdebe is not None:
            res.saldos["total_debe_declarado"] = decl_tdebe
        if decl_nhaber is not None:
            res.saldos["num_movimientos_haber_declarado"] = decl_nhaber
        if decl_thaber is not None:
            res.saldos["total_haber_declarado"] = decl_thaber

        # Modo tolerante: los descuadres de cuadre NO impiden el parseo. Se
        # registran como avisos (visibles) y la bandera `cuadra` los resume,
        # de modo que los movimientos siguen siendo utilizables/exportables.
        incidencias = []  # type: List[str]

        if decl_ndebe is not None and decl_ndebe != num_debe:
            res.warnings.append(
                "El registro 33 declara %d movimientos al debe y se han "
                "parseado %d" % (decl_ndebe, num_debe)
            )
            incidencias.append("num_movimientos_debe")
        if decl_nhaber is not None and decl_nhaber != num_haber:
            res.warnings.append(
                "El registro 33 declara %d movimientos al haber y se han "
                "parseado %d" % (decl_nhaber, num_haber)
            )
            incidencias.append("num_movimientos_haber")
        if decl_tdebe is not None:
            dd = (_to_decimal(decl_tdebe) - debe_q).quantize(Decimal("0.01"))
            if abs(dd) >= Decimal("0.01"):
                res.warnings.append(
                    "Descuadre en el total al debe del registro 33: "
                    "diferencia %s EUR" % dd
                )
                incidencias.append("total_debe")
        if decl_thaber is not None:
            dh = (_to_decimal(decl_thaber) - haber_q).quantize(Decimal("0.01"))
            if abs(dh) >= Decimal("0.01"):
                res.warnings.append(
                    "Descuadre en el total al haber del registro 33: "
                    "diferencia %s EUR" % dh
                )
                incidencias.append("total_haber")

        if declarado is not None:
            base = _to_decimal(inicial) if inicial is not None else Decimal("0.00")
            dif = (_to_decimal(declarado) - (base + suma_q)).quantize(Decimal("0.01"))
            res.saldos["diferencia_saldo_final"] = float(dif)
            if abs(dif) >= Decimal("0.01"):
                incidencias.append("saldo_final")
                if inicial is not None:
                    res.warnings.append(
                        "Descuadre de saldo detectado: diferencia %s EUR "
                        "(saldo inicial + movimientos vs saldo final declarado)" % dif
                    )
                else:
                    res.warnings.append(
                        "Descuadre de saldo detectado: diferencia %s EUR "
                        "(suma movimientos vs saldo final declarado)" % dif
                    )
            else:
                res.warnings.append(
                    "Saldos cuadran con el registro 33 (estándar AEB 43)"
                )
        else:
            if any(l.record_hint == "FINAL_CUENTA" for l in res.lineas):
                res.warnings.append(
                    "Registro 33 sin saldo final legible: no se pudo contrastar cuadre"
                )

        # Bandera de cuadre para API/UI: True (cuadra) / False (descuadre) /
        # None (no hay datos de cierre con los que contrastar).
        hay_datos_cuadre = (
            declarado is not None
            or decl_ndebe is not None
            or decl_tdebe is not None
            or decl_nhaber is not None
            or decl_thaber is not None
        )
        res.saldos["cuadra"] = (not incidencias) if hay_datos_cuadre else None
        if incidencias:
            res.saldos["incidencias_cuadre"] = incidencias

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
            if li.record_hint == "FINAL_CUENTA" and li.length < 73:
                li.warnings.append("Longitud registro 33 < 73 (posible truncado)")
                res.warnings.append("Línea %d: registro 33 corto <73" % li.lineno)

    # ------------------------- RESUMEN / EXPORTACIÓN -------------------------

    def _build_summary(self, res):
        # type: (ParseResult) -> None
        res.resumen = {
            "total_lineas": len(res.lineas),
            "lineas_movimiento": len([l for l in res.lineas if l.record_hint == "MOV"]),
            "lineas_vacias": len([l for l in res.lineas if l.record_hint == "EMPTY"]),
            "tiene_cabecera": any(l.record_hint == "HEADER" for l in res.lineas),
            "tiene_trailer": any(
                l.record_hint in ("TRAILER", "FINAL_CUENTA") for l in res.lineas
            ),
            "con_errores": len(res.errores) > 0,
            "num_errores": len(res.errores),
            "num_warnings": len(res.warnings),
            "num_reparados": len(res.reparado),
            "apto_para_exportar": len(res.movimientos) > 0,
            "cuadra": res.saldos.get("cuadra"),
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
