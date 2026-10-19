# -*- coding: utf-8 -*-
"""
parser_engine.py
----------------
Motor determinista y seguro para ficheros Norma 43 (AEB 43).

Dos modos de parseo, detectados automáticamente:

1. ESTÁNDAR AEB 43 (posiciones fijas):
   - Cada línea se normaliza a EXACTAMENTE 80 caracteres:
     * si es más corta -> se completa con espacios a la derecha (.ljust(80))
     * si es más larga  -> se recorta a los primeros 80 (linea[:80])
   - Registro 11 (cabecera de fichero): saldo inicial en posiciones 34-47
     (14 dígitos, 2 decimales) y su signo en posición 33 ('1' deudor = negativo,
     '2' acreedor = positivo).
   - Registro 22 (movimiento): fecha de operación en posiciones 5-10 (DDMMAA),
     clave de debe/haber en posición 27 ('1' = debe = negativo/gasto,
     '2' = haber = positivo/ingreso) e importe en posiciones 28-41
     (14 dígitos, los 2 últimos son decimales).
   - Registro 33 (final de cuenta): número de movimientos declarados en
     posiciones 20-24, suma de debedores/acreedores y saldo final para
     verificar el cuadre.
   - Registro 88/99 (fin de archivo): reconocidos como tráiler de cierre
     (tiene_trailer = true).

2. HEURÍSTICO (fallback): para ficheros no estándar o con estructura parcial
   se mantiene el análisis orientativo por primer carácter (1/2/9) y patrones
   numéricos.

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
    modo: str = "heurístico"       # "estándar AEB 43" | "heurístico"
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

    Estructura AEB 43 (posiciones fijas, 80 caracteres por línea):
    - 11: cabecera de fichero (saldo inicial pos. 34-47, signo pos. 33)
    - 22: movimiento (fecha pos. 5-10, debe/haber pos. 27, importe pos. 28-41)
    - 33: final de cuenta (nº movimientos pos. 20-24, sumas y saldo final)
    - 88/99: fin de archivo (tráiler de cierre)

    Ficheros que no cumplen el estándar se analizan con un heurístico
    conservador por primer carácter (1/2/9) y patrones numéricos.
    """

    def __init__(self, filename=None):
        # type: (Optional[str]) -> None
        self.filename = filename
        self.filename_safe = secure_filename(filename)

    # ------------------------- DETECCIÓN DE MODO -------------------------

    def _detectar_modo_estandar(self, res):
        # type: (ParseResult) -> bool
        """Detecta si el fichero cumple el formato de posiciones fijas AEB 43.

        Criterio: existe al menos un registro 11 (cabecera de fichero) y algún
        registro 22 cuyo campo de importe (posiciones 28-41) contenga 14 dígitos.
        Los ficheros heurísticos de pruebas/no estándar no cumplen esto y
        quedan en modo fallback.
        """
        lineas = [l.normalized for l in res.lineas]
        if not any(l.startswith("11") for l in lineas):
            return False
        movs = [l for l in lineas if l.startswith("22")]
        if not movs:
            return False
        for m in movs:
            campo = m[27:41]  # posiciones 28-41 (14 dígitos)
            if len(campo) == 14 and campo.isdigit():
                return True
        return False

    # ------------------------- CAMPOS DE POSICIÓN FIJA -------------------------

    @staticmethod
    def _campo_importe(campo):
        # type: (str) -> Optional[Decimal]
        """Convierte un campo numérico de 14 dígitos (2 decimales implícitos) a Decimal.

        Acepta espacios de relleno a la izquierda; devuelve None si no son
        todos dígitos.
        """
        s = campo.replace(" ", "")
        if not s or not s.isdigit():
            return None
        with localcontext() as ctx:
            ctx.prec = 200
            try:
                return (Decimal(s) / Decimal(100)).quantize(Decimal("0.01"))
            except (InvalidOperation, ValueError):
                return None

    @staticmethod
    def _fecha_estandar(campo):
        # type: (str) -> Optional[str]
        """Parsea un campo de fecha AEB: DDMMAAAA (8) o DDMMAA (6) -> ISO."""
        s = campo.strip()
        if len(s) == 8 and s.isdigit():
            try:
                return datetime(int(s[4:8]), int(s[2:4]), int(s[0:2])).strftime("%Y-%m-%d")
            except ValueError:
                return None
        if len(s) == 6:
            return _parse_date_ddmmyy(s)
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
        if self._detectar_modo_estandar(res):
            res.modo = "estándar AEB 43"
            self._extract_cabecera_estandar(res)
            self._extract_movimientos_estandar(res)
            self._extract_final_estandar(res)
            self._validate_balances_estandar(res)
        else:
            res.modo = "heurístico"
            self._extract_header_trailer(res)
            self._extract_movements(res)
            self._validate_balances(res)
        self._validate_lengths(res)
        self._build_summary(res)
        res.ok = len(res.errores) == 0
        return res

    # ------------------------- INFERENCIA DE REGISTROS -------------------------

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
            elif s.startswith("33"):
                # Final de cuenta (estándar AEB 43)
                li.record_hint = "FINAL_CUENTA"
            elif c0 in ("8", "9"):
                # Fin de archivo / tráiler de cierre (88, 99 o 9)
                li.record_hint = "TRAILER"
            else:
                li.record_hint = "OTHER"
                li.warnings.append(
                    "Carácter inicial no estándar Norma 43 (esperado 1/2/3/8/9)"
                )

    # ------------------------- MODO ESTÁNDAR AEB 43 -------------------------

    def _extract_cabecera_estandar(self, res):
        # type: (ParseResult) -> None
        """Registro 11: cabecera de fichero con saldo inicial (pos. 34-47)
        y su signo en posición 33 ('1' deudor = negativo, '2' acreedor = positivo)."""
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
        clave_saldo = l[32:33]
        saldo_dec = self._campo_importe(l[33:47])
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
                "Registro 11: saldo inicial no identificable en posiciones 34-47"
            )
        res.cabecera = {
            "linea": li.lineno,
            "registro": "11",
            "entidad": l[2:6].strip(),
            "oficina": l[6:10].strip(),
            "cuenta": l[10:20].strip(),
            "digitos_control": l[20:22].strip(),
            "fecha_apertura": self._fecha_estandar(l[22:30]),
            "clave_saldo": clave_saldo,
            "saldo_inicial": saldo_inicial,
            "divisa": l[47:50].strip(),
            "longitud": li.length,
        }

    def _extract_movimientos_estandar(self, res):
        # type: (ParseResult) -> None
        """Registro 22: fecha (pos. 5-10), clave debe/haber (pos. 27,
        '1' = negativo/gasto, '2' = positivo/ingreso) e importe (pos. 28-41,
        14 dígitos con 2 decimales implícitos)."""
        movs = [l for l in res.lineas if l.normalized.startswith("22")]
        if not movs:
            res.warnings.append("No se detectan registros de MOVIMIENTO (tipo 22)")
        for ml in movs:
            l = ml.normalized
            m = Movement(linea=ml.lineno)
            m.fecha_operacion = _parse_date_ddmmyy(l[4:10])
            m.fecha_valor = self._fecha_estandar(l[10:18])
            m.concepto = l[18:26].strip() or None
            clave_op = l[2:4].strip()
            clave_dh = l[26:27]
            importe = self._campo_importe(l[27:41])
            mult = None
            if clave_dh == "1":
                mult = Decimal("-1")   # debe: negativo / gasto
            elif clave_dh == "2":
                mult = Decimal("1")    # haber: positivo / ingreso
            else:
                res.warnings.append(
                    "Línea %d: clave de debe/haber %r no válida en registro 22 "
                    "(esperada 1 o 2)" % (ml.lineno, clave_dh)
                )
            if importe is not None:
                valor = importe * (mult if mult is not None else Decimal("1"))
                m.importe = float(valor)
                m.signo = "-" if valor < 0 else "+"
            else:
                res.warnings.append(
                    "Línea %d: importe no identificable para cuadratura" % ml.lineno
                )
            m.referencia = l[41:54].strip() or None
            m.extra = {"clave_operacion": clave_op, "clave_debe_haber": clave_dh}
            res.movimientos.append(m)

    def _extract_final_estandar(self, res):
        # type: (ParseResult) -> None
        """Registro 33 (final de cuenta): nº de movimientos (pos. 20-24),
        suma de debedores/acreedores y saldo final. Registro 88/99: fin de
        archivo, reconocido como tráiler de cierre."""
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
            num_decl = l[19:24].strip()          # posiciones 20-24
            suma_decl = self._campo_importe(l[25:39])
            saldo_decl = self._campo_importe(l[40:54])
            if saldo_decl is None:
                # Fallback conservador: último importe detectable de la línea
                nums = AMOUNT_RE.findall(l)
                if nums:
                    cand = _to_decimal(nums[-1])
                    if cand is not None:
                        saldo_decl = cand
                        res.warnings.append(
                            "Registro 33: saldo final leído por fallback "
                            "(posiciones no estándar)"
                        )
            res.trailer = {
                "linea": li.lineno,
                "registro": "33",
                "num_movimientos_declarado": int(num_decl) if num_decl.isdigit() else None,
                "suma_debedores_acreedores": (
                    float(suma_decl) if suma_decl is not None else None
                ),
                "saldo_final": float(saldo_decl) if saldo_decl is not None else None,
                "longitud": li.length,
            }
        if fin_fichero:
            li = fin_fichero[-1]
            if not res.trailer:
                res.trailer = {}
            res.trailer["fin_fichero"] = {
                "linea": li.lineno,
                "registro": li.normalized[:2],
            }

    def _validate_balances_estandar(self, res):
        # type: (ParseResult) -> None
        """Cuadre estricto AEB: saldo inicial (reg. 11) + movimientos (reg. 22)
        = saldo final declarado (reg. 33); además se contrastan la suma de
        importes y el número de movimientos declarados."""
        with localcontext() as ctx:
            ctx.prec = 200
            suma = Decimal("0.00")
            for m in res.movimientos:
                d = _to_decimal(m.importe) if m.importe is not None else None
                if d is None:
                    continue
                suma += d
            suma_q = suma.quantize(Decimal("0.01"))

        cab = res.cabecera or {}
        tr = res.trailer or {}
        inicial = cab.get("saldo_inicial")
        declarado = tr.get("saldo_final")
        suma_declarada = tr.get("suma_debedores_acreedores")
        num_decl = tr.get("num_movimientos_declarado")

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
        }

        if num_decl is not None:
            res.saldos["num_movimientos_declarado"] = num_decl
            if num_decl != len(res.movimientos):
                res.warnings.append(
                    "El registro 33 declara %d movimientos y se han parseado %d"
                    % (num_decl, len(res.movimientos))
                )
        if suma_declarada is not None:
            res.saldos["suma_importes_declarada"] = suma_declarada
            ds = (_to_decimal(suma_declarada) - suma_q).quantize(Decimal("0.01"))
            if abs(ds) >= Decimal("0.01"):
                res.errores.append(
                    "Descuadre en la suma de movimientos del registro 33: "
                    "diferencia %s EUR" % ds
                )

        if declarado is not None:
            base = _to_decimal(inicial) if inicial is not None else Decimal("0.00")
            dif = (_to_decimal(declarado) - (base + suma_q)).quantize(Decimal("0.01"))
            res.saldos["diferencia_saldo_final"] = float(dif)
            if abs(dif) >= Decimal("0.01"):
                if inicial is not None:
                    res.errores.append(
                        "Descuadre de saldo detectado: diferencia %s EUR "
                        "(saldo inicial + movimientos vs saldo final declarado)" % dif
                    )
                else:
                    res.errores.append(
                        "Descuadre de saldo detectado: diferencia %s EUR "
                        "(suma movimientos vs saldo final declarado)" % dif
                    )
            else:
                res.warnings.append(
                    "Saldos cuadran con el registro 33 (estándar AEB 43)"
                )
        else:
            res.warnings.append(
                "Registro 33 sin saldo final legible: no se pudo contrastar cuadre"
            )

    # ------------------------- MODO HEURÍSTICO (FALLBACK) -------------------------

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

    # ------------------------- RESUMEN / EXPORTACIÓN -------------------------

    def _build_summary(self, res):
        # type: (ParseResult) -> None
        res.resumen = {
            "modo": res.modo,
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
