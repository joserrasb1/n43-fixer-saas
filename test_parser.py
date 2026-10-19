# -*- coding: utf-8 -*-
"""
test_parser.py
--------------
Suite exhaustiva de unit tests para asegurar robustez y seguridad.

Cubre:
- Utilidades numéricas y de fechas
- security_utils (filename, contenido, texto, cabeceras)
- Parser: correcto, descuadres, longitudes, vacíos, encodings, límites
- Inyecciones (XSS, template, code exec, SQL, traversal)
- Exportaciones (JSON, CSV, XLSX)
- API FastAPI end-to-end (TestClient)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import pytest

from parser_engine import (
    N43Parser,
    _parse_date_aammdd,
    _parse_date_ddmmyy,
    _to_decimal,
    AMOUNT_RE,
    DATE_DDMMYY_RE,
)
from security_utils import (
    MAX_LINE_LEN,
    MAX_LINES,
    MAX_UPLOAD_BYTES,
    check_content_security,
    check_filename_security,
    check_text_security,
    secure_filename,
    secure_http_headers,
)

# ============================ UTILIDADES NUMÉRICAS ============================

def test_to_decimal_basic():
    assert _to_decimal("100,00") == 100
    assert _to_decimal("-50,50") == -50.50
    assert _to_decimal("+10,00") == 10.00
    assert float(_to_decimal("1.234,56")) == 1234.56
    assert float(_to_decimal("1234.56")) == 1234.56
    assert _to_decimal("  10,5  ") == 10.5
    assert float(_to_decimal("000123,45")) == 123.45
    assert _to_decimal("") is None
    assert _to_decimal("   ") is None
    assert _to_decimal("abc") is None
    assert _to_decimal("+++") is None
    assert _to_decimal("..") is None
    assert _to_decimal(None) is None
    assert _to_decimal("EUR 100,00") == 100.00


def test_to_decimal_edge():
    assert _to_decimal("0,00") == 0.00
    assert float(_to_decimal("-0,01")) == -0.01
    assert float(_to_decimal("999999999,99")) == 999999999.99
    assert float(_to_decimal("1,234.56")) == 1234.56
    assert _to_decimal("1.000,00") == 1000.00


def test_decimal_rounding():
    assert float(_to_decimal("10,555")) == 10.56
    assert float(_to_decimal("10,554")) == 10.55
    assert float(_to_decimal("-10,555")) == -10.56


# ============================ UTILIDADES DE FECHA ============================

def test_parse_date_ddmmyy():
    assert _parse_date_ddmmyy("010120") == "2020-01-01"
    assert _parse_date_ddmmyy("311299") == "1999-12-31"
    assert _parse_date_ddmmyy("010101") == "2001-01-01"
    assert _parse_date_ddmmyy("150990") == "1990-09-15"
    assert _parse_date_ddmmyy("300230") is None
    assert _parse_date_ddmmyy("000000") is None
    assert _parse_date_ddmmyy("320101") is None
    assert _parse_date_ddmmyy("311302") is None
    assert _parse_date_ddmmyy("abc123") is None
    assert _parse_date_ddmmyy("12345") is None
    assert _parse_date_ddmmyy("1234567") is None


def test_parse_date_aammdd():
    """Formato AAMMDD de la fecha de operación del registro 22."""
    assert _parse_date_aammdd("250105") == "2025-01-05"
    assert _parse_date_aammdd("991231") == "1999-12-31"
    assert _parse_date_aammdd("800101") == "1980-01-01"   # regla de siglo
    assert _parse_date_aammdd("250230") is None           # día inexistente
    assert _parse_date_aammdd("000000") is None
    assert _parse_date_aammdd("abc123") is None
    assert _parse_date_aammdd("12345") is None
    assert _parse_date_aammdd("        ") is None


def test_regexes_compiled():
    assert AMOUNT_RE.findall("10,00 -5,50 +1,23") == ["10,00", "-5,50", "+1,23"]
    assert DATE_DDMMYY_RE.match("010120")
    assert not DATE_DDMMYY_RE.match("1A0120")


# ============================ SECURE FILENAME ============================

def test_secure_filename_basic():
    assert secure_filename("movimientos.txt").endswith(".txt")
    assert secure_filename("EXTRACTO.N43").lower().endswith(".n43")
    assert secure_filename(None) == "upload.txt"
    assert secure_filename("") == "upload.txt"


def test_secure_filename_path_traversal():
    assert "../etc/passwd.txt" not in secure_filename("../etc/passwd.txt")
    assert secure_filename("..\\..\\win.ini.txt").endswith(".txt")
    assert secure_filename("/tmp/evil.txt").endswith("evil.txt")
    assert secure_filename("C:\\Users\\x\\file.txt").endswith("file.txt")


def test_secure_filename_injection_chars():
    fn = secure_filename('"><img src=x onerror=alert(1)>.txt')
    assert "<" not in fn and ">" not in fn and '"' not in fn


def test_secure_filename_nullbyte_like():
    fn = secure_filename("file\x00.txt")
    assert "\x00" not in fn


def test_secure_filename_long():
    longn = "a" * 200 + ".txt"
    fn = secure_filename(longn)
    assert len(fn) <= 160
    assert fn.endswith(".txt")


def test_secure_filename_reserved():
    for r in ["CON.txt", "con.TXT", "PRN.txt", "AUX.n43", "NUL.txt"]:
        fn = secure_filename(r)
        assert fn.startswith("safe_")


def test_secure_filename_hidden_dot():
    fn = secure_filename(".hidden.txt")
    assert not fn.startswith(".")


# ============================ CHECK FILENAME SECURITY ============================

def test_check_filename_security_ok():
    r = check_filename_security("extracto_2025_10.txt")
    assert r.safe is True


def test_check_filename_security_none():
    r = check_filename_security(None)
    assert r.safe is False


def test_check_filename_security_bad_ext():
    r = check_filename_security("malicioso.exe")
    assert r.safe is False
    assert any("extensión" in x.lower() for x in r.blocked_reasons)


def test_check_filename_security_traversal():
    for bad in ["../../etc/passwd.txt", "..\\secret.txt", "dir/../file.txt"]:
        r = check_filename_security(bad)
        assert r.safe is False


def test_check_filename_security_nullbyte():
    r = check_filename_security("file\x00.txt")
    assert r.safe is False


def test_check_filename_security_crlf():
    r = check_filename_security("file\r\n.txt")
    assert r.safe is False
    r2 = check_filename_security("file\nbad.txt")
    assert r2.safe is False


def test_check_filename_security_control():
    r = check_filename_security("file\x01.txt")
    assert r.safe is False


# ============================ CHECK CONTENT SECURITY ============================

def test_check_content_security_ok():
    r = check_content_security(b"111234567890ABCDEFGHIJ1234567890\n220101A\n9000000000")
    assert r.safe is True


def test_check_content_security_empty():
    r = check_content_security(b"")
    assert r.safe is False


def test_check_content_security_nullbyte():
    r = check_content_security(b"1111111111\x001111111111")
    assert r.safe is False


def test_check_content_security_too_big():
    big = b"A" * (MAX_UPLOAD_BYTES + 1)
    r = check_content_security(big)
    assert r.safe is False


def test_check_content_security_script():
    for payload in [
        b"<script>alert(1)</script>",
        b"javascript:alert(1)",
        b"onerror=alert(1)",
        b"<img src=x onerror=alert(1)>",
    ]:
        r = check_content_security(payload)
        assert r.safe is False


def test_check_content_security_template():
    for payload in [b"{{7*7}}", b"${process.env}", b"<%=7*7%>"]:
        r = check_content_security(payload)
        assert r.safe is False


def test_check_content_security_eval_exec():
    for payload in [
        b"eval('1+1')",
        b"__import__('os')",
        b"system('id')",
        b"shell_exec('ls')",
        b"passthru('ls')",
    ]:
        r = check_content_security(payload)
        assert r.safe is False


def test_check_content_security_sql():
    for payload in [
        b"UNION SELECT 1,2,3",
        b"DROP TABLE users",
        b"';--",
        b"DELETE FROM users",
        b"UPDATE users SET a=1",
    ]:
        r = check_content_security(payload)
        assert r.safe is False


def test_check_content_security_urlencoded_traversal():
    r = check_content_security(b"%2e%2e%2f%2e%2e%2fetc/passwd")
    assert r.safe is False


def test_check_content_security_binary_low_ratio():
    binlike = bytes([0x01, 0x02, 0x03, 0x04, 0x05]) * 200
    r = check_content_security(binlike)
    assert "ratio" in " ".join(r.warnings).lower()


# ============================ CHECK TEXT SECURITY ============================

def test_check_text_security_ok():
    txt = "\n".join(["111234567890ABCDEFGHIJ1234567890", "220101A", "9000000000"])
    r = check_text_security(txt)
    assert r.safe is True


def test_check_text_security_empty():
    r = check_text_security("")
    assert r.safe is False


def test_check_text_security_too_many_lines():
    txt = "\n".join(["LINE%d" % i for i in range(MAX_LINES + 5)])
    r = check_text_security(txt)
    assert r.safe is False


def test_check_text_security_long_line():
    longl = "2" + "X" * (MAX_LINE_LEN + 50)
    txt = "111234567890ABCDEFGHIJ1234567890\n" + longl + "\n9000000000"
    r = check_text_security(txt)
    assert any("longitud" in w.lower() for w in r.warnings)


def test_check_text_security_suspicious():
    txt = "11111111111111111111\n<script>\n9000000000"
    r = check_text_security(txt)
    assert r.safe is False


# ============================ SECURE HTTP HEADERS ============================

def test_secure_http_headers():
    hdrs = dict(secure_http_headers())
    assert hdrs["X-Content-Type-Options"] == "nosniff"
    assert hdrs["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in hdrs
    assert "Strict-Transport-Security" in hdrs


# ============================ PARSER: ESTÁNDAR AEB 43 (POSICIONES FIJAS) ============================

def _reg80(clave, campos):
    # type: (str, list) -> str
    """Construye un registro AEB 43 de exactamente 80 caracteres.

    campos: lista de (posición_base_1, texto) según el estándar AEB 43.
    """
    l = [" "] * 80
    for i, ch in enumerate(clave):
        l[i] = ch
    for pos, txt in campos:
        for i, ch in enumerate(txt):
            l[pos - 1 + i] = ch
    return "".join(l)


def _cab(entidad="2100", oficina="0418", cuenta="1234567890", fecha="250915",
         fecha_final=None, clave="2", saldo="00000000500000", divisa="EUR"):
    # type: (str, str, str, str, str, str, str, str) -> str
    """Registro 11 (cabecera de cuenta): entidad 2:6, oficina 6:10, cuenta
    10:20, fecha inicial 20:26 (AAMMDD), fecha final 26:32 (AAMMDD), clave de
    saldo en el índice 32, saldo inicial de 14 dígitos en 33:47 y divisa en
    47:50."""
    return _reg80("11", [
        (3, entidad), (7, oficina), (11, cuenta),
        (21, fecha), (27, fecha_final or fecha), (33, clave),
        (34, saldo), (48, divisa),
    ])


def _mov(fecha_op="250915", fecha_valor="250917", clave_dh="2",
         importe="00000000215000", concepto="NOMINA1"):
    # type: (str, str, str, str, str) -> str
    """Registro 22 (movimiento): fecha operación 10:16 y fecha valor 16:22
    (AAMMDD), clave debe/haber en el índice 27, importe de 14 dígitos en
    28:42 y concepto en 52:80."""
    return _reg80("22", [
        (3, "01"), (11, fecha_op), (17, fecha_valor),
        (28, clave_dh), (29, importe), (53, concepto),
    ])


def _reg33(num_debe="00000", total_debe="00000000000000",
           num_haber="00000", total_haber="00000000000000",
           clave="2", saldo="00000000000000", divisa="EUR"):
    # type: (str, str, str, str, str, str, str) -> str
    """Registro 33 (final de cuenta): núm. movs debe 20:25, total debe 25:39,
    núm. movs haber 39:44, total haber 44:58, clave de saldo final en el
    índice 58, saldo final de 14 dígitos en 59:73 y divisa en 73:76."""
    return _reg80("33", [
        (21, num_debe), (26, total_debe), (40, num_haber),
        (45, total_haber), (59, clave), (60, saldo), (74, divisa),
    ])


def _n43_estandar(descuadre=False, fin="99"):
    # type: (bool, str) -> str
    """Fichero AEB 43 estricto: saldo inicial 5.000,00 y 5 movimientos.

    Movimientos: +2150,00 -875,25 -950,00 +3400,00 -12,50 = +3712,25
    → saldo final debe cuadrar en 8712,25 (cargos 1.837,75; abonos 5.550,00).
    """
    cab = _cab()
    movs = [
        _mov("250915", "250917", "2", "00000000215000", "NOMINA1"),   # +2150,00
        _mov("250910", "250912", "1", "00000000087525", "IVA1"),      #  -875,25
        _mov("251001", "251003", "1", "00000000095000", "ALQ1"),      #  -950,00
        _mov("251003", "251005", "2", "00000000340000", "COB1"),      # +3400,00
        _mov("251001", "251003", "1", "00000000001250", "COM1"),      #   -12,50
    ]
    saldo_final = "00000000871100" if descuadre else "00000000871225"
    fin_cuenta = _reg33(
        num_debe="00003", total_debe="00000000183775",
        num_haber="00002", total_haber="00000000555000",
        clave="2", saldo=saldo_final,
    )
    return "\n".join([cab] + movs + [fin_cuenta, _reg80(fin, [])])


# ---------------------------- CASOS CORRECTOS ----------------------------

def test_parse_correcto_minimo(parser: N43Parser):
    res = parser._parse_text(_n43_estandar(), filename="correcto.txt")
    assert res.ok is True
    assert res.filename == "correcto.txt"
    assert res.filename_safe.endswith(".txt")
    assert res.resumen["tiene_cabecera"] is True
    assert res.resumen["tiene_trailer"] is True
    assert res.resumen["lineas_movimiento"] == 5
    assert len(res.movimientos) == 5
    assert res.saldos["suma_importes"] == 3712.25
    assert res.saldos.get("diferencia_saldo_final") == 0.00


def test_parse_cuadra_exacto_avisa(parser: N43Parser):
    """Con registro 33 que cuadra exacto se emite aviso informativo (ok=True)."""
    cab = _cab(saldo="00000000010000")                    # saldo inicial 100,00
    mov = _mov("251015", "251017", "2", "00000000010000", "ABONO")
    fin = _reg33(
        num_haber="00001", total_haber="00000000010000",
        clave="2", saldo="00000000020000",                 # saldo final 200,00
    )
    txt = "\n".join([cab, mov, fin, _reg80("99", [])])
    res = parser._parse_text(txt, filename="cuadra.txt")
    assert res.ok is True
    assert res.saldos["diferencia_saldo_final"] == 0.00
    assert res.trailer["total_debe"] == 0.00
    assert res.trailer["total_haber"] == 100.00
    assert any("cuadran" in w.lower() for w in res.warnings)


def test_parse_varios_movimientos_signos(parser: N43Parser):
    txt = "\n".join([
        _cab(saldo="00000000000000"),                      # saldo inicial 0,00
        _mov("251001", "251003", "2", "00000000010000", "A"),
        _mov("251002", "251004", "1", "00000000002000", "B"),
        _mov("251003", "251005", "2", "00000000005000", "C"),
        _reg33(
            num_debe="00001", total_debe="00000000002000",
            num_haber="00002", total_haber="00000000015000",
            clave="2", saldo="00000000013000",             # saldo final 130,00
        ),
        _reg80("99", []),
    ])
    res = parser._parse_text(txt, filename="multi.txt")
    assert len(res.movimientos) == 3
    assert [m.signo for m in res.movimientos] == ["+", "-", "+"]
    assert res.saldos["suma_importes"] == 130.00
    assert res.ok is True


def test_parse_fecha_extraccion(parser: N43Parser):
    """Fechas de operación (10:16) y valor (16:22) en formato AAMMDD."""
    cab = _cab(saldo="00000000000000")
    mov = _mov("250105", "250107", "2", "00000000000001", "")
    txt = "\n".join([cab, mov, _reg80("99", [])])
    res = parser._parse_text(txt, filename="fecha.txt")
    assert res.movimientos[0].fecha_operacion == "2025-01-05"
    assert res.movimientos[0].fecha_valor == "2025-01-07"


def test_parse_concepto(parser: N43Parser):
    """El concepto se lee en los índices 52:80."""
    cab = _cab(saldo="00000000000000")
    mov = _mov("251001", "251003", "2", "00000000000001",
               "CONCEPTO LARGO PARA TEST")
    txt = "\n".join([cab, mov, _reg80("99", [])])
    res = parser._parse_text(txt, filename="conc.txt")
    assert res.movimientos[0].concepto == "CONCEPTO LARGO PARA TEST"


def test_parse_summary_counts(parser: N43Parser):
    txt = _n43_estandar()
    res = parser._parse_text(txt, filename="cnt.txt")
    s = res.resumen
    assert s["total_lineas"] == 8
    assert s["lineas_movimiento"] == 5
    assert s["lineas_vacias"] == 0
    assert s["tiene_cabecera"] is True
    assert s["tiene_trailer"] is True
    assert s["con_errores"] is False
    assert s["num_errores"] == 0
    assert "num_warnings" in s
    assert "num_reparados" in s


# ============================ PARSER: ERRORES Y DESCUADRES ============================

def test_parse_con_descuadre(parser: N43Parser):
    """Modo tolerante: un descuadre de saldo NO bloquea el parseo. Se reporta
    como aviso, `saldos.cuadra` queda en False y los movimientos siguen siendo
    exportables (ok=True)."""
    res = parser._parse_text(_n43_estandar(descuadre=True), filename="descuadre.txt")
    assert res.ok is True
    assert "Descuadre de saldo detectado" in " ".join(res.warnings)
    assert not any("Descuadre" in e for e in res.errores)
    assert res.saldos["diferencia_saldo_final"] == -1.25
    assert res.saldos["cuadra"] is False
    assert res.resumen["apto_para_exportar"] is True


def test_parse_longitud_corta(parser: N43Parser):
    txt = "11\n22\n9"
    res = parser._parse_text(txt, filename="corto.txt")
    assert res.resumen["con_errores"] is True
    assert any("longitud" in e.lower() for e in res.errores)


def test_parse_no_cabecera(parser: N43Parser):
    txt = "\n".join([
        _mov("251001", "251003", "2", "00000000010000"),
        _reg80("99", []),
    ])
    res = parser._parse_text(txt, filename="nocab.txt")
    assert "Falta registro de CABECERA" in " ".join(res.errores)


def test_parse_multiples_cabeceras(parser: N43Parser):
    txt = "\n".join([
        _cab(saldo="00000000000000"),
        _cab(saldo="00000000000000"),
        _mov("251001", "251003", "2", "00000000010000"),
        _reg33(num_haber="00001", total_haber="00000000010000",
               clave="2", saldo="00000000010000"),
        _reg80("99", []),
    ])
    res = parser._parse_text(txt, filename="multicab.txt")
    assert any("registros tipo 11" in w.lower() for w in res.warnings)


def test_parse_sin_trailer(parser: N43Parser):
    """Sin registro 33 ni fin de archivo 88/99 se avisa de ambos."""
    txt = "\n".join([
        _cab(saldo="00000000000000"),
        _mov("251001", "251003", "2", "00000000005000"),
    ])
    res = parser._parse_text(txt, filename="sintrailer.txt")
    assert "FINAL DE CUENTA (tipo 33)" in " ".join(res.warnings)
    assert any("FIN DE ARCHIVO" in w for w in res.warnings)


def test_parse_sin_movimientos(parser: N43Parser):
    txt = "\n".join([
        _cab(saldo="00000000000000"),
        _reg80("99", []),
    ])
    res = parser._parse_text(txt, filename="sinmovs.txt")
    assert "No se detectan registros de MOVIMIENTO" in " ".join(res.warnings)


def test_parse_vacio_texto(parser: N43Parser):
    res = parser._parse_text("", filename="vacio.txt")
    assert res.ok is False
    assert "Fichero sin contenido útil" in res.errores


def test_parse_solo_espacios(parser: N43Parser):
    res = parser._parse_text("   \n\t\n   ", filename="espacios.txt")
    assert res.ok is False
    assert len(res.errores) >= 1


def test_parse_otro_tipo(parser: N43Parser):
    """Los registros ajenos a 11/22/33/88/99 se ignoran con aviso."""
    txt = "\n".join([
        _cab(saldo="00000000000000"),
        _reg80("13", []),   # cabecera de cuenta: tipo no soportado
        _mov("251001", "251003", "2", "00000000010000"),
        _reg33(num_haber="00001", total_haber="00000000010000",
               clave="2", saldo="00000000010000"),
        _reg80("99", []),
    ])
    res = parser._parse_text(txt, filename="otro.txt")
    assert any("no reconocido" in w.lower() for w in res.warnings)
    assert any(l.warnings for l in res.lineas if l.record_hint == "OTHER")


def test_parse_importe_no_identificable(parser: N43Parser):
    txt = "\n".join([
        _cab(saldo="00000000000000"),
        "22SINIMPORTECLAROXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        _reg80("99", []),
    ])
    res = parser._parse_text(txt, filename="sinimp.txt")
    assert any("importe no identificable" in w.lower() for w in res.warnings)


def test_parse_reg33_sin_saldo_legible(parser: N43Parser):
    """Sin fallback heurístico: si 59:73 no es numérico se avisa y no se inventa."""
    txt = "\n".join([
        _cab(saldo="00000000000000"),
        _mov("251001", "251003", "2", "00000000010000"),
        _reg33(clave="2", saldo="XXXXXXXXXXXXXX"),
        _reg80("99", []),
    ])
    res = parser._parse_text(txt, filename="reg33sin.txt")
    assert any("sin saldo final legible" in w.lower() for w in res.warnings)
    assert res.trailer["saldo_final"] is None


def test_parse_movimiento_corto(parser: N43Parser):
    txt = "\n".join([
        _cab(saldo="00000000000000"),
        "22ABC",
        _reg80("99", []),
    ])
    res = parser._parse_text(txt, filename="movcorto.txt")
    assert any("movimiento corto" in w.lower() for w in res.warnings)


def test_parse_lineas_vacias_mayoria(parser: N43Parser):
    txt = "\n".join([""] * 9 + ["111234567890ABCDEFGHIJ1234567890"])
    res = parser._parse_text(txt, filename="muchasvacias.txt")
    assert res.resumen["lineas_vacias"] == 9
    assert any("80%" in w for w in res.warnings)


def test_parse_reg33_ultimo_si_multiples(parser: N43Parser):
    txt = "\n".join([
        _cab(saldo="00000000000000"),
        _mov("251001", "251003", "2", "00000000005000"),
        _reg33(clave="2", saldo="00000000000400"),
        _reg33(num_haber="00001", total_haber="00000000005000",
               clave="2", saldo="00000000000500"),
        _reg80("99", []),
    ])
    res = parser._parse_text(txt, filename="multireg33.txt")
    assert res.trailer["linea"] == 4
    assert any("registros tipo 33" in w.lower() for w in res.warnings)


# ---------------------------- CASOS AVANZADOS DEL ESTÁNDAR ----------------------------

def test_estandar_cuadre_completo(parser: N43Parser):
    res = parser._parse_text(_n43_estandar(), filename="estandar.txt")
    assert res.ok is True
    assert res.resumen["tiene_cabecera"] is True
    assert res.resumen["tiene_trailer"] is True
    assert len(res.movimientos) == 5
    # Saldo inicial registro 11 (índices 33:47, clave '2' acreedor = positivo)
    assert res.saldos["saldo_inicial_estimado"] == 5000.00
    # Importes firmados según clave debe/haber (índice 27)
    assert [m.importe for m in res.movimientos] == [
        2150.00, -875.25, -950.00, 3400.00, -12.50,
    ]
    assert [m.signo for m in res.movimientos] == ["+", "-", "-", "+", "-"]
    assert res.saldos["suma_importes"] == 3712.25
    # Cuadre estricto: 5000 + 3712,25 = 8712,25 declarado en el registro 33
    assert res.saldos["saldo_final_declarado_trailer"] == 8712.25
    assert res.saldos["diferencia_saldo_final"] == 0.00
    assert res.saldos["cuadra"] is True
    # Registro 33: contadores y totales al debe/haber (índices 20:25 ... 44:58)
    assert res.trailer["num_movimientos_debe"] == 3
    assert res.trailer["total_debe"] == 1837.75
    assert res.trailer["num_movimientos_haber"] == 2
    assert res.trailer["total_haber"] == 5550.00
    # Clave de saldo final (índice 58) y saldo final (59:73)
    assert res.trailer["clave_saldo_final"] == "2"
    assert res.trailer["saldo_final"] == 8712.25


def test_estandar_registro22_signo_cero_advertencia(parser: N43Parser):
    """Un '0' en el índice 27 no es un signo válido (solo '1' cargo o '2'
    abono): se avisa y el importe queda sin firmar (positivo)."""
    lines = _n43_estandar().splitlines()
    lines[1] = lines[1][:27] + "0" + lines[1][28:]
    res = parser._parse_text("\n".join(lines), filename="signo0.txt")
    assert any("clave de debe/haber '0' no válida" in w for w in res.warnings)
    assert res.movimientos[0].importe == 2150.00  # sin firmar → positivo


def test_estandar_registro11_saldo_deudor(parser: N43Parser):
    """Clave '1' en el índice 32 del registro 11 → saldo inicial negativo."""
    cab = _cab(clave="1", saldo="00000000010000")   # -100,00 (14 dígitos)
    mov = _mov("250915", "250917", "2", "00000000050000", "TEST1")
    fin = _reg80("99", [])
    res = parser._parse_text("\n".join([cab, mov, fin]), filename="deudor.txt")
    assert res.cabecera["registro"] == "11"
    assert res.cabecera["clave_saldo"] == "1"
    assert res.cabecera["saldo_inicial"] == -100.00
    assert res.cabecera["divisa"] == "EUR"
    assert res.saldos["saldo_inicial_estimado"] == -100.00
    assert res.cabecera["entidad"] == "2100"
    assert res.cabecera["cuenta"] == "1234567890"
    assert res.cabecera["fecha_inicial"] == "2025-09-15"
    assert res.cabecera["fecha_final"] == "2025-09-15"


def test_estandar_registro22_fechas_y_concepto(parser: N43Parser):
    res = parser._parse_text(_n43_estandar(), filename="fechas22.txt")
    m = res.movimientos[0]
    assert m.fecha_operacion == "2025-09-15"   # índices 10:16 (AAMMDD "250915")
    assert m.fecha_valor == "2025-09-17"       # índices 16:22 (AAMMDD "250917")
    assert m.extra["clave_debe_haber"] == "2"  # índice 27
    assert m.extra["clave_operacion"] == "01"
    assert m.concepto == "NOMINA1"             # concepto en 52:80


def test_estandar_descuadre_saldo(parser: N43Parser):
    """Modo tolerante: el descuadre del registro 33 se reporta como aviso."""
    res = parser._parse_text(_n43_estandar(descuadre=True), filename="desc.txt")
    assert res.ok is True
    assert any("Descuadre de saldo detectado" in w for w in res.warnings)
    assert res.saldos["diferencia_saldo_final"] == -1.25
    assert res.saldos["cuadra"] is False


def test_estandar_linea_corta_se_rellena_a_80(parser: N43Parser):
    """Líneas cortas se completan con espacios a la derecha (.ljust(80))
    antes de parsear las posiciones absolutas."""
    txt = "\n".join(l[:45] for l in _n43_estandar().splitlines())
    res = parser._parse_text(txt, filename="corta80.txt")
    for l in res.lineas:
        assert len(l.normalized) == 80
    assert [m.importe for m in res.movimientos] == [
        2150.00, -875.25, -950.00, 3400.00, -12.50,
    ]


def test_estandar_linea_larga_se_recorta_a_80(parser: N43Parser):
    """Líneas con basura más allá de la posición 80 se recortan exactamente a 80."""
    txt = "\n".join(l + "XXTRASH" for l in _n43_estandar().splitlines())
    res = parser._parse_text(txt, filename="larga80.txt")
    assert res.ok is True
    assert len(res.movimientos) == 5
    assert res.saldos["diferencia_saldo_final"] == 0.00


def test_estandar_fin_fichero_88(parser: N43Parser):
    txt = _n43_estandar().replace(_reg80("99", []), _reg80("88", []))
    res = parser._parse_text(txt, filename="fin88.txt")
    assert res.resumen["tiene_trailer"] is True
    assert res.trailer["fin_fichero"]["registro"] == "88"
    assert res.ok is True


def test_estandar_fin_fichero_99(parser: N43Parser):
    res = parser._parse_text(_n43_estandar(), filename="fin99.txt")
    assert res.resumen["tiene_trailer"] is True
    assert res.trailer["fin_fichero"]["registro"] == "99"


def test_estandar_parse_bytes_end_to_end(parser: N43Parser):
    res = parser.parse_bytes(_n43_estandar().encode("utf-8"), filename="e2e.txt")
    assert res.ok is True
    assert res.saldos["diferencia_saldo_final"] == 0.00


def test_no_repara_espacios_finales(parser: N43Parser):
    """La Norma 43 requiere el relleno de espacios: NO se recortan ni se
    reportan como reparación."""
    txt = "\r\n".join(l + "   " for l in _n43_estandar().splitlines()) + "\r\n"
    res = parser.parse_bytes(txt.encode("utf-8"), filename="espacios.txt")
    assert not any("espacios finales" in r.lower() for r in res.reparado)
    # Los espacios finales se conservan (raw intacto) y el análisis funciona
    assert res.ok is True
    assert res.saldos["suma_importes"] == 3712.25


# ============================ PARSER: LÍMITES / DoS ============================

def test_parse_too_many_lines(parser: N43Parser):
    lines = ["111234567890ABCDEFGHIJ1234567890"] + [
        "2LINE%06dXXXXXXXXXXXX" % i for i in range(MAX_LINES)
    ] + ["9000000000"]
    txt = "\n".join(lines)
    res = parser._parse_text(txt, filename="mass.txt")
    assert res.ok is False
    assert "Demasiadas líneas" in " ".join(res.errores)


def test_parse_bytes_too_many_lines_blocked(parser: N43Parser):
    lines = ["111234567890ABCDEFGHIJ1234567890"] + [
        "2X%d" % i for i in range(MAX_LINES + 10)
    ] + ["9000000000"]
    data = "\n".join(lines).encode("utf-8")
    res = parser.parse_bytes(data, filename="massb.txt")
    assert res.ok is False
    assert any("Demasiadas líneas" in e for e in res.errores)


def test_normalize_trunca_linea_larga(parser: N43Parser):
    longl = "2" + "Y" * (MAX_LINE_LEN + 500)
    txt = "111234567890ABCDEFGHIJ1234567890\n" + longl + "\n9000000000"
    text_n, rep, warn = parser._normalize_text(txt)
    for l in text_n.splitlines():
        assert len(l) <= MAX_LINE_LEN
    assert any("truncada" in w for w in warn)


def test_very_long_single_token(parser: N43Parser):
    tok = "A" * 5000
    data = ("111234567890%s1234567890\n220101A\n9000000000" % tok).encode("utf-8")
    res = parser.parse_bytes(data, filename="longtok.txt")
    assert res.encoding_used is not None


def test_parse_bytes_max_exact(parser: N43Parser):
    txt = "\n".join(
        [
            "111234567890ABCDEFGHIJ1234567890",
            "22010101234567890CONCEPTO MAX                +1,00",
            "900000000000000000000000000000000000000000000001,00",
        ]
    )
    data = txt.encode("utf-8")
    assert len(data) < MAX_UPLOAD_BYTES
    res = parser.parse_bytes(data, filename="maxok.txt")
    assert res.security["content_check"]["safe"] is True


# ============================ PARSER: BYTES / ENCODING / REPARACIÓN ============================

def test_parse_bytes_utf8_ok(parser: N43Parser):
    txt = "\n".join(
        [
            "111234567890ABCDEFGHIJ1234567890",
            "22010101234567890CONCEPTO UTF8 ÁGUILA       +10,00",
            "900000000000000000000000000000000000000000000010,00",
        ]
    )
    data = txt.encode("utf-8")
    res = parser.parse_bytes(data, filename="utf8.txt")
    assert res.encoding_used is not None
    assert res.ok is True


def test_parse_bytes_latin1(parser: N43Parser):
    data = "111234567890ABCáÉÑ1234567890\n2201010123CONCEPTO\n900000000000".encode("latin-1")
    res = parser.parse_bytes(data, filename="latin1.txt")
    assert res.encoding_used is not None


def test_parse_bytes_cp1252(parser: N43Parser):
    data = "111234567890ABCüö1234567890\n2201010123TEST\n900000000000".encode("cp1252")
    res = parser.parse_bytes(data, filename="cp1252.txt")
    assert res.encoding_used is not None


def test_parse_bytes_crlf_bom(parser: N43Parser):
    data = "\ufeff111234567890ABCDEFGHIJ1234567890\r\n220101A\r\n9000000000\r\n".encode("utf-8")
    res = parser.parse_bytes(data, filename="crlfbom.txt")
    assert any("CRLF" in r or "BOM" in r for r in res.reparado)


def test_parse_bytes_tabs(parser: N43Parser):
    txt = "111234567890ABCDEFGHIJ1234567890\n\t22010101234567890T\t000001000+\n90000000000000000000000000000000000000000000001000"
    res = parser.parse_bytes(txt.encode("utf-8"), filename="tabs.txt")
    assert any("tabulador" in r.lower() for r in res.reparado)


def test_mixed_line_endings(parser: N43Parser):
    txt = "111234567890ABCDEFGHIJ1234567890\r\n22010101234567890X +1,00\n900000000000000000000000000000000000000000000001,00\r"
    res = parser.parse_bytes(txt.encode("utf-8"), filename="mixedle.txt")
    assert any("CRLF" in r or "CR a LF" in r for r in res.reparado)


def test_parse_bytes_replacement_decoding(parser: N43Parser):
    data = b"111234567890ABCDEFGHIJ1234567890\n220101A\xFF\xFE\n9000000000"
    res = parser.parse_bytes(data, filename="replace.txt")
    assert res.encoding_used is not None


def test_parse_bytes_empty(parser: N43Parser):
    res = parser.parse_bytes(b"", filename="empty.txt")
    assert res.ok is False
    assert any("vacío" in e.lower() for e in res.errores)


# ============================ SEGURIDAD EN PARSE_BYTES ============================

def test_parse_bytes_nullbyte_blocked(parser: N43Parser):
    res = parser.parse_bytes(b"11111111111111111111\n22TEST\x00\n9000000000", filename="null.txt")
    assert res.ok is False
    assert any("byte nulo" in e.lower() for e in res.errores)


@pytest.mark.parametrize("payload", [
    b"<script>alert(1)</script>",
    b"{{7*7}}",
    b"eval(123)",
    b"__import__('os')",
    b"UNION SELECT * FROM users",
    b"DROP TABLE users",
    b"';--",
    b"%2e%2e%2fetc/passwd",
    b"javascript:alert(1)",
    b"onerror=alert(1)",
])
def test_injection_payloads_blocked(parser: N43Parser, payload: bytes):
    res = parser.parse_bytes(payload, filename="fuzz.txt")
    assert res.ok is False
    assert len(res.errores) > 0


@pytest.mark.parametrize("fname", [
    "../../root.txt",
    "..\\admin.txt",
    "file\r\n.txt",
    "file\x00.txt",
    "file\x01.txt",
    "cmd.exe",
    "script.sh",
    "payload.php",
    "hack.html",
])
def test_filenames_blocked(parser: N43Parser, fname: str):
    data = b"111234567890ABCDEFGHIJ1234567890\n220101A\n9000000000"
    res = parser.parse_bytes(data, filename=fname)
    assert res.ok is False


def test_parse_bytes_bad_filename_traversal(parser: N43Parser):
    data = b"111234567890ABCDEFGHIJ1234567890\n220101A\n9000000000"
    res = parser.parse_bytes(data, filename="../../evil.txt")
    assert res.ok is False
    assert any("ruta sospechosa" in e.lower() for e in res.errores)


def test_security_blocked_reasons_present(parser: N43Parser):
    res = parser.parse_bytes(b"<script>", filename="sec.txt")
    assert "blocked_reasons" in res.security["content_check"]
    assert len(res.security["content_check"]["blocked_reasons"]) > 0


# ============================ EXPORTACIONES ============================

def test_to_json_structure_and_roundtrip(parser: N43Parser):
    txt = "\n".join(
        [
            "111234567890ABCDEFGHIJ1234567890",
            "22010101234567890R                        +7,50",
            "900000000000000000000000000000000000000000000007,50",
        ]
    )
    res = parser._parse_text(txt, filename="rt.txt")
    jstr = parser.to_json(res)
    obj = json.loads(jstr)
    assert obj["ok"] is True
    assert obj["filename"] == "rt.txt"
    assert obj["filename_safe"].endswith(".txt")
    assert "movimientos" in obj
    assert "saldos" in obj
    assert "security" in obj
    assert "resumen" in obj


def test_to_csv_bytes(parser: N43Parser):
    res = parser._parse_text(_n43_estandar(), filename="csv.txt")
    csvb = parser.to_csv_bytes(res)
    assert isinstance(csvb, bytes)
    assert len(csvb) > 0
    assert b"linea" in csvb


def test_to_excel_bytes(parser: N43Parser):
    res = parser._parse_text(_n43_estandar(), filename="xlsx.txt")
    xlsb = parser.to_excel_bytes(res)
    assert isinstance(xlsb, bytes)
    assert len(xlsb) > 0


def test_exports_empty_movs_safe(parser: N43Parser):
    txt = "\n".join(
        [
            "111234567890ABCDEFGHIJ1234567890",
            "90000000000000000000000000000000000000000000000000",
        ]
    )
    res = parser._parse_text(txt, filename="emptymov.txt")
    csvb = parser.to_csv_bytes(res)
    xlsb = parser.to_excel_bytes(res)
    assert isinstance(csvb, bytes)
    assert isinstance(xlsb, bytes)


# ============================ API FASTAPI (END-TO-END) ============================

VALID_N43 = _n43_estandar().encode("utf-8")


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from main import app

    with TestClient(app) as c:
        # Estado limpio por test para export-404 determinista
        app.state.last = {}
        yield c


def test_api_index(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "Norma 43" in r.text


def test_api_health(client):
    """El health check debe responder 200 con estado ok para las sondas de Render."""
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["service"] == "n43-fixer"


def test_api_no_coep_blocks_external_assets(client):
    """COEP require-corp bloqueaba el script de Tailwind (sin cabecera CORP en el CDN),
    dejando la página sin estilos. Regresión: la cabecera no debe volver."""
    r = client.get("/")
    assert r.headers.get("Cross-Origin-Embedder-Policy") is None
    # Y el CSP debe seguir permitiendo el CDN de Tailwind y sus estilos inline
    csp = r.headers.get("Content-Security-Policy", "")
    assert "https://cdn.tailwindcss.com" in csp
    assert "style-src" in csp and "'unsafe-inline'" in csp


def test_api_security_headers(client):
    r = client.get("/")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert "Content-Security-Policy" in r.headers


def test_api_parse_ok(client):
    r = client.post(
        "/api/parse-n43",
        files={"file": ("extracto.txt", VALID_N43, "text/plain")},
    )
    assert r.status_code == 200
    j = r.json()
    assert j["ok"] is True
    assert j["resumen"]["lineas_movimiento"] == 5
    assert len(j["movimientos"]) == 5
    assert j["saldos"]["suma_importes"] == 3712.25


def test_api_parse_rejects_exe(client):
    r = client.post(
        "/api/parse-n43",
        files={"file": ("virus.exe", VALID_N43, "application/octet-stream")},
    )
    assert r.status_code == 400


def test_api_parse_rejects_traversal_filename(client):
    r = client.post(
        "/api/parse-n43",
        files={"file": ("../../etc/passwd.txt", VALID_N43, "text/plain")},
    )
    assert r.status_code == 400


def test_api_parse_rejects_script_payload(client):
    r = client.post(
        "/api/parse-n43",
        files={"file": ("xss.txt", b"<script>alert(1)</script>", "text/plain")},
    )
    assert r.status_code == 400


def test_api_parse_rejects_empty(client):
    r = client.post(
        "/api/parse-n43",
        files={"file": ("vacio.txt", b"", "text/plain")},
    )
    assert r.status_code == 400


def test_api_parse_rejects_nullbyte(client):
    r = client.post(
        "/api/parse-n43",
        files={"file": ("null.txt", b"11111111\x0011111111", "text/plain")},
    )
    assert r.status_code == 400


def test_api_export_without_parse_404(client):
    r = client.get("/api/export-csv")
    assert r.status_code == 404
    r2 = client.get("/api/export-xlsx")
    assert r2.status_code == 404


def test_api_export_after_parse(client):
    client.post(
        "/api/parse-n43",
        files={"file": ("extracto.txt", VALID_N43, "text/plain")},
    )
    r = client.get("/api/export-csv")
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]
    assert "extracto.csv" in r.headers["content-disposition"]

    r2 = client.get("/api/export-xlsx")
    assert r2.status_code == 200
    assert "spreadsheetml" in r2.headers["content-type"]
    assert "extracto.xlsx" in r2.headers["content-disposition"]


def test_api_export_uses_sanitized_name(client):
    # Filename legítimo con espacios/acentos → se sanea en Content-Disposition
    client.post(
        "/api/parse-n43",
        files={"file": ("extrac to €.txt", VALID_N43, "text/plain")},
    )
    r = client.get("/api/export-csv")
    assert r.status_code == 200
    cd = r.headers["content-disposition"]
    assert '"' in cd  # nombre entre comillas
    assert "€" not in cd  # sin caracteres no ASCII en header
