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


# ============================ PARSER: CASOS CORRECTOS ============================

def _n43_correcto():
    # type: () -> str
    return "\n".join(
        [
            "111234567890ABCDEFGHIJ1234567890",
            "22010101234567890CONCEPTO A                +100,00",
            "22010201234567890CONCEPTO B                -40,00",
            "900000000000000000000000000000000000000000000060,00",
        ]
    )


def test_parse_correcto_minimo(parser: N43Parser):
    res = parser._parse_text(_n43_correcto(), filename="correcto.txt")
    assert res.ok is True
    assert res.filename == "correcto.txt"
    assert res.filename_safe.endswith(".txt")
    assert res.resumen["tiene_cabecera"] is True
    assert res.resumen["tiene_trailer"] is True
    assert res.resumen["lineas_movimiento"] == 2
    assert len(res.movimientos) == 2
    # Saldos cuadran: 100 - 40 = 60
    assert res.saldos["suma_importes"] == 60.00
    assert res.saldos.get("diferencia_saldo_final") == 0.00


def test_parse_cuadra_aproximado(parser: N43Parser):
    txt = "\n".join(
        [
            "111234567890ABCDEFGHIJ1234567890",
            "22010101234567890CONCEPTO A                +100,00",
            "900000000000000000000000000000000000000000000100,00",
        ]
    )
    res = parser._parse_text(txt, filename="cuadra.txt")
    assert res.saldos["diferencia_saldo_final"] == 0.00
    assert any("cuadrar" in w.lower() for w in res.warnings)


def test_parse_varios_movimientos_signos(parser: N43Parser):
    txt = "\n".join(
        [
            "111234567890ABCDEFGHIJ1234567890",
            "22010101234567890A                        +100,00",
            "22010201234567890B                        -20,00",
            "22010301234567890C                        +50,00",
            "900000000000000000000000000000000000000000000130,00",
        ]
    )
    res = parser._parse_text(txt, filename="multi.txt")
    assert len(res.movimientos) == 3
    signos = [m.signo for m in res.movimientos]
    assert signos == ["+", "-", "+"]
    assert res.saldos["suma_importes"] == 130.00


def test_parse_fecha_extraccion(parser: N43Parser):
    txt = "\n".join(
        [
            "111234567890ABCDEFGHIJ1234567890",
            "2 050122234567890FECHA TEST               000001000+",
            "90000000000000000000000000000000000000000000000000",
        ]
    )
    res = parser._parse_text(txt, filename="fecha.txt")
    assert res.movimientos[0].fecha_operacion == "2022-01-05"


def test_parse_concepto_referencia(parser: N43Parser):
    txt = "\n".join(
        [
            "111234567890ABCDEFGHIJ1234567890",
            "22010101234567890CONCEPTO LARGO PARA TEST  REF123456          +1,00",
            "900000000000000000000000000000000000000000000001,00",
        ]
    )
    res = parser._parse_text(txt, filename="conc.txt")
    assert "CONCEPTO LARGO PARA TEST" in res.movimientos[0].concepto
    assert res.movimientos[0].referencia == "REF123456"


def test_parse_summary_counts(parser: N43Parser):
    txt = _n43_correcto()
    res = parser._parse_text(txt, filename="cnt.txt")
    s = res.resumen
    assert s["total_lineas"] == 4
    assert s["lineas_movimiento"] == 2
    assert s["lineas_vacias"] == 0
    assert s["tiene_cabecera"] is True
    assert s["tiene_trailer"] is True
    assert s["con_errores"] is False
    assert s["num_errores"] == 0
    assert "num_warnings" in s
    assert "num_reparados" in s


# ============================ PARSER: ERRORES Y DESCUADRES ============================

def test_parse_con_descuadre(parser: N43Parser):
    txt = "\n".join(
        [
            "111234567890ABCDEFGHIJ1234567890",
            "22010101234567890CONCEPTO A                +100,00",
            "900000000000000000000000000000000000000000000200,00",
        ]
    )
    res = parser._parse_text(txt, filename="descuadre.txt")
    assert res.ok is False
    assert "Descuadre de saldo detectado" in " ".join(res.errores)
    assert res.saldos["diferencia_saldo_final"] == 100.00


def test_parse_longitud_corta(parser: N43Parser):
    txt = "11\n22\n9"
    res = parser._parse_text(txt, filename="corto.txt")
    assert res.resumen["con_errores"] is True
    assert any("longitud" in e.lower() for e in res.errores)


def test_parse_no_cabecera(parser: N43Parser):
    txt = "\n".join(
        [
            "22010101234567890CONCEPTO A                +100,00",
            "900000000000000000000000000000000000000000000100,00",
        ]
    )
    res = parser._parse_text(txt, filename="nocab.txt")
    assert "Falta registro de CABECERA" in " ".join(res.errores)


def test_parse_multiples_cabeceras(parser: N43Parser):
    txt = "\n".join(
        [
            "111234567890ABCDEFGHIJ1234567890",
            "12222222222222222222",
            "22010101234567890CONCEPTO A                +1,00",
            "900000000000000000000000000000000000000000000001,00",
        ]
    )
    res = parser._parse_text(txt, filename="multicab.txt")
    assert any("cabeceras" in w.lower() for w in res.warnings)


def test_parse_sin_trailer(parser: N43Parser):
    txt = "\n".join(
        [
            "111234567890ABCDEFGHIJ1234567890",
            "22010101234567890CONCEPTO A                +50,00",
        ]
    )
    res = parser._parse_text(txt, filename="sintrailer.txt")
    assert "No se detecta registro FINAL/TOTALES" in " ".join(res.warnings)


def test_parse_sin_movimientos(parser: N43Parser):
    txt = "\n".join(
        [
            "111234567890ABCDEFGHIJ1234567890",
            "90000000000000000000000000000000000000000000000000",
        ]
    )
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
    txt = "\n".join(
        [
            "111234567890ABCDEFGHIJ1234567890",
            "3OTRO REGISTRO NO ESTANDAR",
            "22010101234567890CONCEPTO A                +1,00",
            "900000000000000000000000000000000000000000000001,00",
        ]
    )
    res = parser._parse_text(txt, filename="otro.txt")
    assert any("no estándar" in w.lower() for w in res.warnings) or any(
        l.warnings for l in res.lineas
    )


def test_parse_importe_no_identificable(parser: N43Parser):
    txt = "\n".join(
        [
            "111234567890ABCDEFGHIJ1234567890",
            "22SINIMPORTECLAROXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            "90000000000000000000000000000000000000000000000000",
        ]
    )
    res = parser._parse_text(txt, filename="sinimp.txt")
    assert any("importe no identificable" in w.lower() for w in res.warnings)


def test_parse_trailer_sin_importes(parser: N43Parser):
    txt = "\n".join(
        [
            "111234567890ABCDEFGHIJ1234567890",
            "22010101234567890CONCEPTO A                +1,00",
            "900000ABCDEF0000000000000000000000000000000000",
        ]
    )
    res = parser._parse_text(txt, filename="trsinimp.txt")
    assert any("sin importes detectables" in w.lower() for w in res.warnings)


def test_parse_movimiento_corto(parser: N43Parser):
    txt = "\n".join(
        [
            "111234567890ABCDEFGHIJ1234567890",
            "22ABC",
            "90000000000000000000000000000000000000000000000000",
        ]
    )
    res = parser._parse_text(txt, filename="movcorto.txt")
    assert any("movimiento corto" in w.lower() for w in res.warnings)


def test_parse_lineas_vacias_mayoria(parser: N43Parser):
    txt = "\n".join([""] * 9 + ["111234567890ABCDEFGHIJ1234567890"])
    res = parser._parse_text(txt, filename="muchasvacias.txt")
    assert res.resumen["lineas_vacias"] == 9
    assert any("80%" in w for w in res.warnings)


def test_parse_trailer_ultimo_si_multiples(parser: N43Parser):
    txt = "\n".join(
        [
            "111234567890ABCDEFGHIJ1234567890",
            "22010101234567890X                        +5,00",
            "900000000000000000000000000000000000000000000004,00",
            "900000000000000000000000000000000000000000000005,00",
        ]
    )
    res = parser._parse_text(txt, filename="multitrailer.txt")
    assert res.trailer["linea"] == 4


def test_legado_88_reconocido_como_trailer(parser: N43Parser):
    """El registro 88 debe valer como fin de archivo/tráiler también en modo heurístico."""
    txt = "\n".join(
        [
            "111234567890ABCDEFGHIJ1234567890",
            "22010101234567890CONCEPTO A                +50,00",
            "88" + " " * 78,
        ]
    )
    res = parser._parse_text(txt, filename="legado88.txt")
    assert res.resumen["tiene_trailer"] is True
    assert "No se detecta registro FINAL/TOTALES" not in " ".join(res.warnings)


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


def _n43_estandar(descuadre=False, fin="99"):
    # type: (bool, str) -> str
    """Fichero AEB 43 estricto: saldo inicial 5.000,00 y 5 movimientos.

    Movimientos: +2150,00 -875,25 -950,00 +3400,00 -12,50 = +3712,25
    → saldo final debe cuadrar en 8712,25.
    """
    cab = _reg80("11", [
        (3, "2100"), (7, "0418"), (11, "1234567890"),
        (21, "150925"),              # fecha apertura DDMMAA (índices 20:26)
        (27, "2"),                   # clave saldo inicial (índice 26)
        (28, "00000000500000"),      # saldo inicial (índices 27:41)
        (42, "EUR"),                 # divisa (índices 41:44)
    ])

    def mov(fecha, clave_dh, importe, doc):
        return _reg80("22", [
            (3, "01"), (5, fecha), (11, fecha[:4] + "20" + fecha[4:]),
            (19, "02"),              # concepto común (índices 18:20)
            (22, clave_dh),          # debe/haber (índice 21)
            (23, importe),           # importe (índices 22:36)
            (42, doc),               # referencia (índices 41:54)
        ])

    movs = [
        mov("150925", "2", "00000000215000", "NOMINA1"),   # abono  +2150,00
        mov("100925", "1", "00000000087525", "IVA1"),      # cargo   -875,25
        mov("011025", "1", "00000000095000", "ALQ1"),      # cargo   -950,00
        mov("031025", "2", "00000000340000", "COB1"),      # abono  +3400,00
        mov("011025", "1", "00000000001250", "COM1"),      # cargo    -12,50
    ]
    saldo_final = "00000000871100" if descuadre else "00000000871225"
    fin_cuenta = _reg80("33", [
        (3, "2100"), (7, "0418"), (11, "1234567890"), (21, "45"),
        (23, "000003"),              # nº movimientos Debe (índices 22:28)
        (29, "00000000183775"),      # importe total Debe (índices 28:42)
        (43, "000002"),              # nº movimientos Haber (índices 42:48)
        (49, "00000000555000"),      # importe total Haber (índices 48:62)
        (63, "2"),                   # clave saldo final (índice 62)
        (64, saldo_final),           # saldo final (índices 63:77)
        (78, "EUR"),
    ])
    return "\n".join([cab] + movs + [fin_cuenta, _reg80(fin, [])])


def test_estandar_modo_detectado_y_cuadre(parser: N43Parser):
    res = parser._parse_text(_n43_estandar(), filename="estandar.txt")
    assert res.modo == "estándar AEB 43"
    assert res.ok is True
    assert res.resumen["modo"] == "estándar AEB 43"
    assert res.resumen["tiene_cabecera"] is True
    assert res.resumen["tiene_trailer"] is True
    assert len(res.movimientos) == 5
    # Saldo inicial registro 11 (índices 27:41, clave '2' acreedor = positivo)
    assert res.saldos["saldo_inicial_estimado"] == 5000.00
    # Importes firmados según clave debe/haber (índice 21)
    assert [m.importe for m in res.movimientos] == [
        2150.00, -875.25, -950.00, 3400.00, -12.50,
    ]
    assert [m.signo for m in res.movimientos] == ["+", "-", "-", "+", "-"]
    assert res.saldos["suma_importes"] == 3712.25
    # Cuadre estricto: 5000 + 3712,25 = 8712,25 declarado en el registro 33
    assert res.saldos["saldo_final_declarado_trailer"] == 8712.25
    assert res.saldos["diferencia_saldo_final"] == 0.00
    assert res.saldos["num_movimientos_declarado"] == 5
    assert res.saldos["suma_importes_declarada"] == 3712.25
    # Registro 33: desglose oficial Debe/Haber
    assert res.trailer["num_movimientos_debe"] == 3
    assert res.trailer["num_movimientos_haber"] == 2
    assert res.trailer["importe_total_debe"] == 1837.75
    assert res.trailer["importe_total_haber"] == 5550.00
    assert res.trailer["clave_saldo_final"] == "2"


def test_estandar_registro22_signo_cero_advertencia(parser: N43Parser):
    """Un '0' en el índice 21 no es un signo válido (solo '1' cargo o '2'
    abono): se avisa y el importe queda sin firmar (positivo)."""
    lines = _n43_estandar().splitlines()
    lines[1] = lines[1][:21] + "0" + lines[1][22:]
    res = parser._parse_text("\n".join(lines), filename="signo0.txt")
    assert res.modo == "estándar AEB 43"
    assert any("clave de debe/haber '0' no válida" in w for w in res.warnings)
    assert res.movimientos[0].importe == 2150.00  # sin firmar → positivo


def test_estandar_registro11_saldo_deudor(parser: N43Parser):
    """Clave '1' en el índice 26 del registro 11 → saldo inicial negativo."""
    cab = _reg80("11", [
        (3, "2100"), (7, "0418"), (11, "1234567890"),
        (21, "150925"), (27, "1"), (28, "00000000010000"), (42, "EUR"),
    ])
    mov = _reg80("22", [
        (3, "01"), (5, "150925"), (11, "15092025"),
        (19, "02"), (22, "2"), (23, "00000000050000"), (42, "TEST1"),
    ])
    fin = _reg80("99", [])
    res = parser._parse_text("\n".join([cab, mov, fin]), filename="deudor.txt")
    assert res.modo == "estándar AEB 43"
    assert res.cabecera["registro"] == "11"
    assert res.cabecera["clave_saldo"] == "1"
    assert res.cabecera["saldo_inicial"] == -100.00
    assert res.saldos["saldo_inicial_estimado"] == -100.00
    assert res.cabecera["entidad"] == "2100"
    assert res.cabecera["cuenta"] == "1234567890"
    assert res.cabecera["fecha_apertura"] == "2025-09-15"


def test_estandar_registro22_fechas_y_concepto(parser: N43Parser):
    res = parser._parse_text(_n43_estandar(), filename="fechas22.txt")
    m = res.movimientos[0]
    assert m.fecha_operacion == "2025-09-15"   # índices 4:10 (DDMMAA)
    assert m.fecha_valor == "2025-09-15"       # índices 10:18 (DDMMAAAA)
    assert m.extra["clave_debe_haber"] == "2"  # índice 21
    assert m.extra["clave_debe_haber"] == "2"
    assert m.extra["clave_operacion"] == "01"
    assert m.referencia == "NOMINA1"


def test_estandar_descuadre_saldo(parser: N43Parser):
    res = parser._parse_text(_n43_estandar(descuadre=True), filename="desc.txt")
    assert res.modo == "estándar AEB 43"
    assert res.ok is False
    assert any("Descuadre de saldo detectado" in e for e in res.errores)
    assert res.saldos["diferencia_saldo_final"] == -1.25


def test_estandar_num_movimientos_declarado_no_coincide(parser: N43Parser):
    lines = _n43_estandar().splitlines()
    fin = lines[-2]  # registro 33 (penúltima línea)
    # Nº movimientos Debe (índices 22:28): declara 1 (+2 del Haber = 3 en total)
    lines[-2] = fin[:22] + "000001" + fin[28:]
    res = parser._parse_text("\n".join(lines), filename="nummov.txt")
    assert res.saldos["num_movimientos_declarado"] == 3
    assert any("declara 3 movimientos" in w for w in res.warnings)


def test_estandar_linea_corta_se_rellena_a_80(parser: N43Parser):
    """Líneas cortas se completan con espacios a la derecha (.ljust(80))
    antes de parsear las posiciones absolutas."""
    txt = "\n".join(l[:45] for l in _n43_estandar().splitlines())
    res = parser._parse_text(txt, filename="corta80.txt")
    assert res.modo == "estándar AEB 43"
    for l in res.lineas:
        assert len(l.normalized) == 80
    assert [m.importe for m in res.movimientos] == [
        2150.00, -875.25, -950.00, 3400.00, -12.50,
    ]


def test_estandar_linea_larga_se_recorta_a_80(parser: N43Parser):
    """Líneas con basura más allá de la posición 80 se recortan exactamente a 80."""
    txt = "\n".join(l + "XXTRASH" for l in _n43_estandar().splitlines())
    res = parser._parse_text(txt, filename="larga80.txt")
    assert res.modo == "estándar AEB 43"
    assert res.ok is True
    assert len(res.movimientos) == 5
    assert res.saldos["diferencia_saldo_final"] == 0.00


def test_estandar_fin_fichero_88(parser: N43Parser):
    txt = _n43_estandar().replace(_reg80("99", []), _reg80("88", []))
    res = parser._parse_text(txt, filename="fin88.txt")
    assert res.modo == "estándar AEB 43"
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
    assert res.modo == "estándar AEB 43"
    assert res.saldos["diferencia_saldo_final"] == 0.00


def test_no_repara_espacios_finales(parser: N43Parser):
    """La Norma 43 requiere el relleno de espacios: NO se recortan ni se
    reportan como reparación."""
    txt = "111234567890ABCDEFGHIJ1234567890   \r\n22010101234567890A +50,00   \r\n900000000000000000000000000000000000000000000050,00   \r\n"
    res = parser.parse_bytes(txt.encode("utf-8"), filename="espacios.txt")
    assert not any("espacios finales" in r.lower() for r in res.reparado)
    # Los espacios finales se conservan (raw intacto) y el análisis funciona
    assert res.ok is True
    assert res.saldos["suma_importes"] == 50.00


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
    res = parser._parse_text(_n43_correcto(), filename="csv.txt")
    csvb = parser.to_csv_bytes(res)
    assert isinstance(csvb, bytes)
    assert len(csvb) > 0
    assert b"linea" in csvb


def test_to_excel_bytes(parser: N43Parser):
    res = parser._parse_text(_n43_correcto(), filename="xlsx.txt")
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

VALID_N43 = _n43_correcto().encode("utf-8")


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
    assert j["resumen"]["lineas_movimiento"] == 2
    assert len(j["movimientos"]) == 2
    assert j["saldos"]["suma_importes"] == 60.00


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
