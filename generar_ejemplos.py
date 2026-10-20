# -*- coding: utf-8 -*-
"""
generar_ejemplos.py
-------------------
Crea en ./ejemplos ficheros Norma 43 de prueba para la app. El parser es
ESTRICTO (posiciones fijas AEB 43, 80 caracteres por línea, índices 0-based),
así que todos los ejemplos van en formato estándar:

- n43_muestra.txt       → muestra realista: 4 movimientos (2 abonos y 2 cargos)
                          de octubre de 2026, cuadre exacto. Ideal para probar
                          la app con un fichero "conocido bueno"
- n43_ok.txt            → válido, saldos cuadrados (UTF-8, LF)
- n43_descuadre.txt     → estructura válida pero con descuadre de saldo (error)
- n43_codificacion_rota.txt → Latin-1/CP1252 + CRLF + acentos + espacios
                          finales (dispara las "reparaciones" automáticas)

Uso:  python3 generar_ejemplos.py
"""

from pathlib import Path

OUT = Path(__file__).resolve().parent / "ejemplos"


def reg80(clave, campos):
    # type: (str, list) -> str
    """Construye un registro Norma 43 de exactamente 80 caracteres.

    campos: lista de (posición_base_1, texto) según posiciones fijas AEB 43.
    """
    l = [" "] * 80
    for i, ch in enumerate(clave):
        l[i] = ch
    for pos, txt in campos:
        for i, ch in enumerate(txt):
            l[pos - 1 + i] = ch
    return "".join(l)


def mov_std(fecha, clave_dh, importe, doc, fecha_valor=None, clave_concepto="01"):
    # type: (str, str, str, str, str, str) -> str
    """Registro 22 estándar: clave de concepto índices 2:6, fecha operación
    índices 10:16 (AAMMDD), fecha valor índices 16:22 (AAMMDD), debe/haber
    índice 27 ('1' cargo = negativo, '2' abono = positivo), importe índices
    28:42 (14 dígitos, 2 decimales implícitos) y concepto índices 52:80."""
    return reg80("22", [
        (3, clave_concepto),       # clave de concepto (índices 2:6)
        (11, fecha),               # fecha operación AAMMDD (índices 10:16)
        (17, fecha_valor or fecha),  # fecha valor AAMMDD (índices 16:22)
        (28, clave_dh),            # debe/haber (índice 27)
        (29, importe),             # importe 14 dígitos (índices 28:42)
        (53, doc),                 # concepto (índices 52:80)
    ])


def n43_estandar(descuadre=False, acentos=False):
    # type: (bool, bool) -> list
    """Fichero estricto AEB 43 (80 posiciones): saldo inicial 5.000,00 y
    5 movimientos; el saldo final declarado en el registro 33 cuadra en 8.712,25
    (o se descuadra deliberadamente si descuadre=True)."""
    cab = reg80("11", [
        (3, "2100"), (7, "0418"), (11, "1234567890"),
        (21, "250915"),              # fecha inicial AAMMDD (índices 20:26)
        (27, "250915"),              # fecha final AAMMDD (índices 26:32)
        (33, "2"),                   # clave saldo inicial (índice 32)
        (34, "00000000500000"),      # saldo inicial 14 dígitos (índices 33:47)
        (48, "EUR"),                 # divisa (índices 47:50, fuera del saldo)
    ])
    if acentos:
        # Conceptos con acentos y eñe (para demostrar la reparación CP1252)
        movs = [
            mov_std("250915", "2", "00000000215000", "NÓMINA SEPTIEMBRE (año 2025)"),
            mov_std("250910", "1", "00000000087525", "IVA TRIMESTRE HACIENDA"),
            mov_std("251001", "1", "00000000095000", "ALQUILER OFICINA OÑATE"),
            mov_std("251003", "2", "00000000340000", "COBRO CLIENTE AÑORANZA S L"),
            mov_std("251001", "1", "00000000001250", "COMISIONES BANCO"),
        ]
    else:
        movs = [
            mov_std("250915", "2", "00000000215000", "NOMINA1"),   # abono  +2150,00
            mov_std("250910", "1", "00000000087525", "IVA1"),      # cargo   -875,25
            mov_std("251001", "1", "00000000095000", "ALQ1"),      # cargo   -950,00
            mov_std("251003", "2", "00000000340000", "COB1"),      # abono  +3400,00
            mov_std("251001", "1", "00000000001250", "COM1"),      # cargo    -12,50
        ]
    saldo_final = "00000000871100" if descuadre else "00000000871225"
    fin_cuenta = reg80("33", [
        (21, "00003"),               # núm. movimientos al debe (índices 20:25)
        (26, "00000000183775"),      # total debe (índices 25:39) = 1.837,75
        (40, "00002"),               # núm. movimientos al haber (índices 39:44)
        (45, "00000000555000"),      # total haber (índices 44:58) = 5.550,00
        (59, "2"),                   # clave saldo final (índice 58)
        (60, saldo_final),           # saldo final 14 dígitos (índices 59:73)
        (74, "EUR"),                 # divisa (índices 73:76)
    ])
    return [cab] + movs + [fin_cuenta, reg80("99", [])]


def n43_muestra():
    # type: () -> list
    """Muestra "bonita" para probar la app: 4 movimientos reales de octubre
    de 2026 (2 abonos y 2 cargos) con saldos cuadrados al céntimo:

        1.250,00 + 1.850,00 - 89,75 + 640,25 - 125,40 = 3.525,10 EUR
        cargos  89,75 + 125,40 =  215,15 (2 movimientos)
        abonos 1.850,00 + 640,25 = 2.490,25 (2 movimientos)
    """
    cab = reg80("11", [
        (3, "0182"), (7, "0418"), (11, "0102345678"),
        (21, "261001"),              # fecha inicial AAMMDD (índices 20:26)
        (27, "261015"),              # fecha final AAMMDD (índices 26:32)
        (33, "2"),                   # clave saldo inicial (índice 32)
        (34, "00000000125000"),      # saldo inicial 14 dígitos (33:47) = 1.250,00
        (48, "EUR"),                 # divisa (índices 47:50)
    ])
    movs = [
        # clave de concepto: 04 nómina, 03 recibo domiciliado, 01 transferencia
        mov_std("261001", "2", "00000000185000", "NOMINA OCTUBRE 2026",
                clave_concepto="04"),                      # abono  +1.850,00
        mov_std("261005", "1", "00000000008975", "RECIBO LUZ IBERDROLA",
                clave_concepto="03"),                      # cargo     -89,75
        mov_std("261010", "2", "00000000064025", "TRANSFERENCIA CLIENTE S L",
                clave_concepto="01"),                      # abono    +640,25
        mov_std("261014", "1", "00000000012540", "COMPRA TPV TERMINAL 4471",
                clave_concepto="01"),                      # cargo    -125,40
    ]
    fin_cuenta = reg80("33", [
        (21, "00002"),               # núm. movimientos al debe (índices 20:25)
        (26, "00000000021515"),      # total debe (índices 25:39) = 215,15
        (40, "00002"),               # núm. movimientos al haber (índices 39:44)
        (45, "00000000249025"),      # total haber (índices 44:58) = 2.490,25
        (59, "2"),                   # clave saldo final (índice 58)
        (60, "00000000352510"),      # saldo final (índices 59:73) = 3.525,10
        (74, "EUR"),                 # divisa (índices 73:76)
    ])
    return [cab] + movs + [fin_cuenta, reg80("99", [])]


def main():
    OUT.mkdir(exist_ok=True)

    # 1) Muestra realista (cuadre exacto: 1.250,00 + 2.275,10 = 3.525,10)
    (OUT / "n43_muestra.txt").write_text(
        "\n".join(n43_muestra()) + "\n", encoding="utf-8"
    )

    # 2) Fichero correcto (cuadre exacto: 5.000,00 + 3.712,25 = 8.712,25)
    (OUT / "n43_ok.txt").write_text(
        "\n".join(n43_estandar()) + "\n", encoding="utf-8"
    )

    # 3) Fichero con descuadre de saldo (-1,25 EUR en el registro 33)
    (OUT / "n43_descuadre.txt").write_text(
        "\n".join(n43_estandar(descuadre=True)) + "\n", encoding="utf-8"
    )

    # 4) Fichero "roto": CP1252/Latin-1, acentos, CRLF y espacios finales
    rotas = [l + "   " for l in n43_estandar(acentos=True)]
    crlf = ("\r\n".join(rotas) + "\r\n").encode("cp1252")
    (OUT / "n43_codificacion_rota.txt").write_bytes(crlf)

    print("Generados en %s:" % OUT)
    for f in sorted(OUT.iterdir()):
        print("  - %s (%d bytes)" % (f.name, f.stat().st_size))


if __name__ == "__main__":
    main()
