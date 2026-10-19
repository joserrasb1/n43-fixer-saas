# -*- coding: utf-8 -*-
"""
generar_ejemplos.py
-------------------
Crea en ./ejemplos tres ficheros Norma 43 de prueba para la app:

- n43_ok.txt            → válido, saldos cuadrados (UTF-8, LF)
- n43_descuadre.txt     → estructura válida pero con descuadre de saldo (error)
- n43_codificacion_rota.txt → Latin-1/CP1252 + CRLF + espacios finales
                          (dispara las "reparaciones" automáticas)

Uso:  python3 generar_ejemplos.py
"""

from pathlib import Path

OUT = Path(__file__).resolve().parent / "ejemplos"

# Línea de cabecera: registro tipo 1, longitud >= 20.
HEADER = (
    "119100012025091500000001ESBA00012345678900000000000000000000000000000000"
)


def mov(concepto, ref, importe):
    # type: (str, str, str) -> str
    """Registro tipo 2: concepto en [6:42], referencia en [42:62], importe al final.

    El parser extrae el importe como ÚLTIMO patrón numérico con decimales de la
    línea, por eso va al final. La fecha DDMMYY va dentro del concepto (el parser
    la busca como primera secuencia de 6 dígitos válida).
    """
    c = "{:<36.36}".format(concepto)   # índices 6..41
    r = "{:<20.20}".format(ref)        # índices 42..61
    return "2OPER {}{} EUR {}".format(c, r, importe)


def trailer(total):
    # type: (str) -> str
    """Registro tipo 9: el importe final es el saldo declarado a contrastar."""
    return "9190001123456789012320250930CIERRE MES EUR {}".format(total)


MOVIMIENTOS = [
    mov("NOMINA SEPTIEMBRE 150925", "REF0000001", "2150,00"),
    mov("IVA TRIMESTRE HACIENDA 100925", "REF0000002", "-875,25"),
    mov("ALQUILER OFICINA OCTUBRE 011025", "REF0000003", "-950,00"),
    mov("COBRO FACTURA CLIENTE SL 031025", "REF0000004", "3400,00"),
    mov("COMISIONES BANCO 011025", "REF0000005", "-12,50"),
]

# Suma exacta de los movimientos: 2150 - 875,25 - 950 + 3400 - 12,50
TOTAL_OK = "3712,25"
# Descuadre deliberado de 125,30 EUR
TOTAL_DESCUADRE = "3837,55"


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


def mov_std(fecha, clave_dh, importe, doc):
    # type: (str, str, str, str) -> str
    """Registro 22 estándar: fecha pos. 5-10, debe/haber pos. 27 ('1' negativo,
    '2' positivo), importe pos. 28-41 (14 dígitos, 2 decimales implícitos)."""
    return reg80("22", [
        (3, "2100"), (5, fecha), (11, fecha[:4] + "20" + fecha[4:]),
        (19, "02"), (21, "CONCEP"), (27, clave_dh), (28, importe), (42, doc),
    ])


def n43_estandar(descuadre=False):
    # type: (bool) -> list
    """Fichero estricto AEB 43 (80 posiciones): saldo inicial 5.000,00 y
    5 movimientos; el saldo final declarado en el registro 33 cuadra en 8.712,25
    (o se descuadra deliberadamente si descuadre=True)."""
    cab = reg80("11", [
        (3, "2100"), (7, "0418"), (11, "1234567890"), (21, "45"),
        (23, "15092025"), (33, "2"), (34, "00000000500000"), (48, "EUR"),
    ])
    movs = [
        mov_std("150925", "2", "00000000215000", "NOMINA1"),   # haber +2150,00
        mov_std("100925", "1", "00000000087525", "IVA1"),      # debe    -875,25
        mov_std("011025", "1", "00000000095000", "ALQ1"),      # debe    -950,00
        mov_std("031025", "2", "00000000340000", "COB1"),      # haber +3400,00
        mov_std("011025", "1", "00000000001250", "COM1"),      # debe     -12,50
    ]
    saldo_final = "00000000871100" if descuadre else "00000000871225"
    fin_cuenta = reg80("33", [
        (3, "2100"), (7, "0418"), (11, "1234567890"),
        (20, "00005"), (25, "2"), (26, "00000000371225"),
        (40, "2"), (41, saldo_final),
    ])
    return [cab] + movs + [fin_cuenta, reg80("99", [])]


def main():
    OUT.mkdir(exist_ok=True)

    # 1) Fichero correcto
    ok = [HEADER] + MOVIMIENTOS + [trailer(TOTAL_OK)]
    (OUT / "n43_ok.txt").write_text("\n".join(ok) + "\n", encoding="utf-8")

    # 2) Fichero con descuadre de saldo
    des = [HEADER] + MOVIMIENTOS + [trailer(TOTAL_DESCUADRE)]
    (OUT / "n43_descuadre.txt").write_text("\n".join(des) + "\n", encoding="utf-8")

    # 3) Fichero "roto": Latin-1/CP1252, acentos, CRLF y espacios finales
    rotas = [HEADER] + [
        mov("NÓMINA SEPTIEMBRE 150925 (año 2025)", "REF0000001", "2150,00"),
        mov("PAGO PROVEEDOR MUEBLES S L 100925", "REF0000002", "-875,25"),
        mov("ALQUILER OFICINA OCTUBRE 011025", "REF0000003", "-950,00"),
        mov("COBRO CLIENTE AÑORANZA S L 031025", "REF0000004", "3400,00"),
        mov("COMISIONES BANCO 011025", "REF0000005", "-12,50"),
    ] + [trailer(TOTAL_OK)]
    crlf = ("\r\n".join(rotas) + "\r\n").encode("cp1252")
    (OUT / "n43_codificacion_rota.txt").write_bytes(crlf)

    # 4) Estándar AEB 43 estricto (posiciones fijas, 80 caracteres)
    std = "\n".join(n43_estandar()) + "\n"
    (OUT / "n43_estandar_ok.txt").write_text(std, encoding="utf-8")

    # 5) Estándar AEB 43 con descuadre deliberado (-1,25 EUR)
    std_des = "\n".join(n43_estandar(descuadre=True)) + "\n"
    (OUT / "n43_estandar_descuadre.txt").write_text(std_des, encoding="utf-8")

    print("Generados en %s:" % OUT)
    for f in sorted(OUT.iterdir()):
        print("  - %s (%d bytes)" % (f.name, f.stat().st_size))


if __name__ == "__main__":
    main()
