"""Entry WSGI para hosting compartido (Alwaysdata plan Free, PythonAnywhere...).

Alwaysdata (y PythonAnywhere en su web app WSGI clásica) ejecuta las apps
Python bajo uWSGI: basta con que un archivo exponga el objeto WSGI
`application`. Aquí envolvemos la app FastAPI de `main.py` (que es ASGI) con
a2wsgi, que la adapta a WSGI sin tocar el código de la aplicación.

Ventajas frente a Render free:
  * El proceso está siempre encendido: la landing y la API responden al
    instante, sin la página «Application loading...».
  * Al ser un único worker persistente, el estado en memoria
    (`app.state.last`, usado por los exports) sigue funcionando entre
    peticiones, igual que en Render.

También puede ejecutarse en solitario para pruebas locales:

    $ python wsgi.py               # sirve en http://127.0.0.1:8000

Endpoints: los mismos que `main.py`
    GET  /                     landing + demo en vivo
    POST /api/parse-n43        parseo y validación
    GET  /api/export-csv       exportación CSV del último parseo
    GET  /api/export-xlsx      exportación XLSX del último parseo
    GET  /health               sondeo de vida
"""

from __future__ import annotations

from wsgiref.simple_server import make_server

from a2wsgi import ASGIMiddleware

from main import app

# Adaptador ASGI -> WSGI que uWSGI (Alwaysdata) invoca como `application`.
application = ASGIMiddleware(app)


def main() -> None:
    """Servidor de pruebas local (secuencial; no usar en producción)."""
    with make_server("127.0.0.1", 8000, application) as httpd:
        print("N43 Fixer (WSGI) escuchando en http://127.0.0.1:8000")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
