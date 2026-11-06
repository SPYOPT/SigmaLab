from contextlib import redirect_stdout, redirect_stderr
import importlib.metadata as importlib_metadata
from io import BytesIO, TextIOBase
from pathlib import Path
import traceback
import csv
import json
import sys
import yaml


# ============================================================
# CONFIGURACIÓN GENERAL
# ============================================================

BASE = Path(r"C:\SigmaLab")
REGLAS = BASE / "sigma" / "rules"
SALIDA = BASE / "KQL_Output"
LANZADOR = BASE / "sigma_launcher.py"

PYTHON_VENV = Path(sys.executable)

PIPELINE = "microsoft_xdr"
LIMITE = 2000


# ============================================================
# FUNCIONES AUXILIARES
# ============================================================

def convertir_a_texto(valor):
    """
    Convierte valores YAML en texto para almacenarlos en CSV.
    Las listas y diccionarios se guardan como JSON.
    """

    if valor is None:
        return ""

    if isinstance(valor, (list, dict)):
        return json.dumps(
            valor,
            ensure_ascii=False,
            default=str,
        )

    return str(valor)


def obtener_metadata(regla):
    """
    Lee la regla Sigma YAML y obtiene:
    - título
    - descripción
    - alcance o fuente de datos
    - metadata general
    """

    metadata_vacia = {
        "id_sigma": "",
        "titulo": "",
        "descripcion": "",
        "aplica_a": "",
        "producto": "",
        "categoria": "",
        "servicio": "",
        "definicion_logsource": "",
        "estado_sigma": "",
        "nivel": "",
        "autor": "",
        "fecha_creacion": "",
        "fecha_modificacion": "",
        "tags": "",
        "referencias": "",
        "falsos_positivos": "",
        "metadata_completa": "",
        "error_metadata": "",
    }

    try:
        with regla.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as archivo:
            contenido = yaml.safe_load(archivo)

        if not isinstance(contenido, dict):
            metadata_vacia["error_metadata"] = (
                "El archivo YAML no contiene una estructura válida."
            )
            return metadata_vacia

        logsource = contenido.get("logsource") or {}

        if not isinstance(logsource, dict):
            logsource = {}

        producto = convertir_a_texto(
            logsource.get("product")
        )

        categoria = convertir_a_texto(
            logsource.get("category")
        )

        servicio = convertir_a_texto(
            logsource.get("service")
        )

        definicion = convertir_a_texto(
            logsource.get("definition")
        )

        # Construye una descripción sencilla de "a qué aplica".
        partes_aplica = []

        if producto:
            partes_aplica.append(f"Producto: {producto}")

        if categoria:
            partes_aplica.append(f"Categoría: {categoria}")

        if servicio:
            partes_aplica.append(f"Servicio: {servicio}")

        if definicion:
            partes_aplica.append(f"Definición: {definicion}")

        aplica_a = " | ".join(partes_aplica)

        metadata_seleccionada = {
            "id": contenido.get("id"),
            "title": contenido.get("title"),
            "description": contenido.get("description"),
            "status": contenido.get("status"),
            "level": contenido.get("level"),
            "author": contenido.get("author"),
            "date": contenido.get("date"),
            "modified": contenido.get("modified"),
            "logsource": logsource,
            "tags": contenido.get("tags"),
            "references": contenido.get("references"),
            "falsepositives": contenido.get("falsepositives"),
        }

        return {
            "id_sigma": convertir_a_texto(
                contenido.get("id")
            ),
            "titulo": convertir_a_texto(
                contenido.get("title")
            ),
            "descripcion": convertir_a_texto(
                contenido.get("description")
            ),
            "aplica_a": aplica_a,
            "producto": producto,
            "categoria": categoria,
            "servicio": servicio,
            "definicion_logsource": definicion,
            "estado_sigma": convertir_a_texto(
                contenido.get("status")
            ),
            "nivel": convertir_a_texto(
                contenido.get("level")
            ),
            "autor": convertir_a_texto(
                contenido.get("author")
            ),
            "fecha_creacion": convertir_a_texto(
                contenido.get("date")
            ),
            "fecha_modificacion": convertir_a_texto(
                contenido.get("modified")
            ),
            "tags": convertir_a_texto(
                contenido.get("tags")
            ),
            "referencias": convertir_a_texto(
                contenido.get("references")
            ),
            "falsos_positivos": convertir_a_texto(
                contenido.get("falsepositives")
            ),
            "metadata_completa": json.dumps(
                metadata_seleccionada,
                ensure_ascii=False,
                default=str,
            ),
            "error_metadata": "",
        }

    except Exception as error:
        metadata_vacia["error_metadata"] = (
            f"{type(error).__name__}: {error}"
        )
        return metadata_vacia

        


def buscar_reglas():
    """
    Busca reglas Sigma con categoría process_creation.
    """

    candidatos = []

    for archivo in REGLAS.rglob("*.yml"):
        try:
            contenido = archivo.read_text(
                encoding="utf-8",
                errors="replace",
            )

            if "category: process_creation" in contenido:
                candidatos.append(archivo)

        except OSError:
            continue

    return candidatos[:LIMITE]

class CapturadorCompatible(TextIOBase):
    """
    Captura texto y bytes.

    Sigma CLI necesita que sys.stdout tenga el atributo .buffer.
    """

    def __init__(self):
        super().__init__()
        self.buffer = BytesIO()

    @property
    def encoding(self):
        return "utf-8"

    def write(self, texto):
        if texto is None:
            return 0

        if isinstance(texto, bytes):
            datos = texto
            longitud = len(texto)
        else:
            texto = str(texto)
            datos = texto.encode(
                "utf-8",
                errors="replace",
            )
            longitud = len(texto)

        self.buffer.write(datos)
        return longitud

    def flush(self):
        return None

    def isatty(self):
        return False

    def getvalue(self):
        return self.buffer.getvalue().decode(
            "utf-8",
            errors="replace",
        )

def obtener_sigma_cli():
    """
    Localiza Sigma CLI instalado en el entorno actual.
    """

    entradas = [
        entrada
        for entrada in importlib_metadata.entry_points(
            group="console_scripts"
        )
        if entrada.name == "sigma"
    ]

    if not entradas:
        raise RuntimeError(
            "Sigma CLI no está instalado en este entorno: "
            f"{sys.executable}"
        )

    return entradas[0].load()


def convertir(regla):
    """
    Convierte una regla Sigma a KQL dentro del mismo proceso.

    No utiliza subprocess, sigma.exe ni otro python.exe.
    El capturador admite salida de texto y salida binaria.
    """

    argumentos = [
        "sigma",
        "convert",
        "-t",
        "kusto",
        "-p",
        PIPELINE,
        str(regla),
    ]

    salida_estandar = CapturadorCompatible()
    salida_error = CapturadorCompatible()

    argumentos_originales = sys.argv.copy()

    try:
        sigma_cli = obtener_sigma_cli()

        # Sigma CLI lee sus parámetros desde sys.argv.
        sys.argv = argumentos

        with redirect_stdout(salida_estandar):
            with redirect_stderr(salida_error):
                sigma_cli()

        return {
            "returncode": 0,
            "stdout": salida_estandar.getvalue().strip(),
            "stderr": salida_error.getvalue().strip(),
        }

    except SystemExit as error:
        codigo_salida = error.code

        if codigo_salida is None:
            codigo_salida = 0

        if not isinstance(codigo_salida, int):
            codigo_salida = 1

        return {
            "returncode": codigo_salida,
            "stdout": salida_estandar.getvalue().strip(),
            "stderr": salida_error.getvalue().strip(),
        }

    except Exception as error:
        salida = salida_estandar.getvalue().strip()
        diagnostico = salida_error.getvalue().strip()
        traceback_completo = traceback.format_exc()

        mensaje_excepcion = (
            f"{type(error).__name__}: {error}\n"
            f"{traceback_completo}"
        )

        if diagnostico:
            detalle = (
                f"{diagnostico}\n"
                f"{mensaje_excepcion}"
            )
        else:
            detalle = mensaje_excepcion

        return {
            "returncode": 1,
            "stdout": salida,
            "stderr": detalle,
        }

    finally:
        sys.argv = argumentos_originales   

# ============================================================
# PROCESO PRINCIPAL
# ============================================================

def main():
    # Crear la carpeta KQL_Output si todavía no existe.
    # Esta debe ser la primera instrucción dentro de main().
    SALIDA.mkdir(parents=True, exist_ok=True)

    # Verificar que el programa se esté ejecutando dentro del entorno virtual.
    if sys.prefix == sys.base_prefix:
        print("ERROR: El entorno virtual no está activo.")
        print("Ejecuta el programa con este comando:")
        print(r".\.venv\Scripts\python.exe .\convertir_sigma.py")
        sys.exit(1)

    # Mostrar el intérprete y el entorno realmente utilizados.
    print(f"Python actual: {sys.executable}")
    print(f"Entorno virtual: {sys.prefix}")
    print(f"Lanzador Sigma: {LANZADOR}")
    print(f"Carpeta de salida: {SALIDA}")
    print()

    # Verificar que exista sigma_launcher.py.
    if not LANZADOR.exists():
        print("ERROR: No existe sigma_launcher.py:")
        print(LANZADOR)
        sys.exit(1)

    # Verificar que exista el repositorio de reglas Sigma.
    if not REGLAS.exists():
        print("ERROR: No existe la carpeta de reglas Sigma:")
        print(REGLAS)
        sys.exit(1)

    # Buscar las reglas de acuerdo con el filtro y el límite configurados.
    reglas = buscar_reglas()

    if not reglas:
        print("No se encontraron reglas Sigma con el filtro configurado.")
        sys.exit(1)

    print(f"Reglas seleccionadas: {len(reglas)}")
    print(f"Pipeline: {PIPELINE}")
    print("-" * 70)

    # Aquí se almacenará una fila por cada regla procesada.
    reporte = []

    for numero, regla in enumerate(reglas, start=1):
        print(f"[{numero}/{len(reglas)}] {regla.name}")

        # Leer descripción, logsource y demás metadata del YAML.
        metadata = obtener_metadata(regla)

        # Convertir la regla Sigma a KQL.
        resultado = convertir(regla)

        # stdout contiene el posible KQL.
        # stderr contiene errores o mensajes de diagnóstico.
        kql = resultado["stdout"].strip()       
        error_conversion = resultado["stderr"].strip()

        if resultado["returncode"] == 0 and kql:
            archivo_kql = SALIDA / f"{regla.stem}.kql"

            encabezado = (
                f"// Regla Sigma: {regla.name}\n"
                f"// ID Sigma: {metadata['id_sigma']}\n"
                f"// Título: {metadata['titulo']}\n"
                f"// Descripción: {metadata['descripcion']}\n"
                f"// Fecha de creación: {metadata['fecha_creacion']}\n"
                f"// Fecha de modificación: {metadata['fecha_modificacion']}\n"
                f"// Aplica a: {metadata['aplica_a']}\n"
                f"// Producto: {metadata['producto']}\n"
                f"// Categoría: {metadata['categoria']}\n"
                f"// Servicio: {metadata['servicio']}\n"
                f"// Nivel: {metadata['nivel']}\n"
                f"// Pipeline: {PIPELINE}\n"
                f"// Ruta original: {regla}\n"
                "// Requiere validación en el entorno de destino.\n\n"
            )

            archivo_kql.write_text(
                encabezado + kql + "\n",
                encoding="utf-8",
            )

            estado = "EXITOSA"
            archivo_salida = str(archivo_kql)
            detalle = ""

        else:
            estado = "FALLIDA"
            archivo_salida = ""

            detalle = (
                error_conversion
                or "No se obtuvo contenido KQL."
            )

            print(f"  ERROR: {detalle[:300]}")

        # Si la conversión fallida no produjo KQL,
        # resultado_kql simplemente quedará vacío.
        resultado_kql = kql if kql else ""

        reporte.append(
            {
                "regla": regla.name,
                "ruta_sigma": str(regla),
                "id_sigma": metadata["id_sigma"],
                "titulo": metadata["titulo"],
                "descripcion": metadata["descripcion"],
                "aplica_a": metadata["aplica_a"],
                "producto": metadata["producto"],
                "categoria": metadata["categoria"],
                "servicio": metadata["servicio"],
                "definicion_logsource": (
                    metadata["definicion_logsource"]
                ),
                "estado_sigma": metadata["estado_sigma"],
                "nivel": metadata["nivel"],
                "autor": metadata["autor"],
                "fecha_creacion": metadata["fecha_creacion"],
                "fecha_modificacion": (
                    metadata["fecha_modificacion"]
                ),
                "tags": metadata["tags"],
                "referencias": metadata["referencias"],
                "falsos_positivos": (
                    metadata["falsos_positivos"]
                ),
                "metadata_completa": (
                    metadata["metadata_completa"]
                ),
                "pipeline": PIPELINE,
                "estado_conversion": estado,
                "archivo_kql": archivo_salida,
                "resultado_kql": resultado_kql,
                "detalle_error": detalle.replace(
                    "\n",
                    " ",
                ),
                "error_metadata": metadata[
                    "error_metadata"
                ].replace(
                    "\n",
                    " ",
                ),
            }
        )

    # Mantener y actualizar el mismo CSV.
    # No se crea otro reporte diferente.
        # ========================================================
    # GENERACIÓN DE REPORTES CSV
    # ========================================================

    # Reporte general: contiene exitosas y fallidas.
    reporte_csv = SALIDA / "reporte_conversion.csv"

    # Reportes separados.
    reporte_exitosas_csv = SALIDA / "reglas_exitosas.csv"
    reporte_fallidas_csv = SALIDA / "reglas_fallidas.csv"

    columnas = [
    # Identificación de la regla
    "regla",
    "id_sigma",
    "titulo",
    "descripcion",

    # Fechas de la regla
    "fecha_creacion",
    "fecha_modificacion",

    # Alcance de la regla
    "aplica_a",
    "producto",
    "categoria",
    "servicio",
    "definicion_logsource",

    # Clasificación Sigma
    "estado_sigma",
    "nivel",
    "autor",
    "tags",
    "referencias",
    "falsos_positivos",

    # Resultado de conversión
    "pipeline",
    "estado_conversion",
    "archivo_kql",
    "resultado_kql",
    "detalle_error",

    # Información técnica y trazabilidad
    "ruta_sigma",
    "metadata_completa",
    "error_metadata",
]

    # Separar las filas exitosas y fallidas.
    registros_exitosos = [
        elemento
        for elemento in reporte
        if elemento["estado_conversion"] == "EXITOSA"
    ]

    registros_fallidos = [
        elemento
        for elemento in reporte
        if elemento["estado_conversion"] == "FALLIDA"
    ]

    def guardar_reporte_csv(ruta, registros):
        """
        Guarda un reporte CSV utilizando las mismas columnas
        del reporte general.
        """

        with ruta.open(
            "w",
            newline="",
            encoding="utf-8-sig",
        ) as archivo:
            writer = csv.DictWriter(
                archivo,
                fieldnames=columnas,
            )

            writer.writeheader()
            writer.writerows(registros)

    # Guardar o actualizar el reporte general.
    guardar_reporte_csv(
        reporte_csv,
        reporte,
    )

    # Guardar únicamente las conversiones exitosas.
    guardar_reporte_csv(
        reporte_exitosas_csv,
        registros_exitosos,
    )

    # Guardar únicamente las conversiones fallidas.
    guardar_reporte_csv(
        reporte_fallidas_csv,
        registros_fallidos,
    )

    # Calcular el resumen final.
    exitosas = len(registros_exitosos)
    fallidas = len(registros_fallidos)

    print("-" * 70)
    print(f"Reglas procesadas: {len(reporte)}")
    print(f"Exitosas: {exitosas}")
    print(f"Fallidas: {fallidas}")
    print()
    print(f"Reporte general: {reporte_csv}")
    print(f"Reporte de exitosas: {reporte_exitosas_csv}")
    print(f"Reporte de fallidas: {reporte_fallidas_csv}")

if __name__ == "__main__":
    main()