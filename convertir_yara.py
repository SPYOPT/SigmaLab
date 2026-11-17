from pathlib import Path
from urllib.parse import urlparse
from datetime import date, datetime
import csv
import ipaddress
import json
import re
import sys
import hashlib

import plyara
import yara


# ============================================================
# CONFIGURACIÓN
# ============================================================

BASE = Path(r"C:\SigmaLab")

REGLAS_YARA = BASE / "yara_rules"

SALIDA_KQL = (
    BASE
    / "KQL_Output"
    / "YARA"
)

SALIDA_REPORTES = (
    BASE
    / "Reportes"
    / "YARA"
)

# 0 significa procesar todas las reglas.
LIMITE = 0


# ============================================================
# EXPRESIONES REGULARES
# ============================================================

REGEX_MD5 = re.compile(
    r"\b[a-fA-F0-9]{32}\b"
)

REGEX_SHA1 = re.compile(
    r"\b[a-fA-F0-9]{40}\b"
)

REGEX_SHA256 = re.compile(
    r"\b[a-fA-F0-9]{64}\b"
)

REGEX_URL = re.compile(
    r"\bhttps?://[^\s\"'<>]+",
    re.IGNORECASE,
)

REGEX_DOMINIO = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+"
    r"(?:com|net|org|io|info|biz|ru|cn|xyz|top|"
    r"online|site|cloud|co|uk|de|fr|es|pe)\b",
    re.IGNORECASE,
)

REGEX_IPV4 = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

REGEX_ARCHIVO = re.compile(
    r"\b[\w.@()\- ]+\."
    r"(?:exe|dll|sys|bat|cmd|ps1|vbs|js|jar|"
    r"scr|msi|lnk|elf|sh|py|docm|xlsm)\b",
    re.IGNORECASE,
)

REGEX_REGISTRO = re.compile(
    r"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_LOCAL_MACHINE|"
    r"HKEY_CURRENT_USER)\\[^\r\n\"']+",
    re.IGNORECASE,
)


# ============================================================
# FUNCIONES GENERALES
# ============================================================

def convertir_a_texto(valor):
    if valor is None:
        return ""

    if isinstance(valor, (date, datetime)):
        return valor.isoformat()

    if isinstance(valor, (list, dict)):
        return json.dumps(
            valor,
            ensure_ascii=False,
            default=str,
        )

    return str(valor)


def lista_a_texto(valores):
    return " | ".join(
        sorted(set(valores))
    )


def escapar_kql(valor):
    """
    Escapa comillas dobles para insertar el valor
    dentro de una cadena KQL.
    """

    return str(valor).replace(
        '"',
        '\\"',
    )


def lista_kql(valores):
    return ", ".join(
        f'"{escapar_kql(valor)}"'
        for valor in sorted(set(valores))
    )


def validar_ip(valor):
    try:
        ip = ipaddress.ip_address(valor)

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False

        return True

    except ValueError:
        return False


def limpiar_valor_yara(valor):
    """
    Limpia comillas y prefijos comunes de una cadena
    extraída desde una regla YARA.
    """

    if valor is None:
        return ""

    texto = str(valor).strip()

    if (
        len(texto) >= 2
        and texto[0] == '"'
        and texto[-1] == '"'
    ):
        texto = texto[1:-1]

    texto = texto.replace(r"\\", "\\")
    texto = texto.replace(r"\"", '"')
    texto = texto.replace(r"\n", " ")
    texto = texto.replace(r"\r", " ")
    texto = texto.replace(r"\t", " ")

    return texto.strip()

def calcular_hash_archivo(ruta):
    hash_sha256 = hashlib.sha256()

    with ruta.open("rb") as archivo:
        for bloque in iter(
            lambda: archivo.read(1024 * 1024),
            b"",
        ):
            hash_sha256.update(bloque)

    return hash_sha256.hexdigest()

# ============================================================
# VALIDACIÓN Y PARSEO
# ============================================================

def validar_regla_yara(ruta):
    """
    Comprueba que yara-python pueda compilar el archivo.
    """

    try:
        yara.compile(filepath=str(ruta))

        return True, ""

    except Exception as error:
        return (
            False,
            f"{type(error).__name__}: {error}",
        )


def parsear_reglas(ruta):
    """
    Lee el archivo mediante plyara.

    Un archivo puede contener más de una regla YARA.
    """

    contenido = ruta.read_text(
        encoding="utf-8",
        errors="replace",
    )

    parser = plyara.Plyara()

    reglas = parser.parse_string(contenido)

    return reglas


# ============================================================
# EXTRACCIÓN DE STRINGS Y OBSERVABLES
# ============================================================

def obtener_strings(regla):
    strings_texto = []
    strings_regex = []
    strings_hex = []

    for elemento in regla.get("strings", []):
        valor = elemento.get("value", "")
        tipo = str(
            elemento.get("type", "")
        ).lower()

        valor_limpio = limpiar_valor_yara(valor)

        if not valor_limpio:
            continue

        if (
            "byte" in tipo
            or "hex" in tipo
            or valor_limpio.startswith("{")
        ):
            strings_hex.append(valor_limpio)

        elif (
            "regex" in tipo
            or valor_limpio.startswith("/")
        ):
            strings_regex.append(valor_limpio)

        else:
            strings_texto.append(valor_limpio)

    return (
        strings_texto,
        strings_regex,
        strings_hex,
    )


def extraer_observables(strings_texto):
    md5 = set()
    sha1 = set()
    sha256 = set()
    urls = set()
    dominios = set()
    ips = set()
    archivos = set()
    registro = set()
    otros_strings = set()

    for texto in strings_texto:
        coincidencias_sha256 = REGEX_SHA256.findall(texto)

        for valor in coincidencias_sha256:
            sha256.add(valor.lower())

        texto_sin_sha256 = REGEX_SHA256.sub(
            " ",
            texto,
        )

        for valor in REGEX_SHA1.findall(
            texto_sin_sha256
        ):
            sha1.add(valor.lower())

        texto_sin_hashes = REGEX_SHA1.sub(
            " ",
            texto_sin_sha256,
        )

        for valor in REGEX_MD5.findall(
            texto_sin_hashes
        ):
            md5.add(valor.lower())

        for valor in REGEX_URL.findall(texto):
            urls.add(valor.rstrip(".,;)"))

            try:
                host = urlparse(valor).hostname

                if host:
                    dominios.add(host.lower())

            except ValueError:
                pass

        for valor in REGEX_DOMINIO.findall(texto):
            dominios.add(valor.lower())

        for valor in REGEX_IPV4.findall(texto):
            if validar_ip(valor):
                ips.add(valor)

        for valor in REGEX_ARCHIVO.findall(texto):
            archivos.add(valor.strip())

        for valor in REGEX_REGISTRO.findall(texto):
            registro.add(valor.strip())

        es_hash = bool(
         REGEX_SHA256.fullmatch(texto)
         or REGEX_SHA1.fullmatch(texto)
         or REGEX_MD5.fullmatch(texto)
        )

        es_url = bool(
            REGEX_URL.fullmatch(texto)
        )

        es_dominio = bool(
            REGEX_DOMINIO.fullmatch(texto)
        )

        es_ip = bool(
         REGEX_IPV4.fullmatch(texto)
        )

        es_archivo = bool(
            REGEX_ARCHIVO.fullmatch(texto)
        )

        es_registro = bool(
            REGEX_REGISTRO.fullmatch(texto)
        )

        if (
         6 <= len(texto) <= 300
            and not es_hash
            and not es_url
            and not es_dominio
            and not es_ip
            and not es_archivo
            and not es_registro
        ):
            otros_strings.add(texto)

    return {
        "md5": sorted(md5),
        "sha1": sorted(sha1),
        "sha256": sorted(sha256),
        "urls": sorted(urls),
        "dominios": sorted(dominios),
        "ips": sorted(ips),
        "archivos": sorted(archivos),
        "registro": sorted(registro),
        "strings_observables": sorted(
            otros_strings
        ),
    }


# ============================================================
# GENERACIÓN DE KQL
# ============================================================

def crear_consultas_kql(observables):
    consultas = []
    tablas = set()

    hashes = []

    for valor in observables["md5"]:
        hashes.append(
            f'MD5 =~ "{escapar_kql(valor)}"'
        )

    for valor in observables["sha1"]:
        hashes.append(
            f'SHA1 =~ "{escapar_kql(valor)}"'
        )

    for valor in observables["sha256"]:
        hashes.append(
            f'SHA256 =~ "{escapar_kql(valor)}"'
        )

    if hashes:
        tablas.add("DeviceFileEvents")

        consultas.append(
            "(\n"
            "    DeviceFileEvents\n"
            f"    | where {' or '.join(hashes)}\n"
            "    | project Timestamp, DeviceName, "
            "FileName, FolderPath, SHA1, SHA256, MD5,\n"
            '        IndicatorType = "FileHash",\n'
            "        Evidence = FileName\n"
            ")"
        )

    if observables["archivos"]:
        tablas.add("DeviceFileEvents")

        valores = lista_kql(
            observables["archivos"]
        )

        consultas.append(
            "(\n"
            "    DeviceFileEvents\n"
            f"    | where FileName in~ ({valores})\n"
            "    | project Timestamp, DeviceName, "
            "FileName, FolderPath, SHA1, SHA256,\n"
            '        IndicatorType = "FileName",\n'
            "        Evidence = FolderPath\n"
            ")"
        )

    if observables["dominios"]:
        tablas.add("DeviceNetworkEvents")

        valores = lista_kql(
            observables["dominios"]
        )

        consultas.append(
            "(\n"
            "    DeviceNetworkEvents\n"
            f"    | where RemoteUrl has_any ({valores})\n"
            "    | project Timestamp, DeviceName, "
            "RemoteUrl, RemoteIP,\n"
            "        InitiatingProcessFileName,\n"
            '        IndicatorType = "Domain",\n'
            "        Evidence = RemoteUrl\n"
            ")"
        )

    if observables["urls"]:
        tablas.add("DeviceNetworkEvents")

        valores = lista_kql(
            observables["urls"]
        )

        consultas.append(
            "(\n"
            "    DeviceNetworkEvents\n"
            f"    | where RemoteUrl has_any ({valores})\n"
            "    | project Timestamp, DeviceName, "
            "RemoteUrl, RemoteIP,\n"
            "        InitiatingProcessFileName,\n"
            '        IndicatorType = "URL",\n'
            "        Evidence = RemoteUrl\n"
            ")"
        )

    if observables["ips"]:
        tablas.add("DeviceNetworkEvents")

        valores = lista_kql(
            observables["ips"]
        )

        consultas.append(
            "(\n"
            "    DeviceNetworkEvents\n"
            f"    | where RemoteIP in ({valores})\n"
            "    | project Timestamp, DeviceName, "
            "RemoteIP, RemotePort,\n"
            "        InitiatingProcessFileName,\n"
            '        IndicatorType = "IPAddress",\n'
            "        Evidence = RemoteIP\n"
            ")"
        )

    if observables["registro"]:
        tablas.add("DeviceRegistryEvents")

        valores = lista_kql(
            observables["registro"]
        )

        consultas.append(
            "(\n"
            "    DeviceRegistryEvents\n"
            f"    | where RegistryKey has_any ({valores})\n"
            "    | project Timestamp, DeviceName, "
            "RegistryKey, RegistryValueName,\n"
            "        RegistryValueData,\n"
            "        InitiatingProcessFileName,\n"
            '        IndicatorType = "RegistryKey",\n'
            "        Evidence = RegistryKey\n"
            ")"
        )

    if observables["strings_observables"]:
        # Para reducir falsos positivos, solo se incluyen
        # las primeras 20 cadenas observables.
        strings = observables[
            "strings_observables"
        ][:20]

        valores = lista_kql(strings)

        tablas.add("DeviceProcessEvents")

        consultas.append(
            "(\n"
            "    DeviceProcessEvents\n"
            "    | where ProcessCommandLine "
            f"has_any ({valores})\n"
            "    | project Timestamp, DeviceName, "
            "FileName, FolderPath,\n"
            "        ProcessCommandLine,\n"
            '        IndicatorType = "ObservableString",\n'
            "        Evidence = ProcessCommandLine\n"
            ")"
        )

    if not consultas:
        return "", sorted(tablas)

    if len(consultas) == 1:
        resultado = consultas[0]

    else:
        resultado = (
            "union isfuzzy=true\n"
            + ",\n".join(consultas)
        )

    return resultado, sorted(tablas)


# ============================================================
# COBERTURA Y CLASIFICACIÓN
# ============================================================

def evaluar_conversion(
    observables,
    strings_texto,
    strings_regex,
    strings_hex,
):
    convertibles = (
        len(observables["md5"])
        + len(observables["sha1"])
        + len(observables["sha256"])
        + len(observables["urls"])
        + len(observables["dominios"])
        + len(observables["ips"])
        + len(observables["archivos"])
        + len(observables["registro"])
        + min(
            len(observables["strings_observables"]),
            20,
        )
    )

    no_convertibles = (
        len(strings_regex)
        + len(strings_hex)
    )

    total = convertibles + no_convertibles

    if total == 0:
        return (
            "INCOMPATIBLE",
            0,
            "No se encontraron observables compatibles "
            "con Microsoft Defender XDR.",
        )

    cobertura = round(
        convertibles / total * 100,
        2,
    )

    elementos_pendientes = []

    if strings_regex:
        elementos_pendientes.append(
            f"{len(strings_regex)} expresiones regulares"
        )

    if strings_hex:
        elementos_pendientes.append(
            f"{len(strings_hex)} patrones hexadecimales"
        )

    if convertibles == 0:
        estado = "INCOMPATIBLE"

    elif no_convertibles > 0:
        estado = "PARCIAL"

    else:
        estado = "EXITOSA"

    return (
        estado,
        cobertura,
        " | ".join(elementos_pendientes),
    )


# ============================================================
# METADATA
# ============================================================

def obtener_metadata(regla):
    metadata_lista = regla.get("metadata", [])

    metadata = {}

    for elemento in metadata_lista:
        clave = elemento.get("key")
        valor = elemento.get("value")

        if clave:
            metadata[str(clave)] = valor

    return {
        "descripcion": convertir_a_texto(
            metadata.get("description")
            or metadata.get("desc")
        ),
        "autor": convertir_a_texto(
            metadata.get("author")
        ),
        "fecha_creacion": convertir_a_texto(
            metadata.get("date")
            or metadata.get("created")
        ),
        "fecha_modificacion": convertir_a_texto(
            metadata.get("modified")
            or metadata.get("last_modified")
        ),
        "referencia": convertir_a_texto(
            metadata.get("reference")
            or metadata.get("references")
        ),
        "hash_metadata": convertir_a_texto(
            metadata.get("hash")
        ),
        "metadata_completa": json.dumps(
            metadata,
            ensure_ascii=False,
            default=str,
        ),
    }


# ============================================================
# REPORTES
# ============================================================

COLUMNAS = [
    "archivo_yara",
    "nombre_regla",
    "descripcion",
    "autor",
    "fecha_creacion",
    "fecha_modificacion",
    "referencia",
    "tags",
    "condicion_yara",
    "cantidad_strings_texto",
    "cantidad_regex",
    "cantidad_hexadecimal",
    "md5",
    "sha1",
    "sha256",
    "dominios",
    "urls",
    "ips",
    "archivos",
    "registro",
    "tablas_kql",
    "estado_conversion",
    "porcentaje_cobertura",
    "archivo_kql",
    "resultado_kql",
    "elementos_no_convertidos",
    "detalle_error",
    "metadata_completa",
]


def guardar_csv(ruta, registros):
    try:
        with ruta.open(
            "w",
            newline="",
            encoding="utf-8-sig",
        ) as archivo:
            writer = csv.DictWriter(
                archivo,
                fieldnames=COLUMNAS,
                delimiter=";",
                quotechar='"',
                quoting=csv.QUOTE_ALL,
                lineterminator="\n",
            )

            writer.writeheader()
            writer.writerows(registros)

    except PermissionError:
        print()
        print(f"ERROR: El reporte está abierto:")
        print(ruta)
        print("Cierra Excel o VS Code y vuelve a ejecutar.")
        sys.exit(1)


# ============================================================
# PROCESAMIENTO
# ============================================================

def procesar_archivo(ruta):
    resultados = []

    valida, error_validacion = validar_regla_yara(
        ruta
    )

    if not valida:
        resultados.append(
            {
                columna: ""
                for columna in COLUMNAS
            }
        )

        resultados[-1].update(
            {
                "archivo_yara": ruta.name,
                "estado_conversion": "FALLIDA",
                "detalle_error": error_validacion,
            }
        )

        return resultados

    try:
        reglas = parsear_reglas(ruta)

    except Exception as error:
        fila = {
            columna: ""
            for columna in COLUMNAS
        }

        fila.update(
            {
                "archivo_yara": ruta.name,
                "estado_conversion": "FALLIDA",
                "detalle_error": (
                    f"{type(error).__name__}: {error}"
                ),
            }
        )

        return [fila]

    for regla in reglas:
        nombre = regla.get(
            "rule_name",
            ruta.stem,
        )

        metadata = obtener_metadata(regla)

        strings_texto, strings_regex, strings_hex = (
            obtener_strings(regla)
        )

        observables = extraer_observables(
            strings_texto
        )

        kql, tablas = crear_consultas_kql(
            observables
        )

        estado, cobertura, pendientes = (
            evaluar_conversion(
                observables,
                strings_texto,
                strings_regex,
                strings_hex,
            )
        )

        archivo_kql = ""

        if kql:
            ruta_kql = (
                SALIDA_KQL
                / f"{nombre}.kql"
            )

            encabezado = (
                f"// Regla YARA: {nombre}\n"
                f"// Archivo: {ruta.name}\n"
                f"// Descripción: "
                f"{metadata['descripcion']}\n"
                f"// Estado: {estado}\n"
                f"// Cobertura: {cobertura}%\n"
                f"// Elementos no convertidos: "
                f"{pendientes}\n"
                "// Consulta generada para hunting en "
                "Microsoft Defender XDR.\n"
                "// Requiere validación antes de producción.\n\n"
            )

            ruta_kql.write_text(
                encabezado + kql + "\n",
                encoding="utf-8",
            )

            archivo_kql = str(ruta_kql)

        fila = {
            "archivo_yara": ruta.name,
            "nombre_regla": nombre,
            "descripcion": metadata["descripcion"],
            "autor": metadata["autor"],
            "fecha_creacion": (
                metadata["fecha_creacion"]
            ),
            "fecha_modificacion": (
                metadata["fecha_modificacion"]
            ),
            "referencia": metadata["referencia"],
            "tags": lista_a_texto(
                regla.get("tags", [])
            ),
            "condicion_yara": convertir_a_texto(
                regla.get("condition_terms")
                or regla.get("condition")
            ),
            "cantidad_strings_texto": len(
                strings_texto
            ),
            "cantidad_regex": len(strings_regex),
            "cantidad_hexadecimal": len(
                strings_hex
            ),
            "md5": lista_a_texto(
                observables["md5"]
            ),
            "sha1": lista_a_texto(
                observables["sha1"]
            ),
            "sha256": lista_a_texto(
                observables["sha256"]
            ),
            "dominios": lista_a_texto(
                observables["dominios"]
            ),
            "urls": lista_a_texto(
                observables["urls"]
            ),
            "ips": lista_a_texto(
                observables["ips"]
            ),
            "archivos": lista_a_texto(
                observables["archivos"]
            ),
            "registro": lista_a_texto(
                observables["registro"]
            ),
            "tablas_kql": lista_a_texto(tablas),
            "estado_conversion": estado,
            "porcentaje_cobertura": cobertura,
            "archivo_kql": archivo_kql,
            "resultado_kql": kql,
            "elementos_no_convertidos": pendientes,
            "detalle_error": "",
            "metadata_completa": (
                metadata["metadata_completa"]
            ),
        }

        resultados.append(fila)

    return resultados


# ============================================================
# MAIN
# ============================================================

def main():
    REGLAS_YARA.mkdir(
        parents=True,
        exist_ok=True,
    )

    SALIDA_KQL.mkdir(
        parents=True,
        exist_ok=True,
    )

    SALIDA_REPORTES.mkdir(
        parents=True,
        exist_ok=True,
    )

    archivos = sorted(
        list(REGLAS_YARA.rglob("*.yar"))
        + list(REGLAS_YARA.rglob("*.yara"))
    )

    if LIMITE > 0:
        archivos = archivos[:LIMITE]

    if not archivos:
        print("No se encontraron reglas YARA en:")
        print(REGLAS_YARA)
        sys.exit(1)

    print(f"Archivos YARA: {len(archivos)}")
    print(f"Entrada: {REGLAS_YARA}")
    print(f"Salida KQL: {SALIDA_KQL}")
    print(f"Reportes: {SALIDA_REPORTES}")
    print("-" * 70)

    reporte = []

    for numero, ruta in enumerate(
        archivos,
        start=1,
    ):
        print(
            f"[{numero}/{len(archivos)}] "
            f"{ruta.name}"
        )

        reporte.extend(
            procesar_archivo(ruta)
        )

    exitosas = [
        fila
        for fila in reporte
        if fila["estado_conversion"] == "EXITOSA"
    ]

    parciales = [
        fila
        for fila in reporte
        if fila["estado_conversion"] == "PARCIAL"
    ]

    incompatibles = [
        fila
        for fila in reporte
        if fila["estado_conversion"] == "INCOMPATIBLE"
    ]

    fallidas = [
        fila
        for fila in reporte
        if fila["estado_conversion"] == "FALLIDA"
    ]

    guardar_csv(
        SALIDA_REPORTES / "yara_conversion.csv",
        reporte,
    )

    guardar_csv(
        SALIDA_REPORTES / "yara_exitosas.csv",
        exitosas,
    )

    guardar_csv(
        SALIDA_REPORTES / "yara_parciales.csv",
        parciales,
    )

    guardar_csv(
        SALIDA_REPORTES / "yara_incompatibles.csv",
        incompatibles,
    )

    guardar_csv(
        SALIDA_REPORTES / "yara_fallidas.csv",
        fallidas,
    )

    print("-" * 70)
    print(f"Reglas procesadas: {len(reporte)}")
    print(f"Exitosas: {len(exitosas)}")
    print(f"Parciales: {len(parciales)}")
    print(f"Incompatibles: {len(incompatibles)}")
    print(f"Fallidas: {len(fallidas)}")
    print()
    print(
        "Reporte general: "
        f"{SALIDA_REPORTES / 'yara_conversion.csv'}"
    )


if __name__ == "__main__":
    main()