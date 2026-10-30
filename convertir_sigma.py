from pathlib import Path
import csv
import subprocess
import sys


BASE = Path(r"C:\SigmaLab")
REGLAS = BASE / "sigma" / "rules"
SALIDA = BASE / "KQL_Output"
LANZADOR = BASE / "sigma_launcher.py"
PYTHON_VENV = BASE / ".venv" / "Scripts" / "python.exe"

PIPELINE = "microsoft_xdr"
LIMITE = 2000


def buscar_reglas():
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


def convertir(regla):
    comando = [
        str(PYTHON_VENV),
        str(LANZADOR),
        "convert",
        "-t",
        "kusto",
        "-p",
        PIPELINE,
        str(regla),
    ]

    return subprocess.run(
        comando,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def main():
    SALIDA.mkdir(parents=True, exist_ok=True)

    if not PYTHON_VENV.exists():
        print("ERROR: No existe el Python del entorno virtual:")
        print(PYTHON_VENV)
        sys.exit(1)

    if not LANZADOR.exists():
        print("ERROR: No existe sigma_launcher.py:")
        print(LANZADOR)
        sys.exit(1)

    print(f"Python usado para convertir: {PYTHON_VENV}")
    print(f"Lanzador Sigma: {LANZADOR}")
    print()

    reglas = buscar_reglas()

    if not reglas:
        print("No se encontraron reglas Sigma compatibles con el filtro.")
        sys.exit(1)

    print(f"Reglas seleccionadas: {len(reglas)}")
    print(f"Pipeline: {PIPELINE}")
    print("-" * 60)

    reporte = []

    for numero, regla in enumerate(reglas, start=1):
        print(f"[{numero}/{len(reglas)}] {regla.name}")

        resultado = convertir(regla)

        kql = resultado.stdout.strip()
        error = resultado.stderr.strip()

        if resultado.returncode == 0 and kql:
            archivo_kql = SALIDA / f"{regla.stem}.kql"

            encabezado = (
                f"// Regla Sigma: {regla.name}\n"
                f"// Ruta original: {regla}\n"
                f"// Pipeline: {PIPELINE}\n"
                "// Requiere validación en el entorno de destino.\n\n"
            )

            archivo_kql.write_text(
                encabezado + kql + "\n",
                encoding="utf-8",
            )

            estado = "EXITOSA"
            detalle = ""
            salida_kql = str(archivo_kql)

        else:
            estado = "FALLIDA"
            detalle = error or "No se obtuvo contenido KQL."
            salida_kql = ""

            print(f"  ERROR: {detalle[:300]}")

        reporte.append(
            {
                "regla": regla.name,
                "ruta_sigma": str(regla),
                "pipeline": PIPELINE,
                "estado": estado,
                "archivo_kql": salida_kql,
                "detalle": detalle.replace("\n", " "),
            }
        )

    reporte_csv = SALIDA / "reporte_conversion.csv"

    with reporte_csv.open(
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as archivo:
        columnas = [
            "regla",
            "ruta_sigma",
            "pipeline",
            "estado",
            "archivo_kql",
            "detalle",
        ]

        writer = csv.DictWriter(
            archivo,
            fieldnames=columnas,
        )

        writer.writeheader()
        writer.writerows(reporte)

    exitosas = sum(
        1
        for elemento in reporte
        if elemento["estado"] == "EXITOSA"
    )

    fallidas = len(reporte) - exitosas

    print("-" * 60)
    print(f"Exitosas: {exitosas}")
    print(f"Fallidas: {fallidas}")
    print(f"Reporte: {reporte_csv}")


if __name__ == "__main__":
    main()