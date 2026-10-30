import sys
import importlib.metadata as metadata


def main():
    entradas_sigma = [
        entry
        for entry in metadata.entry_points(group="console_scripts")
        if entry.name == "sigma"
    ]

    if not entradas_sigma:
        print(
            "ERROR: Sigma CLI no está instalado en este intérprete:",
            sys.executable,
            file=sys.stderr,
        )
        sys.exit(1)

    sigma_entry = entradas_sigma[0]
    sigma_entry.load()()


if __name__ == "__main__":
    main()