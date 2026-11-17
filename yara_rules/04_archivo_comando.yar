rule Prueba_Archivo_Comando
{
    meta:
        description = "Prueba de archivo y comando"
        author = "SigmaLab"
        date = "2026-11-09"

    strings:
        $file = "payload.exe" ascii wide
        $cmd = "powershell.exe -EncodedCommand" ascii wide

    condition:
        all of them
}