rule Prueba_SHA256
{
    meta:
        description = "Prueba de conversión por SHA256"
        author = "SigmaLab"
        date = "2026-11-09"

    strings:
        $hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    condition:
        $hash
}