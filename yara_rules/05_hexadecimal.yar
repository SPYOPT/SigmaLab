rule Prueba_Hexadecimal
{
    meta:
        description = "Prueba de patrón hexadecimal no convertible"
        author = "SigmaLab"
        date = "2026-11-09"

    strings:
        $mz = { 4D 5A ?? ?? [4-8] 50 45 }

    condition:
        $mz
}