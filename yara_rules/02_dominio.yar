rule Prueba_Dominio
{
    meta:
        description = "Prueba de dominio malicioso"
        author = "SigmaLab"
        date = "2026-11-09"

    strings:
        $domain = "malicious-example.com" ascii wide

    condition:
        $domain
}