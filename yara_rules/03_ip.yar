rule Prueba_IP
{
    meta:
        description = "Prueba de dirección IP"
        author = "SigmaLab"
        date = "2026-11-09"

    strings:
        $ip = "8.8.4.4"

    condition:
        $ip
}