rule Ransomware_Generic {
    meta:
        description = "Generic ransomware behaviour indicators"
        severity = "critical"
    strings:
        $ransom1 = "Your files have been encrypted"  nocase
        $ransom2 = "decrypt your files"              nocase
        $ransom3 = "pay the ransom"                  nocase
        $ransom4 = "bitcoin"                         nocase
        $ransom5 = "TOR browser"                     nocase
        $ransom6 = ".onion"                          nocase
        $crypto1 = "CryptEncrypt"
        $crypto2 = "CryptGenKey"
        $shadow  = "vssadmin delete shadows"         nocase
        $bcdedit = "bcdedit /set {default}"          nocase
    condition:
        2 of ($ransom*) or (1 of ($ransom*) and 1 of ($crypto*)) or ($shadow) or ($bcdedit)
}
