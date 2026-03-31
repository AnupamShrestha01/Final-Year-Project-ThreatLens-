// ─────────────────────────────────────────────────────────────
// packers_obfuscation.yar — Packer and obfuscation detection
// ─────────────────────────────────────────────────────────────

rule Packer_UPX {
    meta:
        description = "UPX packed executable"
        severity = "medium"
    strings:
        $upx1 = "UPX0"
        $upx2 = "UPX1"
        $upx3 = "UPX2"
        $upx4 = { 55 50 58 21 }
    condition:
        2 of them
}

rule Packer_MPRESS {
    meta:
        description = "MPRESS packed executable"
        severity = "medium"
    strings:
        $mp1 = "MPRESS1"
        $mp2 = "MPRESS2"
        $mp3 = ".MPRESS"
    condition:
        any of them
}

rule Packer_Themida {
    meta:
        description = "Themida / WinLicense protected executable"
        severity = "high"
    strings:
        $t1 = "Themida"                  nocase
        $t2 = "WinLicense"               nocase
        $t3 = "Oreans Technologies"      nocase
    condition:
        any of them
}

rule Packer_VMProtect {
    meta:
        description = "VMProtect obfuscated executable"
        severity = "high"
    strings:
        $v1 = "VMProtect"                nocase
        $v2 = ".vmp0"
        $v3 = ".vmp1"
    condition:
        any of them
}

rule Obfuscation_PowerShell {
    meta:
        description = "Obfuscated PowerShell command"
        severity = "high"
    strings:
        $enc  = /powershell\s+(-\w+\s+)*-[Ee][Nn][Cc][Oo][Dd][Ee][Dd][Cc][Oo][Mm][Mm][Aa][Nn][Dd]/  nocase
        $b64  = /[A-Za-z0-9+\/]{100,}={0,2}/
        $iex1 = "IEX("                   nocase
        $iex2 = "Invoke-Expression"      nocase
        $iex3 = "iex("                   nocase
        $bypass = "-ExecutionPolicy Bypass"  nocase
        $hidden = "-WindowStyle Hidden"       nocase
    condition:
        $enc or ($b64 and 1 of ($iex*)) or ($bypass and $hidden)
}

rule Obfuscation_JavaScript {
    meta:
        description = "Heavily obfuscated JavaScript"
        severity = "high"
    strings:
        $eval1 = /eval\s*\(\s*function\s*\(/        nocase
        $eval2 = /eval\s*\(\s*unescape\s*\(/        nocase
        $eval3 = /eval\s*\(\s*atob\s*\(/            nocase
        $fromcc = "String.fromCharCode"              nocase
        $b64long = /[A-Za-z0-9+\/]{500,}={0,2}/
    condition:
        any of ($eval*) or ($fromcc and $b64long)
}

rule Obfuscation_VBA {
    meta:
        description = "Obfuscated VBA macro"
        severity = "high"
    strings:
        $chr1 = /Chr\(\d+\)\s*&\s*Chr\(\d+\)/      nocase
        $chr2 = /Chr\s*\(\s*\d+\s*\)/               nocase
        $xor  = "XOR"                                nocase
        $split = "Split("                            nocase
        $join  = "Join("                             nocase
        $shell = "Shell("                            nocase
    condition:
        ($chr1 or $chr2) and ($shell or ($xor and $split))
}

rule Obfuscation_Base64_Payload {
    meta:
        description = "Large base64 encoded payload likely containing executable"
        severity = "medium"
    strings:
        $mz_b64  = "TVqQ"
        $mz_b642 = "TVoA"
        $elf_b64 = "f0VMR"
        $ps_b64  = "cG93ZXJzaGVsbA"
        $cmd_b64 = "Y21k"
    condition:
        any of them
}
