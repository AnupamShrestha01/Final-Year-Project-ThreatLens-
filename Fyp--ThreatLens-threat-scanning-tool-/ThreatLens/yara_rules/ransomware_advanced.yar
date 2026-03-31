// ─────────────────────────────────────────────────────────────
// ransomware_advanced.yar — Advanced ransomware detection
// ─────────────────────────────────────────────────────────────

rule Ransomware_FileEncryption {
    meta:
        description = "File encryption behaviour common in ransomware"
        severity = "critical"
    strings:
        $enc1 = "CryptEncrypt"
        $enc2 = "CryptGenKey"
        $enc3 = "CryptAcquireContext"
        $enc4 = "BCryptEncrypt"
        $enc5 = "AES"                   nocase
        $enc6 = "RSA"                   nocase
        $note1 = "how to decrypt"       nocase
        $note2 = "your files"           nocase
        $note3 = "ransom"               nocase
        $note4 = "bitcoin"              nocase
        $note5 = "recover"              nocase
    condition:
        (2 of ($enc*) and 1 of ($note*)) or 3 of ($note*)
}

rule Ransomware_ShadowCopy_Deletion {
    meta:
        description = "Ransomware deleting shadow copies to prevent recovery"
        severity = "critical"
    strings:
        $v1 = "vssadmin delete shadows"       nocase
        $v2 = "vssadmin.exe Delete Shadows"   nocase
        $v3 = "Win32_ShadowCopy"              nocase
        $v4 = "wbadmin delete catalog"        nocase
        $v5 = "bcdedit /set {default}"        nocase
        $v6 = "wmic shadowcopy delete"        nocase
        $v7 = "Get-WmiObject Win32_Shadowcopy" nocase
    condition:
        any of them
}

rule Ransomware_WannaCry {
    meta:
        description = "WannaCry ransomware indicators"
        severity = "critical"
    strings:
        $wc1 = "WanaDecryptor"             nocase
        $wc2 = "WANNACRY"                  nocase
        $wc3 = "wncry"                     nocase
        $wc4 = "tasksche.exe"              nocase
        $wc5 = "@Please_Read_Me@"          nocase
        $wc6 = "WannaDecrypt0r"            nocase
        $kill = "MsWinZonesCacheCounterMutexA0"
    condition:
        any of them
}

rule Ransomware_LockBit {
    meta:
        description = "LockBit ransomware family indicators"
        severity = "critical"
    strings:
        $lb1 = "LockBit"                   nocase
        $lb2 = "Restore-My-Files"          nocase
        $lb3 = "lockbit"                   nocase
        $lb4 = "!!-Restore-My-Files-!!"    nocase
        $lb5 = "LockBit_Ransomware"        nocase
    condition:
        any of them
}

rule Ransomware_Ryuk {
    meta:
        description = "Ryuk ransomware indicators"
        severity = "critical"
    strings:
        $r1 = "RyukReadMe"                 nocase
        $r2 = "RYUK"                       nocase
        $r3 = "No system is safe"          nocase
        $r4 = "unique decryption code"     nocase
        $r5 = "hermes"                     nocase
    condition:
        any of them
}

rule Ransomware_Conti {
    meta:
        description = "Conti ransomware indicators"
        severity = "critical"
    strings:
        $c1 = "CONTI"                      nocase
        $c2 = "conti_readme"               nocase
        $c3 = "CONTI NEWS"                 nocase
        $c4 = "contirecovery"              nocase
    condition:
        any of them
}

rule Ransomware_Extension_Rename {
    meta:
        description = "File renaming pattern typical in ransomware"
        severity = "high"
    strings:
        $ext1 = ".locked"                  nocase
        $ext2 = ".encrypted"               nocase
        $ext3 = ".crypted"                 nocase
        $ext4 = ".crypt"                   nocase
        $ext5 = ".enc"                     nocase
        $ext6 = ".ransom"                  nocase
        $mv1  = "MoveFile"
        $mv2  = "ReplaceFile"
    condition:
        1 of ($ext*) and 1 of ($mv*)
}
