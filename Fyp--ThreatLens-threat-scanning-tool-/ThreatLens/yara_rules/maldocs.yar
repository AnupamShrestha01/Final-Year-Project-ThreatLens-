// ─────────────────────────────────────────────────────────────
// maldocs.yar — Malicious document detection
// ─────────────────────────────────────────────────────────────

rule MalDoc_RTF_Exploit {
    meta:
        description = "Malicious RTF document with exploit"
        severity = "high"
    strings:
        $rtf  = "{\\rtf"
        $obj1 = "\\object"
        $obj2 = "\\objemb"
        $obj3 = "\\objupdate"
        $eq   = "Equation.3"             nocase
        $ole  = "OLE2Link"               nocase
    condition:
        $rtf and ($eq or $ole or ($obj1 and $obj2))
}

rule MalDoc_PDF_Exploit {
    meta:
        description = "Malicious PDF with exploit or embedded content"
        severity = "high"
    strings:
        $pdf   = "%PDF"
        $js    = "/JavaScript"
        $js2   = "/JS"
        $aa    = "/AA"
        $oa    = "/OpenAction"
        $emb   = "/EmbeddedFile"
        $enc   = "/Encrypt"
        $launch = "/Launch"
        $eval  = "eval("                 nocase
    condition:
        $pdf and ($launch or ($oa and ($js or $js2)) or ($emb and $eval))
}

rule MalDoc_Excel_4_Macro {
    meta:
        description = "Excel 4.0 XLM macro — ancient but abused technique"
        severity = "high"
    strings:
        $x1 = "EXEC("                    nocase
        $x2 = "CALL("                    nocase
        $x3 = "FORMULA.FILL"             nocase
        $x4 = "RUN("                     nocase
        $x5 = "FOPEN("                   nocase
        $x6 = "GET.WORKSPACE"            nocase
        $x7 = "=EXEC"                    nocase
    condition:
        2 of them
}

rule MalDoc_Word_Template_Inject {
    meta:
        description = "Word template injection for remote macro loading"
        severity = "high"
    strings:
        $t1 = "word/settings.xml"        nocase
        $t2 = "attachedTemplate"         nocase
        $t3 = "http://"
        $t4 = "https://"
        $rel = "relationships"           nocase
    condition:
        ($t1 or $t2) and ($t3 or $t4) and $rel
}

rule MalDoc_PowerShell_In_Doc {
    meta:
        description = "PowerShell command embedded in document"
        severity = "high"
    strings:
        $ps1  = "powershell"             nocase
        $ps2  = "cmd.exe"                nocase
        $enc  = "-EncodedCommand"        nocase
        $iex  = "IEX"                    nocase
        $dl   = "DownloadString"         nocase
        $bp   = "-ExecutionPolicy Bypass" nocase
    condition:
        $ps1 and (1 of ($enc, $iex, $dl, $bp))
}

rule MalDoc_Embedded_PE {
    meta:
        description = "Executable (PE file) embedded inside document"
        severity = "critical"
    strings:
        $mz       = { 4D 5A }
        $pe_sig   = { 50 45 00 00 }
        $doc_ext1 = "word/"
        $doc_ext2 = "xl/"
        $doc_ext3 = "%PDF"
    condition:
        ($doc_ext1 or $doc_ext2 or $doc_ext3) and $mz and $pe_sig
}
