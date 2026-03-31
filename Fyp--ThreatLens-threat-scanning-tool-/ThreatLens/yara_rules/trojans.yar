// ─────────────────────────────────────────────────────────────
// trojans.yar — Trojan / RAT detection rules
// Based on Yara-Rules/rules malware categories
// ─────────────────────────────────────────────────────────────

rule Trojan_RAT_Generic {
    meta:
        description = "Generic Remote Access Trojan indicators"
        severity = "critical"
    strings:
        $remote1 = "RemoteShell"          nocase
        $remote2 = "reverse_shell"        nocase
        $remote3 = "bind_shell"           nocase
        $remote4 = "backdoor"             nocase
        $remote5 = "rat_client"           nocase
        $inject1 = "CreateRemoteThread"
        $inject2 = "VirtualAllocEx"
        $inject3 = "WriteProcessMemory"
        $inject4 = "NtUnmapViewOfSection"
    condition:
        2 of ($remote*) or 2 of ($inject*) or (1 of ($remote*) and 1 of ($inject*))
}

rule Trojan_Keylogger {
    meta:
        description = "Keylogger behaviour — captures keystrokes"
        severity = "high"
    strings:
        $k1 = "SetWindowsHookEx"
        $k2 = "GetAsyncKeyState"
        $k3 = "GetKeyState"
        $k4 = "WH_KEYBOARD_LL"
        $k5 = "keylogger"              nocase
        $k6 = "keystroke"              nocase
        $k7 = "GetForegroundWindow"
    condition:
        2 of them
}

rule Trojan_Banker {
    meta:
        description = "Banking trojan — targets financial credentials"
        severity = "critical"
    strings:
        $b1 = "bank"                    nocase
        $b2 = "paypal"                  nocase
        $b3 = "creditcard"              nocase
        $b4 = "credit card"             nocase
        $b5 = "FormGrabber"             nocase
        $b6 = "WebInject"               nocase
        $b7 = "password stealer"        nocase
        $b8 = "credential harvest"      nocase
        $hook1 = "InternetReadFile"
        $hook2 = "HttpSendRequest"
        $hook3 = "PR_Write"
    condition:
        (2 of ($b*) and 1 of ($hook*)) or 3 of ($b*)
}

rule Trojan_Downloader {
    meta:
        description = "Trojan downloader — fetches and executes payload"
        severity = "high"
    strings:
        $d1 = "URLDownloadToFile"       nocase
        $d2 = "BITSAdmin"               nocase
        $d3 = "certutil -urlcache"      nocase
        $d4 = "Invoke-WebRequest"       nocase
        $d5 = "DownloadFile("           nocase
        $d6 = "wget "                   nocase
        $d7 = "curl -s "                nocase
        $exec1 = "ShellExecute"
        $exec2 = "CreateProcess"
        $exec3 = "WinExec"
    condition:
        1 of ($d*) and 1 of ($exec*)
}

rule Trojan_Infostealer {
    meta:
        description = "Information stealer — harvests credentials and system info"
        severity = "critical"
    strings:
        $s1 = "password"                nocase
        $s2 = "credentials"             nocase
        $s3 = "chrome"                  nocase
        $s4 = "firefox"                 nocase
        $s5 = "Login Data"              nocase
        $s6 = "cookies"                 nocase
        $s7 = "wallet.dat"              nocase
        $s8 = "steal"                   nocase
        $net1 = "smtp"                  nocase
        $net2 = "ftp://"                nocase
        $net3 = "telegram"              nocase
    condition:
        3 of ($s*) and 1 of ($net*)
}

rule Trojan_ProcessHollowing {
    meta:
        description = "Process hollowing / process injection technique"
        severity = "critical"
    strings:
        $ph1 = "NtUnmapViewOfSection"
        $ph2 = "ZwUnmapViewOfSection"
        $ph3 = "VirtualAllocEx"
        $ph4 = "WriteProcessMemory"
        $ph5 = "SetThreadContext"
        $ph6 = "ResumeThread"
        $ph7 = "CreateProcessA"
        $ph8 = "NtResumeThread"
    condition:
        4 of them
}
