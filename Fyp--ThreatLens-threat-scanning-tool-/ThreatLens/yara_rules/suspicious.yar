rule Suspicious_Registry_Persistence {
    meta:
        description = "Detects registry-based persistence mechanisms"
        severity = "medium"
    strings:
        $run1 = "CurrentVersion\\Run"              nocase
        $run2 = "CurrentVersion\\RunOnce"          nocase
        $run3 = "Winlogon\\Shell"                  nocase
        $svc  = "SYSTEM\\CurrentControlSet\\Services" nocase
    condition:
        any of them
}

rule Suspicious_Network_Indicators {
    meta:
        description = "Suspicious network communication patterns"
        severity = "medium"
    strings:
        $raw_ip  = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
        $paste   = "pastebin.com"                  nocase
        $discord = "discord.com/api/webhooks"      nocase
        $ngrok   = ".ngrok.io"                     nocase
    condition:
        any of them
}
