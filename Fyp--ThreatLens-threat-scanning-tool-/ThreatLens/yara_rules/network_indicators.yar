// ─────────────────────────────────────────────────────────────
// network_indicators.yar — C2 and network threat indicators
// ─────────────────────────────────────────────────────────────

rule Network_C2_Cobalt_Strike {
    meta:
        description = "Cobalt Strike beacon / C2 indicators"
        severity = "critical"
    strings:
        $cs1 = "CobaltStrike"            nocase
        $cs2 = "cobaltstrike"
        $cs3 = "beacon"                  nocase
        $cs4 = "sleeptime"               nocase
        $cs5 = "jitter"                  nocase
        $cs6 = "pipename"                nocase
        $cs7 = "spawnto"                 nocase
        $cs8 = "ReflectiveDll"           nocase
    condition:
        any of them
}

rule Network_C2_Generic {
    meta:
        description = "Generic C2 beacon communication pattern"
        severity = "high"
    strings:
        $hb1 = "heartbeat"               nocase
        $hb2 = "checkin"                 nocase
        $hb3 = "callback"                nocase
        $ip   = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
        $onion = ".onion"
        $dga  = /[a-z]{12,20}\.(com|net|org|biz)/
    condition:
        ($ip and 1 of ($hb*)) or $onion
}

rule Network_DNS_Tunneling {
    meta:
        description = "DNS tunneling for data exfiltration"
        severity = "high"
    strings:
        $d1 = "dns tunnel"               nocase
        $d2 = "iodine"                   nocase
        $d3 = "dnscat"                   nocase
        $d4 = "dns2tcp"                  nocase
        $d5 = "TXT record"               nocase
    condition:
        any of them
}

rule Network_TOR_Usage {
    meta:
        description = "TOR network usage indicators"
        severity = "medium"
    strings:
        $t1 = ".onion"
        $t2 = "tor2web"                  nocase
        $t3 = "TOR Browser"              nocase
        $t4 = "SOCKS5"                   nocase
        $t5 = "9050"
        $t6 = "9150"
    condition:
        $t1 or $t2 or ($t4 and ($t5 or $t6))
}

rule Network_Exfiltration {
    meta:
        description = "Data exfiltration indicators"
        severity = "high"
    strings:
        $ex1 = "exfil"                   nocase
        $ex2 = "data exfiltration"       nocase
        $ex3 = "upload"                  nocase
        $api1 = "discord.com/api/webhooks"  nocase
        $api2 = "api.telegram.org"       nocase
        $api3 = "pastebin.com/api"       nocase
        $ftp  = "ftp://"
        $smtp = "smtp"                   nocase
    condition:
        1 of ($api*) or (1 of ($ex*) and ($ftp or $smtp))
}

rule Network_Phishing_Credential_Harvester {
    meta:
        description = "Credential harvesting / phishing page"
        severity = "critical"
    strings:
        $ph1 = "document.getElementById('password').value" nocase
        $ph2 = "document.forms[0].submit()"       nocase
        $ph3 = "credential"                        nocase
        $ph4 = "harvest"                           nocase
        $ph5 = "phishing"                          nocase
        $send = "XMLHttpRequest"
        $post = "method='POST'"                    nocase
    condition:
        (1 of ($ph*) and $send) or 2 of ($ph*)
}
