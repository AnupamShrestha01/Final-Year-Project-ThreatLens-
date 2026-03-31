// ─────────────────────────────────────────────────────────────
// persistence_evasion.yar — Persistence and AV evasion
// ─────────────────────────────────────────────────────────────

rule Persistence_Registry {
    meta:
        description = "Registry-based persistence mechanism"
        severity = "high"
    strings:
        $r1 = "CurrentVersion\\Run"              nocase
        $r2 = "CurrentVersion\\RunOnce"          nocase
        $r3 = "Winlogon\\Shell"                  nocase
        $r4 = "Winlogon\\Userinit"               nocase
        $r5 = "CurrentVersion\\RunServices"      nocase
        $r6 = "SYSTEM\\CurrentControlSet\\Services" nocase
        $api1 = "RegSetValueEx"
        $api2 = "RegCreateKeyEx"
    condition:
        1 of ($r*) and 1 of ($api*)
}

rule Persistence_ScheduledTask {
    meta:
        description = "Scheduled task creation for persistence"
        severity = "high"
    strings:
        $t1 = "schtasks /create"                 nocase
        $t2 = "schtasks.exe"                     nocase
        $t3 = "New-ScheduledTask"                nocase
        $t4 = "Register-ScheduledTask"           nocase
        $t5 = "at.exe"                           nocase
        $t6 = "Task Scheduler"                   nocase
        $t7 = "ITaskScheduler"
    condition:
        any of them
}

rule Persistence_Service_Install {
    meta:
        description = "Windows service installation for persistence"
        severity = "high"
    strings:
        $s1 = "CreateService"
        $s2 = "OpenSCManager"
        $s3 = "sc create"                        nocase
        $s4 = "New-Service"                      nocase
        $s5 = "StartService"
    condition:
        2 of them
}

rule Persistence_Startup_Folder {
    meta:
        description = "Writing to startup folder for persistence"
        severity = "high"
    strings:
        $st1 = "\\Startup\\"                     nocase
        $st2 = "\\Start Menu\\Programs\\Startup" nocase
        $st3 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" nocase
    condition:
        any of them
}

rule Evasion_AntiDebug {
    meta:
        description = "Anti-debugging techniques"
        severity = "high"
    strings:
        $ad1 = "IsDebuggerPresent"
        $ad2 = "CheckRemoteDebuggerPresent"
        $ad3 = "NtQueryInformationProcess"
        $ad4 = "OutputDebugString"
        $ad5 = "FindWindow"
        $ad6 = "GetTickCount"
        $ad7 = "QueryPerformanceCounter"
        $ad8 = "ZwQueryInformationProcess"
        $ad9 = "SetUnhandledExceptionFilter"
    condition:
        3 of them
}

rule Evasion_AntiVM {
    meta:
        description = "Anti-VM / sandbox evasion techniques"
        severity = "high"
    strings:
        $vm1 = "vmware"                          nocase
        $vm2 = "virtualbox"                      nocase
        $vm3 = "vbox"                            nocase
        $vm4 = "sandbox"                         nocase
        $vm5 = "VPCCHECK"                        nocase
        $vm6 = "vmtoolsd.exe"                    nocase
        $vm7 = "vboxservice.exe"                 nocase
        $vm8 = "wireshark"                       nocase
        $vm9 = "procmon"                         nocase
        $vm10 = "HARDWARE\\ACPI\\DSDT\\VBOX"    nocase
    condition:
        2 of them
}

rule Evasion_AMSI_Bypass {
    meta:
        description = "AMSI (Antimalware Scan Interface) bypass attempt"
        severity = "critical"
    strings:
        $a1 = "AmsiScanBuffer"                   nocase
        $a2 = "amsiInitFailed"                   nocase
        $a3 = "amsi.dll"                         nocase
        $a4 = "Disable-AmsiProvider"             nocase
        $a5 = "[Ref].Assembly.GetType"           nocase
        $a6 = "SetValue($null,$true)"            nocase
    condition:
        any of them
}

rule Evasion_ETW_Bypass {
    meta:
        description = "Event Tracing for Windows (ETW) bypass"
        severity = "high"
    strings:
        $e1 = "EtwEventWrite"                    nocase
        $e2 = "NtTraceEvent"                     nocase
        $e3 = "ETWpDispatchEventsToProviders"     nocase
        $patch = { C3 00 00 00 00 }
    condition:
        any of ($e*) or $patch
}

rule Lateral_Movement_PsExec {
    meta:
        description = "PsExec or lateral movement tool indicators"
        severity = "high"
    strings:
        $p1 = "PsExec"                           nocase
        $p2 = "psexesvc"                         nocase
        $p3 = "\\ADMIN$\\"                       nocase
        $p4 = "net use \\\\"                     nocase
        $p5 = "wmic /node:"                      nocase
        $p6 = "Invoke-Command -ComputerName"     nocase
    condition:
        any of them
}

rule Credential_Mimikatz {
    meta:
        description = "Mimikatz credential dumping tool"
        severity = "critical"
    strings:
        $m1 = "mimikatz"                         nocase
        $m2 = "sekurlsa"                         nocase
        $m3 = "lsadump"                          nocase
        $m4 = "kerberos::list"                   nocase
        $m5 = "privilege::debug"                 nocase
        $m6 = "Pass-the-Hash"                    nocase
        $m7 = "WDigest"                          nocase
        $m8 = "SamSs"                            nocase
    condition:
        any of them
}
