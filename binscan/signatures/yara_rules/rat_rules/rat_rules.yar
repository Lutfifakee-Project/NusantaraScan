/*
   NusantaraScan - RAT Detection Rules
   Contoh rule dasar untuk deteksi RAT umum.
   Untuk deteksi lebih luas, integrasikan dengan:
   https://github.com/Yara-Rules/rules
*/

rule DarkComet_RAT
{
    meta:
        description = "Deteksi DarkComet RAT"
        author = "NusantaraScan"
        severity = "high"
    strings:
        $s1 = "DarkComet" ascii wide nocase
        $s2 = "DarkCometRAT" ascii wide nocase
        $s3 = "DC_MUTEX" ascii wide
    condition:
        any of them
}

rule NanoCore_RAT
{
    meta:
        description = "Deteksi NanoCore RAT"
        author = "NusantaraScan"
        severity = "high"
    strings:
        $s1 = "NanoCore" ascii wide nocase
        $s2 = "NanoCoreRAT" ascii wide nocase
        $s3 = "NanoCore.Client" ascii wide
    condition:
        any of them
}

rule NjRAT
{
    meta:
        description = "Deteksi NjRAT / Bladabindi"
        author = "NusantaraScan"
        severity = "high"
    strings:
        $s1 = "njRAT" ascii wide nocase
        $s2 = "Bladabindi" ascii wide nocase
        $s3 = "njw0rm" ascii wide
    condition:
        any of them
}

rule Gh0st_RAT
{
    meta:
        description = "Deteksi Gh0st RAT"
        author = "NusantaraScan"
        severity = "high"
    strings:
        $s1 = "Gh0st" ascii wide nocase
        $s2 = "Gh0stRAT" ascii wide nocase
        $s3 = "gh0st" ascii wide
    condition:
        any of them
}

rule Suspicious_RAT_APIs
{
    meta:
        description = "Kombinasi API yang umum dipakai RAT"
        author = "NusantaraScan"
        severity = "medium"
    strings:
        $a1 = "CreateRemoteThread" ascii
        $a2 = "VirtualAllocEx" ascii
        $a3 = "WriteProcessMemory" ascii
        $a4 = "SetWindowsHookEx" ascii
        $a5 = "GetAsyncKeyState" ascii
    condition:
        3 of them
}

rule Suspicious_Persistence
{
    meta:
        description = "Mekanisme persistence umum malware"
        author = "NusantaraScan"
        severity = "medium"
    strings:
        $r1 = "CurrentVersion\\Run" ascii wide nocase
        $r2 = "CurrentVersion\\RunOnce" ascii wide nocase
        $r3 = "schtasks" ascii wide nocase
        $r4 = "CreateService" ascii wide
    condition:
        2 of them
}

rule Suspicious_PowerShell
{
    meta:
        description = "Penggunaan PowerShell mencurigakan"
        author = "NusantaraScan"
        severity = "medium"
    strings:
        $p1 = "powershell" ascii wide nocase
        $p2 = "-EncodedCommand" ascii wide nocase
        $p3 = "-WindowStyle Hidden" ascii wide nocase
        $p4 = "Bypass" ascii wide nocase
    condition:
        $p1 and 2 of ($p2, $p3, $p4)
}