rule DarkComet_RAT {
    strings:
        $s1 = "DarkComet" ascii
        $s2 = "DARKCOMET" ascii
        $s3 = "DComet" ascii
    condition:
        any of them
}

rule NanoCore_RAT {
    strings:
        $s1 = "NanoCore" ascii
        $s2 = "NanoCore.ClientPluginHost" ascii
        $s3 = "Mutex_NoRun_NC" ascii
    condition:
        any of them
}

rule NjRAT {
    strings:
        $s1 = "NjRAT" ascii
        $s2 = "NjRat" ascii
        $s3 = "Bladabindi" ascii
        $s4 = "PluginCommand" ascii
    condition:
        any of them
}

rule Gh0st_RAT {
    strings:
        $s1 = "Gh0st" ascii
        $s2 = "GH0ST" ascii
        $s3 = "gh0st" ascii
    condition:
        any of them
}

rule Orcus_RAT {
    strings:
        $s1 = "Orcus" ascii
        $s2 = "ORCUS" ascii
        $s3 = "OrcusClient" ascii
    condition:
        any of them
}

rule Quasar_RAT {
    strings:
        $s1 = "Quasar" ascii
        $s2 = "QuasarClient" ascii
        $s3 = "xRAT" ascii
    condition:
        any of them
}

rule Suspicious_RAT_APIs {
    strings:
        $api1 = "CreateRemoteThread" ascii
        $api2 = "VirtualAllocEx" ascii
        $api3 = "WriteProcessMemory" ascii
        $api4 = "GetAsyncKeyState" ascii
        $api5 = "URLDownloadToFile" ascii
    condition:
        2 of them
}