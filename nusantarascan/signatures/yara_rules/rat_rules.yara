rule NanoCore_RAT {
    strings:
        $s1 = "NanoCore.ClientPluginHost" ascii
        $s2 = "NanoCore.ClientPlugin" ascii
        $s3 = "IClientNetworkHost" ascii
    condition:
        any of them
}

rule DarkComet_RAT {
    strings:
        $s1 = "DarkComet" ascii
        $s2 = "DARKCOMET" ascii
        $s3 = "DComet" ascii
    condition:
        any of them
}

rule NjRAT {
    strings:
        $s1 = "NjRAT" ascii
        $s2 = "NjRat" ascii
        $s3 = "PluginCommand" ascii
        $s4 = "FileCommand" ascii
    condition:
        any of them
}

rule Gh0st_RAT {
    strings:
        $s1 = "Gh0st" ascii
        $s2 = "GH0ST" ascii
        $s3 = "Gh0st RAT" ascii
    condition:
        any of them
}