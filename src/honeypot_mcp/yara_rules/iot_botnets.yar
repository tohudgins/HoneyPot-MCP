/*
 * IoT botnet binaries and the shell droppers that fetch them.
 *
 * Written for HoneyPot-MCP from the behaviour these families show on a Cowrie SSH/Telnet
 * honeypot. Original rules, not derived from any third-party rule set. Rules are small and
 * conservative on purpose: a hit should be explainable from the matched strings alone.
 *
 * Every rule carries `severity` (info | low | medium | high) and `family`.
 */

rule IoT_Mirai_Family_ELF
{
    meta:
        author = "HoneyPot-MCP"
        description = "ELF carrying several of the plain-text artefacts Mirai-family bots keep: watchdog device paths, the Source-engine flood query, the Cloudflare challenge path and busybox/proc references"
        reference = "https://attack.mitre.org/techniques/T1498/"
        date = "2026-10-16"
        severity = "high"
        family = "mirai"

    strings:
        $wd1 = "/dev/watchdog"
        $wd2 = "/dev/misc/watchdog"
        $tsrc = "TSource Engine Query"
        $cf = "/cdn-cgi/l/chk_captcha"
        $bb = "/bin/busybox"
        $ptcp = "/proc/net/tcp"
        $dns = "/etc/resolv.conf"

    condition:
        uint32(0) == 0x464c457f and filesize < 2MB and
        (
            ($tsrc and ($wd1 or $wd2)) or
            ($cf and ($wd1 or $wd2 or $bb)) or
            3 of ($wd1, $wd2, $bb, $ptcp, $dns)
        )
}

rule IoT_Gafgyt_Bashlite_ELF
{
    meta:
        author = "HoneyPot-MCP"
        description = "ELF containing two or more of the command words the Gafgyt/Bashlite family's IRC-style controller sends"
        reference = "https://attack.mitre.org/techniques/T1498/"
        date = "2026-10-16"
        severity = "high"
        family = "gafgyt"

    strings:
        $kill = "KILLATTK"
        $lol = "LOLNOGTFO"
        $gip = "GETLOCALIP"
        $scon = "SCANNER ON"
        $scoff = "SCANNER OFF"
        $junk = "JUNK"
        $hold = "HOLD"

    condition:
        uint32(0) == 0x464c457f and filesize < 2MB and
        (2 of ($kill, $lol, $gip, $scon, $scoff) or (1 of ($kill, $lol, $gip, $scon, $scoff) and $junk and $hold))
}

rule IoT_Busybox_Applet_Probe_Script
{
    meta:
        author = "HoneyPot-MCP"
        description = "Shell text that runs busybox with a made-up upper-case applet name, the way IoT droppers test whether the shell they landed in is busybox"
        reference = "https://attack.mitre.org/techniques/T1082/"
        date = "2026-10-16"
        severity = "medium"
        family = "iot-dropper"

    strings:
        $probe = /busybox [A-Z]{3,12}[ \t]*(\r|\n|;|&|\||$)/

    condition:
        uint32(0) != 0x464c457f and filesize < 64KB and #probe >= 1
}

rule IoT_Busybox_Fetch_Chain_Dropper
{
    meta:
        author = "HoneyPot-MCP"
        description = "Shell script that changes to a writable directory, fetches a file with busybox wget/tftp/ftpget and marks it executable"
        reference = "https://attack.mitre.org/techniques/T1105/"
        date = "2026-10-16"
        severity = "high"
        family = "iot-dropper"

    strings:
        $fetch = /busybox (wget|tftp|ftpget|curl) /
        $chmod = /chmod +(\+x|[0-7]?[0-7][0-7][0-7]|a\+x|u\+x)/
        $cd = /cd +(\/tmp|\/var\/run|\/var\/tmp|\/mnt|\/dev\/shm|\/data\/local\/tmp|\/var\/lock)/

    condition:
        uint32(0) != 0x464c457f and filesize < 64KB and $fetch and $chmod and $cd
}

rule IoT_Architecture_Suffix_Download_Script
{
    meta:
        author = "HoneyPot-MCP"
        description = "Shell script that fetches the same payload once per CPU architecture (arm, mips, x86, ppc, sh4, ...), the bins.sh pattern IoT botnets use because they cannot know the target's CPU"
        reference = "https://attack.mitre.org/techniques/T1105/"
        date = "2026-10-16"
        severity = "high"
        family = "iot-dropper"

    strings:
        $fetch1 = "wget"
        $fetch2 = "curl"
        $fetch3 = "tftp"
        $fetch4 = "ftpget"
        $a_arm = /[\/._-]arm[5-8]?\b/
        $a_mips = /[\/._-]mips(el)?\b/
        $a_mpsl = /[\/._-]mpsl\b/
        $a_x86 = /[\/._-](x86|x86_64|i[3-6]86)\b/
        $a_ppc = /[\/._-](ppc|powerpc)\b/
        $a_sh4 = /[\/._-]sh4\b/
        $a_spc = /[\/._-](spc|sparc)\b/
        $a_m68k = /[\/._-]m68k\b/
        $a_arc = /[\/._-]arc\b/
        $a_aarch = /[\/._-](aarch64|arm64)\b/

    condition:
        uint32(0) != 0x464c457f and filesize < 64KB and any of ($fetch*) and 4 of ($a_*)
}

rule IoT_Echo_Hex_Dropper
{
    meta:
        author = "HoneyPot-MCP"
        description = "Shell text that rebuilds a binary on the target with repeated echo -ne \"\\x..\" appends, optionally starting with the ELF magic spelled in hex or octal, so no download is needed"
        reference = "https://attack.mitre.org/techniques/T1027/"
        date = "2026-10-16"
        severity = "high"
        family = "echo-dropper"

    strings:
        $echo = /echo +-[ne]+ +["']?(\\x[0-9a-fA-F]{2}){6,}/
        $elf_hex = /\\x7[fF]\\x45\\x4[cC]\\x46/
        $elf_oct = "\\177ELF"

    condition:
        uint32(0) != 0x464c457f and
        (#echo >= 3 or (#echo >= 1 and ($elf_hex or $elf_oct)))
}

rule ELF_UPX_Packed
{
    meta:
        author = "HoneyPot-MCP"
        description = "ELF executable compressed with UPX (the UPX! trailer magic or the packer's banner string); IoT bot builds are routinely UPX-packed to shrink the download"
        reference = "https://attack.mitre.org/techniques/T1027/002/"
        date = "2026-10-16"
        severity = "medium"
        family = "packed"

    strings:
        $magic = "UPX!"
        $banner = "This file is packed with the UPX executable packer"

    condition:
        uint32(0) == 0x464c457f and filesize < 8MB and ($magic or $banner)
}

rule ELF_Small_Static_Stripped_Loader
{
    meta:
        author = "HoneyPot-MCP"
        description = "Heuristic: a very small ELF with no dynamic linker, no symbol table and a network or shell reference, which is the shape of a minimal downloader/loader stage"
        reference = "https://attack.mitre.org/techniques/T1105/"
        date = "2026-10-16"
        severity = "low"
        family = "iot-loader-heuristic"

    strings:
        $interp1 = "/lib/ld-"
        $interp2 = "/lib64/ld-"
        $interp3 = "/system/bin/linker"
        $symtab = ".symtab"
        $net1 = "GET /"
        $net2 = "HTTP/1."
        $net3 = "/bin/sh"
        $net4 = "wget"
        $net5 = "/proc/"

    condition:
        uint32(0) == 0x464c457f and filesize < 40KB and
        not any of ($interp*) and not $symtab and any of ($net*)
}
