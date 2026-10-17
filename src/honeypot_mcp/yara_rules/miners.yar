/*
 * Cryptominers: the binary, its configuration and the command lines that start it.
 * Original HoneyPot-MCP rules.
 */

rule Miner_XMRig_Artefacts
{
    meta:
        author = "HoneyPot-MCP"
        description = "XMRig or an XMRig-derived miner: its name together with algorithm or pool-configuration strings, or two strings only this miner family carries"
        reference = "https://attack.mitre.org/techniques/T1496/"
        date = "2026-10-16"
        severity = "high"
        family = "xmrig"

    strings:
        $name = "xmrig" nocase
        $donate_flag = "--donate-level"
        $donate_host = "donate.v2.xmrig.com"
        $randomx = "randomx" nocase
        $cn = "cryptonight" nocase
        $algo_rx = "rx/0"
        $stratum = "stratum+tcp://"

    condition:
        filesize < 32MB and
        (($name and 2 of ($donate_flag, $donate_host, $randomx, $cn, $algo_rx, $stratum)) or
         2 of ($donate_flag, $donate_host))
}

rule Miner_Stratum_Pool_Reference
{
    meta:
        author = "HoneyPot-MCP"
        description = "A stratum mining-pool URL (stratum+tcp, stratum+ssl, stratum2+tcp) in a config file, script or command line; plain text, so it also catches miners that are not XMRig"
        reference = "https://attack.mitre.org/techniques/T1496/"
        date = "2026-10-16"
        severity = "medium"
        family = "generic-miner"

    strings:
        $stratum = /stratum2?\+(tcp|ssl|tls):\/\/[A-Za-z0-9._-]{3,80}(:[0-9]{2,5})?/ nocase

    condition:
        filesize < 8MB and $stratum
}

rule Miner_Monero_Wallet_With_Pool
{
    meta:
        author = "HoneyPot-MCP"
        description = "A Monero primary address (95 base58 characters starting 4) in the same file as a pool or miner option, the typical shape of a mining command line or JSON config"
        reference = "https://attack.mitre.org/techniques/T1496/"
        date = "2026-10-16"
        severity = "medium"
        family = "generic-miner"

    strings:
        $wallet = /\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/
        $pool1 = "stratum"
        $pool2 = "pool" nocase
        $pool3 = "--donate-level"
        $pool4 = "\"algo\""

    condition:
        filesize < 8MB and $wallet and any of ($pool*)
}

rule Miner_Minerd_CPUMiner
{
    meta:
        author = "HoneyPot-MCP"
        description = "minerd / cpuminer (the pooler CPU miners older botnets drop): the program name with its own option strings"
        reference = "https://attack.mitre.org/techniques/T1496/"
        date = "2026-10-16"
        severity = "medium"
        family = "cpuminer"

    strings:
        $name1 = "minerd"
        $name2 = "cpuminer" nocase
        $opt1 = "--cputest"
        $opt2 = "--benchmark"
        $opt3 = "--no-longpoll"
        $stratum = "stratum+tcp://"

    condition:
        filesize < 16MB and any of ($name*) and 2 of ($opt1, $opt2, $opt3, $stratum)
}
