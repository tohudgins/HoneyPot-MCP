/*
 * Shell-level behaviour that matters regardless of which family wrote it: reverse shells,
 * persistence through SSH keys, fetch-and-run droppers, credential theft, and the harmless
 * "can I execute a file here" probe. Original HoneyPot-MCP rules.
 */

rule Shell_Reverse_Shell_Oneliner
{
    meta:
        author = "HoneyPot-MCP"
        description = "Reverse-shell one-liner: bash /dev/tcp redirection, nc/ncat -e, a mkfifo relay or a scripted socket with its descriptors duplicated onto a shell"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
        date = "2026-10-16"
        severity = "high"
        family = "reverse-shell"

    strings:
        $bash = /bash +-i +>& *\/dev\/tcp\/[^ \r\n]{3,60}/
        $devtcp_exec = /exec +[0-9]+<> *\/dev\/tcp\//
        $nc_e = /\bn(c|cat|etcat) [^\r\n]{0,60}-[a-z]*e +\/bin\/(ba|da|z)?sh/
        $mkfifo = /mkfifo +[^\r\n;|]{1,40}; *(cat|nc)/
        $py_sock = "socket.socket("
        $py_dup = "os.dup2("
        $py_sh = /pty\.spawn\(|\/bin\/(ba)?sh/

    condition:
        filesize < 1MB and
        (any of ($bash, $devtcp_exec, $nc_e, $mkfifo) or ($py_sock and $py_dup and $py_sh))
}

rule Shell_SSH_Authorized_Keys_Injection
{
    meta:
        author = "HoneyPot-MCP"
        description = "Appends a public key to authorized_keys (a >> or tee redirection into it, or the file name next to an inline ssh-rsa/ssh-ed25519 key): persistence by SSH key"
        reference = "https://attack.mitre.org/techniques/T1098/004/"
        date = "2026-10-16"
        severity = "high"
        family = "ssh-key-persistence"

    strings:
        $file = "authorized_keys"
        $key = /ssh-(rsa|ed25519|dss) +AAAA[0-9A-Za-z+\/=]{40,}/
        $redir = /(>>?|tee( +-a)?) *[~\/.a-zA-Z0-9_$"']{0,40}authorized_keys/

    condition:
        filesize < 256KB and ($redir or ($file and $key))
}

rule Shell_Fetch_Chmod_Execute_Delete
{
    meta:
        author = "HoneyPot-MCP"
        description = "Script that downloads a file, marks it executable, runs it and removes it: the dropper's whole life in a few lines"
        reference = "https://attack.mitre.org/techniques/T1105/"
        date = "2026-10-16"
        severity = "high"
        family = "dropper"

    strings:
        $fetch = /\b(wget|curl|tftp|ftpget|fetch)\b[^\r\n]{0,200}(https?|ftp):\/\/[^ \r\n]{4,}|\btftp +(-g|-r)\b/
        $chmod = /chmod +(\+x|[0-7]?[0-7][0-7][0-7]|a\+x|u\+x)/
        $run = /(\.\/[A-Za-z0-9._-]{1,40}|\bsh +[A-Za-z0-9._\/-]{1,60}|\bbash +[A-Za-z0-9._\/-]{1,60}|\/(tmp|var\/tmp|dev\/shm|var\/run)\/[A-Za-z0-9._-]{1,40} *(;|&|\r|\n|$))/
        $rm = /\brm +(-[rf]+ +)?[^\r\n;|&]{1,60}/

    condition:
        uint32(0) != 0x464c457f and filesize < 128KB and $fetch and $chmod and $run and $rm
}

rule Shell_Credential_Theft_Strings
{
    meta:
        author = "HoneyPot-MCP"
        description = "Text that names several credential stores (shadow file, SSH keys, cloud and container credentials, wallets), alone or with a way to send them out"
        reference = "https://attack.mitre.org/techniques/T1552/001/"
        date = "2026-10-16"
        severity = "medium"
        family = "credential-theft"

    strings:
        $p1 = "/etc/shadow"
        $p2 = ".aws/credentials"
        $p3 = ".ssh/id_rsa"
        $p4 = ".git-credentials"
        $p5 = ".docker/config.json"
        $p6 = ".kube/config"
        $p7 = "wallet.dat"
        $p8 = ".pgpass"
        $p9 = ".npmrc"
        $s1 = /\bcurl +[^\r\n]{0,80}(-d|--data|-F|-T|--upload-file)/
        $s2 = /\bnc +[^\r\n]{0,40}[0-9]{2,5}/
        $s3 = "scp "
        $s4 = "base64"

    condition:
        filesize < 1MB and (3 of ($p*) or (2 of ($p*) and any of ($s*)))
}

rule Shell_Exec_Capability_Probe
{
    meta:
        author = "HoneyPot-MCP"
        description = "A tiny script that writes a one-line file, makes it executable, runs it and deletes it, with no download and no network use: a check that the shell can execute files, not malware"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
        date = "2026-10-16"
        severity = "info"
        family = "capability-probe"

    strings:
        $write = /\b(echo|printf|cat)\b/
        $chmod = /chmod +(\+x|[0-7]?[0-7][0-7][0-7]|a\+x|u\+x)/
        $run = /(\.\/[A-Za-z0-9._-]{1,40}|\bsh +[A-Za-z0-9._\/-]{1,60}|\/tmp\/[A-Za-z0-9._-]{1,40} *($|;|&|\r|\n))/
        $rm = /\brm +/
        $net1 = "wget"
        $net2 = "curl"
        $net3 = "tftp"
        $net4 = "ftpget"
        $net5 = "http"
        $net6 = /\bnc /
        $net7 = "/dev/tcp"
        $net8 = "base64"

    condition:
        uint32(0) != 0x464c457f and filesize < 1KB and
        $write and $chmod and $run and $rm and not any of ($net*)
}
