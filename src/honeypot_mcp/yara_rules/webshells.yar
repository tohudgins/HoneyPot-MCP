/*
 * PHP webshell markers and the PHPUnit eval-stdin probe web scanners send. Original
 * HoneyPot-MCP rules.
 */

rule Webshell_PHP_Eval_Decode_Exec
{
    meta:
        author = "HoneyPot-MCP"
        description = "PHP that evaluates decoded or request-supplied code: eval(base64_decode(..)), eval(gzinflate(..)), eval of php://input, or a shell function called on a request parameter"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
        date = "2026-10-16"
        severity = "high"
        family = "php-webshell"

    strings:
        $php = /<\?(php|=)/ nocase
        $eval_decode = /eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode)\s*\(/ nocase
        $eval_input = /eval\s*\([^)]{0,40}php:\/\/input/ nocase
        $call_request = /\b(system|passthru|shell_exec|exec|popen|proc_open|assert)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase

    condition:
        filesize < 2MB and $php and any of ($eval_decode, $eval_input, $call_request)
}

rule PHPUnit_Eval_Stdin_Reference
{
    meta:
        author = "HoneyPot-MCP"
        description = "Reference to PHPUnit's eval-stdin.php (the CVE-2017-9841 remote-code-execution path scanners request); in a captured file this is a scanner's target list or an exploit script"
        reference = "https://attack.mitre.org/techniques/T1190/"
        date = "2026-10-16"
        severity = "medium"
        family = "phpunit-rce"

    strings:
        $path = "eval-stdin.php"
        $vendor = "phpunit/src/Util/PHP" nocase

    condition:
        filesize < 1MB and ($path or $vendor)
}
