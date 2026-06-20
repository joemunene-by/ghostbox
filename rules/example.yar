/*
 * Example YARA rules for ghostbox.
 *
 * These are illustrative, low-confidence heuristics for demonstration only.
 * Replace them with your own curated rule set for real triage. ghostbox loads
 * every .yar / .yara file under the directory passed to --yara-dir.
 */

rule Suspicious_PowerShell_EncodedCommand
{
    meta:
        description = "PowerShell invoked with an encoded command argument"
        author = "joemunene-by"
        severity = "medium"
    strings:
        $a = "powershell" nocase
        $b = "-enc" nocase
        $c = "-EncodedCommand" nocase
    condition:
        $a and ($b or $c)
}

rule Ransomware_Note_Indicator
{
    meta:
        description = "Common ransom-note phrasing"
        author = "joemunene-by"
        severity = "high"
    strings:
        $a = "your files have been encrypted" nocase
        $b = "to decrypt" nocase
        $c = "bitcoin" nocase
    condition:
        any of them
}

rule Persistence_Run_Key
{
    meta:
        description = "Reference to a Windows Run autostart registry key"
        author = "joemunene-by"
        severity = "medium"
    strings:
        $a = "CurrentVersion\\Run" nocase
    condition:
        $a
}
