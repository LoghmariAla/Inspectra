rule RansomwareIndicators
{
    meta:
        description = "Detect files related to ransomware activity"
        author = "Loghmari Ala"
        date = "2024-12-15"

    strings:
        $encrypted_ext1 = ".locked" ascii
        $encrypted_ext2 = ".crypt" ascii
        $ransom_note = "Your files have been encrypted" ascii
        $btc_wallet = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ // Bitcoin wallet regex

    condition:
        any of ($encrypted_ext*) or $ransom_note or $btc_wallet
}


rule MaliciousScript
{
    meta:
        description = "Detects malicious patterns in script files"
        author = "Loghmari Ala"
        date = "2024-12-15"

    strings:
        $powershell_obf = "Powershell -EncodedCommand" ascii
        $eval = "eval(" ascii
        $exec = "exec(" ascii

    condition:
        uint16(0) == 0x2321 or any of ($*)
}

rule MaliciousPDF
{
    meta:
        description = "Detects suspicious PDFs with embedded JavaScript"
        author = "Loghmari Ala"
        date = "2024-12-15"

    strings:
        $js = "/JavaScript" ascii
        $launch = "/Launch" ascii
        $action = "/OpenAction" ascii

    condition:
        uint16(0) == 0x2550 and any of ($*)
}

rule MalwareInDocuments
{
    meta:
        description = "Detects malicious scripts embedded in document files"
        author = "Loghmari Ala"
        date = "2024-12-15"

    strings:
        $macro1 = "AutoOpen" ascii
        $macro2 = "Document_Open" ascii
        $macro3 = "WScript.Shell" ascii
        $suspicious_url = "http://" ascii

    condition:
        any of ($macro*) or $suspicious_url
}

rule HiddenPayload
{
    meta:
        description = "Detect files with embedded or hidden payloads"
        author = "Loghmari Ala"
        date = "2024-12-15"

    strings:
        $powershell = "powershell.exe" ascii
        $cmd_exec = "cmd.exe" ascii
        $shell_exec = "ShellExecute" ascii
        $url_call = "http://" ascii

    condition:
        any of them
}

rule SuspiciousImports
{
    meta:
        description = "Detect executables importing suspicious functions"
        author = "Loghmari Ala"
        date = "2024-12-15"

    strings:
        $func1 = "VirtualAlloc" ascii
        $func2 = "LoadLibrary" ascii
        $func3 = "GetProcAddress" ascii
        $func4 = "WinExec" ascii

    condition:
        uint16(0) == 0x5A4D and any of them // PE file
}
