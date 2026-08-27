// YARA rules de base pour sentimail file-sandbox.
// Couvre des patterns classiques. À étendre.

rule SENTIMAIL_PE_EXECUTABLE
{
    meta:
        description = "Windows PE executable header"
        severity = "high"
    condition:
        uint16(0) == 0x5A4D
}

rule SENTIMAIL_ELF_EXECUTABLE
{
    meta:
        description = "Linux ELF executable header"
        severity = "high"
    condition:
        uint32(0) == 0x464C457F
}

rule SENTIMAIL_VBA_AUTOEXEC
{
    meta:
        description = "VBA macro auto-exec keywords"
        severity = "critical"
    strings:
        $auto1 = "AutoOpen" nocase
        $auto2 = "Auto_Open" nocase
        $auto3 = "Document_Open" nocase
        $auto4 = "Workbook_Open" nocase
        $shell = "Shell" nocase
        $exec = "WScript.Shell" nocase
        $env = "Environ" nocase
    condition:
        any of ($auto*) and (any of ($shell, $exec, $env))
}

rule SENTIMAIL_POWERSHELL_DOWNLOAD
{
    meta:
        description = "PowerShell download cradle"
        severity = "critical"
    strings:
        $a = "DownloadString" nocase
        $b = "IEX" nocase
        $c = "Invoke-Expression" nocase
        $d = "WebClient" nocase
    condition:
        2 of them
}

rule SENTIMAIL_BASE64_PAYLOAD
{
    meta:
        description = "Long suspicious base64 blob (>1KB)"
        severity = "medium"
    strings:
        $b64 = /[A-Za-z0-9+\/]{1024,}={0,2}/
    condition:
        $b64
}

rule SENTIMAIL_LNK_FILE
{
    meta:
        description = "Windows LNK shortcut"
        severity = "high"
    condition:
        uint32(0) == 0x0000004C and uint16(4) == 0x0001
}
