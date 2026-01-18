rule Suspicious_PowerShell_Indicators
{
  strings:
    $a = "IEX" nocase
    $b = "FromBase64String" nocase
    $c = "DownloadString" nocase
    $d = "Add-MpPreference" nocase
  condition:
    2 of them
}

rule Suspicious_JS_Indicators
{
  strings:
    $a = "eval(" nocase
    $b = "atob(" nocase
    $c = "XMLHttpRequest" nocase
    $d = "fetch(" nocase
  condition:
    2 of them
}