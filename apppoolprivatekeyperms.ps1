Clear-Host
$title = $host.ui.RawUI.WindowTitle; # save original title
$host.ui.RawUI.WindowTitle = "Application Pool private key permissions"
Write-Host #newline
Write-Host This script allows you to give any Application Pool read permissions on a private key.
Write-Host Cancel at any time by pressing Ctrl+C.
Write-Host #newline

# make sure stuff crashes on error and doesn't ruin permissions!
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSDefaultParameterValues['*:ErrorAction']='Stop'
function ThrowOnNativeFailure {
    if (-not $?)
    {
        $host.ui.RawUI.WindowTitle = $title # restore original title
        throw 'Native Failure'
    }
}

Import-Module WebAdministration

$pools = Get-ChildItem -Path 'IIS:\AppPools'

for ($i=0; $i -lt $pools.Count; $i++) {
    Write-Host [$i] $pools[$i].name -ForegroundColor Yellow
}

Write-Host #newline
$pickedPool = Read-Host "Pick an Application Pool [0-$($pools.Count - 1)]"

if (-Not ($pickedPool -In 0..$($pools.Count - 1))) {
    $host.ui.RawUI.WindowTitle = $title # restore original title
    throw "$pickedPool is not a valid Application Pool"
}

$selectedPool = $pools[$pickedPool]
Write-Host #newline

Write-Host "You selected " -NoNewline
Write-Host $selectedPool.name -ForegroundColor Yellow
Write-Host #newline

$appPoolSid = $selectedPool.applicationPoolSid
$appPoolSecIdentifier = New-Object System.Security.Principal.SecurityIdentifier $appPoolSid
$appPoolNTAccount = $appPoolSecIdentifier.Translate([System.Security.Principal.NTAccount])

$certs = Get-ChildItem -Path 'Cert:\LocalMachine\my'

for ($i=0; $i -lt $certs.Count; $i++) {
    Write-Host [$i] $certs[$i].Thumbprint $certs[$i].FriendlyName "($($certs[$i].DnsNameList[0]))" -ForegroundColor Yellow
}

Write-Host #newline
$pickedCert = Read-Host "Pick a certificate [0-$($certs.Count - 1)]"

if (-Not ($pickedCert -In 0..$($certs.Count - 1))) {
    $host.ui.RawUI.WindowTitle = $title # restore original title
    throw "$pickedCert is not a valid Certificate"
}

$selectedCert = $certs[$pickedCert]

Write-Host #newline

Write-Host "You selected " -NoNewline
Write-Host $selectedCert.Thumbprint $selectedCert.FriendlyName "($($selectedCert.DnsNameList[0]))" -ForegroundColor Yellow
Write-Host "This certificate is valid until " -NoNewline
Write-Host $(Get-Date ($selectedCert.NotAfter) -Format f) -ForegroundColor Yellow


# try to get UniqueKeyContainerName (CAPI1)
$pk = $selectedCert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
if(([string]::IsNullOrEmpty($pk))) {
     # try to get UniqueName (CNG)
    $pk = ([System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($selectedCert)).key.UniqueName
}

# check if getting key name was successful
if(([string]::IsNullOrEmpty($pk))) {
    throw "No private key for $($selectedCert.Thumbprint) or not enough permissions."
}

# check if CAPI1 private key exists
$keytype = ""
$keyexists = Test-Path ("$($env:ProgramData)\Microsoft\Crypto\RSA\MachineKeys\" + $pk)
if($keyexists -ne $true) {
    # check if CNG private key exists
    $keyexists = Test-Path ("$($env:ProgramData)\Microsoft\Crypto\Keys\" + $pk)
    if($keyexists -ne $true) {
        throw "File not found or not enough permissions to get the private key for $($selectedCert.Thumbprint)"
    }else{
        # set CNG keypath
        Write-Host "CNG private key found for " -NoNewline
        Write-Host $($selectedCert.Thumbprint) -ForegroundColor Yellow
        $keytype = "CNG"
        $keypath = ("$($env:ProgramData)\Microsoft\Crypto\Keys\" + $pk)
    }
}else{
    # set CAPI1 keypath
    Write-Host "CAPI1 private key found for " -NoNewline
    Write-Host $($selectedCert.Thumbprint) -ForegroundColor Yellow
    $keytype = "CAPI1"
    $keypath = ("$($env:ProgramData)\Microsoft\Crypto\RSA\MachineKeys\" + $pk)
}

Write-Host #newline

$Acl = Get-Acl $keypath # get current ACL
$Ar = New-Object System.Security.AccessControl.FileSystemAccessRule($appPoolNTAccount, "Read", "Allow")
$Acl.SetAccessRule($Ar)

Write-Host "Are you sure you want to give the Application Pool " -NoNewline
Write-Host $selectedPool.name -ForegroundColor Yellow -NoNewline
Write-Host " permissions on the private key of certificate " -NoNewline
Write-Host $selectedCert.Thumbprint $selectedCert.FriendlyName "($($selectedCert.DnsNameList[0]))" -ForegroundColor Yellow -NoNewline

$confirmation = Read-Host " [y/n]?"
if ($confirmation -eq 'y') {
    Set-Acl $keypath $Acl # set new ACL
}

Write-Host #newline
Write-Host "Permissions set! New permissions on this file:"
Write-Output $Acl.Access | Format-Table -Property IdentityReference, FileSystemRights

$host.ui.RawUI.WindowTitle = $title # restore original title
