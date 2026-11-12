# HotPot one-line install for Windows (PowerShell):
#   irm https://raw.githubusercontent.com/kvviingu/HotPot/main/get.ps1 | iex
# Downloads the latest release into .\hotpot (or $env:HOTPOT_DIR) and starts the setup questions.
# Nothing is installed system-wide; delete the folder to remove it.
$ErrorActionPreference = "Stop"
$repo = "kvviingu/HotPot"
$dir = if ($env:HOTPOT_DIR) { $env:HOTPOT_DIR } else { "hotpot" }

$py = $null
foreach ($c in @(@("py", "-3"), @("python"))) {
    if (Get-Command $c[0] -ErrorAction SilentlyContinue) {
        $args_ = @($c | Select-Object -Skip 1) + @("-c", "import sys; sys.exit(sys.version_info < (3, 10))")
        & $c[0] @args_ 2>$null
        if ($LASTEXITCODE -eq 0) { $py = $c; break }
    }
}
if (-not $py) { Write-Host "HotPot needs Python 3.10 or newer (python.org or the Microsoft Store). Install it, then run this again."; return }
if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) { Write-Host "HotPot needs the OpenSSH client: Settings > System > Optional features > OpenSSH Client."; return }
if (Test-Path $dir) { Write-Host "$dir already exists. To update it: cd $dir; .\hotpot update"; return }

Write-Host "Looking up the latest HotPot release..."
$rel = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest" -Headers @{ "User-Agent" = "hotpot-get" }
$zip = Join-Path $env:TEMP ("hotpot-" + [guid]::NewGuid() + ".zip")
$tmp = Join-Path $env:TEMP ("hotpot-" + [guid]::NewGuid())
try {
    Invoke-WebRequest $rel.zipball_url -OutFile $zip -UseBasicParsing -Headers @{ "User-Agent" = "hotpot-get" }
    Expand-Archive $zip $tmp
    Move-Item (Get-ChildItem $tmp | Select-Object -First 1).FullName $dir
} finally {
    Remove-Item $zip, $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host "HotPot $($rel.tag_name) is in $((Resolve-Path $dir).Path). Starting the setup."
Set-Location $dir
& .\hotpot.cmd setup
