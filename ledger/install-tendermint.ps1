$ErrorActionPreference = 'Stop'
# Pin the release and its SHA256 from the official v0.34.24 release manifest.
$toolDirectory = Join-Path $PSScriptRoot '../data/tooling'
New-Item -ItemType Directory -Force $toolDirectory | Out-Null
$archive = Join-Path $toolDirectory 'tendermint.tar.gz'
Invoke-WebRequest 'https://github.com/tendermint/tendermint/releases/download/v0.34.24/tendermint_0.34.24_windows_amd64.tar.gz' -OutFile $archive
$expected = '7fd9161c6f75daddd97b07aca17a0ae357291e74027f0fb710f7948f22c322f6'
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant() -ne $expected) {
    throw 'Tendermint archive checksum mismatch'
}
tar -xf $archive -C $toolDirectory
if ($LASTEXITCODE -ne 0) { throw 'Extraction failed' }
& (Join-Path $toolDirectory 'tendermint.exe') version
if ($LASTEXITCODE -ne 0) { throw 'Tendermint executable failed' }
