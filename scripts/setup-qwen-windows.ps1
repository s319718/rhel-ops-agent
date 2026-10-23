$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$target = Join-Path $projectRoot ".env.windows"
$key = $env:DASHSCOPE_API_KEY

if ([string]::IsNullOrWhiteSpace($key)) {
    $secure = Read-Host "Enter DashScope API Key (input is hidden)" -AsSecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $key = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

$key = $key.Trim()
if ([string]::IsNullOrWhiteSpace($key)) {
    throw "API key cannot be empty."
}
if ($key.IndexOf([char]13) -ge 0 -or $key.IndexOf([char]10) -ge 0) {
    throw "API key cannot contain line breaks."
}

$content = @(
    "RHEL_OPS_LLM_ENABLED=1",
    "RHEL_OPS_LLM_MODE=hybrid",
    "RHEL_OPS_LLM_PROVIDER=qwen",
    "RHEL_OPS_LLM_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1",
    "RHEL_OPS_LLM_MODEL=qwen-plus",
    "RHEL_OPS_LLM_API_KEY=$key",
    "RHEL_OPS_LLM_TIMEOUT=20",
    "RHEL_OPS_LLM_CONFIDENCE=0.55",
    "RHEL_OPS_LLM_STRUCTURED_OUTPUT=1"
) -join [Environment]::NewLine

[IO.File]::WriteAllText(
    $target,
    $content + [Environment]::NewLine,
    (New-Object Text.UTF8Encoding($false))
)

$key = $null
$secure = $null

Write-Host ""
Write-Host "Qwen API configuration written to $target"
Write-Host "Model: qwen-plus"
Write-Host "Linux commands remain simulated in the Windows demo."
Write-Host "Double-click start-windows.bat to test."
