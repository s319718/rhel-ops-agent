$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$target = Join-Path $projectRoot ".env.windows"
$key = $env:GLM_API_KEY
if ([string]::IsNullOrWhiteSpace($key)) {
    $key = $env:ZHIPU_API_KEY
}

if ([string]::IsNullOrWhiteSpace($key)) {
    $secure = Read-Host "Enter Zhipu GLM API Key (input is hidden)" -AsSecureString
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
    "RHEL_OPS_LLM_MODE=llm_first",
    "RHEL_OPS_LLM_PROVIDER=openai-compatible",
    "RHEL_OPS_LLM_BASE_URL=https://open.bigmodel.cn/api/paas/v4",
    "RHEL_OPS_LLM_MODEL=glm-4-plus",
    "RHEL_OPS_LLM_API_KEY=$key",
    "RHEL_OPS_LLM_TIMEOUT=40",
    "RHEL_OPS_LLM_CONFIDENCE=0.55",
    "RHEL_OPS_LLM_STRUCTURED_OUTPUT=0"
) -join [Environment]::NewLine

[IO.File]::WriteAllText(
    $target,
    $content + [Environment]::NewLine,
    (New-Object Text.UTF8Encoding($false))
)

$key = $null
$secure = $null

Write-Host ""
Write-Host "GLM API configuration written to $target"
Write-Host "Model: glm-4-plus (base: https://open.bigmodel.cn/api/paas/v4)"
Write-Host "Linux commands remain simulated in the Windows demo."
Write-Host "Double-click start-windows.bat to test."
