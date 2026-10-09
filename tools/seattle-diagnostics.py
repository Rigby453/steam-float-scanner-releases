"""Fixed read-only Seattle diagnostic. No arbitrary commands or remote paths."""
import base64
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import tempfile

HOST = '66.55.78.51'
KNOWN_HOST = '66.55.78.51 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH+Lb9WiprmxxnSlIAWML4ssXSAqepKuyGd6dJTD1D1j\n'
EXPECTED_FINGERPRINT = 'SHA256:SMiwmr6wDqJPie5j7HFLDk9XXaZ2ifTm7KZFN+NGk/A'
SAFE_CODES = (
    'PURCHASE_CONTRACT_MODULE_CHANGED', 'PURCHASE_CONTRACT_PARSE_FAILED',
    'PURCHASE_CONTRACT_UNAVAILABLE', 'PURCHASE_GATE_REQUIRED',
    'AUTO_BUY_NOT_READY', 'AUTO_BUY_ARM_REQUIRED', 'AUTO_BUY_PREFLIGHT_STALE',
    'ACCOUNT_NOT_READY', 'SESSION_EXPIRED', 'BUY_LANE_NOT_READY',
    'STEAM_CONFIRM_REQUIRED', 'PURCHASE_NOT_ALLOWED',
    'STORAGE_FAILURE', 'SCANNER_START_FAILED', 'LISTING_GONE',
    'PRICE_CHANGED', 'AMBIGUOUS', 'NEEDS_CONFIRMATION',
)
REMOTE_SCRIPT = r'''
$ErrorActionPreference='Stop'
if ($env:COMPUTERNAME -ine 'SFSPR') { throw 'HOST_IDENTITY_MISMATCH' }
$taskWho=[Security.Principal.WindowsIdentity]::GetCurrent().Name
if ($taskWho -ine 'SFSPR\Administrator') { throw 'ACCOUNT_IDENTITY_MISMATCH' }
$taskExe='C:\Users\Administrator\AppData\Local\Programs\Steam Float Scanner\Steam Float Scanner.exe'
$taskLog='C:\Users\Administrator\AppData\Roaming\@sfs\desktop\logs\steam-float-scanner.current.jsonl'
$taskVersion=$null
if(Test-Path -LiteralPath $taskExe){$taskVersion=(Get-Item -LiteralPath $taskExe).VersionInfo.ProductVersion}
$taskProcesses=@(Get-Process -Name 'Steam Float Scanner' -ErrorAction SilentlyContinue)
$taskCodes=__SAFE_CODES__
$taskCounts=[ordered]@{}
foreach($taskCode in $taskCodes){$taskCounts[$taskCode]=0}
$taskLines=@()
$taskLogModified=$null
if(Test-Path -LiteralPath $taskLog){
  $taskLogModified=(Get-Item -LiteralPath $taskLog).LastWriteTimeUtc.ToString('o')
  $taskStream=[IO.FileStream]::new($taskLog,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
  try{
    $taskOffset=[Math]::Max(0,$taskStream.Length-262144)
    $null=$taskStream.Seek($taskOffset,[IO.SeekOrigin]::Begin)
    $taskBuffer=New-Object byte[] 262144
    $taskRead=$taskStream.Read($taskBuffer,0,$taskBuffer.Length)
    $taskText=[Text.Encoding]::UTF8.GetString($taskBuffer,0,$taskRead)
    $taskSplit=@($taskText -split '\r?\n')
    if($taskOffset -gt 0 -and $taskSplit.Count -gt 1){$taskSplit=@($taskSplit|Select-Object -Skip 1)}
    $taskLines=@($taskSplit|Select-Object -Last 500)
  }finally{$taskStream.Dispose()}
}
$taskValidLines=0
foreach($taskLine in $taskLines){
  if($taskLine.Length -gt 1048576){continue}
  try{$null=ConvertFrom-Json -InputObject $taskLine -ErrorAction Stop;$taskValidLines++}catch{continue}
  foreach($taskCode in $taskCodes){
    if($taskLine -match ('(?<![A-Z0-9_])'+[regex]::Escape($taskCode)+'(?![A-Z0-9_])')){$taskCounts[$taskCode]++}
  }
}
[ordered]@{
  capturedUtc=[DateTime]::UtcNow.ToString('o');computer='SFSPR';account='Administrator';
  installedVersion=$taskVersion;scannerProcessCount=$taskProcesses.Count;
  logExists=(Test-Path -LiteralPath $taskLog);logModifiedUtc=$taskLogModified;
  tailLines=$taskLines.Count;validJsonLines=$taskValidLines;observedCodeCounts=$taskCounts;
  scope='read-only identity, installed file version, process count and at most 500 lines from last 256KiB; code mentions are not a current purchase readiness check'
}|ConvertTo-Json -Depth 4 -Compress
'''.replace('__SAFE_CODES__', '@(' + ','.join("'" + code + "'" for code in SAFE_CODES) + ')')


def sanitize(value):
    """Never relay remote free text, extra fields, exception messages, or raw logs."""
    if not isinstance(value, dict) or value.get('computer') != 'SFSPR' or value.get('account') != 'Administrator':
        raise ValueError('HOST_IDENTITY_MISMATCH')
    import re
    version = value.get('installedVersion')
    if version is not None and (not isinstance(version, str) or not re.fullmatch(r'\d+\.\d+\.\d+(?:[.\-+][0-9A-Za-z.-]+)?', version)):
        raise ValueError('INVALID_VERSION_RESPONSE')
    def timestamp(key):
        text = value.get(key)
        if text is None:
            return None
        if not isinstance(text, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z', text):
            raise ValueError('INVALID_TIME_RESPONSE')
        return text
    def bounded_int(key, maximum):
        result = value.get(key)
        if type(result) is not int or not 0 <= result <= maximum:
            raise ValueError('INVALID_COUNT_RESPONSE')
        return result
    codes = value.get('observedCodeCounts')
    if not isinstance(codes, dict):
        raise ValueError('INVALID_CODE_RESPONSE')
    selected = {}
    for code in SAFE_CODES:
        count = codes.get(code, 0)
        if type(count) is not int or not 0 <= count <= 500:
            raise ValueError('INVALID_CODE_COUNT')
        if count:
            selected[code] = count
    if type(value.get('logExists')) is not bool:
        raise ValueError('INVALID_LOG_RESPONSE')
    return {
        'capturedUtc': timestamp('capturedUtc'), 'computer': 'SFSPR', 'account': 'Administrator',
        'installedVersion': version, 'scannerProcessCount': bounded_int('scannerProcessCount', 1000),
        'logExists': value['logExists'], 'logModifiedUtc': timestamp('logModifiedUtc'),
        'tailLines': bounded_int('tailLines', 500), 'validJsonLines': bounded_int('validJsonLines', 500),
        'observedCodeCounts': selected,
        'scope': 'Read-only identity/version/process count and at most 500 lines from last 256KiB; code mentions do not prove current AUTO_BUY readiness.',
    }


def ssh_arguments(key, pin, windows=False):
    return [
        'ssh.exe' if windows else 'ssh', '-F', 'NUL' if windows else '/dev/null', '-T', '-i', str(key),
        '-o', f'UserKnownHostsFile={pin}', '-o', 'GlobalKnownHostsFile=NUL' if windows else 'GlobalKnownHostsFile=/dev/null',
        '-o', 'StrictHostKeyChecking=yes', '-o', 'HostKeyAlgorithms=ssh-ed25519',
        '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'PasswordAuthentication=no',
        '-o', 'KbdInteractiveAuthentication=no', '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes',
        '-o', 'ConnectTimeout=8', '-o', 'ConnectionAttempts=1',
        '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2',
        'Administrator@' + HOST, 'powershell.exe', '-NoProfile', '-NonInteractive',
        '-EncodedCommand', base64.b64encode(REMOTE_SCRIPT.encode('utf-16-le')).decode('ascii'),
    ]


def main():
    if (os.environ.get('GITHUB_REPOSITORY') != 'Rigby453/steam-float-scanner-releases'
            or os.environ.get('GITHUB_REF') != 'refs/heads/main'
            or os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'
            or os.environ.get('GITHUB_WORKFLOW_REF') != 'Rigby453/steam-float-scanner-releases/.github/workflows/seattle-diagnostics.yml@refs/heads/main'):
        raise ValueError('UNTRUSTED_WORKFLOW_CONTEXT')
    key_text = os.environ.pop('SFS_SEATTLE_SSH_PRIVATE_KEY', '')
    if not key_text.startswith('-----BEGIN OPENSSH PRIVATE KEY-----') or len(key_text) > 16384:
        raise ValueError('KEY_NOT_PROVISIONED')
    # No value-bearing env is passed to curl, ssh-keygen or ssh.
    child_env = os.environ.copy()
    ip = subprocess.run(['curl', '-4', '--fail', '--silent', '--max-time', '8', 'https://checkip.amazonaws.com'],
                        capture_output=True, text=True, timeout=10, env=child_env)
    if ip.returncode:
        raise ValueError('CURRENT_IP_CHECK_FAILED')
    public_ip = str(ipaddress.IPv4Address(ip.stdout.strip()))
    with tempfile.TemporaryDirectory(prefix='sfs-seattle-diagnostic-') as directory:
        key = Path(directory) / 'identity'
        fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as handle:
            handle.write(key_text.replace('\r\n', '\n').rstrip() + '\n')
        del key_text
        pin = Path(directory) / 'known_hosts'
        pin.write_text(KNOWN_HOST, encoding='ascii')
        proof = subprocess.run(['ssh-keygen', '-lf', str(pin), '-E', 'sha256'], capture_output=True,
                               text=True, timeout=5, env=child_env)
        if proof.returncode or EXPECTED_FINGERPRINT not in proof.stdout.split():
            raise ValueError('HOST_PIN_MISMATCH')
        result = subprocess.run(ssh_arguments(key, pin), capture_output=True, text=True,
                                timeout=25, env=child_env)
        if result.returncode:
            raise ValueError('SSH_DIAGNOSTIC_FAILED')
        if len(result.stdout) > 16384:
            raise ValueError('DIAGNOSTIC_RESPONSE_TOO_LARGE')
        safe = sanitize(json.loads(result.stdout.lstrip('\ufeff')))
        safe['runnerHttpsExternalIPv4'] = public_ip
        print(json.dumps(safe, ensure_ascii=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except subprocess.TimeoutExpired:
        print('DIAGNOSTIC_TIMEOUT_UNKNOWN')
        raise SystemExit(1)
    except Exception as error:
        import re
        text = str(error)
        print(text if re.fullmatch(r'[A-Z][A-Z0-9_]{1,80}', text) else 'DIAGNOSTIC_FAILED')
        raise SystemExit(1)
