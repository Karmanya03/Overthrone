# Add doc comments to undocumented public items in Rust source files.
# This script understands Rust structure at the line level.
param(
    [Parameter(Mandatory=$true)]
    [string]$CratePath,
    [switch]$DryRun
)

$script:braceDepth = 0
$script:inImpl = $false
$script:inTestMod = $false
$script:inFnBody = $false
$script:lastNonBlankLine = ""

function Get-Desc($name, $kind) {
    $words = $name -replace '_', ' ' -replace '([a-z])([A-Z])', '$1 $2' -replace '([A-Z])([A-Z][a-z])', '$1 $2'
    $lc = "$words"  # don't lower-case to preserve acronyms
    switch ($kind) {
        "fn" { return "$words function" }
        "struct" { return "$words struct" }
        "enum" { return "$words enum variants" }
        "trait" { return "$words trait" }
        "const" { return "$words constant" }
        "static" { return "$words static variable" }
        "type" { return "$words type alias" }
        "mod" { return "$words module" }
        "use" { return "Re-export of $name" }
        default { return "$words" }
    }
}

function Update-BraceDepth($line) {
    $trimmed = $line.Trim()
    # Track brace depth, but skip string literals and comments
    foreach ($ch in $trimmed) {
        if ($ch -eq '{') { $script:braceDepth++ }
        elseif ($ch -eq '}') {
            $script:braceDepth--
            if ($script:braceDepth -le 0 -and $script:inImpl) { $script:inImpl = $false }
            if ($script:braceDepth -le 0 -and $script:inTestMod) { $script:inTestMod = $false }
        }
    }
}

function Is-Documented($prevLines, $checkFrom) {
    for ($j = $checkFrom; $j -ge 0; $j--) {
        $p = $prevLines[$j].Trim()
        if ($p -match '^///' -or $p -match '^//!') { return $true }
        if ($p -match '^#\[') { continue }
        if ([string]::IsNullOrEmpty($p)) { continue }
        # Empty braces line like "}" or "{"
        if ($p -eq '{' -or $p -eq '}') { continue }
        break
    }
    return $false
}

function Add-DocsToFile($filePath) {
    $lines = Get-Content -LiteralPath $filePath
    $modified = $false
    $newLines = [System.Collections.Generic.List[string]]::new()
    
    # Reset per-file state
    $script:braceDepth = 0
    $script:inImpl = $false
    $script:inTestMod = $false
    $script:inFnBody = $false
    
    # Look ahead to find `#[cfg(test)] mod tests` blocks
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line.Trim() -match '#\[cfg\(test\)\]' -and $i + 1 -lt $lines.Count -and $lines[$i+1].Trim() -match '^\s*(pub\s+)?mod\s+tests') {
            $script:inTestMod = $true
        }
    }

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        $trimmed = $line.Trim()
        
        # Track cfg(test) mod tests
        if ($trimmed -match '#\[cfg\(test\)\]' -and $i + 1 -lt $lines.Count) {
            $next = $lines[$i+1].Trim()
            if ($next -match '^\s*(pub\s+)?mod\s+tests') {
                $script:inTestMod = $true
            }
        }
        
        # Detect impl blocks
        if ($trimmed -match '^impl\s') { $script:inImpl = $true }
        
        # Detect fn bodies (when we enter an fn body at depth > 0)
        if ($trimmed -match '^\s*(pub\s+)?(async\s+)?(unsafe\s+)?fn\s+\w+\s*\(') {
            # This is an fn declaration - add to newLines, then continue
            $newLines.Add($line)
            continue
        }
        
        # Skip items inside impl blocks or test modules
        if ($script:inImpl -or $script:inTestMod) {
            Update-BraceDepth $line
            $newLines.Add($line)
            # Don't modify inside impl blocks
            continue
        }
        
        # Detect pub declarations
        $pubMatch = $null
        $kind = ""
        $name = ""
        
        if ($trimmed -match '^pub\s+async\s+fn\s+(\w+)') { $kind = "fn"; $name = $matches[1] }
        elseif ($trimmed -match '^pub\s+(unsafe\s+)?fn\s+(\w+)') { $kind = "fn"; $name = $matches[2] }
        elseif ($trimmed -match '^pub\s+(unsafe\s+)?struct\s+(\w+)') { $kind = "struct"; $name = $matches[0] }
        elseif ($trimmed -match '^pub\s+(unsafe\s+)?struct\s+(\w+)') { $kind = "struct"; $name = $matches[2] }
        # ... this is getting messy, let me use a simpler approach
        elseif ($trimmed -match '^pub\s+\w+\s+(\w+)') { $kind = "item"; $name = $matches[1] }
        else { $kind = "" }
        
        # More precise matching
        $kind = ""
        $name = ""
        if ($trimmed -match '^pub\s+mod\s+(\w+)') { $kind = "mod"; $name = $matches[1] }
        elseif ($trimmed -match '^pub\s+use\s+') { $kind = "use"; $name = "(re-export)" }
        elseif ($trimmed -match '^pub\s+(async\s+)?fn\s+(\w+)') { $kind = "fn"; $name = $matches[2] }
        elseif ($trimmed -match '^pub\s+(unsafe\s+)?struct\s+(\w+)') { $kind = "struct"; $name = $matches[2] }
        elseif ($trimmed -match '^pub\s+(unsafe\s+)?enum\s+(\w+)') { $kind = "enum"; $name = $matches[2] }
        elseif ($trimmed -match '^pub\s+(unsafe\s+)?trait\s+(\w+)') { $kind = "trait"; $name = $matches[2] }
        elseif ($trimmed -match '^pub\s+type\s+(\w+)') { $kind = "type"; $name = $matches[1] }
        elseif ($trimmed -match '^pub\s+const\s+(\w+)') { $kind = "const"; $name = $matches[1] }
        elseif ($trimmed -match '^pub\s+static\s+(\w+)') { $kind = "static"; $name = $matches[1] }
        
        if ($kind -ne "" -and -not (Is-Documented $lines ($i - 1))) {
            $indent = ""
            if ($line -match '^(\s*)') { $indent = $matches[1] }
            $desc = Get-Desc $name $kind
            
            # Add blank line before if previous is not blank
            if ($newLines.Count -gt 0 -and ![string]::IsNullOrEmpty($newLines[$newLines.Count-1].Trim())) {
                $newLines.Add("")
            }
            
            $newLines.Add("$indent/// $desc")
            $modified = $true
            Write-Host "  + $kind $name at $($filePath) line $($i+1)"
        }
        
        Update-BraceDepth $line
        $newLines.Add($line)
    }
    
    if ($modified -and -not $DryRun) {
        Set-Content -LiteralPath $filePath -Value ($newLines -join "`r`n") -NoNewline
        Write-Host "  Saved: $filePath"
    }
    return $modified
}

$files = Get-ChildItem -Path $CratePath -Recurse -Filter "*.rs" | Where-Object { -not $_.FullName.Contains('\target\') }

$count = 0
foreach ($file in $files) {
    $changed = Add-DocsToFile $file.FullName
    if ($changed) { $count++ }
}

Write-Host "Modified $count files in $CratePath"
if ($DryRun) { Write-Host "DRY RUN: no changes written" }
