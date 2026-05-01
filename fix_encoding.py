#!/usr/bin/env python3
"""Clean up excessively long section dividers in mod.rs."""

filepath = r"c:\Users\ACER\Documents\VSCFiles1\Overthrone\crates\overthrone-core\src\graph\mod.rs"

with open(filepath, 'r', encoding='utf-8') as f:
    lines = f.readlines()

fixed_lines = []
for line in lines:
    stripped = line.rstrip('\r\n')
    # Fix lines that are just "// " followed by many '=' or '-' chars
    if stripped.startswith('// ') and len(stripped) > 80:
        content_after_prefix = stripped[3:]
        if all(c == '=' for c in content_after_prefix):
            fixed_lines.append('// ' + '=' * 60 + '\n')
            continue
        if all(c == '-' for c in content_after_prefix):
            fixed_lines.append('// ' + '-' * 60 + '\n')
            continue
    
    # Fix inline section comments with long dashes
    # Pattern: "// -- Title --" followed by many dashes
    if stripped.startswith('    // --') and len(stripped) > 80:
        # Extract the title part
        import re
        m = re.match(r'^(\s*)// (-+) (.+?) (-+)$', stripped)
        if m:
            indent = m.group(1)
            title = m.group(3)
            fixed_lines.append(f'{indent}// -- {title} --\n')
            continue
    
    fixed_lines.append(line)

with open(filepath, 'w', encoding='utf-8') as f:
    f.writelines(fixed_lines)

print(f"Fixed {len(lines)} lines -> {len(fixed_lines)} lines")
