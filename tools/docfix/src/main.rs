/// Add doc comments to undocumented public items in Rust source.
/// Uses `syn` for reliable parsing and inserts into original source text.
use std::path::Path;
use syn::{spanned::Spanned, visit::Visit, Item};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: docfix <crate-src-path> [--dry-run]");
        std::process::exit(1);
    }
    let crate_path = Path::new(&args[1]);
    let dry_run = args.get(2).map(|s| s == "--dry-run").unwrap_or(false);
    let mut total = 0u32;

    let files = collect_rs_files(crate_path);

    for path in &files {
        let content = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let syntax = match syn::parse_file(&content) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let mut collector = UndocumentedCollector::new(&content);
        collector.visit_file(&syntax);

        if collector.items.is_empty() {
            continue;
        }

        let rel = path.strip_prefix(crate_path).unwrap_or(path);
        println!("{}: {} missing docs", rel.display(), collector.items.len());

        if dry_run {
            for (line, _, _, kind, name) in &collector.items {
                println!("  L{line}: [{kind}] {name}");
            }
        } else {
            let mut lines: Vec<&str> = content.lines().collect();
            // Sort by line descending, then column descending to maintain offset
            collector.items.sort_by(|a, b| {
                b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1))
            });
            for (line, _col, byte_offset, kind, name) in &collector.items {
                let indent = calculate_indent(&content, *byte_offset);
                let doc_line = format!("{}/// {}",
                    indent,
                    doc_text(name, kind));
                lines.insert(*line - 1, &doc_line);
            }
            let new_content = lines.join("\n");
            std::fs::write(path, new_content).unwrap();
        }
        total += collector.items.len() as u32;
    }

    println!("\nTotal: {total} doc comments added (or would add)");
    if dry_run { println!("Dry-run: no files modified"); }
}

fn collect_rs_files(crate_path: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(crate_path).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() { continue; }
        let p = entry.path();
        if p.extension().map_or(true, |e| e != "rs") { continue; }
        let s = p.to_string_lossy();
        if s.contains("/target/") || s.contains("\\target\\") { continue; }
        files.push(p.to_path_buf());
    }
    files.sort();
    files
}

fn calculate_indent(source: &str, byte_offset: usize) -> String {
    // Find the beginning of the line containing byte_offset
    let line_start = source[..byte_offset].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let line = &source[line_start..];
    line.chars().take_while(|c| c.is_whitespace()).collect()
}

fn doc_text(name: &str, kind: &str) -> String {
    match kind {
        "struct" | "struct_field" => {
            let words = name.replace('_', " ");
            format!("{words}")
        }
        "enum_variant" => {
            format!("`{name}` variant")
        }
        "fn" => {
            let desc = name.replace('_', " ");
            format!("{desc}")
        }
        "const" => {
            let desc = name.replace('_', " ");
            format!("{desc} constant")
        }
        "type" => {
            format!("type alias for `{name}`")
        }
        "mod" => {
            let desc = name.replace('_', " ");
            format!("{desc} module")
        }
        "use" => {
            format!("Re-export")
        }
        "trait" => {
            format!("`{name}` trait")
        }
        "enum" => {
            let desc = name.replace('_', " ");
            format!("{desc} variants")
        }
        "static" => {
            format!("{name} static")
        }
        _ => format!("{name}"),
    }
}

fn has_doc(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| a.path().is_ident("doc"))
}

fn line_to_byte_offset(source: &str, line: usize) -> Option<usize> {
    // line is 1-indexed; find the byte offset of the start of this line
    let mut byte = 0usize;
    let mut current = 1usize;
    if current == line { return Some(0); }
    for c in source.chars() {
        if c == '\n' {
            current += 1;
            if current == line { return Some(byte + 1); }
        }
        byte += c.len_utf8();
    }
    None
}

fn byte_offset_from_line_col(source: &str, line: usize, col: usize) -> Option<usize> {
    let line_start = line_to_byte_offset(source, line)?;
    // Column is 1-indexed in syn
    let mut byte_offset = line_start;
    let mut current_col = 1usize;
    for c in source[line_start..].chars() {
        if current_col >= col {
            return Some(byte_offset);
        }
        byte_offset += c.len_utf8();
        current_col += 1;
    }
    Some(byte_offset)
}

struct UndocumentedCollector<'a> {
    source: &'a str,
    items: Vec<(usize, usize, usize, String, String)>, // (line, col, byte_offset, kind, name)
    inside_impl: bool,
    inside_test: bool,
}

impl<'a> UndocumentedCollector<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            items: Vec::new(),
            inside_impl: false,
            inside_test: false,
        }
    }

    fn add(&mut self, item: &dyn Spanned, kind: &str, name: &str) {
        let span = item.span();
        let line = span.start_line();
        let col = span.start_column();
        let byte_off = byte_offset_from_line_col(self.source, line, col).unwrap_or(0);
        self.items.push((line, col, byte_off, kind.to_string(), name.to_string()));
    }
}

impl<'a> Visit<'a> for UndocumentedCollector<'a> {
    fn visit_item(&mut self, item: &'a Item) {
        let in_test_save = self.inside_test;

        match item {
            Item::Mod(m) if m.ident == "tests" => {
                self.inside_test = true;
            }
            Item::Impl(_) => {
                self.inside_impl = true;
            }
            _ => {}
        }

        if !self.inside_test {
            match item {
                Item::Fn(f) => {
                    if matches!(f.vis, syn::Visibility::Public(_)) && !has_doc(&f.attrs) {
                        self.add(f, "fn", &f.sig.ident.to_string());
                    }
                }
                Item::Struct(s) => {
                    if matches!(s.vis, syn::Visibility::Public(_)) {
                        if !has_doc(&s.attrs) {
                            self.add(s, "struct", &s.ident.to_string());
                        }
                        // Add struct fields
                        for field in &s.fields {
                            if !has_doc(&field.attrs) {
                                if let Some(ident) = &field.ident {
                                    self.add(field, "struct_field", &ident.to_string());
                                }
                            }
                        }
                    }
                }
                Item::Enum(en) => {
                    if matches!(en.vis, syn::Visibility::Public(_)) {
                        if !has_doc(&en.attrs) {
                            self.add(en, "enum", &en.ident.to_string());
                        }
                        for variant in &en.variants {
                            if !has_doc(&variant.attrs) {
                                self.add(variant, "enum_variant", &variant.ident.to_string());
                            }
                        }
                    }
                }
                Item::Const(c) => {
                    if matches!(c.vis, syn::Visibility::Public(_)) && !has_doc(&c.attrs) {
                        self.add(c, "const", &c.ident.to_string());
                    }
                }
                Item::Static(st) => {
                    if matches!(st.vis, syn::Visibility::Public(_)) && !has_doc(&st.attrs) {
                        self.add(st, "static", &st.ident.to_string());
                    }
                }
                Item::Type(t) => {
                    if matches!(t.vis, syn::Visibility::Public(_)) && !has_doc(&t.attrs) {
                        self.add(t, "type", &t.ident.to_string());
                    }
                }
                Item::Trait(t) => {
                    if matches!(t.vis, syn::Visibility::Public(_)) && !has_doc(&t.attrs) {
                        self.add(t, "trait", &t.ident.to_string());
                    }
                }
                Item::Mod(m) => {
                    if matches!(m.vis, syn::Visibility::Public(_)) && !m.attrs.iter().any(|a| {
                        a.path().is_ident("doc") || (a.path().is_ident("cfg") && a.to_token_stream().to_string().contains("test"))
                    }) && !has_doc(&m.attrs) {
                        self.add(m, "mod", &m.ident.to_string());
                    }
                }
                Item::Use(u) => {
                    if matches!(u.vis, syn::Visibility::Public(_)) && !has_doc(&u.attrs) {
                        self.add(u, "use", "re-export");
                    }
                }
                _ => {}
            }
        }

        // Don't recurse into impl blocks or nested modules that are tested
        if !self.inside_impl {
            syn::visit::visit_item(self, item);
        }

        self.inside_test = in_test_save;
    }
}

// Need this for to_token_stream
use syn::__private::ToTokens;
