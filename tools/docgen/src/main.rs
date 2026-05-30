/// Add doc comments to undocumented public items in Rust source files.
/// Works by finding items via syn and inserting lines into the raw source.
use std::path::Path;
use syn::spanned::Spanned;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: docgen <crate-src-path> [--dry-run]");
        std::process::exit(1);
    }
    let crate_path = Path::new(&args[1]);
    let dry_run = args.get(2).map(|s| s == "--dry-run").unwrap_or(false);
    let mut total = 0u32;

    let mut files: Vec<_> = walkdir::WalkDir::new(crate_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "rs"))
        .filter(|e| !e.path().to_string_lossy().contains("/target/"))
        .filter(|e| !e.path().to_string_lossy().contains("\\target\\"))
        .map(|e| e.path().to_path_buf())
        .collect();
    files.sort();

    for path in &files {
        let content = std::fs::read_to_string(path).unwrap();
        let syntax = match syn::parse_file(&content) {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Collect items that need docs
        let mut inserts: Vec<(usize, String)> = Vec::new();

        for item in &syntax.items {
            if let Some((line, doc)) = needs_doc(item, &content) {
                inserts.push((line, doc));
            }
        }

        // Sort by line descending so we insert bottom-up without offset issues
        inserts.sort_by(|a, b| b.0.cmp(&a.0));

        if !inserts.is_empty() {
            total += inserts.len() as u32;
            let rel = path.strip_prefix(crate_path).unwrap_or(path);
            println!("{}: {} missing docs", rel.display(), inserts.len());
            for (line, doc) in &inserts {
                println!("  L{}: {}", line, doc);
            }

            if !dry_run {
                let mut lines: Vec<&str> = content.lines().collect();
                for (line, doc) in &inserts {
                    // Insert the doc comment BEFORE the line (0-indexed, so line-1 is the target)
                    let indent = get_indent(lines[*line - 1]);
                    let doc_line = format!("{}{}", indent, doc);
                    lines.insert(*line - 1, &doc_line);
                }
                std::fs::write(path, lines.join("\n")).unwrap();
            }
        }
    }

    println!("\nTotal: {} doc comments added", total);
    if dry_run {
        println!("Dry-run mode: no files modified");
    }
}

fn get_indent(line: &str) -> String {
    line.chars().take_while(|c| c.is_whitespace()).collect()
}

fn needs_doc(item: &syn::Item, source: &str) -> Option<(usize, String)> {
    use syn::Item::*;

    let (attrs, name, kind) = match item {
        Fn(i) => (&i.attrs, i.sig.ident.to_string(), "function"),
        Struct(i) => (&i.attrs, i.ident.to_string(), "struct"),
        Enum(i) => (&i.attrs, i.ident.to_string(), "enum"),
        Trait(i) => (&i.attrs, i.ident.to_string(), "trait"),
        Const(i) => (&i.attrs, i.ident.to_string(), "const"),
        Static(i) => (&i.attrs, i.ident.to_string(), "static"),
        Type(i) => (&i.attrs, i.ident.to_string(), "type"),
        Mod(m) => {
            if m.ident == "tests" { return None; }
            (&m.attrs, m.ident.to_string(), "mod")
        }
        Use(u) => {
            if !matches!(u.vis, syn::Visibility::Public(_)) { return None; }
            let name = "re-export".to_string();
            (&u.attrs, name, "use")
        }
        _ => return None,
    };

    // Check visibility
    let is_pub = match item {
        Use(_) => true,
        _ => matches!(visibility(item), syn::Visibility::Public(_)),
    };
    if !is_pub {
        return None;
    }

    // Check existing doc attrs
    let has_doc = attrs.iter().any(|a| a.path().is_ident("doc"));
    if has_doc {
        return None;
    }

    let line = item.span().start_line();
    let doc = doc_comment(&name, kind);

    Some((line, doc))
}

fn visibility(item: &syn::Item) -> &syn::Visibility {
    use syn::Item::*;
    match item {
        Fn(i) => &i.vis,
        Struct(i) => &i.vis,
        Enum(i) => &i.vis,
        Trait(i) => &i.vis,
        Const(i) => &i.vis,
        Static(i) => &i.vis,
        Type(i) => &i.vis,
        Mod(i) => &i.vis,
        Use(i) => &i.vis,
        _ => unreachable!(),
    }
}

fn doc_comment(name: &str, kind: &str) -> String {
    let desc = match kind {
        "fn" => format!("`{}` — (FIXME: add description)", name),
        "struct" => format!("`{}` — (FIXME: add description)", name),
        "enum" => format!("`{}` — variant options", name),
        "trait" => format!("`{}` — trait definition", name),
        "const" => format!("`{}` — constant value", name),
        "static" => format!("`{}` — static variable", name),
        "type" => format!("`{}` — type alias", name),
        "mod" => format!("`{}` — module", name),
        "use" => format!("(Re-export)", name),
        _ => format!("`{}`", name),
    };
    format!("/// {} // FIXME: replace with meaningful doc", desc)
}
