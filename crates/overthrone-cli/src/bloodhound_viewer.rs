#[allow(dead_code)]
fn relationship_name(raw: &str) -> String {
    let cleaned = raw
        .trim()
        .trim_start_matches("Custom(")
        .trim_end_matches(')')
        .replace([' ', '-', '_'], "");

    match cleaned.to_ascii_lowercase().as_str() {
        "memberof" => "MemberOf",
        "adminto" | "localadmins" => "AdminTo",
        "hassession" | "sessions" => "HasSession",
        "canrdp" | "rdpusers" | "remotedesktopusers" => "CanRDP",
        "canpsremote" | "psremoteusers" => "CanPSRemote",
        "executedcom" | "dcomusers" => "ExecuteDCOM",
        "sqladmin" | "sqladminusers" => "SQLAdmin",
        "genericall" => "GenericAll",
        "genericwrite" => "GenericWrite",
        "writeowner" => "WriteOwner",
        "writedacl" => "WriteDacl",
        "forcechangepassword" => "ForceChangePassword",
        "addmembers" => "AddMembers",
        "addself" => "AddSelf",
        "readlapspassword" => "ReadLapsPassword",
        "readgmsapassword" => "ReadGmsaPassword",
        "allowedtodelegate" => "AllowedToDelegate",
        "allowedtoact" => "AllowedToAct",
        "hassidhistory" => "HasSidHistory",
        "dcsync" => "DcSync",
        "getchanges" => "GetChanges",
        "getchangesall" => "GetChangesAll",
        "trustedby" | "trusts" => "TrustedBy",
        "hasspn" | "spntargets" => "HasSpn",
        "dontreqpreauth" => "DontReqPreauth",
        "gpolink" | "links" | "gpochanges" => "GpoLink",
        "contains" | "childobjects" => "Contains",
        "owns" => "Owns",
        // ── Attribute-level WriteProperty edges ─────────────────────────────────
        "writespn" => "WriteSPN",
        "writeallowedtodelegateto" => "WriteAllowedToDelegateTo",
        "addallowedtoact" => "AddAllowedToAct",
        "writeaccountrestrictions" => "WriteAccountRestrictions",
        "writelogonscript" => "WriteLogonScript",
        "writeprofilepath" => "WriteProfilePath",
        "writescriptpath" => "WriteScriptPath",
        "writednshostname" => "WriteDnsHostName",
        "writeserviceprincipalname" => "WriteServicePrincipalName",
        "writekeycredentiallink" => "WriteKeyCredentialLink",
        "writemsdskeycredentiallink" => "WriteMsDsKeyCredentialLink",
        "addkeycredentiallink" => "AddKeyCredentialLink",
        "writeproperty" => "WriteProperty",
        "" => "Relationship",
        _ => &cleaned,
    }
    .to_string()
}

/// Load and display BloodHound-compatible graph data from source files.
///
/// This is a placeholder viewer that loads graph JSON files and prints
/// summary statistics. A full TUI viewer is available via the `tui` module.
pub fn run(sources: &[String]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use overthrone_core::graph::AttackGraph;

    let mut merged_graph: Option<AttackGraph> = None;
    let mut total_files = 0;

    for source in sources {
        let path_obj = std::path::Path::new(source);
        if path_obj.is_dir() {
            // Load all JSON files from directory
            let json_files: Vec<_> = std::fs::read_dir(path_obj)?
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.path())
                .filter(|p| p.extension().map(|ext| ext == "json").unwrap_or(false))
                .collect();

            if json_files.is_empty() {
                eprintln!("  ⚠ No JSON files found in directory: {}", source);
                continue;
            }

            println!("Loading {} JSON file(s) from directory: {}", json_files.len(), source);

            for file_path in json_files {
                let file_str = file_path.to_string_lossy();
                println!("  Loading: {}", file_str);
                let graph = AttackGraph::from_json_path(&file_str)
                    .map_err(|e| format!("Failed to load {}: {}", file_str, e))?;
                total_files += 1;

                match merged_graph {
                    None => merged_graph = Some(graph),
                    Some(ref mut base) => base.merge(graph)
                        .map_err(|e| format!("Failed to merge graph from {}: {}", file_str, e))?,
                }
            }
        } else {
            // Load single file
            println!("Loading graph from: {}", source);
            let graph = AttackGraph::from_json_path(source)
                .map_err(|e| format!("Failed to load {}: {}", source, e))?;
            total_files += 1;

            match merged_graph {
                None => merged_graph = Some(graph),
                Some(ref mut base) => base.merge(graph)
                    .map_err(|e| format!("Failed to merge graph from {}: {}", source, e))?,
            }
        }
    }

    if let Some(graph) = merged_graph {
        let stats = graph.stats();
        println!();
        println!("=== Combined Graph Statistics ===");
        println!(
            "  Nodes: {} (Users: {}, Computers: {}, Groups: {}, Domains: {})",
            stats.total_nodes, stats.users, stats.computers, stats.groups, stats.domains
        );
        println!("  Edges: {}", stats.total_edges);
        println!("  Files loaded: {}", total_files);
        println!();
        println!("  Edge Distribution:");
        let mut edge_counts: Vec<_> = stats.edge_type_counts.iter().collect();
        edge_counts.sort_by(|a, b| b.1.cmp(a.1));
        for (edge_type, count) in edge_counts.iter().take(15) {
            println!("    {}: {}", edge_type, count);
        }

        let hvt = graph.high_value_targets(5);
        if !hvt.is_empty() {
            println!();
            println!("  High-Value Targets:");
            for (name, node_type, degree) in &hvt {
                println!("    {} ({:?}) - degree {}", name, node_type, degree);
            }
        }
    } else {
        return Err("No valid graph data found in any source".into());
    }

    Ok(())
}
