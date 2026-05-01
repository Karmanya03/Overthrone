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

    for source in sources {
        println!("Loading graph from: {}", source);
        let graph = AttackGraph::from_json_file(source)
            .map_err(|e| format!("Failed to load {}: {}", source, e))?;

        let stats = graph.stats();
        println!(
            "  Nodes: {} (Users: {}, Computers: {}, Groups: {}, Domains: {})",
            stats.total_nodes, stats.users, stats.computers, stats.groups, stats.domains
        );
        println!("  Edges: {}", stats.total_edges);

        for (edge_type, count) in &stats.edge_type_counts {
            println!("    {}: {}", edge_type, count);
        }

        let hvt = graph.high_value_targets(5);
        if !hvt.is_empty() {
            println!("  High-Value Targets:");
            for (name, node_type, degree) in &hvt {
                println!("    {} ({:?}) - degree {}", name, node_type, degree);
            }
        }
    }
    Ok(())
}
