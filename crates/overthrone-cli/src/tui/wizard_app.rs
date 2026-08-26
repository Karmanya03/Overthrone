//! TUI Wizard App -- Interactive menu-driven AD attack wizard.
//!
//! Provides a visual interface for selecting and running Overthrone modules
//! without typing individual commands. Users navigate menus with arrow keys,
//! configure targets with input forms, and watch execution in real-time.

use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use ratatui::prelude::*;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Tabs};

// ===========================================================
// Screen / Page Definitions
// ===========================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardScreen {
    /// Main category selection menu
    MainMenu,
    /// Credential attack sub-menu
    CredentialAttacks,
    /// Ticket attack sub-menu
    TicketAttacks,
    /// Remote execution sub-menu
    ExecutionMethods,
    /// Lateral movement sub-menu
    LateralMovement,
    /// Post-exploitation sub-menu
    PostExploitation,
    /// CVE exploit sub-menu
    CVEModules,
    /// Coercion / relay sub-menu
    CoercionRelay,
    /// Enumeration sub-menu
    Enumeration,
    /// Target configuration form
    TargetConfig,
    /// Running selected modules
    Running,
    /// Results display
    #[allow(dead_code)]
    Results,
}

// ===========================================================
// Module Definitions
// ===========================================================

#[derive(Debug, Clone)]
pub struct AttackModule {
    pub name: &'static str,
    pub description: &'static str,
    pub category: ModuleCategory,
    pub selected: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleCategory {
    Credential,
    Ticket,
    Execution,
    Lateral,
    PostEx,
    Cve,
    Coercion,
    Enum,
}

impl ModuleCategory {
    pub fn label(self) -> &'static str {
        match self {
            Self::Credential => "Credential Attacks",
            Self::Ticket => "Ticket Forgery",
            Self::Execution => "Remote Execution",
            Self::Lateral => "Lateral Movement",
            Self::PostEx => "Post-Exploitation",
            Self::Cve => "CVE Exploits",
            Self::Coercion => "Coercion / Relay",
            Self::Enum => "Enumeration",
        }
    }

    pub fn color(self) -> Color {
        match self {
            Self::Credential => Color::Red,
            Self::Ticket => Color::Magenta,
            Self::Execution => Color::Blue,
            Self::Lateral => Color::Yellow,
            Self::PostEx => Color::LightRed,
            Self::Cve => Color::Cyan,
            Self::Coercion => Color::LightMagenta,
            Self::Enum => Color::Green,
        }
    }
}

/// Build the full module catalog
pub fn build_module_catalog() -> Vec<AttackModule> {
    vec![
        // Credential Attacks
        AttackModule {
            name: "Kerberoast (RC4/AES)",
            description: "Extract TGS hashes from SPN accounts",
            category: ModuleCategory::Credential,
            selected: false,
        },
        AttackModule {
            name: "AS-REP Roast",
            description: "Extract AS-REP hashes from DONT_REQ_PREAUTH accounts",
            category: ModuleCategory::Credential,
            selected: false,
        },
        AttackModule {
            name: "Password Spray",
            description: "Lockout-safe password spray against all accounts",
            category: ModuleCategory::Credential,
            selected: false,
        },
        AttackModule {
            name: "NTLMv1 Roast",
            description: "Downgrade NTLMv1 and extract crackable hashes",
            category: ModuleCategory::Credential,
            selected: false,
        },
        AttackModule {
            name: "Timeroast",
            description: "Roast machine passwords via MS-SNTP",
            category: ModuleCategory::Credential,
            selected: false,
        },
        AttackModule {
            name: "Pre-2K Spray",
            description: "Spray blank/default machine passwords",
            category: ModuleCategory::Credential,
            selected: false,
        },
        // Ticket Attacks
        AttackModule {
            name: "Golden Ticket",
            description: "Forge TGT with arbitrary SIDs",
            category: ModuleCategory::Ticket,
            selected: false,
        },
        AttackModule {
            name: "Silver Ticket",
            description: "Forge TGS for specific services",
            category: ModuleCategory::Ticket,
            selected: false,
        },
        AttackModule {
            name: "Diamond Ticket",
            description: "Modify legit TGT with DA group",
            category: ModuleCategory::Ticket,
            selected: false,
        },
        AttackModule {
            name: "Skeleton Key",
            description: "Inject skeleton key into DC LSASS",
            category: ModuleCategory::Ticket,
            selected: false,
        },
        AttackModule {
            name: "Inter-Realm TGT",
            description: "Forge cross-realm TGT for trust abuse",
            category: ModuleCategory::Ticket,
            selected: false,
        },
        // Execution
        AttackModule {
            name: "PSExec",
            description: "Remote code execution via SCM",
            category: ModuleCategory::Execution,
            selected: false,
        },
        AttackModule {
            name: "SMBExec",
            description: "Command execution via SMB pipe",
            category: ModuleCategory::Execution,
            selected: false,
        },
        AttackModule {
            name: "WMIExec",
            description: "WMI-based remote execution",
            category: ModuleCategory::Execution,
            selected: false,
        },
        AttackModule {
            name: "DCOMExec",
            description: "MMC20 DCOM execution",
            category: ModuleCategory::Execution,
            selected: false,
        },
        AttackModule {
            name: "ATExec",
            description: "Scheduled task remote execution",
            category: ModuleCategory::Execution,
            selected: false,
        },
        AttackModule {
            name: "WinRM",
            description: "PowerShell remoting execution",
            category: ModuleCategory::Execution,
            selected: false,
        },
        // Lateral Movement
        AttackModule {
            name: "Pass-the-Hash",
            description: "Authenticate with NTLM hash",
            category: ModuleCategory::Lateral,
            selected: false,
        },
        AttackModule {
            name: "Pass-the-Ticket",
            description: "Use Kerberos ticket for auth",
            category: ModuleCategory::Lateral,
            selected: false,
        },
        AttackModule {
            name: "Overpass-the-Hash",
            description: "Use NTLM hash to get Kerberos TGT",
            category: ModuleCategory::Lateral,
            selected: false,
        },
        AttackModule {
            name: "RBCD Attack",
            description: "Resource-Based Constrained Delegation",
            category: ModuleCategory::Lateral,
            selected: false,
        },
        AttackModule {
            name: "Constrained Delegation",
            description: "Abuse constrained delegation S4U",
            category: ModuleCategory::Lateral,
            selected: false,
        },
        AttackModule {
            name: "Unconstrained Delegation",
            description: "Harvest TGTs from unconstrained hosts",
            category: ModuleCategory::Lateral,
            selected: false,
        },
        // Post-Exploitation
        AttackModule {
            name: "DCSync",
            description: "Replicate NTDS.dit via DRSUAPI",
            category: ModuleCategory::PostEx,
            selected: false,
        },
        AttackModule {
            name: "SecretsDump",
            description: "Dump SAM/SECURITY/NTDS hashes",
            category: ModuleCategory::PostEx,
            selected: false,
        },
        AttackModule {
            name: "DPAPI Extract",
            description: "Extract DPAPI master keys and credentials",
            category: ModuleCategory::PostEx,
            selected: false,
        },
        AttackModule {
            name: "LAPS Password",
            description: "Read LAPS local admin passwords",
            category: ModuleCategory::PostEx,
            selected: false,
        },
        AttackModule {
            name: "GPP Password",
            description: "Extract Group Policy Preferences passwords",
            category: ModuleCategory::PostEx,
            selected: false,
        },
        AttackModule {
            name: "Credential Vault",
            description: "Dump Windows Credential Vault",
            category: ModuleCategory::PostEx,
            selected: false,
        },
        AttackModule {
            name: "Browser Creds",
            description: "Extract saved browser credentials",
            category: ModuleCategory::PostEx,
            selected: false,
        },
        // CVE Exploits
        AttackModule {
            name: "CVE-2026-54121 (Certighost)",
            description: "AD CS enrollment fallback -- DC impersonation",
            category: ModuleCategory::Cve,
            selected: false,
        },
        AttackModule {
            name: "CVE-2026-41089 (Netlogon RCE)",
            description: "Unauthenticated RCE on DC via Netlogon",
            category: ModuleCategory::Cve,
            selected: false,
        },
        AttackModule {
            name: "CVE-2026-27912 (ResetNightmare)",
            description: "Reset any AD account password via Kerberos",
            category: ModuleCategory::Cve,
            selected: false,
        },
        AttackModule {
            name: "CVE-2026-33826 (AD RCE)",
            description: "RCE via DRS input validation flaw",
            category: ModuleCategory::Cve,
            selected: false,
        },
        AttackModule {
            name: "CVE-2026-62818 (AD CS UAF)",
            description: "Use-after-free RCE on AD CS server",
            category: ModuleCategory::Cve,
            selected: false,
        },
        AttackModule {
            name: "CVE-2025-53779 (BadSuccessor)",
            description: "dMSA privilege escalation",
            category: ModuleCategory::Cve,
            selected: false,
        },
        AttackModule {
            name: "CVE-2026-25177 (AD DS EoP)",
            description: "DACL bypass privilege escalation",
            category: ModuleCategory::Cve,
            selected: false,
        },
        AttackModule {
            name: "CVE-2024-21410 (Exchange Relay)",
            description: "NTLM relay to Exchange",
            category: ModuleCategory::Cve,
            selected: false,
        },
        // Coercion / Relay
        AttackModule {
            name: "PetitPotam",
            description: "MS-EFSR coercion to DC",
            category: ModuleCategory::Coercion,
            selected: false,
        },
        AttackModule {
            name: "PrinterBug",
            description: "MS-RPRN coercion via Print Spooler",
            category: ModuleCategory::Coercion,
            selected: false,
        },
        AttackModule {
            name: "DFSCoerce",
            description: "MS-DFSR coercion to DC",
            category: ModuleCategory::Coercion,
            selected: false,
        },
        AttackModule {
            name: "NTLM Relay (SMB)",
            description: "Relay NTLM auth to SMB",
            category: ModuleCategory::Coercion,
            selected: false,
        },
        AttackModule {
            name: "NTLM Relay (LDAP)",
            description: "Relay NTLM auth to LDAP/LDAPS",
            category: ModuleCategory::Coercion,
            selected: false,
        },
        AttackModule {
            name: "ADCS Relay",
            description: "Relay to AD CS web enrollment",
            category: ModuleCategory::Coercion,
            selected: false,
        },
        // Enumeration
        AttackModule {
            name: "LDAP Enum",
            description: "Full LDAP domain enumeration",
            category: ModuleCategory::Enum,
            selected: false,
        },
        AttackModule {
            name: "BloodHound Ingest",
            description: "Collect data for BloodHound analysis",
            category: ModuleCategory::Enum,
            selected: false,
        },
        AttackModule {
            name: "SPN Discovery",
            description: "Discover all Service Principal Names",
            category: ModuleCategory::Enum,
            selected: false,
        },
        AttackModule {
            name: "ACL Enumeration",
            description: "Enumerate DACLs for attack paths",
            category: ModuleCategory::Enum,
            selected: false,
        },
        AttackModule {
            name: "Delegation Check",
            description: "Find delegation configurations",
            category: ModuleCategory::Enum,
            selected: false,
        },
        AttackModule {
            name: "GPO Enumeration",
            description: "Enumerate Group Policy Objects",
            category: ModuleCategory::Enum,
            selected: false,
        },
        AttackModule {
            name: "Certify Scan",
            description: "Enumerate AD CS templates and CAs",
            category: ModuleCategory::Enum,
            selected: false,
        },
    ]
}

// ===========================================================
// Target Configuration
// ===========================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputField {
    DomainController,
    Domain,
    Username,
    Password,
    NtHash,
    Wordlist,
    Template,
    OutputDir,
}

impl InputField {
    pub fn label(&self) -> &'static str {
        match self {
            Self::DomainController => "Domain Controller IP",
            Self::Domain => "Domain (e.g., corp.local)",
            Self::Username => "Username",
            Self::Password => "Password",
            Self::NtHash => "NT Hash (optional)",
            Self::Wordlist => "Wordlist Path (optional)",
            Self::Template => "Certificate Template",
            Self::OutputDir => "Output Directory",
        }
    }

    pub fn placeholder(&self) -> &'static str {
        match self {
            Self::DomainController => "10.10.10.1",
            Self::Domain => "corp.local",
            Self::Username => "administrator",
            Self::Password => "P@ssw0rd!",
            Self::NtHash => "aad3b435b51404eeaad3b435b51404ee:...",
            Self::Wordlist => "./assets/wordlist_top10k.txt.zst",
            Self::Template => "User",
            Self::OutputDir => "./results",
        }
    }

    pub fn is_secret(&self) -> bool {
        matches!(self, Self::Password | Self::NtHash)
    }
}

pub const ALL_INPUT_FIELDS: &[InputField] = &[
    InputField::DomainController,
    InputField::Domain,
    InputField::Username,
    InputField::Password,
    InputField::NtHash,
    InputField::Wordlist,
    InputField::Template,
    InputField::OutputDir,
];

// ===========================================================
// Application State
// ===========================================================

pub struct WizardApp {
    pub screen: WizardScreen,
    pub modules: Vec<AttackModule>,
    pub menu_state: ListState,
    pub category_index: usize,
    pub input_fields: Vec<(InputField, String)>,
    pub active_input: Option<usize>,
    pub input_cursor: usize,
    pub log_lines: Vec<String>,
    pub log_scroll: usize,
    pub should_quit: bool,
    pub running: bool,
    #[allow(dead_code)]
    pub results_summary: String,
    pub status_message: String,
    pub categories: Vec<ModuleCategory>,
}

impl WizardApp {
    pub fn new() -> Self {
        let modules = build_module_catalog();
        let categories = vec![
            ModuleCategory::Credential,
            ModuleCategory::Ticket,
            ModuleCategory::Execution,
            ModuleCategory::Lateral,
            ModuleCategory::PostEx,
            ModuleCategory::Cve,
            ModuleCategory::Coercion,
            ModuleCategory::Enum,
        ];

        let input_fields: Vec<(InputField, String)> = ALL_INPUT_FIELDS
            .iter()
            .map(|f| (f.clone(), String::new()))
            .collect();

        let mut menu_state = ListState::default();
        menu_state.select(Some(0));

        Self {
            screen: WizardScreen::MainMenu,
            modules,
            menu_state,
            category_index: 0,
            input_fields,
            active_input: None,
            input_cursor: 0,
            log_lines: Vec::new(),
            log_scroll: 0,
            should_quit: false,
            running: false,
            results_summary: String::new(),
            status_message: "Press Enter to select, q to quit, Tab to switch screens".to_string(),
            categories,
        }
    }

    pub fn selected_count(&self) -> usize {
        self.modules.iter().filter(|m| m.selected).count()
    }

    pub fn selected_modules(&self) -> Vec<&AttackModule> {
        self.modules.iter().filter(|m| m.selected).collect()
    }

    pub fn get_input(&self, field: &InputField) -> &str {
        self.input_fields
            .iter()
            .find(|(f, _)| f == field)
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    }

    pub fn set_input(&mut self, field: &InputField, value: String) {
        if let Some((_, v)) = self.input_fields.iter_mut().find(|(f, _)| f == field) {
            *v = value;
        }
    }
}

// ===========================================================
// Event Handling
// ===========================================================

pub fn handle_event(app: &mut WizardApp) -> std::io::Result<bool> {
    if !event::poll(Duration::from_millis(50))? {
        return Ok(false);
    }

    match event::read()? {
        Event::Key(key) => {
            // Global quit
            if key.code == KeyCode::Char('q') && app.active_input.is_none() {
                app.should_quit = true;
                return Ok(true);
            }
            if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                app.should_quit = true;
                return Ok(true);
            }

            match app.screen {
                WizardScreen::MainMenu => handle_main_menu(app, key),
                WizardScreen::TargetConfig => handle_target_config(app, key),
                WizardScreen::Running => handle_running(app, key),
                WizardScreen::Results => handle_results(app, key),
                _ => handle_sub_menu(app, key),
            }
        }
        Event::Mouse(mouse) => {
            handle_mouse(app, mouse);
        }
        _ => {}
    }

    Ok(true)
}

fn handle_mouse(app: &mut WizardApp, mouse: crossterm::event::MouseEvent) {
    use crossterm::event::{MouseButton, MouseEventKind};

    match mouse.kind {
        // Scroll wheel -- navigate up/down or scroll content
        MouseEventKind::ScrollUp => match app.screen {
            WizardScreen::MainMenu => {
                let i = app.category_index;
                app.category_index = if i > 0 {
                    i - 1
                } else {
                    app.categories.len() - 1
                };
                app.menu_state.select(Some(app.category_index));
            }
            WizardScreen::CredentialAttacks
            | WizardScreen::TicketAttacks
            | WizardScreen::ExecutionMethods
            | WizardScreen::LateralMovement
            | WizardScreen::PostExploitation
            | WizardScreen::CVEModules
            | WizardScreen::CoercionRelay
            | WizardScreen::Enumeration => {
                let cur = app.menu_state.selected().unwrap_or(0);
                app.menu_state
                    .select(Some(if cur > 0 { cur - 1 } else { 0 }));
            }
            WizardScreen::TargetConfig => {
                let cur = app.menu_state.selected().unwrap_or(0);
                app.menu_state
                    .select(Some(if cur > 0 { cur - 1 } else { 0 }));
            }
            WizardScreen::Results | WizardScreen::Running => {
                app.log_scroll = app.log_scroll.saturating_sub(3);
            }
        },
        MouseEventKind::ScrollDown => match app.screen {
            WizardScreen::MainMenu => {
                let i = app.category_index;
                app.category_index = if i + 1 < app.categories.len() {
                    i + 1
                } else {
                    0
                };
                app.menu_state.select(Some(app.category_index));
            }
            WizardScreen::CredentialAttacks
            | WizardScreen::TicketAttacks
            | WizardScreen::ExecutionMethods
            | WizardScreen::LateralMovement
            | WizardScreen::PostExploitation
            | WizardScreen::CVEModules
            | WizardScreen::CoercionRelay
            | WizardScreen::Enumeration => {
                let cur = app.menu_state.selected().unwrap_or(0);
                let max = app
                    .modules
                    .iter()
                    .filter(|m| {
                        matches!(
                            (m.category, &app.screen),
                            (ModuleCategory::Credential, WizardScreen::CredentialAttacks)
                                | (ModuleCategory::Ticket, WizardScreen::TicketAttacks)
                                | (ModuleCategory::Execution, WizardScreen::ExecutionMethods)
                                | (ModuleCategory::Lateral, WizardScreen::LateralMovement)
                                | (ModuleCategory::PostEx, WizardScreen::PostExploitation)
                                | (ModuleCategory::Cve, WizardScreen::CVEModules)
                                | (ModuleCategory::Coercion, WizardScreen::CoercionRelay)
                                | (ModuleCategory::Enum, WizardScreen::Enumeration)
                        )
                    })
                    .count();
                let max = max.saturating_sub(1);
                app.menu_state
                    .select(Some(if cur < max { cur + 1 } else { max }));
            }
            WizardScreen::TargetConfig => {
                let cur = app.menu_state.selected().unwrap_or(0);
                let max = app.input_fields.len().saturating_sub(1);
                app.menu_state
                    .select(Some(if cur < max { cur + 1 } else { max }));
            }
            WizardScreen::Results | WizardScreen::Running => {
                app.log_scroll += 3;
            }
        },

        // Left click -- select item under cursor
        MouseEventKind::Down(MouseButton::Left) => {
            match app.screen {
                WizardScreen::MainMenu => {
                    // Left panel is categories (40% width)
                    // Header is 3 lines, so content starts at row 3
                    let content_row = mouse.row.saturating_sub(3) as usize;
                    // Left panel is 40% width, approximate with 40 columns
                    if mouse.column < 40 {
                        // Click on category list
                        if content_row < app.categories.len() {
                            app.category_index = content_row;
                            app.menu_state.select(Some(content_row));
                        }
                    } else {
                        // Right panel -- check if clicking "Run" button area
                        // The help panel is informational, no action on click
                    }
                }
                WizardScreen::CredentialAttacks
                | WizardScreen::TicketAttacks
                | WizardScreen::ExecutionMethods
                | WizardScreen::LateralMovement
                | WizardScreen::PostExploitation
                | WizardScreen::CVEModules
                | WizardScreen::CoercionRelay
                | WizardScreen::Enumeration => {
                    let content_row = mouse.row.saturating_sub(3) as usize;
                    let modules_in_screen: Vec<usize> = app
                        .modules
                        .iter()
                        .enumerate()
                        .filter(|(_, m)| {
                            matches!(
                                (m.category, &app.screen),
                                (ModuleCategory::Credential, WizardScreen::CredentialAttacks)
                                    | (ModuleCategory::Ticket, WizardScreen::TicketAttacks)
                                    | (ModuleCategory::Execution, WizardScreen::ExecutionMethods)
                                    | (ModuleCategory::Lateral, WizardScreen::LateralMovement)
                                    | (ModuleCategory::PostEx, WizardScreen::PostExploitation)
                                    | (ModuleCategory::Cve, WizardScreen::CVEModules)
                                    | (ModuleCategory::Coercion, WizardScreen::CoercionRelay)
                                    | (ModuleCategory::Enum, WizardScreen::Enumeration)
                            )
                        })
                        .map(|(i, _)| i)
                        .collect();
                    if content_row < modules_in_screen.len() {
                        let prev = app.menu_state.selected();
                        app.menu_state.select(Some(content_row));
                        // If clicking the same item, toggle selection
                        if prev == Some(content_row) {
                            if let Some(&idx) = modules_in_screen.get(content_row) {
                                app.modules[idx].selected = !app.modules[idx].selected;
                            }
                        }
                    }
                }
                WizardScreen::TargetConfig => {
                    let content_row = mouse.row.saturating_sub(3) as usize;
                    if content_row < app.input_fields.len() {
                        let prev = app.menu_state.selected();
                        app.menu_state.select(Some(content_row));
                        // Double-click (same row) enters edit mode
                        if prev == Some(content_row) {
                            app.active_input = Some(content_row);
                            app.input_cursor = 0;
                        }
                    }
                }
                WizardScreen::Results | WizardScreen::Running => {
                    // Click on log area does nothing special
                }
            }
        }

        // Right click -- toggle selection in module lists
        MouseEventKind::Down(MouseButton::Right) => match app.screen {
            WizardScreen::CredentialAttacks
            | WizardScreen::TicketAttacks
            | WizardScreen::ExecutionMethods
            | WizardScreen::LateralMovement
            | WizardScreen::PostExploitation
            | WizardScreen::CVEModules
            | WizardScreen::CoercionRelay
            | WizardScreen::Enumeration => {
                let content_row = mouse.row.saturating_sub(3) as usize;
                let modules_in_screen: Vec<usize> = app
                    .modules
                    .iter()
                    .enumerate()
                    .filter(|(_, m)| {
                        matches!(
                            (m.category, &app.screen),
                            (ModuleCategory::Credential, WizardScreen::CredentialAttacks)
                                | (ModuleCategory::Ticket, WizardScreen::TicketAttacks)
                                | (ModuleCategory::Execution, WizardScreen::ExecutionMethods)
                                | (ModuleCategory::Lateral, WizardScreen::LateralMovement)
                                | (ModuleCategory::PostEx, WizardScreen::PostExploitation)
                                | (ModuleCategory::Cve, WizardScreen::CVEModules)
                                | (ModuleCategory::Coercion, WizardScreen::CoercionRelay)
                                | (ModuleCategory::Enum, WizardScreen::Enumeration)
                        )
                    })
                    .map(|(i, _)| i)
                    .collect();
                if content_row < modules_in_screen.len() {
                    app.menu_state.select(Some(content_row));
                    if let Some(&idx) = modules_in_screen.get(content_row) {
                        app.modules[idx].selected = !app.modules[idx].selected;
                    }
                }
            }
            _ => {}
        },

        // Drag -- scroll content
        MouseEventKind::Drag(MouseButton::Left) => match app.screen {
            WizardScreen::Results | WizardScreen::Running => {
                app.log_scroll = app.log_scroll.saturating_add(1);
            }
            _ => {}
        },

        _ => {}
    }
}

fn handle_main_menu(app: &mut WizardApp, key: KeyEvent) {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            let i = app.category_index;
            app.category_index = if i > 0 {
                i - 1
            } else {
                app.categories.len() - 1
            };
            app.menu_state.select(Some(app.category_index));
        }
        KeyCode::Down | KeyCode::Char('j') => {
            let i = app.category_index;
            app.category_index = if i + 1 < app.categories.len() {
                i + 1
            } else {
                0
            };
            app.menu_state.select(Some(app.category_index));
        }
        KeyCode::Enter => {
            let cat = app.categories[app.category_index];
            app.screen = match cat {
                ModuleCategory::Credential => WizardScreen::CredentialAttacks,
                ModuleCategory::Ticket => WizardScreen::TicketAttacks,
                ModuleCategory::Execution => WizardScreen::ExecutionMethods,
                ModuleCategory::Lateral => WizardScreen::LateralMovement,
                ModuleCategory::PostEx => WizardScreen::PostExploitation,
                ModuleCategory::Cve => WizardScreen::CVEModules,
                ModuleCategory::Coercion => WizardScreen::CoercionRelay,
                ModuleCategory::Enum => WizardScreen::Enumeration,
            };
            app.menu_state.select(Some(0));
        }
        KeyCode::Tab | KeyCode::Char('t') => {
            app.screen = WizardScreen::TargetConfig;
        }
        KeyCode::Char('r') | KeyCode::Char('R') => {
            if app.selected_count() > 0 {
                app.screen = WizardScreen::Running;
                app.running = true;
            }
        }
        _ => {}
    }
}

fn handle_sub_menu(app: &mut WizardApp, key: KeyEvent) {
    let modules_in_screen: Vec<usize> = app
        .modules
        .iter()
        .enumerate()
        .filter(|(_, m)| {
            matches!(
                (m.category, &app.screen),
                (ModuleCategory::Credential, WizardScreen::CredentialAttacks)
                    | (ModuleCategory::Ticket, WizardScreen::TicketAttacks)
                    | (ModuleCategory::Execution, WizardScreen::ExecutionMethods)
                    | (ModuleCategory::Lateral, WizardScreen::LateralMovement)
                    | (ModuleCategory::PostEx, WizardScreen::PostExploitation)
                    | (ModuleCategory::Cve, WizardScreen::CVEModules)
                    | (ModuleCategory::Coercion, WizardScreen::CoercionRelay)
                    | (ModuleCategory::Enum, WizardScreen::Enumeration)
            )
        })
        .map(|(i, _)| i)
        .collect();

    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            let cur = app.menu_state.selected().unwrap_or(0);
            app.menu_state.select(Some(if cur > 0 {
                cur - 1
            } else {
                modules_in_screen.len().saturating_sub(1)
            }));
        }
        KeyCode::Down | KeyCode::Char('j') => {
            let cur = app.menu_state.selected().unwrap_or(0);
            let max = modules_in_screen.len().saturating_sub(1);
            app.menu_state
                .select(Some(if cur < max { cur + 1 } else { 0 }));
        }
        KeyCode::Char(' ') | KeyCode::Right | KeyCode::Char('l') => {
            if let Some(selected) = app.menu_state.selected() {
                if let Some(&idx) = modules_in_screen.get(selected) {
                    app.modules[idx].selected = !app.modules[idx].selected;
                }
            }
        }
        KeyCode::Left | KeyCode::Char('h') => {
            if let Some(selected) = app.menu_state.selected() {
                if let Some(&idx) = modules_in_screen.get(selected) {
                    app.modules[idx].selected = false;
                }
            }
        }
        KeyCode::Char('a') => {
            // Select all in category
            for &idx in &modules_in_screen {
                app.modules[idx].selected = true;
            }
        }
        KeyCode::Char('d') => {
            // Deselect all in category
            for &idx in &modules_in_screen {
                app.modules[idx].selected = false;
            }
        }
        KeyCode::Esc | KeyCode::Backspace | KeyCode::Char('b') => {
            app.screen = WizardScreen::MainMenu;
            app.menu_state.select(Some(app.category_index));
        }
        KeyCode::Tab | KeyCode::Char('t') => {
            app.screen = WizardScreen::TargetConfig;
        }
        KeyCode::Char('r') | KeyCode::Char('R') => {
            if app.selected_count() > 0 {
                app.screen = WizardScreen::Running;
                app.running = true;
            }
        }
        _ => {}
    }
}

fn handle_target_config(app: &mut WizardApp, key: KeyEvent) {
    if app.active_input.is_some() {
        // Text input mode
        let input_idx = app.active_input.unwrap();
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                app.active_input = None;
            }
            KeyCode::Backspace => {
                if let Some((_, v)) = app.input_fields.get_mut(input_idx) {
                    v.pop();
                }
            }
            KeyCode::Left => {
                app.input_cursor = app.input_cursor.saturating_sub(1);
            }
            KeyCode::Right => {
                app.input_cursor += 1;
            }
            KeyCode::Char(c) => {
                if let Some((_, v)) = app.input_fields.get_mut(input_idx) {
                    v.push(c);
                }
            }
            _ => {}
        }
        return;
    }

    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            let cur = app.menu_state.selected().unwrap_or(0);
            app.menu_state.select(Some(if cur > 0 {
                cur - 1
            } else {
                app.input_fields.len() - 1
            }));
        }
        KeyCode::Down | KeyCode::Char('j') => {
            let cur = app.menu_state.selected().unwrap_or(0);
            let max = app.input_fields.len() - 1;
            app.menu_state
                .select(Some(if cur < max { cur + 1 } else { 0 }));
        }
        KeyCode::Enter | KeyCode::Char('e') => {
            app.active_input = app.menu_state.selected();
            app.input_cursor = 0;
        }
        KeyCode::Tab | KeyCode::Char('t') => {
            app.screen = WizardScreen::MainMenu;
            app.menu_state.select(Some(0));
        }
        KeyCode::Char('r') | KeyCode::Char('R') => {
            if app.selected_count() > 0 {
                app.screen = WizardScreen::Running;
                app.running = true;
            }
        }
        _ => {}
    }
}

fn handle_running(_app: &mut WizardApp, _key: KeyEvent) {
    // During execution, only Esc cancels
}

fn handle_results(app: &mut WizardApp, key: KeyEvent) {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            app.log_scroll = app.log_scroll.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.log_scroll += 1;
        }
        KeyCode::PageUp => {
            app.log_scroll = app.log_scroll.saturating_sub(10);
        }
        KeyCode::PageDown => {
            app.log_scroll += 10;
        }
        KeyCode::Esc | KeyCode::Backspace | KeyCode::Char('b') => {
            app.screen = WizardScreen::MainMenu;
            app.running = false;
            app.menu_state.select(Some(0));
        }
        _ => {}
    }
}

// ===========================================================
// UI Rendering
// ===========================================================

pub fn draw(frame: &mut Frame, app: &WizardApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Main content
            Constraint::Length(3), // Footer / status
        ])
        .split(frame.area());

    draw_header(frame, chunks[0], app);

    match app.screen {
        WizardScreen::MainMenu => draw_main_menu(frame, chunks[1], app),
        WizardScreen::CredentialAttacks
        | WizardScreen::TicketAttacks
        | WizardScreen::ExecutionMethods
        | WizardScreen::LateralMovement
        | WizardScreen::PostExploitation
        | WizardScreen::CVEModules
        | WizardScreen::CoercionRelay
        | WizardScreen::Enumeration => draw_module_list(frame, chunks[1], app),
        WizardScreen::TargetConfig => draw_target_config(frame, chunks[1], app),
        WizardScreen::Running => draw_running(frame, chunks[1], app),
        WizardScreen::Results => draw_results(frame, chunks[1], app),
    }

    draw_footer(frame, chunks[2], app);
}

fn draw_header(frame: &mut Frame, area: Rect, app: &WizardApp) {
    let header_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(20), Constraint::Length(30)])
        .split(area);

    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            " OVERTHRONE ",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "TUI Wizard",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" | {} modules selected", app.selected_count()),
            Style::default().fg(Color::DarkGray),
        ),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red)),
    );
    frame.render_widget(title, header_chunks[0]);

    let tabs = Tabs::new(vec![
        Line::from(Span::styled(
            " 1:Menu ",
            Style::default().fg(if app.screen == WizardScreen::MainMenu {
                Color::Cyan
            } else {
                Color::DarkGray
            }),
        )),
        Line::from(Span::styled(
            " 2:Config ",
            Style::default().fg(if app.screen == WizardScreen::TargetConfig {
                Color::Cyan
            } else {
                Color::DarkGray
            }),
        )),
        Line::from(Span::styled(
            " 3:Run ",
            Style::default().fg(if app.screen == WizardScreen::Running {
                Color::Cyan
            } else {
                Color::DarkGray
            }),
        )),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    )
    .highlight_style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    frame.render_widget(tabs, header_chunks[1]);
}

fn draw_main_menu(frame: &mut Frame, area: Rect, app: &WizardApp) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    // Category list
    let items: Vec<ListItem> = app
        .categories
        .iter()
        .enumerate()
        .map(|(i, cat)| {
            let count = app.modules.iter().filter(|m| m.category == *cat).count();
            let selected = app
                .modules
                .iter()
                .filter(|m| m.category == *cat && m.selected)
                .count();
            let style = if i == app.category_index {
                Style::default()
                    .fg(Color::Black)
                    .bg(cat.color())
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(cat.color())
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {:<3} ", cat.label()), style),
                Span::styled(
                    format!("[{}/{}]", selected, count),
                    Style::default().fg(if selected > 0 {
                        Color::Green
                    } else {
                        Color::DarkGray
                    }),
                ),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title("  Select Attack Category  ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Red)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );

    frame.render_stateful_widget(list, chunks[0], &mut app.menu_state.clone());

    // Help panel
    let help_lines = vec![
        Line::from(vec![Span::styled(
            "  Navigation",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  j/k", Style::default().fg(Color::Yellow)),
            Span::raw("  Move up/down"),
        ]),
        Line::from(vec![
            Span::styled("  Enter", Style::default().fg(Color::Yellow)),
            Span::raw("  Open category"),
        ]),
        Line::from(vec![
            Span::styled("  Space", Style::default().fg(Color::Yellow)),
            Span::raw("  Toggle module (in sub-menus)"),
        ]),
        Line::from(vec![
            Span::styled("  Tab", Style::default().fg(Color::Yellow)),
            Span::raw("  Switch to Target Config"),
        ]),
        Line::from(vec![
            Span::styled("  R", Style::default().fg(Color::Yellow)),
            Span::raw("  Run selected modules"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "  Selected",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(": {} modules", app.selected_count())),
        ]),
        Line::from(vec![
            Span::styled("  DC: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                app.get_input(&InputField::DomainController),
                if app.get_input(&InputField::DomainController).is_empty() {
                    Style::default().fg(Color::Red)
                } else {
                    Style::default().fg(Color::Green)
                },
            ),
        ]),
        Line::from(vec![
            Span::styled("  Domain: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                app.get_input(&InputField::Domain),
                if app.get_input(&InputField::Domain).is_empty() {
                    Style::default().fg(Color::Red)
                } else {
                    Style::default().fg(Color::Green)
                },
            ),
        ]),
        Line::from(vec![
            Span::styled("  User: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                app.get_input(&InputField::Username),
                if app.get_input(&InputField::Username).is_empty() {
                    Style::default().fg(Color::Red)
                } else {
                    Style::default().fg(Color::Green)
                },
            ),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "  Quick Start",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![Span::styled(
            "  1. Press Tab to configure target",
            Style::default().fg(Color::DarkGray),
        )]),
        Line::from(vec![Span::styled(
            "  2. Press Tab back, pick category",
            Style::default().fg(Color::DarkGray),
        )]),
        Line::from(vec![Span::styled(
            "  3. Space to select modules",
            Style::default().fg(Color::DarkGray),
        )]),
        Line::from(vec![Span::styled(
            "  4. Press R to run",
            Style::default().fg(Color::DarkGray),
        )]),
    ];

    let help = Paragraph::new(help_lines).block(
        Block::default()
            .title("  Quick Guide  ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(help, chunks[1]);
}

fn draw_module_list(frame: &mut Frame, area: Rect, app: &WizardApp) {
    let screen = app.screen;
    let category = match screen {
        WizardScreen::CredentialAttacks => ModuleCategory::Credential,
        WizardScreen::TicketAttacks => ModuleCategory::Ticket,
        WizardScreen::ExecutionMethods => ModuleCategory::Execution,
        WizardScreen::LateralMovement => ModuleCategory::Lateral,
        WizardScreen::PostExploitation => ModuleCategory::PostEx,
        WizardScreen::CVEModules => ModuleCategory::Cve,
        WizardScreen::CoercionRelay => ModuleCategory::Coercion,
        WizardScreen::Enumeration => ModuleCategory::Enum,
        _ => ModuleCategory::Credential,
    };

    let modules: Vec<&AttackModule> = app
        .modules
        .iter()
        .filter(|m| m.category == category)
        .collect();

    let selected_count = modules.iter().filter(|m| m.selected).count();

    let items: Vec<ListItem> = modules
        .iter()
        .map(|m| {
            let checkbox = if m.selected { " [x] " } else { " [ ] " };
            let style = if m.selected {
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    checkbox,
                    if m.selected {
                        Style::default().fg(Color::Green)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    },
                ),
                Span::styled(m.name, style),
                Span::styled(
                    format!("  -- {}", m.description),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title(format!(
                    "  {} ({}/{}) [Space: toggle, a: select all, d: deselect all, Esc: back]  ",
                    category.label(),
                    selected_count,
                    modules.len()
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(category.color())),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );

    frame.render_stateful_widget(list, area, &mut app.menu_state.clone());
}

fn draw_target_config(frame: &mut Frame, area: Rect, app: &WizardApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(app.input_fields.len() as u16 + 2), // Input fields
            Constraint::Min(5),                                    // Help
        ])
        .split(area);

    let mut lines: Vec<Line> = Vec::new();
    for (i, (field, value)) in app.input_fields.iter().enumerate() {
        let is_active = app.active_input == Some(i);
        let is_selected = app.menu_state.selected() == Some(i);

        let label_style = if is_active {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else if is_selected {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };

        let value_style = if is_active {
            Style::default().fg(Color::Black).bg(Color::Yellow)
        } else if value.is_empty() {
            Style::default().fg(Color::DarkGray)
        } else if field.is_secret() {
            Style::default().fg(Color::Red)
        } else {
            Style::default().fg(Color::Green)
        };

        let display_value = if value.is_empty() {
            field.placeholder().to_string()
        } else if field.is_secret() {
            format!(
                "{}{}",
                "*".repeat(value.len().min(20)),
                if is_active { "_" } else { "" }
            )
        } else {
            value.clone()
        };

        lines.push(Line::from(vec![
            Span::styled(format!("  {:<22} ", field.label()), label_style),
            Span::styled(format!("[{}]", display_value), value_style),
            Span::styled(
                if is_active { "  <-- editing" } else { "" },
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
    }

    let form = Paragraph::new(lines).block(
        Block::default()
            .title("  Target Configuration  ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    frame.render_widget(form, chunks[0]);

    let help = Paragraph::new(vec![
        Line::from(vec![Span::styled(
            "  Controls:",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![
            Span::styled("  j/k", Style::default().fg(Color::Yellow)),
            Span::raw("  Move between fields"),
        ]),
        Line::from(vec![
            Span::styled("  Enter/e", Style::default().fg(Color::Yellow)),
            Span::raw("  Edit selected field"),
        ]),
        Line::from(vec![
            Span::styled("  Esc", Style::default().fg(Color::Yellow)),
            Span::raw("  Stop editing field"),
        ]),
        Line::from(vec![
            Span::styled("  Tab", Style::default().fg(Color::Yellow)),
            Span::raw("  Back to main menu"),
        ]),
        Line::from(vec![
            Span::styled("  R", Style::default().fg(Color::Yellow)),
            Span::raw("  Run selected modules"),
        ]),
    ])
    .block(
        Block::default()
            .title("  Help  ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(help, chunks[1]);
}

fn draw_running(frame: &mut Frame, area: Rect, app: &WizardApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(3)])
        .split(area);

    let log_lines: Vec<Line> = app
        .log_lines
        .iter()
        .map(|line| Line::from(Span::raw(line.as_str())))
        .collect();

    let log_widget = Paragraph::new(log_lines)
        .block(
            Block::default()
                .title(format!("  Running {} modules...  ", app.selected_count()))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .scroll((app.log_scroll as u16, 0));

    frame.render_widget(log_widget, chunks[0]);

    let status = Paragraph::new(Line::from(vec![
        Span::styled("  ", Style::default()),
        Span::styled(
            "Running",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            " -- press Esc to stop",
            Style::default().fg(Color::DarkGray),
        ),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(status, chunks[1]);
}

fn draw_results(frame: &mut Frame, area: Rect, app: &WizardApp) {
    let log_lines: Vec<Line> = app
        .log_lines
        .iter()
        .map(|line| Line::from(Span::raw(line.as_str())))
        .collect();

    let results = Paragraph::new(log_lines)
        .block(
            Block::default()
                .title(format!(
                    "  Results ({}) [j/k: scroll, Esc: back]  ",
                    app.log_lines.len()
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green)),
        )
        .scroll((app.log_scroll as u16, 0));

    frame.render_widget(results, area);
}

fn draw_footer(frame: &mut Frame, area: Rect, app: &WizardApp) {
    let footer = Paragraph::new(Line::from(vec![Span::styled(
        format!(" {} ", app.status_message),
        Style::default().fg(Color::DarkGray),
    )]))
    .style(Style::default().bg(Color::DarkGray));
    frame.render_widget(footer, area);
}
