//! overthrone-pilot — Autonomous AD attack orchestration engine.
//!
//! Pilot is the "brain" of Overthrone. Given a goal (e.g., "achieve Domain Admin"),
//! it plans an attack chain, executes each step, adapts when a step fails,
//! and re-plans dynamically until the goal is reached or all paths exhausted.
//!
//! Architecture:
//! - `goals`    — Define attack objectives and success criteria
//! - `planner`  — Build ordered attack plans from current state → goal
//! - `playbook` — Predefined attack sequences (recon, roast, delegate, exec, dump)
//! - `executor` — Execute individual attack actions via core/hunter/crawler
//! - `adaptive` — React to failures, re-score paths, try alternatives
//! - `runner`   — Top-level orchestrator tying everything together

#![allow(dead_code, unused_imports)]

pub mod adaptive;
pub mod executor;
pub mod goals;
pub mod planner;
pub mod playbook;
pub mod runner;

// Re-exports for CLI integration
pub use goals::{AttackGoal, GoalStatus};
pub use planner::{AttackPlan, PlanStep};
pub use playbook::{Playbook, PlaybookId};
pub use runner::{AutoPwnConfig, AutoPwnResult, ExecMethod, Stage, run};
