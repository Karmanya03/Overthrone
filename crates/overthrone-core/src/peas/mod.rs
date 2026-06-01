pub mod system;
pub mod users;
pub mod services;
pub mod tasks;
pub mod registry;
pub mod credentials;
pub mod network;
pub mod tokens;
pub mod software;
pub mod env;

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct PeasResult {
    pub category: String,
    pub findings: Vec<PeasFinding>,
}

#[derive(Debug, Clone)]
pub struct PeasFinding {
    pub name: String,
    pub description: String,
    pub severity: PeasSeverity,
    pub data: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeasSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

pub async fn run_all_peas() -> Vec<PeasResult> {
    let mut results = Vec::new();
    results.push(system::enumerate().await);
    results.push(users::enumerate().await);
    results.push(services::enumerate().await);
    results.push(tasks::enumerate().await);
    results.push(registry::enumerate().await);
    results.push(credentials::enumerate().await);
    results.push(network::enumerate().await);
    results.push(tokens::enumerate().await);
    results.push(software::enumerate().await);
    results.push(env::enumerate().await);
    results
}
