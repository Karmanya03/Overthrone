//! Q-learning adaptive engine — Reinforcement learning layer over the
//! heuristic `AdaptiveEngine` to gradually learn optimal responses to
//! step outcomes across engagements.
//!
//! Uses the `rurel` crate for trait definitions (`State`, `Agent`) and
//! a custom online Q-learning implementation for real-time updates
//! (rurel's built-in trainer is designed for simulated environments).
//!
//! # Architecture
//!
//! - `EngagementStateKey` — discretized, hashable snapshot of state
//! - `AdaptiveAction` — maps to `AdaptiveDecision` variants
//! - `AdaptiveAgent` — implements `rurel::mdp::Agent`
//! - `AdaptiveQLearner` — wraps the heuristic engine, adds Q-learning
//!
//! The ε-greedy policy delegates to the heuristic engine with probability ε
//! (exploration) and selects the highest-Q-value action otherwise (exploitation).
//! Over time, ε decays from 0.3 → 0.05, shifting toward learned behavior.

use std::collections::HashMap;
use std::path::PathBuf;

use rurel::mdp::{Agent, State};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::adaptive::{
    AdaptiveDecision, AdaptiveEngine, AdaptiveSummary, FailureClass, StepModification,
};
use crate::goals::{AttackGoal, EngagementState};
use crate::planner::{AttackPlan, PlanStep, StepResult};

// ═══════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════

/// Q-learning rate (α)
const ALPHA: f64 = 0.1;
/// Discount factor (γ)
const GAMMA: f64 = 0.95;
/// Initial exploration rate
const EPSILON_START: f64 = 0.3;
/// Minimum exploration rate
const EPSILON_MIN: f64 = 0.05;
/// Epsilon decay per episode (multiplicative)
const EPSILON_DECAY: f64 = 0.995;

// ═══════════════════════════════════════════════════════════
// Reward Constants
// ═══════════════════════════════════════════════════════════

/// Reward when goal is achieved
pub const REWARD_GOAL_ACHIEVED: f64 = 100.0;
/// Reward for obtaining a new credential
pub const REWARD_NEW_CRED: f64 = 10.0;
/// Reward for gaining admin on a new host
pub const REWARD_NEW_ADMIN_HOST: f64 = 5.0;
/// Reward for a successful step
pub const REWARD_SUCCESS: f64 = 1.0;
/// Penalty for a failed step
pub const REWARD_FAIL: f64 = -1.0;
/// Penalty for being detected by security controls
pub const REWARD_DETECTED: f64 = -15.0;
/// Penalty for an unnecessary replan
pub const REWARD_UNNECESSARY_REPLAN: f64 = -5.0;
/// Penalty for aborting
pub const REWARD_ABORT: f64 = -20.0;
/// Bonus for obtaining DA-equivalent access (cert, golden ticket, etc.)
pub const REWARD_DA_EQUIVALENT: f64 = 50.0;

// ═══════════════════════════════════════════════════════════
// Adaptive Mode
// ═══════════════════════════════════════════════════════════

/// Selects which adaptive strategy the runner uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AdaptiveMode {
    /// Pure heuristic (original `AdaptiveEngine`)
    Heuristic,
    /// Pure Q-learning (falls back to heuristic for unknown states)
    QLearning,
    /// Hybrid — Q-learner with ε-greedy exploration via heuristic fallback
    #[default]
    Hybrid,
}

// ═══════════════════════════════════════════════════════════
// EngagementStateKey — discretized, hashable state snapshot
// ═══════════════════════════════════════════════════════════

/// Discretized snapshot of the engagement state used as a Q-table key.
///
/// Fields are bucketed to keep the state space manageable while preserving
/// the most decision-relevant information.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EngagementStateKey {
    /// Credential count bucket: 0=none, 1=one, 2=2-5, 3=6+
    pub cred_bucket: u8,
    /// Whether we hold Domain Admin credentials
    pub has_domain_admin: bool,
    /// Whether we hold any admin-level credentials
    pub has_any_admin: bool,
    /// Admin host count bucket: 0, 1, 2=2-5, 3=6+
    pub admin_hosts_bucket: u8,
    /// Kerberoastable account bucket: 0, 1=1-5, 2=6+
    pub kerberoastable_bucket: u8,
    /// AS-REP roastable account bucket: 0, 1=1-5, 2=6+
    pub asrep_bucket: u8,
    /// Discovered user bucket: 0, 1=1-50, 2=51-500, 3=500+
    pub users_bucket: u8,
    /// Consecutive failure bucket: 0, 1=1-2, 2=3+
    pub consec_failures: u8,
    /// Current attack stage index (0-5)
    pub current_stage: u8,
    /// Whether stealth mode is active
    pub stealth: bool,
    /// Index of the last failure class (0-6)
    pub last_failure: u8,
}

impl EngagementStateKey {
    /// Encode live engagement state into a discretized key.
    pub fn encode(
        state: &EngagementState,
        step: &PlanStep,
        result: &StepResult,
        stealth: bool,
        consecutive_failures: u32,
    ) -> Self {
        let cred_count = state.credentials.len();
        let admin_host_count = state.admin_hosts.len();
        let kerberoastable_count = state.kerberoastable.len();
        let asrep_count = state.asrep_roastable.len();
        let user_count = state.users.len();

        let failure_class = if result.success {
            FailureClass::Unknown // no failure — index 6
        } else {
            FailureClass::classify(&result.output)
        };

        Self {
            cred_bucket: bucket_count(cred_count, &[0, 1, 5]),
            has_domain_admin: state.has_domain_admin,
            has_any_admin: state.has_any_admin(),
            admin_hosts_bucket: bucket_count(admin_host_count, &[0, 1, 5]),
            kerberoastable_bucket: bucket_small(kerberoastable_count),
            asrep_bucket: bucket_small(asrep_count),
            users_bucket: bucket_users(user_count),
            consec_failures: bucket_failures(consecutive_failures),
            current_stage: step.stage as u8,
            stealth,
            last_failure: failure_class_index(&failure_class),
        }
    }
}

/// Map a `FailureClass` to a stable integer index.
fn failure_class_index(fc: &FailureClass) -> u8 {
    match fc {
        FailureClass::AuthFailure => 0,
        FailureClass::NetworkError => 1,
        FailureClass::AccessDenied => 2,
        FailureClass::NotFound => 3,
        FailureClass::Detected => 4,
        FailureClass::Timeout => 5,
        FailureClass::Unknown => 6,
    }
}

// ── Bucketing helpers ──

fn bucket_count(n: usize, thresholds: &[usize]) -> u8 {
    // thresholds = [0, 1, 5] → buckets 0, 1, 2, 3
    let mut bucket = 0u8;
    for &t in thresholds {
        if n > t {
            bucket += 1;
        }
    }
    bucket
}

fn bucket_small(n: usize) -> u8 {
    match n {
        0 => 0,
        1..=5 => 1,
        _ => 2,
    }
}

fn bucket_users(n: usize) -> u8 {
    match n {
        0 => 0,
        1..=50 => 1,
        51..=500 => 2,
        _ => 3,
    }
}

fn bucket_failures(n: u32) -> u8 {
    match n {
        0 => 0,
        1..=2 => 1,
        _ => 2,
    }
}

// ═══════════════════════════════════════════════════════════
// AdaptiveAction — discrete action space
// ═══════════════════════════════════════════════════════════

/// Discrete actions the Q-learner can select.
///
/// Each maps back to an `AdaptiveDecision` variant when executed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AdaptiveAction {
    Continue,             // 0
    RetryPlain,           // 1
    RetrySwapCreds,       // 2
    RetryExtendTimeout,   // 3
    RetryReduceNoise,     // 4
    RetryAltMethod,       // 5
    Skip,                 // 6
    SubstituteLowerPriv,  // 7
    SubstituteStealthier, // 8
    Replan,               // 9
    Abort,                // 10
}

impl AdaptiveAction {
    /// All possible actions (used by `State::actions()`).
    pub fn all() -> Vec<Self> {
        vec![
            Self::Continue,
            Self::RetryPlain,
            Self::RetrySwapCreds,
            Self::RetryExtendTimeout,
            Self::RetryReduceNoise,
            Self::RetryAltMethod,
            Self::Skip,
            Self::SubstituteLowerPriv,
            Self::SubstituteStealthier,
            Self::Replan,
            Self::Abort,
        ]
    }
}

// ═══════════════════════════════════════════════════════════
// rurel trait implementations
// ═══════════════════════════════════════════════════════════

impl State for EngagementStateKey {
    type A = AdaptiveAction;

    fn reward(&self) -> f64 {
        // Rewards are assigned externally via `record_outcome()`
        0.0
    }

    fn actions(&self) -> Vec<AdaptiveAction> {
        AdaptiveAction::all()
    }
}

/// Agent that tracks the current state and selected action.
///
/// This is used for rurel trait compatibility; actual Q-value updates
/// happen outside the rurel training loop (online learning).
pub struct AdaptiveAgent {
    current: EngagementStateKey,
    last_action: Option<AdaptiveAction>,
}

impl AdaptiveAgent {
    pub fn new(state: EngagementStateKey) -> Self {
        Self {
            current: state,
            last_action: None,
        }
    }

    pub fn set_state(&mut self, state: EngagementStateKey) {
        self.current = state;
    }

    pub fn last_action(&self) -> Option<&AdaptiveAction> {
        self.last_action.as_ref()
    }
}

impl Agent<EngagementStateKey> for AdaptiveAgent {
    fn current_state(&self) -> &EngagementStateKey {
        &self.current
    }

    fn take_action(&mut self, action: &AdaptiveAction) {
        self.last_action = Some(action.clone());
    }
}

// ═══════════════════════════════════════════════════════════
// Q-Table — online learning storage
// ═══════════════════════════════════════════════════════════

/// Persistent Q-value table for online reinforcement learning.
///
/// Internally stores a `HashMap` but serializes as a `Vec` of entries
/// because JSON map keys must be strings.
#[derive(Debug, Clone)]
struct QTable {
    values: HashMap<EngagementStateKey, HashMap<AdaptiveAction, f64>>,
}

/// Serialization wrapper — JSON requires string keys.
#[derive(Serialize, Deserialize)]
struct QTableEntry {
    state: EngagementStateKey,
    actions: Vec<(AdaptiveAction, f64)>,
}

impl Serialize for QTable {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let entries: Vec<QTableEntry> = self
            .values
            .iter()
            .map(|(state, acts)| QTableEntry {
                state: state.clone(),
                actions: acts.iter().map(|(a, v)| (a.clone(), *v)).collect(),
            })
            .collect();
        entries.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for QTable {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let entries: Vec<QTableEntry> = Vec::deserialize(deserializer)?;
        let mut values = HashMap::new();
        for entry in entries {
            let acts: HashMap<AdaptiveAction, f64> = entry.actions.into_iter().collect();
            values.insert(entry.state, acts);
        }
        Ok(QTable { values })
    }
}

impl QTable {
    fn new() -> Self {
        Self {
            values: HashMap::new(),
        }
    }

    /// Get Q(s, a), defaulting to 0.0 for unseen state-action pairs.
    fn get(&self, state: &EngagementStateKey, action: &AdaptiveAction) -> f64 {
        self.values
            .get(state)
            .and_then(|acts| acts.get(action))
            .copied()
            .unwrap_or(0.0)
    }

    /// Set Q(s, a).
    fn set(&mut self, state: &EngagementStateKey, action: &AdaptiveAction, value: f64) {
        self.values
            .entry(state.clone())
            .or_default()
            .insert(action.clone(), value);
    }

    /// Get the best action and its Q-value for a given state.
    /// Returns `None` if the state has never been visited.
    fn best_action(&self, state: &EngagementStateKey) -> Option<(AdaptiveAction, f64)> {
        self.values.get(state).and_then(|acts| {
            acts.iter()
                .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
                .map(|(a, v)| (a.clone(), *v))
        })
    }

    /// Max Q-value for a state (used in Q-learning update).
    fn max_q(&self, state: &EngagementStateKey) -> f64 {
        self.values
            .get(state)
            .and_then(|acts| {
                acts.values()
                    .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            })
            .copied()
            .unwrap_or(0.0)
    }

    /// Whether the Q-table has any data for the given state.
    fn has_state(&self, state: &EngagementStateKey) -> bool {
        self.values.contains_key(state)
    }

    /// Total number of state entries.
    fn len(&self) -> usize {
        self.values.len()
    }

    /// Online Q-learning update:
    ///   Q(s,a) ← Q(s,a) + α·[r + γ·max_a'(Q(s',a')) − Q(s,a)]
    fn update(
        &mut self,
        state: &EngagementStateKey,
        action: &AdaptiveAction,
        reward: f64,
        next_state: &EngagementStateKey,
    ) {
        let current_q = self.get(state, action);
        let max_next_q = self.max_q(next_state);
        let new_q = current_q + ALPHA * (reward + GAMMA * max_next_q - current_q);
        self.set(state, action, new_q);
    }
}

// ═══════════════════════════════════════════════════════════
// AdaptiveQLearner — main public struct
// ═══════════════════════════════════════════════════════════

/// Q-learning adaptive engine that wraps the heuristic `AdaptiveEngine`
/// and gradually learns optimal responses to step outcomes.
///
/// In ε-greedy mode:
/// - With probability ε → delegate to heuristic (exploration)
/// - With probability 1−ε → pick the highest Q-value action (exploitation)
///
/// ε decays from 0.3 → 0.05 over episodes.
pub struct AdaptiveQLearner {
    /// The Q-value table (persisted across engagements)
    q_table: QTable,
    /// Heuristic fallback engine (original `AdaptiveEngine`)
    heuristic_fallback: AdaptiveEngine,
    /// Current exploration rate
    epsilon: f64,
    /// Number of completed episodes (engagements)
    episode_count: u64,
    /// Path for Q-table persistence
    q_table_path: PathBuf,
    /// Whether stealth mode is enabled
    stealth: bool,
    /// The rurel-compatible agent (for trait compatibility)
    _agent: AdaptiveAgent,
    /// Last decision metadata for display (action, q_value, was_exploring)
    last_decision_meta: Option<(AdaptiveAction, f64, bool)>,
}

impl AdaptiveQLearner {
    /// Create a new Q-learner with heuristic fallback.
    pub fn new(stealth: bool, q_table_path: PathBuf) -> Self {
        let initial_state = EngagementStateKey {
            cred_bucket: 0,
            has_domain_admin: false,
            has_any_admin: false,
            admin_hosts_bucket: 0,
            kerberoastable_bucket: 0,
            asrep_bucket: 0,
            users_bucket: 0,
            consec_failures: 0,
            current_stage: 0,
            stealth,
            last_failure: 6, // Unknown
        };

        Self {
            q_table: QTable::new(),
            heuristic_fallback: AdaptiveEngine::new(stealth),
            epsilon: EPSILON_START,
            episode_count: 0,
            q_table_path,
            stealth,
            _agent: AdaptiveAgent::new(initial_state),
            last_decision_meta: None,
        }
    }

    /// Load a previously saved Q-table from disk.
    ///
    /// If the file doesn't exist or is corrupt, starts fresh with a warning.
    pub fn load(stealth: bool, path: PathBuf) -> Self {
        let mut learner = Self::new(stealth, path.clone());

        if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(json) => {
                    #[derive(Deserialize)]
                    struct Saved {
                        q_table: QTable,
                        epsilon: f64,
                        episode_count: u64,
                    }

                    match serde_json::from_str::<Saved>(&json) {
                        Ok(saved) => {
                            info!(
                                "Q-learner: Loaded Q-table ({} states, ε={:.3}, {} episodes)",
                                saved.q_table.len(),
                                saved.epsilon,
                                saved.episode_count
                            );
                            learner.q_table = saved.q_table;
                            learner.epsilon = saved.epsilon;
                            learner.episode_count = saved.episode_count;
                        }
                        Err(e) => {
                            warn!(
                                "Q-learner: Failed to parse Q-table from {}: {e}",
                                path.display()
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Q-learner: Failed to read Q-table from {}: {e}",
                        path.display()
                    );
                }
            }
        } else {
            debug!(
                "Q-learner: No existing Q-table at {}, starting fresh",
                path.display()
            );
        }

        learner
    }

    /// Save the Q-table to disk.
    pub fn save(&self) -> anyhow::Result<()> {
        #[derive(Serialize)]
        struct Saved<'a> {
            q_table: &'a QTable,
            epsilon: f64,
            episode_count: u64,
        }

        let saved = Saved {
            q_table: &self.q_table,
            epsilon: self.epsilon,
            episode_count: self.episode_count,
        };

        let json = serde_json::to_string_pretty(&saved)?;

        // Ensure parent directory exists
        if let Some(parent) = self.q_table_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.q_table_path, json)?;

        info!(
            "Q-learner: Saved Q-table ({} states) to {}",
            self.q_table.len(),
            self.q_table_path.display()
        );
        Ok(())
    }

    /// Evaluate a step result and decide what to do next.
    ///
    /// ε-greedy policy:
    /// - With probability ε → delegate to heuristic engine (exploration)
    /// - Otherwise → pick the highest Q-value action (exploitation)
    /// - If Q-table has no data for the state → always fall back to heuristic
    pub fn evaluate(
        &mut self,
        step: &PlanStep,
        result: &StepResult,
        state: &EngagementState,
        goal: &AttackGoal,
    ) -> AdaptiveDecision {
        let state_key = EngagementStateKey::encode(
            state,
            step,
            result,
            self.stealth,
            self.heuristic_fallback.consecutive_failures(),
        );

        // Always delegate to heuristic on success (no learning needed for Continue)
        if result.success {
            self.heuristic_fallback.reset_failure_streak();
            let decision = self.heuristic_fallback.evaluate(step, result, state, goal);
            self.last_decision_meta = Some((decision_to_action(&decision), 0.0, true));
            return decision;
        }

        // ε-greedy: explore with probability ε, or if state is unseen
        let explore = !self.q_table.has_state(&state_key) || rand::random::<f64>() < self.epsilon;

        if explore {
            debug!(
                "Q-learner: Exploring (ε={:.3}, state_known={})",
                self.epsilon,
                self.q_table.has_state(&state_key)
            );
            let decision = self.heuristic_fallback.evaluate(step, result, state, goal);
            let action = decision_to_action(&decision);
            let q = self.q_table.get(&state_key, &action);
            self.last_decision_meta = Some((action, q, true));
            return decision;
        }

        // Exploit: find the best Q-value action
        let (best_action, best_q) = match self.q_table.best_action(&state_key) {
            Some(pair) => pair,
            None => {
                // No Q-values recorded — fall back to heuristic
                let decision = self.heuristic_fallback.evaluate(step, result, state, goal);
                let action = decision_to_action(&decision);
                self.last_decision_meta = Some((action, 0.0, true));
                return decision;
            }
        };

        debug!(
            "Q-learner: Exploiting — best action {:?} (Q={:.2})",
            best_action, best_q
        );

        self.last_decision_meta = Some((best_action.clone(), best_q, false));

        // Convert AdaptiveAction → AdaptiveDecision
        self.action_to_decision(&best_action, step)
    }

    /// Convert an `AdaptiveAction` into an `AdaptiveDecision`, using the
    /// heuristic engine's helpers for substitute lookups.
    fn action_to_decision(&self, action: &AdaptiveAction, step: &PlanStep) -> AdaptiveDecision {
        match action {
            AdaptiveAction::Continue => AdaptiveDecision::Continue,

            AdaptiveAction::RetryPlain => AdaptiveDecision::Retry {
                delay_secs: 2,
                modify: None,
            },

            AdaptiveAction::RetrySwapCreds => AdaptiveDecision::Retry {
                delay_secs: 2,
                modify: Some(StepModification::SwapCredentials),
            },

            AdaptiveAction::RetryExtendTimeout => AdaptiveDecision::Retry {
                delay_secs: 3,
                modify: Some(StepModification::ExtendTimeout),
            },

            AdaptiveAction::RetryReduceNoise => AdaptiveDecision::Retry {
                delay_secs: 2,
                modify: Some(StepModification::ReduceNoise),
            },

            AdaptiveAction::RetryAltMethod => AdaptiveDecision::Retry {
                delay_secs: 2,
                modify: Some(StepModification::AlternateMethod),
            },

            AdaptiveAction::Skip => AdaptiveDecision::Skip {
                reason: "Q-learner: skipping based on learned policy".to_string(),
            },

            AdaptiveAction::SubstituteLowerPriv => {
                match self
                    .heuristic_fallback
                    .find_lower_priv_alternative_pub(&step.action)
                {
                    Some(alt) => AdaptiveDecision::Substitute { replacement: alt },
                    None => AdaptiveDecision::Skip {
                        reason: "Q-learner: no lower-priv alternative available".to_string(),
                    },
                }
            }

            AdaptiveAction::SubstituteStealthier => {
                match self
                    .heuristic_fallback
                    .find_stealthier_alternative_pub(&step.action)
                {
                    Some(alt) => AdaptiveDecision::Substitute { replacement: alt },
                    None => AdaptiveDecision::Skip {
                        reason: "Q-learner: no stealthier alternative available".to_string(),
                    },
                }
            }

            AdaptiveAction::Replan => AdaptiveDecision::Replan {
                reason: "Q-learner: replan based on learned policy".to_string(),
            },

            AdaptiveAction::Abort => AdaptiveDecision::Abort {
                reason: "Q-learner: abort based on learned policy".to_string(),
            },
        }
    }

    /// Record the outcome of an action for Q-table update.
    ///
    /// Should be called after every step execution with the computed reward.
    pub fn record_outcome(
        &mut self,
        state_key: &EngagementStateKey,
        action: &AdaptiveAction,
        reward: f64,
        next_state_key: &EngagementStateKey,
    ) {
        self.q_table
            .update(state_key, action, reward, next_state_key);
        debug!(
            "Q-learner: Updated Q({:?}, {:?}) — reward={:.1}",
            state_key.current_stage, action, reward
        );
    }

    /// Compute the reward for a step result.
    ///
    /// Reward table:
    /// - Goal achieved: +100
    /// - New credential: +10 per credential
    /// - New admin host: +5 per host
    /// - Success: +1
    /// - Failure: -1
    /// - Detected: -15
    /// - Unnecessary replan: -5
    /// - Abort: -20
    pub fn compute_reward(
        result: &StepResult,
        goal_achieved: bool,
        decision: &AdaptiveDecision,
    ) -> f64 {
        let mut reward = 0.0;

        if goal_achieved {
            reward += REWARD_GOAL_ACHIEVED;
        }

        if result.success {
            reward += REWARD_SUCCESS;
            reward += result.new_credentials as f64 * REWARD_NEW_CRED;
            reward += result.new_admin_hosts as f64 * REWARD_NEW_ADMIN_HOST;

            // Bonus for high-value steps that yield both creds and admin
            // (e.g., ADCS cert for administrator, golden ticket)
            if result.new_credentials > 0 && result.new_admin_hosts > 0 {
                reward += REWARD_DA_EQUIVALENT;
            }
        } else {
            let failure_class = FailureClass::classify(&result.output);
            if failure_class == FailureClass::Detected {
                reward += REWARD_DETECTED;
            } else {
                reward += REWARD_FAIL;
            }
        }

        // Penalize replans and aborts that don't stem from a good reason
        match decision {
            AdaptiveDecision::Replan { .. } if result.success => {
                reward += REWARD_UNNECESSARY_REPLAN;
            }
            AdaptiveDecision::Abort { .. } => {
                reward += REWARD_ABORT;
            }
            _ => {}
        }

        reward
    }

    /// Signal the end of an engagement episode.
    ///
    /// Decays ε and increments the episode counter.
    /// Call `save()` after this to persist.
    pub fn end_episode(&mut self) {
        self.episode_count += 1;
        self.epsilon = (self.epsilon * EPSILON_DECAY).max(EPSILON_MIN);
        info!(
            "Q-learner: Episode {} complete (ε={:.3}, states={})",
            self.episode_count,
            self.epsilon,
            self.q_table.len()
        );
    }

    /// Delegate plan adjustment to the heuristic engine.
    pub fn adjust_plan(&self, plan: &mut AttackPlan, state: &EngagementState) {
        self.heuristic_fallback.adjust_plan(plan, state);
    }

    /// Reset the consecutive failure streak (delegate to heuristic).
    pub fn reset_failure_streak(&mut self) {
        self.heuristic_fallback.reset_failure_streak();
    }

    /// Get the list of blacklisted/failed actions (delegate to heuristic).
    pub fn failed_actions(&self) -> &[String] {
        self.heuristic_fallback.failed_actions()
    }

    /// Whether re-plan attempts are exhausted (delegate to heuristic).
    pub fn replans_exhausted(&self) -> bool {
        self.heuristic_fallback.replans_exhausted()
    }

    /// Get the heuristic engine's summary for reporting.
    pub fn summary(&self) -> AdaptiveSummary {
        self.heuristic_fallback.summary()
    }

    /// Current exploration rate.
    pub fn epsilon(&self) -> f64 {
        self.epsilon
    }

    /// Last decision metadata: (action, q_value, was_exploring).
    pub fn last_decision_meta(&self) -> Option<&(AdaptiveAction, f64, bool)> {
        self.last_decision_meta.as_ref()
    }

    /// Number of episodes completed.
    pub fn episode_count(&self) -> u64 {
        self.episode_count
    }

    /// Number of unique states in the Q-table.
    pub fn q_table_size(&self) -> usize {
        self.q_table.len()
    }

    /// Get the Q-value for a specific (state, action) pair.
    pub fn q_value(&self, state_key: &EngagementStateKey, action: &AdaptiveAction) -> f64 {
        self.q_table.get(state_key, action)
    }

    /// Get the consecutive failure count from the underlying heuristic engine.
    pub fn consecutive_failures(&self) -> u32 {
        self.heuristic_fallback.consecutive_failures()
    }

    /// Format a state key as a compact human-readable snapshot for terminal display.
    pub fn format_state_snapshot(key: &EngagementStateKey, epsilon: f64) -> String {
        let stage_name = match key.current_stage {
            0 => "ENUM",
            1 => "ATTACK",
            2 => "ESCALATE",
            3 => "LATERAL",
            4 => "LOOT",
            5 => "CLEANUP",
            _ => "?",
        };
        let failure_name = match key.last_failure {
            0 => "auth",
            1 => "net",
            2 => "denied",
            3 => "notfound",
            4 => "detected",
            5 => "timeout",
            _ => "none",
        };
        format!(
            "stage={} creds={} da={} admins={} kerb={} asrep={} users={} fail={}/{} stealth={} ε={:.3}",
            stage_name,
            key.cred_bucket,
            if key.has_domain_admin { "Y" } else { "N" },
            key.admin_hosts_bucket,
            key.kerberoastable_bucket,
            key.asrep_bucket,
            key.users_bucket,
            key.consec_failures,
            failure_name,
            if key.stealth { "Y" } else { "N" },
            epsilon,
        )
    }

    /// Format a Q-learner decision for terminal display.
    pub fn format_decision(action: &AdaptiveAction, q_value: f64, exploring: bool) -> String {
        let mode = if exploring { "exploring" } else { "exploiting" };
        format!("{:?}  Q={:+.2}  ({})", action, q_value, mode)
    }

    /// Build a Q-learner session summary string for the final report.
    pub fn session_summary(&self) -> String {
        let most_used = self.most_used_action();
        format!(
            "Episode: {} | ε: {:.3} | States: {} | Most-used action: {:?}",
            self.episode_count,
            self.epsilon,
            self.q_table.len(),
            most_used,
        )
    }

    /// Find the action with the most Q-table entries across all states.
    fn most_used_action(&self) -> AdaptiveAction {
        let mut counts: HashMap<AdaptiveAction, usize> = HashMap::new();
        for actions in self.q_table.values.values() {
            for action in actions.keys() {
                *counts.entry(action.clone()).or_default() += 1;
            }
        }
        counts
            .into_iter()
            .max_by_key(|(_, c)| *c)
            .map(|(a, _)| a)
            .unwrap_or(AdaptiveAction::Continue)
    }
}

// ═══════════════════════════════════════════════════════════
// Decision-to-Action mapping (for recording outcomes)
// ═══════════════════════════════════════════════════════════

/// Convert an `AdaptiveDecision` back to the closest `AdaptiveAction`
/// (used when recording heuristic decisions into the Q-table).
pub fn decision_to_action(decision: &AdaptiveDecision) -> AdaptiveAction {
    match decision {
        AdaptiveDecision::Continue => AdaptiveAction::Continue,
        AdaptiveDecision::Retry { modify: None, .. } => AdaptiveAction::RetryPlain,
        AdaptiveDecision::Retry {
            modify: Some(StepModification::SwapCredentials),
            ..
        } => AdaptiveAction::RetrySwapCreds,
        AdaptiveDecision::Retry {
            modify: Some(StepModification::ExtendTimeout),
            ..
        } => AdaptiveAction::RetryExtendTimeout,
        AdaptiveDecision::Retry {
            modify: Some(StepModification::ReduceNoise),
            ..
        } => AdaptiveAction::RetryReduceNoise,
        AdaptiveDecision::Retry {
            modify: Some(StepModification::AlternateMethod),
            ..
        } => AdaptiveAction::RetryAltMethod,
        AdaptiveDecision::Skip { .. } => AdaptiveAction::Skip,
        AdaptiveDecision::Substitute { .. } => {
            // We can't distinguish lower-priv vs stealthier from the decision alone;
            // default to lower-priv.
            AdaptiveAction::SubstituteLowerPriv
        }
        AdaptiveDecision::Replan { .. } => AdaptiveAction::Replan,
        AdaptiveDecision::Abort { .. } => AdaptiveAction::Abort,
        AdaptiveDecision::PauseForOperator { .. } => AdaptiveAction::Skip,
    }
}

// ═══════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::planner::NoiseLevel;
    use crate::planner::PlannedAction;
    use crate::runner::Stage;

    fn dummy_state() -> EngagementState {
        EngagementState::new()
    }

    fn dummy_step() -> PlanStep {
        PlanStep {
            id: "test-step".to_string(),
            description: "Test step".to_string(),
            stage: Stage::Enumerate,
            action: PlannedAction::EnumerateUsers,
            priority: 10,
            noise: NoiseLevel::Silent,
            depends_on: vec![],
            executed: false,
            result: None,
            retries: 0,
            max_retries: 3,
        }
    }

    fn dummy_result_success() -> StepResult {
        StepResult {
            success: true,
            output: "OK".to_string(),
            new_credentials: 0,
            new_admin_hosts: 0,
        }
    }

    fn dummy_result_failure() -> StepResult {
        StepResult {
            success: false,
            output: "auth fail".to_string(),
            new_credentials: 0,
            new_admin_hosts: 0,
        }
    }

    #[test]
    fn test_state_key_encoding() {
        let state = dummy_state();
        let step = dummy_step();
        let result = dummy_result_success();

        let key = EngagementStateKey::encode(&state, &step, &result, false, 0);
        assert_eq!(key.cred_bucket, 0);
        assert!(!key.has_domain_admin);
        assert!(!key.has_any_admin);
        assert_eq!(key.current_stage, 0); // Enumerate
    }

    #[test]
    fn test_q_table_update() {
        let mut q = QTable::new();
        let state = EngagementStateKey {
            cred_bucket: 1,
            has_domain_admin: false,
            has_any_admin: false,
            admin_hosts_bucket: 0,
            kerberoastable_bucket: 0,
            asrep_bucket: 0,
            users_bucket: 1,
            consec_failures: 0,
            current_stage: 0,
            stealth: false,
            last_failure: 6,
        };
        let next_state = state.clone();
        let action = AdaptiveAction::RetrySwapCreds;

        // Initial Q-value should be 0
        assert_eq!(q.get(&state, &action), 0.0);

        // Update with positive reward
        q.update(&state, &action, 10.0, &next_state);
        assert!(q.get(&state, &action) > 0.0);

        // Best action should be RetrySwapCreds
        let (best, _) = q.best_action(&state).unwrap();
        assert_eq!(best, AdaptiveAction::RetrySwapCreds);
    }

    #[test]
    fn test_adaptive_action_count() {
        assert_eq!(AdaptiveAction::all().len(), 11);
    }

    #[test]
    fn test_state_actions_via_rurel() {
        let state = EngagementStateKey {
            cred_bucket: 0,
            has_domain_admin: false,
            has_any_admin: false,
            admin_hosts_bucket: 0,
            kerberoastable_bucket: 0,
            asrep_bucket: 0,
            users_bucket: 0,
            consec_failures: 0,
            current_stage: 0,
            stealth: false,
            last_failure: 6,
        };
        // Test rurel State trait
        let actions = state.actions();
        assert_eq!(actions.len(), 11);
        assert_eq!(state.reward(), 0.0);
    }

    #[test]
    fn test_decision_to_action_round_trip() {
        let decision = AdaptiveDecision::Retry {
            delay_secs: 2,
            modify: Some(StepModification::SwapCredentials),
        };
        let action = decision_to_action(&decision);
        assert_eq!(action, AdaptiveAction::RetrySwapCreds);
    }

    #[test]
    fn test_compute_reward() {
        let result_ok = dummy_result_success();
        let result_fail = dummy_result_failure();
        let decision_continue = AdaptiveDecision::Continue;

        // Success → positive reward
        let r = AdaptiveQLearner::compute_reward(&result_ok, false, &decision_continue);
        assert!(r > 0.0);

        // Goal achieved → large positive reward
        let r = AdaptiveQLearner::compute_reward(&result_ok, true, &decision_continue);
        assert!(r >= 100.0);

        // Failure → negative reward
        let r = AdaptiveQLearner::compute_reward(&result_fail, false, &decision_continue);
        assert!(r < 0.0);
    }

    #[test]
    fn test_q_learner_new_and_save_load() {
        let dir = std::env::temp_dir().join("overthrone_qtest");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test_qtable.json");

        let mut learner = AdaptiveQLearner::new(false, path.clone());
        assert_eq!(learner.q_table_size(), 0);
        assert_eq!(learner.episode_count(), 0);

        // Record a fake outcome
        let s1 = EngagementStateKey {
            cred_bucket: 0,
            has_domain_admin: false,
            has_any_admin: false,
            admin_hosts_bucket: 0,
            kerberoastable_bucket: 0,
            asrep_bucket: 0,
            users_bucket: 0,
            consec_failures: 0,
            current_stage: 0,
            stealth: false,
            last_failure: 0,
        };
        learner.record_outcome(&s1, &AdaptiveAction::RetrySwapCreds, 10.0, &s1);
        assert_eq!(learner.q_table_size(), 1);

        // Save
        learner.save().unwrap();
        assert!(path.exists());

        // Load
        let loaded = AdaptiveQLearner::load(false, path.clone());
        assert_eq!(loaded.q_table_size(), 1);

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_bucketing() {
        assert_eq!(bucket_count(0, &[0, 1, 5]), 0);
        assert_eq!(bucket_count(1, &[0, 1, 5]), 1);
        assert_eq!(bucket_count(3, &[0, 1, 5]), 2);
        assert_eq!(bucket_count(10, &[0, 1, 5]), 3);

        assert_eq!(bucket_small(0), 0);
        assert_eq!(bucket_small(3), 1);
        assert_eq!(bucket_small(100), 2);

        assert_eq!(bucket_users(0), 0);
        assert_eq!(bucket_users(25), 1);
        assert_eq!(bucket_users(200), 2);
        assert_eq!(bucket_users(1000), 3);

        assert_eq!(bucket_failures(0), 0);
        assert_eq!(bucket_failures(1), 1);
        assert_eq!(bucket_failures(5), 2);
    }
}
