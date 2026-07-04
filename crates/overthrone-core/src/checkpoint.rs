use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::info;

/// A single recorded result entry in the checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointEntry {
    pub item: String,
    pub status: String,
    pub detail: Option<String>,
}

/// Persistent checkpoint data stored as JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointData {
    pub operation: String,
    pub target: String,
    pub domain: String,
    pub started_at: String,
    pub total_items: usize,
    pub processed: Vec<String>,
    pub results: Vec<CheckpointEntry>,
}

/// Tracks brute‑force progress, persists to disk, supports resume.
///
/// Usage:
/// ```
/// let ckpt = Checkpoint::load_or_new("path.json", "user-enum", "dc", "dom");
/// for user in users {
///     if ckpt.is_processed(user) { continue; }
///     let result = do_probe(user);
///     ckpt.record(user, "valid", Some("KRB_ERROR 25"));
/// }
/// ```
#[derive(Debug)]
pub struct Checkpoint {
    path: PathBuf,
    data: CheckpointData,
    processed_set: HashSet<String>,
    save_count: Arc<AtomicU64>,
    save_threshold: u64,
    dirty: bool,
}

impl Checkpoint {
    /// Load an existing checkpoint or create a new one.
    pub fn load_or_new(
        path: impl Into<PathBuf>,
        operation: &str,
        target: &str,
        domain: &str,
        total_items: usize,
    ) -> Self {
        let path = path.into();
        let (data, processed_set) = if path.exists() {
            match Self::load_inner(&path) {
                Some(d) => {
                    let set: HashSet<String> = d.processed.iter().cloned().collect();
                    info!("Resumed checkpoint: {} items already processed", set.len());
                    (d, set)
                }
                None => {
                    let d = CheckpointData {
                        operation: operation.to_string(),
                        target: target.to_string(),
                        domain: domain.to_string(),
                        started_at: chrono::Utc::now().to_rfc3339(),
                        total_items,
                        processed: Vec::new(),
                        results: Vec::new(),
                    };
                    (d, HashSet::new())
                }
            }
        } else {
            let d = CheckpointData {
                operation: operation.to_string(),
                target: target.to_string(),
                domain: domain.to_string(),
                started_at: chrono::Utc::now().to_rfc3339(),
                total_items,
                processed: Vec::new(),
                results: Vec::new(),
            };
            (d, HashSet::new())
        };

        Self {
            path,
            data,
            processed_set,
            save_count: Arc::new(AtomicU64::new(0)),
            save_threshold: 10,
            dirty: false,
        }
    }

    fn load_inner(path: &Path) -> Option<CheckpointData> {
        let content = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&content).ok()
    }

    /// Has this item already been processed?
    pub fn is_processed(&self, item: &str) -> bool {
        self.processed_set.contains(item)
    }

    /// Record a result and persist.
    pub fn record(&mut self, item: &str, status: &str, detail: Option<String>) {
        if self.processed_set.insert(item.to_string()) {
            self.data.processed.push(item.to_string());
            self.data.results.push(CheckpointEntry {
                item: item.to_string(),
                status: status.to_string(),
                detail,
            });
            self.dirty = true;

            let count = self.save_count.fetch_add(1, Ordering::Relaxed) + 1;
            if count.is_multiple_of(self.save_threshold) {
                self.save();
            }
        }
    }

    /// How many items have been processed so far?
    pub fn processed_count(&self) -> usize {
        self.processed_set.len()
    }

    /// All recorded results.
    pub fn results(&self) -> &[CheckpointEntry] {
        &self.data.results
    }

    /// Total items in the operation.
    pub fn total_items(&self) -> usize {
        self.data.total_items
    }

    /// Persist checkpoint to disk now.
    pub fn save(&self) {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(&self.data) {
            let _ = std::fs::write(&self.path, json);
        }
    }

    /// Return items from a list that haven't been processed yet.
    pub fn pending<'a>(&self, items: &'a [String]) -> Vec<&'a str> {
        items
            .iter()
            .filter(|i| !self.is_processed(i))
            .map(|s| s.as_str())
            .collect()
    }

    /// Path to the checkpoint file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Checkpoint {
    fn drop(&mut self) {
        if self.dirty {
            self.save();
        }
    }
}

/// Generate a deterministic checkpoint path for a given operation and target.
pub fn checkpoint_path(
    base_dir: Option<&Path>,
    operation: &str,
    domain: &str,
    target: &str,
) -> PathBuf {
    let dir = base_dir.map(|d| d.to_path_buf()).unwrap_or_else(|| {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".overthrone").join("checkpoints")
    });
    let safe_name = format!("{}_{}_{}", operation, domain, target)
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>();
    dir.join(format!("{}.json", safe_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp_path() -> PathBuf {
        let p = std::env::temp_dir().join(format!("ckpt_test_{}.json", std::process::id()));
        let _ = fs::remove_file(&p);
        p
    }

    #[test]
    fn test_new_checkpoint_not_processed() {
        let p = tmp_path();
        let mut ckpt = Checkpoint::load_or_new(&p, "test", "dc1", "dom", 100);
        assert!(!ckpt.is_processed("user1"));
        ckpt.record("user1", "valid", None);
        assert!(ckpt.is_processed("user1"));
    }

    #[test]
    fn test_resume_from_checkpoint() {
        let p = tmp_path();
        {
            let mut ckpt = Checkpoint::load_or_new(&p, "test", "dc1", "dom", 100);
            ckpt.record("user1", "valid", None);
            ckpt.record("user2", "not_found", None);
            ckpt.save();
        }
        let ckpt = Checkpoint::load_or_new(&p, "test", "dc1", "dom", 100);
        assert!(ckpt.is_processed("user1"));
        assert!(ckpt.is_processed("user2"));
        assert!(!ckpt.is_processed("user3"));
        assert_eq!(ckpt.processed_count(), 2);
    }

    #[test]
    fn test_pending_items() {
        let p = tmp_path();
        let mut ckpt = Checkpoint::load_or_new(&p, "test", "dc1", "dom", 5);
        ckpt.record("a", "valid", None);
        ckpt.record("b", "valid", None);
        let all = vec!["a".into(), "b".into(), "c".into(), "d".into()];
        let pending = ckpt.pending(&all);
        assert_eq!(pending, vec!["c", "d"]);
    }

    #[test]
    fn test_checkpoint_path_consistency() {
        let p1 = checkpoint_path(None, "user-enum", "test.dom", "10.0.0.1");
        let p2 = checkpoint_path(None, "user-enum", "test.dom", "10.0.0.1");
        assert_eq!(p1, p2);
    }
}
