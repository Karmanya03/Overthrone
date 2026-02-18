use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum NodeType {
    User(String),
    Computer(String),
    Group(String),
    Domain(String),
    Gpo(String),
    Ou(String),
    CertTemplate(String),
}
