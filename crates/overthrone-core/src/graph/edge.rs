use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EdgeType {
    // Group membership
    MemberOf,
    
    // Administrative access
    AdminTo,
    
    // Session-based
    HasSession,
    
    // Remote access
    CanRDP,
    CanPSRemote,
    ExecuteDCOM,
    
    // ACL-based edges (traversable in graph)
    GenericAll,
    GenericWrite,
    WriteDacl,
    WriteOwner,
    ForceChangePassword,
    AddMember,        // Alias: AddMembers
    AllExtendedRights,
    Owns,
    ReadLapsPassword,
    ReadGmsaPassword,
    
    // Container/OU
    Contains,
    GpLink,
    
    // Trusts
    TrustedBy,
    
    // Delegation
    AllowedToDelegate,
    AllowedToAct,
    
    // Kerberos attack surfaces
    HasSPN,
    DontReqPreauth,
    
    // ADCS
    EnrollOnBehalfOf,
    
    // Custom/extended edge type
    Custom(String),
}

impl EdgeType {
    /// Check if this edge type is traversable in attack path finding.
    /// ACL-based edges are all traversable and should be followed.
    pub fn is_traversable(&self) -> bool {
        matches!(
            self,
            EdgeType::MemberOf
                | EdgeType::AdminTo
                | EdgeType::HasSession
                | EdgeType::GenericAll
                | EdgeType::GenericWrite
                | EdgeType::WriteDacl
                | EdgeType::WriteOwner
                | EdgeType::ForceChangePassword
                | EdgeType::AddMember
                | EdgeType::AllExtendedRights
                | EdgeType::Owns
                | EdgeType::ReadLapsPassword
                | EdgeType::ReadGmsaPassword
                | EdgeType::AllowedToDelegate
                | EdgeType::AllowedToAct
        )
    }
    
    /// Get the attack cost for this edge type (lower = easier).
    /// Used by Dijkstra pathfinding to prefer certain attack paths.
    pub fn attack_cost(&self) -> u32 {
        match self {
            // Direct access - cheapest
            EdgeType::AdminTo => 1,
            EdgeType::HasSession => 2,
            
            // Group membership - very important
            EdgeType::MemberOf => 1,
            
            // Powerful ACL rights
            EdgeType::GenericAll => 2,
            EdgeType::Owns => 2,
            EdgeType::WriteDacl => 3,
            EdgeType::WriteOwner => 3,
            
            // Moderate ACL rights
            EdgeType::GenericWrite => 4,
            EdgeType::ForceChangePassword => 4,
            EdgeType::AddMember => 4,
            EdgeType::AllExtendedRights => 4,
            
            // Password reading
            EdgeType::ReadLapsPassword => 3,
            EdgeType::ReadGmsaPassword => 3,
            
            // Delegation
            EdgeType::AllowedToDelegate => 3,
            EdgeType::AllowedToAct => 4,
            
            // Remote access
            EdgeType::CanRDP => 5,
            EdgeType::CanPSRemote => 5,
            EdgeType::ExecuteDCOM => 5,
            
            // Container/OU
            EdgeType::Contains => 1,
            EdgeType::GpLink => 2,
            
            // Trust
            EdgeType::TrustedBy => 3,
            
            // Kerberos attack surfaces
            EdgeType::HasSPN => 3,
            EdgeType::DontReqPreauth => 2,
            
            // ADCS
            EdgeType::EnrollOnBehalfOf => 4,
            
            // Custom edges
            EdgeType::Custom(_) => 5,
        }
    }
}

impl std::fmt::Display for EdgeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EdgeType::Custom(s) => write!(f, "{}", s),
            _ => write!(f, "{:?}", self),
        }
    }
}
