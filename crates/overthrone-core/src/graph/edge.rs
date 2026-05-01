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
    SQLAdmin,
    
    // ACL-based edges (traversable in graph)
    GenericAll,
    GenericWrite,
    WriteDacl,
    WriteOwner,
    AddSelf,
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
    
    // Marker edges
    HasSidHistory,
    DcSync,
    GetChanges,
    GetChangesAll,
    
    // Kerberos attack surfaces
    HasSPN,
    DontReqPreauth,
    
    // ADCS
    EnrollOnBehalfOf,
    
    // Attribute-level WriteProperty edges
    WriteSPN,
    WriteAllowedToDelegateTo,
    AddAllowedToAct,
    WriteAccountRestrictions,
    WriteLogonScript,
    WriteProfilePath,
    WriteScriptPath,
    WriteDnsHostName,
    WriteServicePrincipalName,
    WriteKeyCredentialLink,
    WriteMsDsKeyCredentialLink,
    WriteAltSecurityIdentities,
    WriteUserParameters,
    WritePwdProperties,
    WriteLockoutThreshold,
    WriteMinPwdLength,
    WritePwdHistoryLength,
    WritePwdComplexity,
    WritePwdReversibleEncryption,
    WritePwdAge,
    WriteLockoutDuration,
    WriteLockoutObservationWindow,
    WriteGPLink,
    AddKeyCredentialLink,
    
    // Custom/extended edge type
    Custom(String),
}

impl EdgeType {
    /// Check if this edge type is traversable in attack path finding.
    /// ACL-based edges are all traversable and should be followed.
    /// Marker edges (HasSpn, DontReqPreauth, HasSidHistory, etc.) are NOT traversable.
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
                | EdgeType::AddSelf
                | EdgeType::Owns
                | EdgeType::ReadLapsPassword
                | EdgeType::ReadGmsaPassword
                | EdgeType::AllowedToDelegate
                | EdgeType::AllowedToAct
                | EdgeType::WriteSPN
                | EdgeType::WriteAllowedToDelegateTo
                | EdgeType::AddAllowedToAct
                | EdgeType::WriteAccountRestrictions
                | EdgeType::WriteLogonScript
                | EdgeType::WriteProfilePath
                | EdgeType::WriteScriptPath
                | EdgeType::WriteDnsHostName
                | EdgeType::WriteServicePrincipalName
                | EdgeType::WriteKeyCredentialLink
                | EdgeType::WriteMsDsKeyCredentialLink
                | EdgeType::WriteAltSecurityIdentities
                | EdgeType::WriteUserParameters
                | EdgeType::WritePwdProperties
                | EdgeType::WriteLockoutThreshold
                | EdgeType::WriteMinPwdLength
                | EdgeType::WritePwdHistoryLength
                | EdgeType::WritePwdComplexity
                | EdgeType::WritePwdReversibleEncryption
                | EdgeType::WritePwdAge
                | EdgeType::WriteLockoutDuration
                | EdgeType::WriteLockoutObservationWindow
                | EdgeType::WriteGPLink
                | EdgeType::AddKeyCredentialLink
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
            EdgeType::AddSelf => 4,
            
            // Password reading
            EdgeType::ReadLapsPassword => 3,
            EdgeType::ReadGmsaPassword => 3,
            
            // Delegation
            EdgeType::AllowedToDelegate => 3,
            EdgeType::AllowedToAct => 4,
            
            // Attribute-level write properties
            EdgeType::WriteSPN => 2,
            EdgeType::WriteAllowedToDelegateTo => 1,
            EdgeType::AddAllowedToAct => 1,
            EdgeType::WriteAccountRestrictions => 1,
            EdgeType::WriteLogonScript => 3,
            EdgeType::WriteProfilePath => 3,
            EdgeType::WriteScriptPath => 2,
            EdgeType::WriteDnsHostName => 2,
            EdgeType::WriteServicePrincipalName => 2,
            EdgeType::WriteKeyCredentialLink => 2,
            EdgeType::WriteMsDsKeyCredentialLink => 2,
            EdgeType::WriteAltSecurityIdentities => 1,
            EdgeType::WriteUserParameters => 2,
            EdgeType::WritePwdProperties => 1,
            EdgeType::WriteLockoutThreshold => 1,
            EdgeType::WriteMinPwdLength => 1,
            EdgeType::WritePwdHistoryLength => 1,
            EdgeType::WritePwdComplexity => 1,
            EdgeType::WritePwdReversibleEncryption => 1,
            EdgeType::WritePwdAge => 1,
            EdgeType::WriteLockoutDuration => 1,
            EdgeType::WriteLockoutObservationWindow => 1,
            EdgeType::WriteGPLink => 3,
            EdgeType::AddKeyCredentialLink => 2,
            
            // Remote access
            EdgeType::CanRDP => 5,
            EdgeType::CanPSRemote => 5,
            EdgeType::ExecuteDCOM => 5,
            
            // Container/OU
            EdgeType::Contains => 1,
            EdgeType::GpLink => 2,
            
            // Trust
            EdgeType::TrustedBy => 3,
            
            // Marker edges
            EdgeType::HasSidHistory => 2,
            EdgeType::DcSync => 1,
            EdgeType::GetChanges => 2,
            EdgeType::GetChangesAll => 2,
            
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
