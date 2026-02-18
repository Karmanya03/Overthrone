use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EdgeType {
    MemberOf,
    AdminTo,
    HasSession,
    CanRDP,
    CanPSRemote,
    ExecuteDCOM,
    GenericAll,
    GenericWrite,
    WriteDacl,
    WriteOwner,
    ForceChangePassword,
    AddMember,
    AllExtendedRights,
    Owns,
    Contains,
    GpLink,
    TrustedBy,
    AllowedToDelegate,
    AllowedToAct,
    HasSPN,
    DontReqPreauth,
    EnrollOnBehalfOf,
}
