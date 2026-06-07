#![no_main]
use libfuzzer_sys::fuzz_target;

/// Fuzz Kerberos ASN.1 message parsing with arbitrary byte sequences.
/// Exercises the kerberos_asn1 crate's parsers for AS-REP, TGS-REP, and KRB-ERROR.
fuzz_target!(|data: &[u8]| {
    // Try parsing as different Kerberos message types
    let _ = kerberos_asn1::KrbError::parse(data);
    let _ = kerberos_asn1::AsRep::parse(data);
    let _ = kerberos_asn1::TgsRep::parse(data);
    let _ = kerberos_asn1::AsReq::parse(data);
    let _ = kerberos_asn1::TgsReq::parse(data);
    let _ = kerberos_asn1::ApReq::parse(data);
});
