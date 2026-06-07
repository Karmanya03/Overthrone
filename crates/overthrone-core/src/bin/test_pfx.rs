#![doc = "Test binary for PFX/keystore certificate loading."]

use p12_keystore::KeyStore;

fn main() {
    let _store = KeyStore::new();
}
