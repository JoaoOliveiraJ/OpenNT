//! Catálogo do Microsoft Primitive Provider — `system32/ntos/cm/primitive-provider.js`.
//!
//! Metadados públicos do catálogo criptográfico da instalação Windows dos
//! binários: nomes, modalidades e módulos, com os identificadores oficiais
//! de interface e algoritmo. Nenhuma entrada contém chaves ou recipientes.

pub struct Interface {
    pub id: &'static str,
    pub name: &'static str,
    pub flags: u32,
    pub functions: &'static [&'static str],
}

pub struct Mode {
    pub mode: &'static str,
    pub image: &'static str,
    pub interfaces: &'static [Interface],
}

const CIPHERS: &[&str] = &["AES", "3DES", "3DES_112", "XTS-AES", "DESX", "DES", "RC2", "RC4"];
const HASHES: &[&str] = &["SHA256", "SHA384", "SHA512", "SHA1", "MD5", "MD4", "MD2", "AES-GMAC", "AES-CMAC"];
const ASYMMETRIC: &[&str] = &["RSA"];
const AGREEMENT: &[&str] = &["DH", "ECDH_P256", "ECDH_P384", "ECDH_P521", "ECDH"];
const RNG: &[&str] = &["RNG", "FIPS186DSARNG", "DUALECRNG"];
const KEY_DERIVATION: &[&str] = &["SP800_108_CTR_HMAC", "SP800_56A_CONCAT", "PBKDF2", "CAPI_KDF", "TLS1_1_KDF", "TLS1_2_KDF", "HKDF"];

/// Provedor de usuário (bcryptprimitives.dll) e o catálogo de kernel
/// (cng.sys); a presença é inscrição de configuração, não prova de execução.
pub const PROVIDERS: &[Mode] = &[
    Mode {
        mode: "UM",
        image: "bcryptprimitives.dll",
        interfaces: &[
            Interface { id: "00000001", name: "CRYPT_CIPHER_INTERFACE", flags: 1, functions: CIPHERS },
            Interface { id: "00000002", name: "CRYPT_HASH_INTERFACE", flags: 1, functions: HASHES },
            Interface { id: "00000003", name: "CRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE", flags: 1, functions: ASYMMETRIC },
            Interface { id: "00000004", name: "CRYPT_SECRET_AGREEMENT_INTERFACE", flags: 1, functions: AGREEMENT },
            Interface { id: "00000005", name: "CRYPT_SIGNATURE_INTERFACE", flags: 1, functions: &["RSA_SIGN", "ECDSA_P256", "ECDSA_P384", "ECDSA_P521", "ECDSA", "DSA"] },
            Interface { id: "00000006", name: "CRYPT_RNG_INTERFACE", flags: 1, functions: RNG },
            Interface { id: "00000007", name: "CRYPT_KEY_DERIVATION_INTERFACE", flags: 1, functions: KEY_DERIVATION },
        ],
    },
    Mode {
        mode: "KM",
        image: "cng.sys",
        interfaces: &[
            Interface { id: "00000001", name: "CRYPT_CIPHER_INTERFACE", flags: 1, functions: CIPHERS },
            Interface { id: "00000002", name: "CRYPT_HASH_INTERFACE", flags: 1, functions: HASHES },
            Interface { id: "00000003", name: "CRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE", flags: 1, functions: ASYMMETRIC },
            Interface { id: "00000004", name: "CRYPT_SECRET_AGREEMENT_INTERFACE", flags: 1, functions: AGREEMENT },
            Interface { id: "00000005", name: "CRYPT_SIGNATURE_INTERFACE", flags: 1, functions: &["RSA_SIGN", "ECDSA_P256", "ECDSA_P384", "ECDSA_P521", "ECDSA"] },
            Interface { id: "00000006", name: "CRYPT_RNG_INTERFACE", flags: 1, functions: RNG },
            Interface { id: "00000007", name: "CRYPT_KEY_DERIVATION_INTERFACE", flags: 1, functions: KEY_DERIVATION },
        ],
    },
];
