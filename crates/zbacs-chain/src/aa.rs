//! Z-1.H.8 — the owner's smart account, in Rust: everything needed to turn "the owner approved"
//! into a user operation the bundler accepts, without a browser, Node or permissionless.js.
//!
//! The account is ZeroDev Kernel v3.1 (ERC-7579), reached through its meta factory, with the
//! owner's approval key as the root validator — Kernel's WebAuthn validator for the passkey
//! path, Z-BACS's own `P256Validator` for the device-key path (ADR-0006). Every encoding here
//! was derived from the Base Sepolia spike (`spikes/aa-passkey`, `docs/research/aa_passkey_spike.md`)
//! and is tested byte for byte against the vectors permissionless.js produced there, so the
//! Rust side cannot drift from what the chain accepted.
//!
//! Nothing here talks to the network: [`crate::bundler`] does. Nothing here signs: the
//! Agent's `AuthProvider` does, over [`PackedUserOperation::hash`].

use alloy::primitives::{keccak256, Address, Bytes, FixedBytes, B256, U256};
use alloy::sol_types::SolValue;

/// ERC-4337 EntryPoint v0.7, the same address on every chain.
pub const ENTRY_POINT_V07: Address = alloy::primitives::address!("0000000071727De22E5E9d8BAf0edAc6f37da032");

/// Kernel v3.1 as deployed by ZeroDev (same addresses on Base Sepolia and Base).
pub mod kernel_v31 {
    use alloy::primitives::{address, Address};

    /// `KernelFactory` — `createAccount(bytes data, bytes32 salt)`.
    pub const FACTORY: Address = address!("aac5D4240AF87249B3f71BC8E4A2cae074A3E419");
    /// `FactoryStaker` — `deployWithFactory(address factory, bytes createData, bytes32 salt)`;
    /// the `initCode` target, so the bundler sees one whitelisted factory.
    pub const META_FACTORY: Address = address!("d703aaE79538628d27099B8c4f621bE4CCd142d5");
    /// Kernel implementation behind every ERC-1967 clone.
    pub const ACCOUNT_LOGIC: Address = address!("BAC849bB641841b44E965fB01A4Bf5F074f84b4D");
    /// ZeroDev's WebAuthn validator (passkey path).
    pub const WEBAUTHN_VALIDATOR: Address = address!("7ab16Ff354AcB328452F1D445b3Ddee9a91e9e69");
}

/// Which validator is the account's root, and what it needs at install.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RootValidator {
    /// Kernel's WebAuthn validator: the passkey's P-256 public key and its credential id.
    WebAuthn {
        /// Public key x.
        x: [u8; 32],
        /// Public key y.
        y: [u8; 32],
        /// The credential id the authenticator returned, raw bytes.
        credential_id: Vec<u8>,
    },
    /// Z-BACS `P256Validator` (Z-1.H.10): a device-bound P-256 key.
    DeviceKey {
        /// Where `P256Validator` is deployed (per chain, `deployments/<chainId>.json`).
        validator: Address,
        /// Public key x.
        x: [u8; 32],
        /// Public key y.
        y: [u8; 32],
        /// Whether the OS must confirm before this key is used (T23), recorded on chain.
        require_os_confirm: bool,
    },
}

impl RootValidator {
    /// The validator contract.
    pub fn address(&self) -> Address {
        match self {
            Self::WebAuthn { .. } => kernel_v31::WEBAUTHN_VALIDATOR,
            Self::DeviceKey { validator, .. } => *validator,
        }
    }

    /// What Kernel hands the validator's `onInstall`.
    pub fn install_data(&self) -> Bytes {
        match self {
            // permissionless.js: abi.encode((x, y), keccak256(credentialId))
            Self::WebAuthn { x, y, credential_id } => {
                let key = (U256::from_be_bytes(*x), U256::from_be_bytes(*y));
                let id_hash = keccak256(credential_id);
                (key, id_hash).abi_encode().into()
            }
            // P256Validator.onInstall: abi.encodePacked(x, y, requireOsConfirm)
            Self::DeviceKey { x, y, require_os_confirm, .. } => {
                let mut d = Vec::with_capacity(65);
                d.extend_from_slice(x);
                d.extend_from_slice(y);
                d.push(u8::from(*require_os_confirm));
                d.into()
            }
        }
    }
}

/// A Kernel v3.1 account for one owner key, before or after deployment.
#[derive(Clone, Debug)]
pub struct KernelAccount {
    root: RootValidator,
    /// Account index for the same key; 0 for the owner's one account.
    index: u64,
}

/// `initialize(bytes21,address,bytes,bytes,bytes[])` selector.
const INITIALIZE_SELECTOR: [u8; 4] = [0x3c, 0x3b, 0x75, 0x2b];
/// `createAccount(bytes,bytes32)` on the factory is what the meta factory calls; the
/// `initCode` itself targets `deployWithFactory(address,bytes,bytes32)`.
const DEPLOY_WITH_FACTORY_SELECTOR: [u8; 4] = [0xc5, 0x26, 0x5d, 0x5d];
/// ERC-7579 `execute(bytes32 mode, bytes executionCalldata)`.
const EXECUTE_SELECTOR: [u8; 4] = [0xe9, 0xae, 0x5c, 0x53];

impl KernelAccount {
    /// The owner's account for this root validator.
    pub fn new(root: RootValidator) -> Self {
        Self { root, index: 0 }
    }

    /// A further account for the same key.
    pub fn with_index(mut self, index: u64) -> Self {
        self.index = index;
        self
    }

    /// The root validator.
    pub fn root(&self) -> &RootValidator {
        &self.root
    }

    /// Kernel's `initialize` calldata: root validator id (`0x01` type byte + address), no hook,
    /// the validator's install data, no hook data, no init config.
    pub fn initialize_calldata(&self) -> Bytes {
        let mut root_id = [0u8; 21];
        root_id[0] = 0x01; // VALIDATOR_TYPE.VALIDATOR
        root_id[1..].copy_from_slice(self.root.address().as_slice());
        let args = (
            FixedBytes::<21>::from(root_id),
            Address::ZERO,
            self.root.install_data(),
            Bytes::new(),
            Vec::<Bytes>::new(),
        )
            .abi_encode_params();
        let mut out = INITIALIZE_SELECTOR.to_vec();
        out.extend_from_slice(&args);
        out.into()
    }

    /// The `salt` the factory receives (the account index).
    pub fn salt(&self) -> B256 {
        B256::from(U256::from(self.index))
    }

    /// `initCode` for the user operation that deploys the account: meta factory address ++
    /// `deployWithFactory(factory, initialize calldata, salt)`.
    pub fn init_code(&self) -> Bytes {
        let args = (kernel_v31::FACTORY, self.initialize_calldata(), self.salt()).abi_encode_params();
        let mut out = kernel_v31::META_FACTORY.to_vec();
        out.extend_from_slice(&DEPLOY_WITH_FACTORY_SELECTOR);
        out.extend_from_slice(&args);
        out.into()
    }

    /// The counterfactual address: the factory's CREATE2 of a solady ERC-1967 clone of the
    /// Kernel logic, salted with `keccak256(initialize calldata ++ salt)`.
    pub fn address(&self) -> Address {
        let mut salted = self.initialize_calldata().to_vec();
        salted.extend_from_slice(self.salt().as_slice());
        let actual_salt = keccak256(&salted);
        let init_code_hash = erc1967_clone_init_code_hash(kernel_v31::ACCOUNT_LOGIC);
        kernel_v31::FACTORY.create2(actual_salt, init_code_hash)
    }

    /// The 192-bit nonce key Kernel v3 expects for the root validator:
    /// `mode(0x00) ‖ type(0x00) ‖ validator ‖ 0x0000`, then the 64-bit sequence.
    pub fn nonce(&self, sequence: u64) -> U256 {
        let mut key = [0u8; 24];
        key[2..22].copy_from_slice(self.root.address().as_slice());
        let mut n = [0u8; 32];
        n[..24].copy_from_slice(&key);
        n[24..].copy_from_slice(&sequence.to_be_bytes());
        U256::from_be_bytes(n)
    }

    /// `callData` for one call from the account: ERC-7579 single execution, default exec type.
    pub fn execute_call(target: Address, value: U256, data: &[u8]) -> Bytes {
        let mut exec = target.to_vec();
        exec.extend_from_slice(&value.to_be_bytes::<32>());
        exec.extend_from_slice(data);
        let args = (B256::ZERO, Bytes::from(exec)).abi_encode_params();
        let mut out = EXECUTE_SELECTOR.to_vec();
        out.extend_from_slice(&args);
        out.into()
    }
}

/// solady `LibClone.initCodeHashERC1967(implementation)`: the fixed minimal-proxy creation
/// code with the implementation address spliced in.
pub fn erc1967_clone_init_code_hash(implementation: Address) -> B256 {
    let mut code = Vec::with_capacity(95);
    code.extend_from_slice(&[0x60, 0x3d, 0x3d, 0x81, 0x60, 0x22, 0x3d, 0x39, 0x73]);
    code.extend_from_slice(implementation.as_slice());
    code.extend_from_slice(&[0x60, 0x09]);
    code.extend_from_slice(&[
        0x51, 0x55, 0xf3, 0x36, 0x3d, 0x3d, 0x37, 0x3d, 0x3d, 0x36, 0x3d, 0x7f, 0x36, 0x08, 0x94, 0xa1, 0x3b,
        0xa1, 0xa3, 0x21, 0x06, 0x67, 0xc8, 0x28, 0x49, 0x2d, 0xb9, 0x8d, 0xca, 0x3e, 0x20, 0x76,
    ]);
    code.extend_from_slice(&[
        0xcc, 0x37, 0x35, 0xa9, 0x20, 0xa3, 0xca, 0x50, 0x5d, 0x38, 0x2b, 0xbc, 0x54, 0x5a, 0xf4, 0x3d, 0x60,
        0x00, 0x80, 0x3e, 0x60, 0x38, 0x57, 0x3d, 0x60, 0x00, 0xfd, 0x5b, 0x3d, 0x60, 0x00, 0xf3,
    ]);
    keccak256(&code)
}

/// ERC-4337 v0.7 packed user operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackedUserOperation {
    /// The account.
    pub sender: Address,
    /// Kernel nonce (key ‖ sequence).
    pub nonce: U256,
    /// Factory ++ factory calldata for an undeployed account, else empty.
    pub init_code: Bytes,
    /// What the account executes.
    pub call_data: Bytes,
    /// Verification gas limit (upper 128 bits) ‖ call gas limit.
    pub account_gas_limits: B256,
    /// Gas paid before validation.
    pub pre_verification_gas: U256,
    /// Max priority fee (upper 128 bits) ‖ max fee.
    pub gas_fees: B256,
    /// Paymaster address ++ limits ++ data, or empty.
    pub paymaster_and_data: Bytes,
    /// The validator's signature over [`Self::hash`].
    pub signature: Bytes,
}

/// Pack two u128 gas values into one word, the way EntryPoint v0.7 reads them.
pub fn pack_pair(high: u128, low: u128) -> B256 {
    let mut w = [0u8; 32];
    w[..16].copy_from_slice(&high.to_be_bytes());
    w[16..].copy_from_slice(&low.to_be_bytes());
    B256::from(w)
}

impl PackedUserOperation {
    /// `EntryPoint.getUserOpHash`: what the owner's key signs.
    pub fn hash(&self, chain_id: u64, entry_point: Address) -> B256 {
        let inner = (
            self.sender,
            self.nonce,
            keccak256(&self.init_code),
            keccak256(&self.call_data),
            self.account_gas_limits,
            self.pre_verification_gas,
            self.gas_fees,
            keccak256(&self.paymaster_and_data),
        )
            .abi_encode();
        keccak256((keccak256(&inner), entry_point, U256::from(chain_id)).abi_encode())
    }
}

/// Kernel WebAuthn validator signature: `abi.encode(authenticatorData, clientDataJSON,
/// responseTypeLocation, r, s, usePrecompiled)`. Base has the P-256 precompile, so
/// `use_precompiled = true` is the default and saves ~340k gas (spike §2b).
pub fn webauthn_signature(
    authenticator_data: &[u8],
    client_data_json: &str,
    r: [u8; 32],
    s: [u8; 32],
    use_precompiled: bool,
) -> Bytes {
    let type_index = client_data_json.find("\"type\":").unwrap_or(0);
    (
        Bytes::copy_from_slice(authenticator_data),
        client_data_json.to_string(),
        U256::from(type_index),
        U256::from_be_bytes(r),
        U256::from_be_bytes(s),
        use_precompiled,
    )
        .abi_encode_params()
        .into()
}

/// `P256Validator` signature: `abi.encodePacked(keyId, r, s)` (Z-1.H.10).
pub fn p256_raw_signature(key_id: [u8; 32], r: [u8; 32], s: [u8; 32]) -> Bytes {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(&key_id);
    out.extend_from_slice(&r);
    out.extend_from_slice(&s);
    out.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::hex;

    /// The user operation permissionless.js built and Base Sepolia accepted (spike Z-0.H.2).
    fn vector() -> serde_json::Value {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../spikes/aa-passkey/vectors/userop.json");
        serde_json::from_str(&std::fs::read_to_string(path).expect("spike vector")).unwrap()
    }

    fn b64url(s: &str) -> Vec<u8> {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = Vec::new();
        let mut acc: u32 = 0;
        let mut bits = 0;
        for c in s.bytes() {
            let v = T.iter().position(|&t| t == c).expect("base64url") as u32;
            acc = (acc << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
                acc &= (1 << bits) - 1;
            }
        }
        out
    }

    fn account_from_vector(v: &serde_json::Value) -> KernelAccount {
        let pk = &v["passkey"]["publicKey"];
        let x: [u8; 32] = hex::decode(pk["x"].as_str().unwrap()).unwrap().try_into().unwrap();
        let y: [u8; 32] = hex::decode(pk["y"].as_str().unwrap()).unwrap().try_into().unwrap();
        let credential_id = b64url(v["passkey"]["credentialId"].as_str().unwrap());
        KernelAccount::new(RootValidator::WebAuthn { x, y, credential_id })
    }

    fn bytes(v: &serde_json::Value) -> Vec<u8> {
        hex::decode(v.as_str().unwrap()).unwrap()
    }

    #[test]
    fn the_init_code_and_address_match_permissionless() {
        let v = vector();
        let account = account_from_vector(&v);
        assert_eq!(account.init_code().to_vec(), bytes(&v["packed"]["initCode"]), "initCode byte for byte");
        let sender: Address = v["packed"]["sender"].as_str().unwrap().parse().unwrap();
        assert_eq!(account.address(), sender, "the counterfactual address");
        let nonce = U256::from_str_radix(v["packed"]["nonce"].as_str().unwrap().trim_start_matches("0x"), 16)
            .unwrap();
        assert_eq!(account.nonce(0), nonce, "the root validator's nonce key");
    }

    #[test]
    fn the_single_call_matches_permissionless() {
        let v = vector();
        // record(bytes32) on the fixed target the spike used
        let target: Address = v["target"].as_str().unwrap().parse().unwrap();
        let recorded: [u8; 32] = bytes(&v["recorded"]).try_into().unwrap();
        let selector = &keccak256("record(bytes32)")[..4];
        let mut data = selector.to_vec();
        data.extend_from_slice(&recorded);
        assert_eq!(
            KernelAccount::execute_call(target, U256::ZERO, &data).to_vec(),
            bytes(&v["packed"]["callData"])
        );
    }

    #[test]
    fn the_user_op_hash_matches_the_entry_point() {
        let v = vector();
        let p = &v["packed"];
        let op = PackedUserOperation {
            sender: p["sender"].as_str().unwrap().parse().unwrap(),
            nonce: U256::from_str_radix(p["nonce"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap(),
            init_code: bytes(&p["initCode"]).into(),
            call_data: bytes(&p["callData"]).into(),
            account_gas_limits: B256::from_slice(&bytes(&p["accountGasLimits"])),
            pre_verification_gas: U256::from_str_radix(
                p["preVerificationGas"].as_str().unwrap().trim_start_matches("0x"),
                16,
            )
            .unwrap(),
            gas_fees: B256::from_slice(&bytes(&p["gasFees"])),
            paymaster_and_data: Bytes::new(),
            signature: Bytes::new(),
        };
        let expected = B256::from_slice(&bytes(&v["userOpHash"]));
        assert_eq!(op.hash(v["chainId"].as_u64().unwrap(), ENTRY_POINT_V07), expected);
        assert_eq!(pack_pair(1_500_000, 300_000), op.account_gas_limits, "gas limits pack the same way");
    }

    #[test]
    fn the_webauthn_signature_encoding_round_trips_the_vector() {
        let v = vector();
        let sig = bytes(&v["packed"]["signature"]);
        type Enc = (Bytes, String, U256, U256, U256, bool);
        let (ad, cdj, loc, r, s, pre) = <Enc as SolValue>::abi_decode_params(&sig).unwrap();
        assert!(!pre, "permissionless hard-codes usePrecompiled=false");
        assert_eq!(loc, U256::from(cdj.find("\"type\":").unwrap()));
        let ours = webauthn_signature(&ad, &cdj, r.to_be_bytes(), s.to_be_bytes(), false);
        assert_eq!(ours.to_vec(), sig);
        let precompiled = bytes(&v["signaturePrecompiled"]);
        assert_eq!(
            webauthn_signature(&ad, &cdj, r.to_be_bytes(), s.to_be_bytes(), true).to_vec(),
            precompiled
        );
    }

    #[test]
    fn the_device_key_install_data_is_what_p256validator_reads() {
        let root = RootValidator::DeviceKey {
            validator: Address::repeat_byte(0x11),
            x: [1; 32],
            y: [2; 32],
            require_os_confirm: true,
        };
        let data = root.install_data();
        assert_eq!(data.len(), 65);
        assert_eq!(&data[..32], &[1; 32]);
        assert_eq!(&data[32..64], &[2; 32]);
        assert_eq!(data[64], 1);
        let account = KernelAccount::new(root.clone());
        assert_eq!(&account.nonce(7).to_be_bytes::<32>()[2..22], Address::repeat_byte(0x11).as_slice());
        assert_eq!(account.nonce(7).to_be_bytes::<32>()[31], 7);
        assert_ne!(
            account.address(),
            KernelAccount::new(root).with_index(1).address(),
            "index changes the address"
        );
        assert_eq!(p256_raw_signature([3; 32], [4; 32], [5; 32]).len(), 96);
    }
}
