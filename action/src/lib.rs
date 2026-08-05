#![no_std]

extern crate alloc;

mod confirmation;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use anyhow::{anyhow, Result};
use oskey_chain::eth::{Eip2930Transaction, OSKeyTxEip191, OSKeyTxEip2930};
pub use oskey_chain::{ConfirmationDetails, FidoOperation};
use oskey_protocol::proto::{req_data, res_data};
pub use oskey_protocol::{proto, FrameParser};
use oskey_wallet::alg::crypto;
use oskey_wallet::path::DerivationPath;
use oskey_wallet::{mnemonic, wallets};
use zeroize::{Zeroize, Zeroizing};

pub use confirmation::PreparedResult;
use confirmation::{ConfirmationService, PendingConfirmation};

const PIN_SALT: &[u8] = b"&%OSKey1$!@";
const MAX_FAILED_UNLOCKS: u8 = 10;
const STORED_SEED_BYTES: usize = 92;

fn mnemonic_entropy_bytes(words: u32) -> Result<usize> {
    match words {
        12 => Ok(16),
        15 => Ok(20),
        18 => Ok(24),
        21 => Ok(28),
        24 => Ok(32),
        _ => Err(anyhow!("Invalid mnemonic length")),
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    Uart,
    Bluetooth,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportRoute {
    pub transport: Transport,
    pub session_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalRequestKind {
    Unlock,
    InitCustom,
    GenerateMnemonic,
    Restart,
    ResetStorage,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FidoRequestKind {
    Register,
    Validate,
    Sign,
    Confirm,
    CancelConfirmation,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FidoStatus {
    Success,
    Failed,
    Cancelled,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalAction {
    Ready,
    Mnemonic,
    Error,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfirmationChoice {
    Approve,
    Reject,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfirmationOutcome {
    Approved,
    Rejected,
    Cancelled,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletState {
    Disabled,
    Setup,
    Locked,
    Ready,
    Busy,
}

pub enum LocalRequest<'a> {
    Unlock(&'a str),
    InitCustom {
        words: &'a str,
        passphrase: &'a str,
        pin: &'a str,
    },
    GenerateMnemonic {
        words: u32,
        entropy: &'a [u8],
    },
    Restart,
    ResetStorage,
}

pub enum FidoRequest<'a> {
    Register {
        rp_id: &'a str,
        cred_protect: u8,
    },
    Validate {
        credential_id: &'a [u8],
        rp_id_hash: &'a [u8],
    },
    Sign {
        credential_id: &'a [u8],
        rp_id_hash: &'a [u8],
        hash: &'a [u8],
        preflight: bool,
    },
    Confirm {
        operation: FidoOperation,
        rp_id: &'a [u8],
        account: &'a [u8],
    },
    CancelConfirmation,
}

#[derive(Debug, Eq, PartialEq)]
pub struct LocalResult {
    pub action: LocalAction,
    pub error: proto::AppError,
    pub value: u32,
    pub text: String,
}

#[derive(Debug, Eq, PartialEq)]
pub struct FidoOutput {
    pub status: FidoStatus,
    pub credential_id: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub enum CoreEffect {
    Transport(TransportRoute, proto::ResData),
    Local(LocalResult),
    Fido {
        id: u32,
        result: FidoOutput,
    },
    ConfirmationRequired(u32),
    ConfirmationCompleted {
        id: u32,
        outcome: ConfirmationOutcome,
    },
    WalletState(WalletState),
}

pub enum CoreRequest<'a> {
    Protocol {
        route: TransportRoute,
        request: proto::ReqData,
    },
    ProtocolError {
        route: TransportRoute,
    },
    Local(LocalRequest<'a>),
    Fido {
        id: u32,
        request: FidoRequest<'a>,
    },
    Confirm {
        id: u32,
        choice: ConfirmationChoice,
    },
}

pub trait WalletPlatform {
    fn version(&self) -> String;
    fn serial_number(&self) -> String;
    fn support_mask(&self) -> Vec<u8>;
    fn local_ui_enabled(&self) -> bool;
    fn storage_ready(&self) -> bool;
    fn seed_exists(&self) -> Result<bool>;
    fn random(&self, len: usize) -> Vec<u8>;
    fn read_seed(&self, data: &mut [u8]) -> Result<usize>;
    fn write_seed(&self, data: &[u8]) -> Result<()>;
    fn unlock_failures(&self) -> Result<u8>;
    fn write_unlock_failures(&self, failures: u8) -> bool;
    fn recover_fido_pin(&self);
    fn reset_storage(&self) -> bool;
    fn restart(&self);
}

struct PendingSign {
    id: i32,
    reply_to: TransportRoute,
}

enum PendingAction {
    Sign(PendingSign),
    Fido(u32),
}

enum UnlockFailure {
    Attempts(u8),
    Reset,
    Storage,
}

enum SeedLoadError {
    Credentials,
    Storage,
}

pub struct WalletRuntime<P> {
    platform: P,
    pin_cache: [u8; 32],
    locked: bool,
    failed_unlocks: u8,
    storage_failed: bool,
    confirmation: ConfirmationService<PendingAction>,
    authorized_fido: Option<PendingConfirmation<PendingAction>>,
}

impl<P> Drop for WalletRuntime<P> {
    fn drop(&mut self) {
        self.pin_cache.zeroize();
    }
}

impl<P: WalletPlatform> WalletRuntime<P> {
    pub fn new(platform: P) -> Self {
        let (mut locked, mut failed_unlocks, storage_failed) = match platform.seed_exists() {
            Ok(false) => (false, 0, false),
            Ok(true) => match platform.unlock_failures() {
                Ok(failures) => (true, failures.min(MAX_FAILED_UNLOCKS), false),
                Err(_) => (true, MAX_FAILED_UNLOCKS, true),
            },
            Err(_) => (true, MAX_FAILED_UNLOCKS, true),
        };

        if locked
            && !storage_failed
            && failed_unlocks >= MAX_FAILED_UNLOCKS
            && platform.reset_storage()
        {
            locked = false;
            failed_unlocks = 0;
        }

        Self {
            platform,
            pin_cache: [0; 32],
            locked,
            failed_unlocks,
            storage_failed,
            confirmation: ConfirmationService::new(),
            authorized_fido: None,
        }
    }

    pub fn confirmation(&self, id: u32) -> Option<(&ConfirmationDetails, Option<&PreparedResult>)> {
        self.confirmation.get(id)
    }

    pub fn handle(&mut self, request: CoreRequest<'_>) -> Vec<CoreEffect> {
        match request {
            CoreRequest::Protocol { route, request: _ } if self.is_busy() => {
                self.transport_error_output(route, proto::AppError::Busy)
            }
            CoreRequest::Protocol { route, request } => self.handle_protocol(route, request),
            CoreRequest::ProtocolError { route } => {
                self.transport_error_output(route, proto::AppError::Failed)
            }
            CoreRequest::Local(request) => self.handle_local(request),
            CoreRequest::Fido { id, request } => self.handle_fido(id, request),
            CoreRequest::Confirm { id, choice } => self.handle_confirmation(id, choice),
        }
    }

    fn is_busy(&self) -> bool {
        self.confirmation.is_waiting() || self.authorized_fido.is_some()
    }

    pub fn state(&self) -> WalletState {
        let Ok(seed_exists) = self.seed_exists() else {
            return WalletState::Disabled;
        };

        if self.is_busy() {
            WalletState::Busy
        } else if !seed_exists {
            WalletState::Setup
        } else if self.locked {
            WalletState::Locked
        } else {
            WalletState::Ready
        }
    }

    fn handle_protocol(
        &mut self,
        route: TransportRoute,
        request: proto::ReqData,
    ) -> Vec<CoreEffect> {
        let Some(payload) = request.payload else {
            return self.transport_reply(route, res_data::Payload::Unknown(proto::Unknown {}));
        };

        match payload {
            req_data::Payload::Unknown(_) => {
                self.transport_reply(route, res_data::Payload::Unknown(proto::Unknown {}))
            }
            req_data::Payload::VersionRequest(_) => {
                let features = proto::Features {
                    initialized: self.seed_exists().unwrap_or(true),
                    support_mask: self.platform.support_mask(),
                };
                self.transport_reply(
                    route,
                    res_data::Payload::VersionResponse(proto::VersionResponse {
                        version: self.platform.version(),
                        features: Some(features),
                        sn: self.platform.serial_number(),
                    }),
                )
            }
            req_data::Payload::StatusRequest(_) => {
                self.transport_reply(route, self.status_response())
            }
            req_data::Payload::LockRequest(_) => {
                self.locked = true;
                self.pin_cache.zeroize();
                vec![
                    Self::transport(route, self.status_response()),
                    CoreEffect::WalletState(self.state()),
                ]
            }
            req_data::Payload::UnlockRequest(request) => {
                self.handle_external_unlock(route, request)
            }
            req_data::Payload::InitRequest(request) => self.handle_external_init(route, request),
            req_data::Payload::InitCustomRequest(request) => {
                self.handle_external_init_custom(route, request)
            }
            req_data::Payload::DerivePublicKeyRequest(request) => {
                if self.locked {
                    return self.transport_error_output(route, proto::AppError::Locked);
                }
                match self.derive_public_key(request) {
                    Ok(payload) => self.transport_reply(route, payload),
                    Err(_) => self.transport_error_output(route, proto::AppError::Failed),
                }
            }
            req_data::Payload::SignEthRequest(request) => self.handle_sign_request(route, request),
        }
    }

    fn handle_local(&mut self, request: LocalRequest<'_>) -> Vec<CoreEffect> {
        if self.is_busy() {
            return vec![Self::local_error(proto::AppError::Busy, 0)];
        }

        match request {
            LocalRequest::Unlock(pin) => self.handle_local_unlock(pin),
            LocalRequest::InitCustom {
                words,
                passphrase,
                pin,
            } => self.handle_local_init_custom(words, passphrase, pin),
            LocalRequest::GenerateMnemonic { words, entropy } => {
                self.handle_generate_mnemonic(words, entropy)
            }
            LocalRequest::Restart => {
                self.platform.restart();
                Vec::new()
            }
            LocalRequest::ResetStorage => {
                if self.platform.reset_storage() {
                    self.storage_reset_succeeded();
                    vec![CoreEffect::WalletState(WalletState::Setup)]
                } else {
                    vec![Self::local_error(proto::AppError::Failed, 0)]
                }
            }
        }
    }

    fn handle_fido(&mut self, id: u32, request: FidoRequest<'_>) -> Vec<CoreEffect> {
        if self.confirmation.is_waiting() {
            if matches!(request, FidoRequest::CancelConfirmation) {
                return self.cancel_fido_confirmation(id);
            }
            return vec![Self::fido(id, Self::fido_error())];
        }

        match request {
            FidoRequest::Register {
                rp_id,
                cred_protect,
            } => self.handle_fido_register(id, rp_id, cred_protect),
            FidoRequest::Validate {
                credential_id,
                rp_id_hash,
            } => self.handle_fido_credential(id, credential_id, rp_id_hash, None, false),
            FidoRequest::Sign {
                credential_id,
                rp_id_hash,
                hash,
                preflight,
            } => self.handle_fido_credential(id, credential_id, rp_id_hash, Some(hash), preflight),
            FidoRequest::Confirm {
                operation,
                rp_id,
                account,
            } => self.start_fido_confirmation(id, operation, rp_id, account),
            FidoRequest::CancelConfirmation => Vec::new(),
        }
    }

    fn handle_confirmation(&mut self, id: u32, choice: ConfirmationChoice) -> Vec<CoreEffect> {
        let Some(pending) = self.confirmation.finish(id) else {
            return Vec::new();
        };

        let mut outputs = Vec::new();
        let completed = if matches!(&pending.action, PendingAction::Sign(_)) {
            self.handle_sign_decision(pending, choice, &mut outputs)
        } else {
            self.handle_fido_decision(pending, choice, &mut outputs)
        };
        if completed {
            outputs.push(CoreEffect::ConfirmationCompleted {
                id,
                outcome: match choice {
                    ConfirmationChoice::Approve => ConfirmationOutcome::Approved,
                    ConfirmationChoice::Reject => ConfirmationOutcome::Rejected,
                },
            });
        }

        outputs.push(CoreEffect::WalletState(self.state()));
        outputs
    }

    fn handle_sign_decision(
        &mut self,
        mut pending: PendingConfirmation<PendingAction>,
        choice: ConfirmationChoice,
        outputs: &mut Vec<CoreEffect>,
    ) -> bool {
        let PendingAction::Sign(sign) = &pending.action else {
            unreachable!();
        };
        if choice == ConfirmationChoice::Reject {
            outputs.insert(
                0,
                Self::transport_error(sign.reply_to, proto::AppError::Rejected),
            );
            return true;
        }

        if pending.prepared.is_none() {
            let Ok(prepared) = self.prepare_signature(&pending.review) else {
                outputs.insert(
                    0,
                    Self::transport_error(sign.reply_to, proto::AppError::Failed),
                );
                return true;
            };
            pending.prepared = Some(prepared);
            let id = pending.id;
            assert!(self.confirmation.restore(pending));
            outputs.push(CoreEffect::ConfirmationRequired(id));
            return false;
        }

        let PendingAction::Sign(sign) = pending.action else {
            unreachable!();
        };
        let signing_hash = match pending.review {
            ConfirmationDetails::EthMessage(details) => details.signing_hash,
            ConfirmationDetails::EthTransaction(details) => details.signing_hash,
            ConfirmationDetails::Fido(_) => unreachable!(),
        };
        let prepared = pending.prepared.expect("prepared result was checked above");
        outputs.insert(
            0,
            Self::transport(
                sign.reply_to,
                res_data::Payload::SignResponse(proto::SignResponse {
                    id: sign.id,
                    message: Vec::new(),
                    public_key: prepared.public_key,
                    pre_hash: signing_hash.to_vec(),
                    signature: prepared.signature,
                    recovery_id: None,
                }),
            ),
        );
        true
    }

    fn handle_fido_decision(
        &mut self,
        mut pending: PendingConfirmation<PendingAction>,
        choice: ConfirmationChoice,
        outputs: &mut Vec<CoreEffect>,
    ) -> bool {
        let PendingAction::Fido(request_id) = &pending.action else {
            unreachable!();
        };
        let request_id = *request_id;
        let ConfirmationDetails::Fido(details) = &pending.review else {
            unreachable!();
        };
        if choice == ConfirmationChoice::Reject {
            outputs.insert(0, Self::fido(request_id, Self::fido_error()));
            true
        } else if matches!(
            details.operation,
            FidoOperation::Register | FidoOperation::Authenticate
        ) && pending.prepared.is_none()
        {
            self.authorized_fido = Some(pending);
            outputs.insert(
                0,
                Self::fido(
                    request_id,
                    FidoOutput {
                        status: FidoStatus::Success,
                        credential_id: Vec::new(),
                        data: Vec::new(),
                    },
                ),
            );
            false
        } else {
            let prepared = pending.prepared.take().unwrap_or_default();
            let output = match details.operation {
                FidoOperation::Register => FidoOutput {
                    status: FidoStatus::Success,
                    credential_id: prepared.credential_id,
                    data: prepared.public_key,
                },
                FidoOperation::Authenticate => FidoOutput {
                    status: FidoStatus::Success,
                    credential_id: Vec::new(),
                    data: prepared.signature,
                },
                _ => FidoOutput {
                    status: FidoStatus::Success,
                    credential_id: Vec::new(),
                    data: Vec::new(),
                },
            };
            outputs.insert(0, Self::fido(request_id, output));
            true
        }
    }

    fn status_response(&self) -> res_data::Payload {
        let mut status_mask = vec![0; 16];
        status_mask[0] = self.platform.storage_ready() as u8;
        status_mask[1] = self.locked as u8;
        res_data::Payload::StatusResponse(proto::StatusResponse { status_mask })
    }

    fn handle_external_unlock(
        &mut self,
        route: TransportRoute,
        mut request: proto::UnlockRequest,
    ) -> Vec<CoreEffect> {
        let effects = match self.seed_exists() {
            Err(_) => self.transport_error_output(route, proto::AppError::Failed),
            Ok(false) => self.transport_error_output(route, proto::AppError::InvalidAction),
            Ok(true) if self.platform.local_ui_enabled() => {
                self.transport_error_output(route, proto::AppError::DisplayRequired)
            }
            Ok(true) if request.hash.len() != 32 => {
                self.transport_error_output(route, proto::AppError::InvalidAction)
            }
            Ok(true) if self.failed_unlocks >= MAX_FAILED_UNLOCKS => {
                self.transport_error_output(route, proto::AppError::Failed)
            }
            Ok(true) => {
                let result = self
                    .set_pin_hash(&request.hash)
                    .map_err(|_| SeedLoadError::Storage)
                    .and_then(|_| self.load_seed_classified().map(|_| ()));

                match self.complete_unlock(result) {
                    Ok(()) => {
                        vec![
                            Self::transport(route, self.status_response()),
                            CoreEffect::WalletState(WalletState::Ready),
                        ]
                    }
                    Err(UnlockFailure::Reset) => vec![
                        Self::transport_error(route, proto::AppError::Failed),
                        CoreEffect::WalletState(WalletState::Setup),
                    ],
                    Err(_) => vec![
                        Self::transport_error(route, proto::AppError::Failed),
                        CoreEffect::WalletState(WalletState::Locked),
                    ],
                }
            }
        };
        request.hash.zeroize();
        effects
    }

    fn handle_local_unlock(&mut self, pin: &str) -> Vec<CoreEffect> {
        match self.seed_exists() {
            Err(_) => return vec![Self::local_error(proto::AppError::Failed, 0)],
            Ok(false) => return vec![Self::local_error(proto::AppError::InvalidAction, 0)],
            Ok(true) => {}
        }

        if self.failed_unlocks >= MAX_FAILED_UNLOCKS {
            return vec![Self::local_error(
                proto::AppError::UnlockFailed,
                MAX_FAILED_UNLOCKS.into(),
            )];
        }

        let result = self
            .set_pin_text(pin)
            .map_err(|_| SeedLoadError::Storage)
            .and_then(|_| self.load_seed_classified().map(|_| ()));

        match self.complete_unlock(result) {
            Ok(()) => {
                vec![
                    Self::local(LocalAction::Ready, String::new()),
                    CoreEffect::WalletState(WalletState::Ready),
                ]
            }
            Err(UnlockFailure::Attempts(failures)) => {
                vec![
                    Self::local_error(proto::AppError::UnlockFailed, failures.into()),
                    CoreEffect::WalletState(WalletState::Locked),
                ]
            }
            Err(UnlockFailure::Reset) => vec![
                Self::local_error(proto::AppError::UnlockFailed, MAX_FAILED_UNLOCKS.into()),
                CoreEffect::WalletState(WalletState::Setup),
            ],
            Err(UnlockFailure::Storage) => {
                vec![
                    Self::local_error(proto::AppError::Failed, 0),
                    CoreEffect::WalletState(WalletState::Locked),
                ]
            }
        }
    }

    fn complete_unlock(
        &mut self,
        result: core::result::Result<(), SeedLoadError>,
    ) -> core::result::Result<(), UnlockFailure> {
        if result.is_ok() {
            if self.platform.write_unlock_failures(0) {
                self.locked = false;
                self.failed_unlocks = 0;
                self.platform.recover_fido_pin();
                return Ok(());
            }

            self.locked = true;
            self.pin_cache.zeroize();
            return Err(UnlockFailure::Storage);
        }

        self.locked = true;
        self.pin_cache.zeroize();
        if matches!(result, Err(SeedLoadError::Storage)) {
            return Err(UnlockFailure::Storage);
        }
        let failures = self.failed_unlocks.saturating_add(1);
        if !self.platform.write_unlock_failures(failures) {
            return Err(UnlockFailure::Storage);
        }
        self.failed_unlocks = failures;
        if self.failed_unlocks >= MAX_FAILED_UNLOCKS {
            if !self.platform.reset_storage() {
                return Err(UnlockFailure::Storage);
            }
            self.storage_reset_succeeded();
            return Err(UnlockFailure::Reset);
        }
        Err(UnlockFailure::Attempts(self.failed_unlocks))
    }

    fn storage_reset_succeeded(&mut self) {
        self.pin_cache.zeroize();
        self.storage_failed = false;
        self.locked = false;
        self.failed_unlocks = 0;
    }

    fn handle_generate_mnemonic(&self, words: u32, entropy: &[u8]) -> Vec<CoreEffect> {
        let result: Result<String> = (|| {
            let entropy_len = mnemonic_entropy_bytes(words)?;
            let entropy = Zeroizing::new(if entropy.is_empty() {
                self.platform.random(entropy_len)
            } else {
                if entropy.len() != entropy_len {
                    return Err(anyhow!("Invalid entropy length"));
                }
                entropy.to_vec()
            });
            Ok(mnemonic::Mnemonic::from_entropy(&entropy)?.words.join(" "))
        })();

        match result {
            Ok(words) => vec![Self::local(LocalAction::Mnemonic, words)],
            Err(_) => vec![Self::local_error(proto::AppError::Failed, 0)],
        }
    }

    fn handle_external_init(
        &mut self,
        route: TransportRoute,
        mut request: proto::InitWalletRequest,
    ) -> Vec<CoreEffect> {
        let effects = match self.seed_exists() {
            Err(_) => self.transport_error_output(route, proto::AppError::Failed),
            Ok(true) => self.transport_error_output(route, proto::AppError::InvalidAction),
            Ok(false) if self.platform.local_ui_enabled() => {
                self.transport_error_output(route, proto::AppError::DisplayRequired)
            }
            Ok(false) => {
                let result = (|| {
                    let entropy_len = mnemonic_entropy_bytes(request.length)?;
                    self.set_pin_hash(&request.pin)?;
                    let entropy = Zeroizing::new(self.platform.random(entropy_len));
                    let mnemonic = mnemonic::Mnemonic::from_entropy(&entropy)?;
                    self.initialize_seed(&mnemonic, &request.passphrase)?;
                    Ok(mnemonic.words.join(" "))
                })();
                self.external_init_result(route, result)
            }
        };
        request.passphrase.zeroize();
        request.pin.zeroize();
        request.seed.zeroize();
        effects
    }

    fn handle_external_init_custom(
        &mut self,
        route: TransportRoute,
        mut request: proto::InitWalletCustomRequest,
    ) -> Vec<CoreEffect> {
        let effects = match self.seed_exists() {
            Err(_) => self.transport_error_output(route, proto::AppError::Failed),
            Ok(true) => self.transport_error_output(route, proto::AppError::InvalidAction),
            Ok(false) if self.platform.local_ui_enabled() => {
                self.transport_error_output(route, proto::AppError::DisplayRequired)
            }
            Ok(false) => {
                let result = (|| {
                    self.set_pin_hash(&request.pin)?;
                    let mnemonic = mnemonic::Mnemonic::from_phrase(&request.words)?;
                    self.initialize_seed(&mnemonic, &request.passphrase)?;
                    Ok(mnemonic.words.join(" "))
                })();
                self.external_init_result(route, result)
            }
        };
        request.words.zeroize();
        request.passphrase.zeroize();
        request.pin.zeroize();
        effects
    }

    fn handle_local_init_custom(
        &mut self,
        words: &str,
        passphrase: &str,
        pin: &str,
    ) -> Vec<CoreEffect> {
        match self.seed_exists() {
            Err(_) => return vec![Self::local_error(proto::AppError::Failed, 0)],
            Ok(true) => return vec![Self::local_error(proto::AppError::InvalidAction, 0)],
            Ok(false) => {}
        }

        let result = (|| {
            self.set_pin_text(pin)?;
            let mnemonic = mnemonic::Mnemonic::from_phrase(words)?;
            self.initialize_seed(&mnemonic, passphrase)
        })();

        match result {
            Ok(()) => vec![
                Self::local(LocalAction::Ready, String::new()),
                CoreEffect::WalletState(WalletState::Ready),
            ],
            Err(_) => vec![Self::local_error(proto::AppError::Failed, 0)],
        }
    }

    fn initialize_seed(&mut self, mnemonic: &mnemonic::Mnemonic, passphrase: &str) -> Result<()> {
        let mut seed = mnemonic.to_seed(passphrase)?;
        if !self.platform.write_unlock_failures(0) {
            seed.zeroize();
            return Err(anyhow!("Failed to initialize unlock counter"));
        }
        let result = self.save_seed(&seed);
        seed.zeroize();
        result?;
        self.locked = false;
        self.failed_unlocks = 0;
        Ok(())
    }

    fn external_init_result(
        &self,
        route: TransportRoute,
        result: Result<String>,
    ) -> Vec<CoreEffect> {
        match result {
            Ok(words) => vec![
                Self::transport(
                    route,
                    res_data::Payload::InitWalletResponse(proto::InitWalletResponse {
                        mnemonic: Some(words),
                    }),
                ),
                CoreEffect::WalletState(WalletState::Ready),
            ],
            Err(_) => self.transport_error_output(route, proto::AppError::Failed),
        }
    }

    fn derive_public_key(
        &self,
        request: proto::DerivePublicKeyRequest,
    ) -> Result<res_data::Payload> {
        let key = wallets::ExtendedPrivKey::derive(
            &self.load_seed()?,
            request.path.parse()?,
            wallets::Curve::K256,
        )?
        .export_pk()?;

        Ok(res_data::Payload::DerivePublicKeyResponse(
            proto::DerivePublicKeyResponse {
                path: request.path,
                public_key: key.to_vec(),
            },
        ))
    }

    fn handle_sign_request(
        &mut self,
        route: TransportRoute,
        request: proto::SignEthRequest,
    ) -> Vec<CoreEffect> {
        if self.locked {
            return self.transport_error_output(route, proto::AppError::Locked);
        }

        // TODO: Support requests larger than 8 KiB with chunked transport and streaming hashing.
        let (pending, details) = match self.prepare_sign(route, request) {
            Ok(prepared) => prepared,
            Err(_) => return self.transport_error_output(route, proto::AppError::Failed),
        };
        let Some(id) = self
            .confirmation
            .start(PendingAction::Sign(pending), details)
        else {
            return self.transport_error_output(route, proto::AppError::Busy);
        };

        vec![
            Self::transport(
                route,
                res_data::Payload::WaitForUserActionResponse(proto::WaitForUserActionResponse {}),
            ),
            CoreEffect::ConfirmationRequired(id),
            CoreEffect::WalletState(WalletState::Busy),
        ]
    }

    fn start_fido_confirmation(
        &mut self,
        request_id: u32,
        operation: FidoOperation,
        rp_id: &[u8],
        account: &[u8],
    ) -> Vec<CoreEffect> {
        let details = match oskey_chain::fido::confirmation(operation, rp_id, account) {
            Ok(details) => ConfirmationDetails::Fido(details),
            Err(_) => return vec![Self::fido(request_id, Self::fido_error())],
        };
        self.authorized_fido = None;
        let Some(id) = self
            .confirmation
            .start(PendingAction::Fido(request_id), details)
        else {
            return vec![Self::fido(request_id, Self::fido_error())];
        };

        vec![
            CoreEffect::ConfirmationRequired(id),
            CoreEffect::WalletState(WalletState::Busy),
        ]
    }

    fn cancel_fido_confirmation(&mut self, request_id: u32) -> Vec<CoreEffect> {
        let Some(pending) = self.confirmation.cancel_if(
            |pending| matches!(pending.action, PendingAction::Fido(id) if id == request_id),
        ) else {
            return Vec::new();
        };
        let PendingAction::Fido(request_id) = pending.action else {
            unreachable!();
        };

        vec![
            Self::fido(request_id, Self::fido_cancelled()),
            CoreEffect::ConfirmationCompleted {
                id: pending.id,
                outcome: ConfirmationOutcome::Cancelled,
            },
            CoreEffect::WalletState(self.state()),
        ]
    }

    fn handle_fido_register(&mut self, id: u32, rp_id: &str, cred_protect: u8) -> Vec<CoreEffect> {
        if self.locked {
            return vec![Self::fido(id, Self::fido_error())];
        }

        let Some(pending) = self.authorized_fido.take() else {
            return vec![Self::fido(id, Self::fido_error())];
        };
        if !matches!(
                &pending.review,
                ConfirmationDetails::Fido(details)
                    if details.operation == FidoOperation::Register && details.rp_id == rp_id
        ) {
            return self.fail_fido_confirmation(id, pending.id);
        }

        let result: Result<PreparedResult> = (|| {
            let nonce = self.platform.random(oskey_chain::fido::NONCE_SIZE);
            let credential = oskey_chain::fido::create(
                &self.load_seed()?,
                rp_id,
                nonce.as_slice().try_into()?,
                cred_protect,
            )?;
            Ok(PreparedResult {
                credential_id: credential.id.to_vec(),
                public_key: credential.public_key.to_vec(),
                ..Default::default()
            })
        })();

        self.restore_fido_confirmation(id, pending, result)
    }

    fn handle_fido_credential(
        &mut self,
        id: u32,
        credential_id: &[u8],
        rp_id_hash: &[u8],
        hash: Option<&[u8]>,
        preflight: bool,
    ) -> Vec<CoreEffect> {
        if self.locked {
            return vec![Self::fido(id, Self::fido_error())];
        }

        if let Some(hash) = hash {
            let pending = if preflight {
                None
            } else {
                let Some(pending) = self.authorized_fido.take() else {
                    return vec![Self::fido(id, Self::fido_error())];
                };
                if !matches!(
                        &pending.review,
                        ConfirmationDetails::Fido(details)
                            if details.operation == FidoOperation::Authenticate
                ) {
                    return self.fail_fido_confirmation(id, pending.id);
                }
                Some(pending)
            };

            if let Some(pending) = pending.as_ref() {
                let ConfirmationDetails::Fido(details) = &pending.review else {
                    unreachable!();
                };
                let Ok(displayed_hash) = crypto::Hash::sha256(details.rp_id.as_bytes()) else {
                    return self.fail_fido_confirmation(id, pending.id);
                };
                if displayed_hash != rp_id_hash {
                    return self.fail_fido_confirmation(id, pending.id);
                }
            }

            let result = self
                .load_seed()
                .and_then(|seed| oskey_chain::fido::sign(&seed, credential_id, rp_id_hash, hash));
            if let Some(pending) = pending {
                return self.restore_fido_confirmation(
                    id,
                    pending,
                    result.map(|signature| PreparedResult {
                        signature,
                        ..Default::default()
                    }),
                );
            }
            return vec![Self::fido(
                id,
                result.map_or_else(
                    |_| Self::fido_error(),
                    |signature| FidoOutput {
                        status: FidoStatus::Success,
                        credential_id: Vec::new(),
                        data: signature,
                    },
                ),
            )];
        }

        let result = self
            .load_seed()
            .and_then(|seed| oskey_chain::fido::validate(&seed, credential_id, rp_id_hash));
        vec![Self::fido(
            id,
            result.map_or_else(
                |_| Self::fido_error(),
                |cred_protect| FidoOutput {
                    status: FidoStatus::Success,
                    credential_id: Vec::new(),
                    data: vec![cred_protect],
                },
            ),
        )]
    }

    fn restore_fido_confirmation(
        &mut self,
        request_id: u32,
        mut pending: PendingConfirmation<PendingAction>,
        result: Result<PreparedResult>,
    ) -> Vec<CoreEffect> {
        let id = pending.id;
        let Ok(prepared) = result else {
            return self.fail_fido_confirmation(request_id, id);
        };
        pending.action = PendingAction::Fido(request_id);
        pending.prepared = Some(prepared);
        if !self.confirmation.restore(pending) {
            return self.fail_fido_confirmation(request_id, id);
        }
        vec![
            CoreEffect::ConfirmationRequired(id),
            CoreEffect::WalletState(WalletState::Busy),
        ]
    }

    fn fail_fido_confirmation(&self, request_id: u32, confirmation_id: u32) -> Vec<CoreEffect> {
        vec![
            Self::fido(request_id, Self::fido_error()),
            CoreEffect::ConfirmationCompleted {
                id: confirmation_id,
                outcome: ConfirmationOutcome::Cancelled,
            },
            CoreEffect::WalletState(self.state()),
        ]
    }

    fn prepare_sign(
        &self,
        route: TransportRoute,
        request: proto::SignEthRequest,
    ) -> Result<(PendingSign, ConfirmationDetails)> {
        let proto::SignEthRequest { id, path, tx, .. } = request;
        path.parse::<DerivationPath>()?;
        let tx = tx.ok_or_else(|| anyhow!("Transaction data is missing"))?;

        let details = match tx {
            proto::sign_eth_request::Tx::Eip2930(transaction) => {
                if transaction
                    .access_list
                    .as_ref()
                    .is_some_and(|access_list| !access_list.is_empty())
                {
                    return Err(anyhow!("EIP-2930 access lists are unsupported"));
                }
                let transaction = OSKeyTxEip2930::new(Eip2930Transaction {
                    chain_id: transaction.chain_id,
                    nonce: transaction.nonce,
                    gas_price: transaction.gas_price,
                    gas_limit: transaction.gas_limit,
                    to: transaction.to,
                    value: transaction.value,
                    input: transaction.input.unwrap_or_default(),
                })?;
                ConfirmationDetails::EthTransaction(transaction.confirmation(path))
            }
            proto::sign_eth_request::Tx::Eip191(message) => {
                if message.is_personal == Some(false) {
                    return Err(anyhow!("Non-personal message signing is unsupported"));
                }
                ConfirmationDetails::EthMessage(OSKeyTxEip191::confirmation(
                    &message.message,
                    path,
                )?)
            }
        };

        Ok((
            PendingSign {
                id,
                reply_to: route,
            },
            details,
        ))
    }

    fn prepare_signature(&self, details: &ConfirmationDetails) -> Result<PreparedResult> {
        let (path, hash) = match details {
            ConfirmationDetails::EthMessage(details) => {
                (details.path.parse()?, details.signing_hash)
            }
            ConfirmationDetails::EthTransaction(details) => {
                (details.path.parse()?, details.signing_hash)
            }
            ConfirmationDetails::Fido(_) => unreachable!(),
        };
        let private_key =
            wallets::ExtendedPrivKey::derive(&self.load_seed()?, path, wallets::Curve::K256)?;
        let public_key = private_key.export_pk()?;
        Ok(PreparedResult {
            from: Some(OSKeyTxEip191::address(&public_key)?),
            public_key,
            signature: private_key.sign(&hash)?,
            ..Default::default()
        })
    }

    fn set_pin_text(&mut self, pin: &str) -> Result<()> {
        let mut input = Vec::with_capacity(pin.len() + PIN_SALT.len());
        input.extend_from_slice(pin.as_bytes());
        input.extend_from_slice(PIN_SALT);
        let hash = crypto::Hash::sha256(&input);
        input.zeroize();
        let hash = Zeroizing::new(hash?);
        self.set_pin_hash(&hash[..])
    }

    fn set_pin_hash(&mut self, hash: &[u8]) -> Result<()> {
        if hash.len() != 32 {
            return Err(anyhow!("PIN hash must contain 32 bytes"));
        }

        let mnemonic = mnemonic::Mnemonic::from_entropy(hash)?;
        let mut bytes = mnemonic.to_seed("OSKey")?;
        self.pin_cache.copy_from_slice(&bytes[..32]);
        bytes.zeroize();
        Ok(())
    }

    fn save_seed(&self, seed: &[u8]) -> Result<()> {
        let nonce_bytes = self.platform.random(12);
        if nonce_bytes.len() != 12 {
            return Err(anyhow!("Random source returned an invalid nonce"));
        }

        let mut nonce = [0; 12];
        nonce.copy_from_slice(&nonce_bytes);
        let encrypted = crypto::ChaCha20Poly1305Cipher::encrypt(&self.pin_cache, &nonce, seed)?;
        let mut stored = Vec::with_capacity(nonce.len() + encrypted.len());
        stored.extend_from_slice(&nonce);
        stored.extend_from_slice(&encrypted);
        self.platform.write_seed(&stored)
    }

    fn load_seed_classified(&self) -> core::result::Result<Zeroizing<Vec<u8>>, SeedLoadError> {
        let mut stored = vec![0; 128];
        let len = self
            .platform
            .read_seed(&mut stored)
            .map_err(|_| SeedLoadError::Storage)?;
        if len != STORED_SEED_BYTES {
            return Err(SeedLoadError::Storage);
        }
        stored.truncate(len);

        let mut nonce = [0; 12];
        nonce.copy_from_slice(&stored[..12]);
        let seed = crypto::ChaCha20Poly1305Cipher::decrypt(&self.pin_cache, &nonce, &stored[12..])
            .map_err(|_| SeedLoadError::Credentials)?;
        Ok(Zeroizing::new(seed))
    }

    fn load_seed(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.load_seed_classified()
            .map_err(|_| anyhow!("Failed to load seed"))
    }

    fn seed_exists(&self) -> Result<bool> {
        if self.storage_failed {
            Err(anyhow!("Storage unavailable"))
        } else {
            self.platform.seed_exists()
        }
    }

    fn transport_reply(
        &self,
        route: TransportRoute,
        payload: res_data::Payload,
    ) -> Vec<CoreEffect> {
        vec![Self::transport(route, payload)]
    }

    fn transport_error_output(
        &self,
        route: TransportRoute,
        error: proto::AppError,
    ) -> Vec<CoreEffect> {
        vec![Self::transport_error(route, error)]
    }

    fn transport(route: TransportRoute, payload: res_data::Payload) -> CoreEffect {
        CoreEffect::Transport(
            route,
            proto::ResData {
                payload: Some(payload),
            },
        )
    }

    fn transport_error(route: TransportRoute, error: proto::AppError) -> CoreEffect {
        Self::transport(
            route,
            res_data::Payload::ErrorResponse(proto::ErrorResponse {
                code: error as i32,
                message: String::new(),
            }),
        )
    }

    fn local(action: LocalAction, text: String) -> CoreEffect {
        CoreEffect::Local(LocalResult {
            action,
            error: proto::AppError::Unspecified,
            value: 0,
            text,
        })
    }

    fn local_error(error: proto::AppError, value: u32) -> CoreEffect {
        CoreEffect::Local(LocalResult {
            action: LocalAction::Error,
            error,
            value,
            text: String::new(),
        })
    }

    fn fido_error() -> FidoOutput {
        FidoOutput {
            status: FidoStatus::Failed,
            credential_id: Vec::new(),
            data: Vec::new(),
        }
    }

    fn fido_cancelled() -> FidoOutput {
        FidoOutput {
            status: FidoStatus::Cancelled,
            credential_id: Vec::new(),
            data: Vec::new(),
        }
    }

    fn fido(id: u32, result: FidoOutput) -> CoreEffect {
        CoreEffect::Fido { id, result }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::rc::Rc;
    use core::cell::RefCell;

    #[derive(Clone)]
    struct TestPlatform {
        seed: Rc<RefCell<Vec<u8>>>,
        unlock_failures: Rc<RefCell<u8>>,
        random_lengths: Rc<RefCell<Vec<usize>>>,
        reset_calls: Rc<RefCell<usize>>,
        fido_recovery_calls: Rc<RefCell<usize>>,
        local_ui: bool,
        reset_succeeds: bool,
        seed_check_fails: bool,
        seed_read_fails: bool,
        unlock_failures_exists: bool,
        unlock_failures_read_fails: bool,
        random_succeeds: bool,
    }

    impl TestPlatform {
        fn new(local_ui: bool) -> Self {
            Self {
                seed: Rc::new(RefCell::new(Vec::new())),
                unlock_failures: Rc::new(RefCell::new(0)),
                random_lengths: Rc::new(RefCell::new(Vec::new())),
                reset_calls: Rc::new(RefCell::new(0)),
                fido_recovery_calls: Rc::new(RefCell::new(0)),
                local_ui,
                reset_succeeds: true,
                seed_check_fails: false,
                seed_read_fails: false,
                unlock_failures_exists: true,
                unlock_failures_read_fails: false,
                random_succeeds: true,
            }
        }
    }

    impl WalletPlatform for TestPlatform {
        fn version(&self) -> String {
            "1.0.0".into()
        }

        fn serial_number(&self) -> String {
            "TEST".into()
        }

        fn support_mask(&self) -> Vec<u8> {
            let mut features = vec![0; 16];
            features[5] = self.local_ui as u8;
            features
        }

        fn local_ui_enabled(&self) -> bool {
            self.local_ui
        }

        fn storage_ready(&self) -> bool {
            !self.seed_check_fails && !self.seed_read_fails && !self.unlock_failures_read_fails
        }

        fn seed_exists(&self) -> Result<bool> {
            if self.seed_check_fails {
                Err(anyhow!("Seed check failed"))
            } else {
                Ok(!self.seed.borrow().is_empty())
            }
        }

        fn random(&self, len: usize) -> Vec<u8> {
            self.random_lengths.borrow_mut().push(len);
            if self.random_succeeds {
                vec![7; len]
            } else {
                Vec::new()
            }
        }

        fn read_seed(&self, data: &mut [u8]) -> Result<usize> {
            if self.seed_read_fails {
                return Err(anyhow!("Seed read failed"));
            }
            let seed = self.seed.borrow();
            if seed.is_empty() {
                return Err(anyhow!("Seed not found"));
            }
            data[..seed.len()].copy_from_slice(&seed);
            Ok(seed.len())
        }

        fn write_seed(&self, data: &[u8]) -> Result<()> {
            *self.seed.borrow_mut() = data.to_vec();
            Ok(())
        }

        fn unlock_failures(&self) -> Result<u8> {
            if self.unlock_failures_read_fails {
                Err(anyhow!("Unlock counter read failed"))
            } else if !self.unlock_failures_exists {
                Ok(0)
            } else {
                Ok(*self.unlock_failures.borrow())
            }
        }

        fn write_unlock_failures(&self, failures: u8) -> bool {
            *self.unlock_failures.borrow_mut() = failures;
            true
        }

        fn recover_fido_pin(&self) {
            *self.fido_recovery_calls.borrow_mut() += 1;
        }

        fn reset_storage(&self) -> bool {
            *self.reset_calls.borrow_mut() += 1;
            if !self.reset_succeeds {
                return false;
            }
            self.seed.borrow_mut().clear();
            *self.unlock_failures.borrow_mut() = 0;
            true
        }

        fn restart(&self) {}
    }

    fn protocol_request(payload: req_data::Payload) -> proto::ReqData {
        proto::ReqData {
            payload: Some(payload),
        }
    }

    fn init(runtime: &mut WalletRuntime<TestPlatform>) {
        let outputs = runtime.handle(CoreRequest::Local(LocalRequest::InitCustom {
            words: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            passphrase: "",
            pin: "Password1!",
        }));
        assert!(outputs
            .iter()
            .any(|output| matches!(output, CoreEffect::WalletState(WalletState::Ready))));
    }

    #[test]
    fn local_init_uses_mnemonic_passphrase() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(true));
        let outputs = runtime.handle(CoreRequest::Local(LocalRequest::InitCustom {
            words: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            passphrase: "TREZOR",
            pin: "Password1!",
        }));

        assert!(outputs
            .iter()
            .any(|output| matches!(output, CoreEffect::WalletState(WalletState::Ready))));
        assert_eq!(
            hex::encode(runtime.load_seed().unwrap()),
            concat!(
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553",
                "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
            )
        );
    }

    fn protocol(
        runtime: &mut WalletRuntime<TestPlatform>,
        transport: Transport,
        request: &proto::ReqData,
    ) -> Vec<CoreEffect> {
        runtime.handle(CoreRequest::Protocol {
            route: TransportRoute {
                transport,
                session_id: if transport == Transport::Bluetooth {
                    7
                } else {
                    0
                },
            },
            request: request.clone(),
        })
    }

    fn fido(
        runtime: &mut WalletRuntime<TestPlatform>,
        id: u32,
        request: FidoRequest<'_>,
    ) -> Vec<CoreEffect> {
        runtime.handle(CoreRequest::Fido { id, request })
    }

    fn confirm(
        runtime: &mut WalletRuntime<TestPlatform>,
        id: u32,
        choice: ConfirmationChoice,
    ) -> Vec<CoreEffect> {
        runtime.handle(CoreRequest::Confirm { id, choice })
    }

    fn required_id(effects: &[CoreEffect]) -> u32 {
        effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::ConfirmationRequired(id) => Some(*id),
                _ => None,
            })
            .expect("confirmation was not requested")
    }

    fn sign_request(message: String) -> req_data::Payload {
        req_data::Payload::SignEthRequest(proto::SignEthRequest {
            id: 1,
            path: "m/44'/60'/0'/0/0".into(),
            tx: Some(proto::sign_eth_request::Tx::Eip191(proto::AppEthTxEip191 {
                message,
                is_personal: None,
            })),
            debug_text: None,
        })
    }

    fn transaction_request() -> req_data::Payload {
        req_data::Payload::SignEthRequest(proto::SignEthRequest {
            id: 2,
            path: "m/44'/60'/0'/0/0".into(),
            tx: Some(proto::sign_eth_request::Tx::Eip2930(
                proto::AppEthTxEip2930 {
                    chain_id: 1,
                    nonce: 7,
                    gas_price: "1000000000".into(),
                    gas_limit: 50000,
                    to: Some("0x00Ab1EAd740f95aDE25b78B3137fdcC333326e7d".into()),
                    value: "42".into(),
                    input: Some(vec![0xa9, 0x05, 0x9c, 0xbb, 1, 2, 3]),
                    access_list: None,
                },
            )),
            debug_text: None,
        })
    }

    #[test]
    fn version_replies_to_origin() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(false));
        let request = protocol_request(req_data::Payload::VersionRequest(proto::VersionRequest {}));
        let outputs = protocol(&mut runtime, Transport::Bluetooth, &request);
        assert!(matches!(
            outputs.as_slice(),
            [CoreEffect::Transport(
                TransportRoute {
                    transport: Transport::Bluetooth,
                    session_id: 7
                },
                _
            )]
        ));
    }

    #[test]
    fn seed_check_failure_is_fail_closed() {
        let mut platform = TestPlatform::new(false);
        platform.seed_check_fails = true;
        let mut runtime = WalletRuntime::new(platform);

        assert_eq!(runtime.state(), WalletState::Disabled);

        let version = protocol(
            &mut runtime,
            Transport::Uart,
            &protocol_request(req_data::Payload::VersionRequest(proto::VersionRequest {})),
        );
        let [CoreEffect::Transport(
            _,
            proto::ResData {
                payload: Some(res_data::Payload::VersionResponse(response)),
            },
        )] = version.as_slice()
        else {
            panic!("expected version response");
        };
        assert_eq!(
            response
                .features
                .as_ref()
                .map(|features| features.initialized),
            Some(true)
        );

        assert!(matches!(
            runtime
                .handle(CoreRequest::Local(LocalRequest::InitCustom {
                    words: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                    passphrase: "",
                    pin: "Password1!",
                }))
                .as_slice(),
            [CoreEffect::Local(LocalResult {
                error: proto::AppError::Failed,
                ..
            })]
        ));
        assert!(matches!(
            protocol(
                &mut runtime,
                Transport::Uart,
                &protocol_request(req_data::Payload::InitRequest(proto::InitWalletRequest {
                    length: 12,
                    passphrase: String::new(),
                    seed: None,
                    pin: vec![0; 32],
                })),
            )
            .as_slice(),
            [CoreEffect::Transport(
                _,
                proto::ResData {
                    payload: Some(res_data::Payload::ErrorResponse(error))
                }
            )] if error.code == proto::AppError::Failed as i32
        ));
    }

    #[test]
    fn unlock_counter_failure_is_fail_closed() {
        let mut platform = TestPlatform::new(false);
        platform.seed.borrow_mut().push(1);
        platform.unlock_failures_read_fails = true;
        let mut runtime = WalletRuntime::new(platform);

        assert_eq!(runtime.state(), WalletState::Disabled);
        assert!(matches!(
            runtime
                .handle(CoreRequest::Local(LocalRequest::Unlock("Password1!")))
                .as_slice(),
            [CoreEffect::Local(LocalResult {
                error: proto::AppError::Failed,
                ..
            })]
        ));
        assert!(matches!(
            protocol(
                &mut runtime,
                Transport::Uart,
                &protocol_request(req_data::Payload::UnlockRequest(proto::UnlockRequest {
                    hash: vec![0; 32],
                })),
            )
            .as_slice(),
            [CoreEffect::Transport(
                _,
                proto::ResData {
                    payload: Some(res_data::Payload::ErrorResponse(error))
                }
            )] if error.code == proto::AppError::Failed as i32
        ));
    }

    #[test]
    fn missing_unlock_counter_uses_zero_for_existing_seed() {
        let mut platform = TestPlatform::new(false);
        platform.seed.borrow_mut().push(1);
        platform.unlock_failures_exists = false;
        let runtime = WalletRuntime::new(platform);

        assert_eq!(runtime.state(), WalletState::Locked);
        assert_eq!(runtime.failed_unlocks, 0);
    }

    #[test]
    fn local_initialization_uses_native_request() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(true));
        init(&mut runtime);
        assert_eq!(runtime.state(), WalletState::Ready);
    }

    #[test]
    fn mnemonic_word_counts_use_bip39_entropy_sizes() {
        let platform = TestPlatform::new(true);
        let mut runtime = WalletRuntime::new(platform.clone());

        for words in [12, 15, 18, 21, 24] {
            assert!(matches!(
                runtime
                    .handle(CoreRequest::Local(LocalRequest::GenerateMnemonic {
                        words,
                        entropy: &[],
                    }))
                    .as_slice(),
                [CoreEffect::Local(LocalResult {
                    action: LocalAction::Mnemonic,
                    ..
                })]
            ));
        }

        assert_eq!(*platform.random_lengths.borrow(), [16, 20, 24, 28, 32]);
    }

    #[test]
    fn invalid_mnemonic_lengths_do_not_request_randomness() {
        let platform = TestPlatform::new(false);
        let mut runtime = WalletRuntime::new(platform.clone());

        for length in [0, 11, 13, 16, 22, 25, u32::MAX] {
            let outputs = protocol(
                &mut runtime,
                Transport::Uart,
                &protocol_request(req_data::Payload::InitRequest(proto::InitWalletRequest {
                    length,
                    passphrase: String::new(),
                    seed: None,
                    pin: vec![0; 32],
                })),
            );
            assert!(matches!(
                outputs.as_slice(),
                [CoreEffect::Transport(
                    _,
                    proto::ResData {
                        payload: Some(res_data::Payload::ErrorResponse(_))
                    }
                )]
            ));
        }

        assert!(matches!(
            runtime
                .handle(CoreRequest::Local(LocalRequest::GenerateMnemonic {
                    words: u32::MAX,
                    entropy: &[],
                }))
                .as_slice(),
            [CoreEffect::Local(LocalResult {
                action: LocalAction::Error,
                ..
            })]
        ));
        assert!(platform.random_lengths.borrow().is_empty());
    }

    #[test]
    fn unavailable_randomness_rejects_mnemonic_generation() {
        let mut platform = TestPlatform::new(false);
        platform.random_succeeds = false;
        let mut runtime = WalletRuntime::new(platform.clone());

        assert!(matches!(
            runtime
                .handle(CoreRequest::Local(LocalRequest::GenerateMnemonic {
                    words: 12,
                    entropy: &[],
                }))
                .as_slice(),
            [CoreEffect::Local(LocalResult {
                action: LocalAction::Error,
                ..
            })]
        ));

        let outputs = protocol(
            &mut runtime,
            Transport::Uart,
            &protocol_request(req_data::Payload::InitRequest(proto::InitWalletRequest {
                length: 12,
                passphrase: String::new(),
                seed: None,
                pin: vec![0; 32],
            })),
        );
        assert!(matches!(
            outputs.as_slice(),
            [CoreEffect::Transport(
                _,
                proto::ResData {
                    payload: Some(res_data::Payload::ErrorResponse(error))
                }
            )] if error.code == proto::AppError::Failed as i32
        ));
        assert!(platform.seed.borrow().is_empty());
        assert_eq!(*platform.random_lengths.borrow(), [16, 16]);
    }

    #[test]
    fn initialization_cannot_replace_existing_seed() {
        let platform = TestPlatform::new(false);
        let mut runtime = WalletRuntime::new(platform.clone());
        init(&mut runtime);
        let original_seed = platform.seed.borrow().clone();
        let original_random_lengths = platform.random_lengths.borrow().clone();

        assert!(matches!(
            runtime
                .handle(CoreRequest::Local(LocalRequest::InitCustom {
                    words: "legal winner thank year wave sausage worth useful legal winner thank yellow",
                    passphrase: "",
                    pin: "Different1!",
                }))
                .as_slice(),
            [CoreEffect::Local(LocalResult {
                error: proto::AppError::InvalidAction,
                ..
            })]
        ));

        for payload in [
            req_data::Payload::InitRequest(proto::InitWalletRequest {
                length: 12,
                passphrase: String::new(),
                seed: None,
                pin: vec![0; 32],
            }),
            req_data::Payload::InitCustomRequest(proto::InitWalletCustomRequest {
                words:
                    "legal winner thank year wave sausage worth useful legal winner thank yellow"
                        .into(),
                passphrase: String::new(),
                pin: vec![0; 32],
            }),
        ] {
            assert!(matches!(
                protocol(&mut runtime, Transport::Uart, &protocol_request(payload)).as_slice(),
                [CoreEffect::Transport(
                    _,
                    proto::ResData {
                        payload: Some(res_data::Payload::ErrorResponse(error))
                    }
                )] if error.code == proto::AppError::InvalidAction as i32
            ));
        }

        assert_eq!(*platform.seed.borrow(), original_seed);
        assert_eq!(*platform.random_lengths.borrow(), original_random_lengths);
    }

    #[test]
    fn unlock_before_initialization_does_not_change_storage() {
        let platform = TestPlatform::new(false);
        *platform.unlock_failures.borrow_mut() = 4;
        let mut runtime = WalletRuntime::new(platform.clone());

        for _ in 0..=MAX_FAILED_UNLOCKS {
            assert!(matches!(
                runtime
                    .handle(CoreRequest::Local(LocalRequest::Unlock("Password1!")))
                    .as_slice(),
                [CoreEffect::Local(LocalResult {
                    error: proto::AppError::InvalidAction,
                    ..
                })]
            ));
        }

        assert!(matches!(
            protocol(
                &mut runtime,
                Transport::Uart,
                &protocol_request(req_data::Payload::UnlockRequest(proto::UnlockRequest {
                    hash: vec![0; 32],
                })),
            )
            .as_slice(),
            [CoreEffect::Transport(
                _,
                proto::ResData {
                    payload: Some(res_data::Payload::ErrorResponse(error))
                }
            )] if error.code == proto::AppError::InvalidAction as i32
        ));
        assert!(platform.seed.borrow().is_empty());
        assert_eq!(*platform.unlock_failures.borrow(), 4);
        assert_eq!(*platform.reset_calls.borrow(), 0);
    }

    #[test]
    fn seed_read_failure_does_not_consume_unlock_attempt() {
        let mut platform = TestPlatform::new(false);
        init(&mut WalletRuntime::new(platform.clone()));
        platform.seed_read_fails = true;
        let mut runtime = WalletRuntime::new(platform.clone());

        for _ in 0..=MAX_FAILED_UNLOCKS {
            assert!(matches!(
                runtime
                    .handle(CoreRequest::Local(LocalRequest::Unlock("Password1!")))
                    .as_slice(),
                [
                    CoreEffect::Local(LocalResult {
                        error: proto::AppError::Failed,
                        ..
                    }),
                    CoreEffect::WalletState(WalletState::Locked)
                ]
            ));
        }
        assert_eq!(platform.unlock_failures().unwrap(), 0);
        assert_eq!(*platform.reset_calls.borrow(), 0);
    }

    #[test]
    fn invalid_seed_length_does_not_consume_unlock_attempt() {
        let platform = TestPlatform::new(false);
        init(&mut WalletRuntime::new(platform.clone()));
        platform.seed.borrow_mut().pop();
        let mut runtime = WalletRuntime::new(platform.clone());

        for _ in 0..=MAX_FAILED_UNLOCKS {
            runtime.handle(CoreRequest::Local(LocalRequest::Unlock("Password1!")));
        }
        assert_eq!(platform.unlock_failures().unwrap(), 0);
        assert_eq!(*platform.reset_calls.borrow(), 0);
    }

    #[test]
    fn invalid_external_pin_hash_is_rejected() {
        let platform = TestPlatform::new(false);
        init(&mut WalletRuntime::new(platform.clone()));
        let mut runtime = WalletRuntime::new(platform.clone());
        let output = protocol(
            &mut runtime,
            Transport::Uart,
            &protocol_request(req_data::Payload::UnlockRequest(proto::UnlockRequest {
                hash: Vec::new(),
            })),
        );
        assert!(matches!(
            &output[0],
            CoreEffect::Transport(
                _,
                proto::ResData {
                    payload: Some(res_data::Payload::ErrorResponse(error))
                }
            ) if error.code == proto::AppError::InvalidAction as i32
        ));
        assert_eq!(platform.unlock_failures().unwrap(), 0);
        assert!(!platform.seed.borrow().is_empty());
    }

    #[test]
    fn external_unlock_emits_one_reply_and_one_state_change() {
        let platform = TestPlatform::new(false);
        init(&mut WalletRuntime::new(platform.clone()));
        let mut runtime = WalletRuntime::new(platform.clone());
        let mut input = b"Password1!".to_vec();
        input.extend_from_slice(PIN_SALT);
        let hash = crypto::Hash::sha256(&input).unwrap();

        let outputs = protocol(
            &mut runtime,
            Transport::Uart,
            &protocol_request(req_data::Payload::UnlockRequest(proto::UnlockRequest {
                hash: hash.to_vec(),
            })),
        );
        assert!(matches!(
            outputs.as_slice(),
            [
                CoreEffect::Transport(_, _),
                CoreEffect::WalletState(WalletState::Ready)
            ]
        ));
        assert_eq!(*platform.fido_recovery_calls.borrow(), 1);
    }

    #[test]
    fn unlock_failures_survive_restart_and_clear_after_success() {
        let platform = TestPlatform::new(true);
        init(&mut WalletRuntime::new(platform.clone()));
        let mut runtime = WalletRuntime::new(platform.clone());

        for expected in 1..=3 {
            assert!(matches!(
                runtime
                    .handle(CoreRequest::Local(LocalRequest::Unlock("wrong")))
                    .as_slice(),
                [CoreEffect::Local(LocalResult {
                    error: proto::AppError::UnlockFailed,
                    value,
                    ..
                }), CoreEffect::WalletState(WalletState::Locked)] if *value == expected
            ));
        }

        assert_eq!(*platform.fido_recovery_calls.borrow(), 0);

        let mut restarted = WalletRuntime::new(platform.clone());
        assert_eq!(restarted.failed_unlocks, 3);
        assert!(matches!(
            restarted
                .handle(CoreRequest::Local(LocalRequest::Unlock("Password1!")))
                .as_slice(),
            [
                CoreEffect::Local(LocalResult {
                    action: LocalAction::Ready,
                    ..
                }),
                CoreEffect::WalletState(WalletState::Ready)
            ]
        ));
        assert_eq!(platform.unlock_failures().unwrap(), 0);
    }

    #[test]
    fn failed_erase_keeps_wallet_locked_after_attempt_limit() {
        let mut platform = TestPlatform::new(true);
        init(&mut WalletRuntime::new(platform.clone()));
        platform.reset_succeeds = false;
        let persisted = platform.clone();
        let mut runtime = WalletRuntime::new(platform);

        for _ in 0..MAX_FAILED_UNLOCKS {
            runtime.handle(CoreRequest::Local(LocalRequest::Unlock("wrong")));
        }

        let mut restarted = WalletRuntime::new(persisted);
        assert!(matches!(
            restarted
                .handle(CoreRequest::Local(LocalRequest::Unlock("Password1!")))
                .as_slice(),
            [CoreEffect::Local(LocalResult {
                error: proto::AppError::UnlockFailed,
                value,
                ..
            })] if *value == u32::from(MAX_FAILED_UNLOCKS)
        ));
        assert_eq!(restarted.state(), WalletState::Locked);
    }

    #[test]
    fn pending_erase_is_retried_after_restart() {
        let mut platform = TestPlatform::new(true);
        init(&mut WalletRuntime::new(platform.clone()));
        platform.reset_succeeds = false;
        let mut runtime = WalletRuntime::new(platform.clone());

        for _ in 0..MAX_FAILED_UNLOCKS {
            runtime.handle(CoreRequest::Local(LocalRequest::Unlock("wrong")));
        }

        platform.reset_succeeds = true;
        let restarted = WalletRuntime::new(platform.clone());
        assert_eq!(restarted.state(), WalletState::Setup);
        assert!(platform.seed.borrow().is_empty());
        assert_eq!(platform.unlock_failures().unwrap(), 0);
    }

    #[test]
    fn automatic_erase_publishes_setup_for_local_and_external_unlock() {
        let local_platform = TestPlatform::new(false);
        init(&mut WalletRuntime::new(local_platform.clone()));
        let mut local = WalletRuntime::new(local_platform.clone());

        for _ in 1..MAX_FAILED_UNLOCKS {
            local.handle(CoreRequest::Local(LocalRequest::Unlock("wrong")));
        }
        assert!(matches!(
            local
                .handle(CoreRequest::Local(LocalRequest::Unlock("wrong")))
                .as_slice(),
            [
                CoreEffect::Local(LocalResult {
                    error: proto::AppError::UnlockFailed,
                    value,
                    ..
                }),
                CoreEffect::WalletState(WalletState::Setup)
            ] if *value == u32::from(MAX_FAILED_UNLOCKS)
        ));
        assert_eq!(local.state(), WalletState::Setup);
        assert!(!local.storage_failed);
        assert!(!local.locked);
        assert_eq!(local.failed_unlocks, 0);
        assert!(local_platform.seed.borrow().is_empty());

        let external_platform = TestPlatform::new(false);
        init(&mut WalletRuntime::new(external_platform.clone()));
        let mut external = WalletRuntime::new(external_platform.clone());
        let wrong_pin = protocol_request(req_data::Payload::UnlockRequest(proto::UnlockRequest {
            hash: vec![1; 32],
        }));

        for _ in 1..MAX_FAILED_UNLOCKS {
            protocol(&mut external, Transport::Uart, &wrong_pin);
        }
        assert!(matches!(
            protocol(&mut external, Transport::Uart, &wrong_pin).as_slice(),
            [
                CoreEffect::Transport(
                    _,
                    proto::ResData {
                        payload: Some(res_data::Payload::ErrorResponse(error))
                    }
                ),
                CoreEffect::WalletState(WalletState::Setup)
            ] if error.code == proto::AppError::Failed as i32
        ));
        assert_eq!(external.state(), WalletState::Setup);
        assert!(!external.storage_failed);
        assert!(!external.locked);
        assert_eq!(external.failed_unlocks, 0);
        assert!(external_platform.seed.borrow().is_empty());
    }

    #[test]
    fn lock_and_reset_publish_the_resulting_state() {
        let mut setup = WalletRuntime::new(TestPlatform::new(false));
        assert!(matches!(
            protocol(
                &mut setup,
                Transport::Uart,
                &protocol_request(req_data::Payload::LockRequest(proto::LockRequest {})),
            )
            .as_slice(),
            [
                CoreEffect::Transport(_, _),
                CoreEffect::WalletState(WalletState::Setup)
            ]
        ));

        let mut ready = WalletRuntime::new(TestPlatform::new(true));
        init(&mut ready);
        assert_ne!(ready.pin_cache, [0; 32]);
        ready.storage_failed = true;
        ready.locked = true;
        ready.failed_unlocks = 3;
        assert!(matches!(
            ready
                .handle(CoreRequest::Local(LocalRequest::ResetStorage))
                .as_slice(),
            [CoreEffect::WalletState(WalletState::Setup)]
        ));
        assert_eq!(ready.pin_cache, [0; 32]);
        assert!(!ready.storage_failed);
        assert!(!ready.locked);
        assert_eq!(ready.failed_unlocks, 0);

        let mut platform = TestPlatform::new(false);
        platform.reset_succeeds = false;
        let mut failed = WalletRuntime::new(platform);
        assert!(matches!(
            failed
                .handle(CoreRequest::Local(LocalRequest::ResetStorage))
                .as_slice(),
            [CoreEffect::Local(LocalResult {
                action: LocalAction::Error,
                error: proto::AppError::Failed,
                ..
            })]
        ));
    }

    #[test]
    fn sending_a_signature_does_not_use_the_private_key_again() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(false));
        init(&mut runtime);
        runtime.platform.seed_read_fails = true;

        let outputs = protocol(
            &mut runtime,
            Transport::Bluetooth,
            &protocol_request(sign_request("hello".into())),
        );
        assert!(matches!(
            outputs.as_slice(),
            [
                CoreEffect::Transport(
                    TransportRoute {
                        transport: Transport::Bluetooth,
                        session_id: 7
                    },
                    _
                ),
                CoreEffect::ConfirmationRequired(_),
                CoreEffect::WalletState(WalletState::Busy)
            ]
        ));
        let id = outputs
            .iter()
            .find_map(|output| match output {
                CoreEffect::ConfirmationRequired(id) => Some(*id),
                _ => None,
            })
            .unwrap();
        let Some((ConfirmationDetails::EthMessage(details), prepared)) = runtime.confirmation(id)
        else {
            panic!("expected Ethereum message confirmation");
        };
        let confirmation_hash = details.signing_hash;
        assert!(prepared.is_none());

        runtime.platform.seed_read_fails = false;
        let updated = confirm(&mut runtime, id, ConfirmationChoice::Approve);
        assert!(matches!(
            updated.as_slice(),
            [
                CoreEffect::ConfirmationRequired(updated_id),
                CoreEffect::WalletState(WalletState::Busy)
            ] if *updated_id == id
        ));
        let Some((ConfirmationDetails::EthMessage(_), Some(prepared))) = runtime.confirmation(id)
        else {
            panic!("expected prepared Ethereum message confirmation");
        };
        let confirmation_from = prepared.from.unwrap();
        assert_eq!(prepared.public_key.len(), 65);
        assert_eq!(prepared.signature.len(), 64);

        runtime.platform.seed_read_fails = true;
        let completed = confirm(&mut runtime, id, ConfirmationChoice::Approve);
        let CoreEffect::Transport(
            _,
            proto::ResData {
                payload: Some(res_data::Payload::SignResponse(response)),
            },
        ) = &completed[0]
        else {
            panic!("expected Ethereum signature response");
        };
        assert_eq!(
            oskey_chain::eth::OSKeyTxEip191::address(&response.public_key).unwrap(),
            confirmation_from
        );
        assert_eq!(response.pre_hash, confirmation_hash);
        assert_eq!(response.signature.len(), 64);
        assert!(matches!(
            &completed[1],
            CoreEffect::ConfirmationCompleted {
                id: completed_id,
                outcome: ConfirmationOutcome::Approved
            } if *completed_id == id
        ));
        assert!(runtime.confirmation(id).is_none());
    }

    #[test]
    fn unsupported_access_list_is_rejected_at_protocol_boundary() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(false));
        init(&mut runtime);
        let request = proto::SignEthRequest {
            id: 1,
            path: "m/44'/60'/0'/0/0".into(),
            tx: Some(proto::sign_eth_request::Tx::Eip2930(
                proto::AppEthTxEip2930 {
                    chain_id: 1,
                    nonce: 0,
                    gas_price: "1".into(),
                    gas_limit: 21000,
                    to: None,
                    value: "0".into(),
                    input: None,
                    access_list: Some(vec![0xc0]),
                },
            )),
            debug_text: None,
        };
        let outputs = protocol(
            &mut runtime,
            Transport::Uart,
            &protocol_request(req_data::Payload::SignEthRequest(request)),
        );

        assert!(matches!(
            outputs.as_slice(),
            [CoreEffect::Transport(
                _,
                proto::ResData {
                    payload: Some(res_data::Payload::ErrorResponse(_))
                }
            )]
        ));
    }

    #[test]
    fn invalid_signing_path_is_rejected_before_confirmation() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(false));
        init(&mut runtime);
        let req_data::Payload::SignEthRequest(mut request) = sign_request("hello".into()) else {
            unreachable!();
        };
        request.path = "not/a/path".into();

        let outputs = protocol(
            &mut runtime,
            Transport::Uart,
            &protocol_request(req_data::Payload::SignEthRequest(request)),
        );

        assert!(matches!(
            outputs.as_slice(),
            [CoreEffect::Transport(
                _,
                proto::ResData {
                    payload: Some(res_data::Payload::ErrorResponse(_))
                }
            )]
        ));
    }

    #[test]
    fn transaction_confirmation_uses_a_bounded_display_summary() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(false));
        init(&mut runtime);
        runtime.platform.seed_read_fails = true;

        let requested = protocol(
            &mut runtime,
            Transport::Uart,
            &protocol_request(transaction_request()),
        );
        let first_id = required_id(&requested);
        let Some((ConfirmationDetails::EthTransaction(transaction), prepared)) =
            runtime.confirmation(first_id)
        else {
            panic!("expected Ethereum transaction confirmation");
        };
        assert_eq!(transaction.chain_id, 1);
        assert_eq!(transaction.nonce, 7);
        assert_eq!(transaction.gas_price, "1000000000");
        assert_eq!(transaction.gas_limit, 50000);
        assert_eq!(transaction.value, "42");
        assert_eq!(transaction.input_length, 7);
        assert_eq!(transaction.selector, [0xa9, 0x05, 0x9c, 0xbb]);
        assert!(prepared.is_none());

        runtime.platform.seed_read_fails = false;
        let updated = confirm(&mut runtime, first_id, ConfirmationChoice::Approve);
        let updated_id = required_id(&updated);
        assert_eq!(updated_id, first_id);
        let Some((ConfirmationDetails::EthTransaction(_), Some(prepared))) =
            runtime.confirmation(updated_id)
        else {
            panic!("expected prepared Ethereum transaction confirmation");
        };
        assert!(prepared.from.is_some());
        assert_eq!(prepared.public_key.len(), 65);
        assert_eq!(prepared.signature.len(), 64);
    }

    #[test]
    fn stale_and_duplicate_confirmation_decisions_are_ignored() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(false));
        init(&mut runtime);
        let outputs = protocol(
            &mut runtime,
            Transport::Uart,
            &protocol_request(sign_request("hello".into())),
        );
        let id = outputs
            .iter()
            .find_map(|output| match output {
                CoreEffect::ConfirmationRequired(id) => Some(*id),
                _ => None,
            })
            .unwrap();

        assert!(confirm(&mut runtime, id + 1, ConfirmationChoice::Approve).is_empty());
        let rejected = confirm(&mut runtime, id, ConfirmationChoice::Reject);
        assert!(matches!(
            rejected.first(),
            Some(CoreEffect::Transport(
                _,
                proto::ResData {
                    payload: Some(res_data::Payload::ErrorResponse(proto::ErrorResponse {
                        code,
                        ..
                    })),
                },
            )) if *code == proto::AppError::Rejected as i32
        ));
        assert!(confirm(&mut runtime, id, ConfirmationChoice::Approve).is_empty());
    }

    #[test]
    fn pending_confirmation_rejects_other_requests_as_busy() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(false));
        init(&mut runtime);
        let pending = protocol(
            &mut runtime,
            Transport::Uart,
            &protocol_request(sign_request("hello".into())),
        );
        let confirmation_id = pending
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::ConfirmationRequired(id) => Some(*id),
                _ => None,
            })
            .unwrap();

        let status = protocol_request(req_data::Payload::StatusRequest(proto::StatusRequest {}));
        let outputs = protocol(&mut runtime, Transport::Uart, &status);
        let [CoreEffect::Transport(
            _,
            proto::ResData {
                payload: Some(res_data::Payload::ErrorResponse(error)),
            },
        )] = outputs.as_slice()
        else {
            panic!("expected busy response");
        };
        assert_eq!(error.code, proto::AppError::Busy as i32);
        assert!(matches!(
            protocol(&mut runtime, Transport::Uart, &status).as_slice(),
            [CoreEffect::Transport(
                _,
                proto::ResData {
                    payload: Some(res_data::Payload::ErrorResponse(error)),
                },
            )] if error.code == proto::AppError::Busy as i32
        ));

        confirm(&mut runtime, confirmation_id, ConfirmationChoice::Reject);
        let pending = protocol(
            &mut runtime,
            Transport::Uart,
            &protocol_request(sign_request("again".into())),
        );
        assert!(pending
            .iter()
            .any(|effect| matches!(effect, CoreEffect::ConfirmationRequired(_))));
        assert!(matches!(
            protocol(&mut runtime, Transport::Uart, &status).as_slice(),
            [CoreEffect::Transport(
                _,
                proto::ResData {
                    payload: Some(res_data::Payload::ErrorResponse(_))
                }
            )]
        ));
    }

    #[test]
    fn fido_keeps_confirmation_active_until_the_result_is_ready() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(false));
        init(&mut runtime);
        let outputs = fido(
            &mut runtime,
            42,
            FidoRequest::Confirm {
                operation: FidoOperation::Authenticate,
                rp_id: b"ssh:",
                account: b"OSKey",
            },
        );
        assert!(matches!(
            outputs.as_slice(),
            [
                CoreEffect::ConfirmationRequired(_),
                CoreEffect::WalletState(WalletState::Busy)
            ]
        ));
        let id = outputs
            .iter()
            .find_map(|output| match output {
                CoreEffect::ConfirmationRequired(id) => Some(*id),
                _ => None,
            })
            .unwrap();
        assert!(matches!(
            runtime.confirmation(id),
            Some((ConfirmationDetails::Fido(_), None))
        ));
        assert!(matches!(
            confirm(&mut runtime, id, ConfirmationChoice::Approve).as_slice(),
            [
                CoreEffect::Fido {
                    id: 42,
                    result: FidoOutput {
                        status: FidoStatus::Success,
                        ..
                    }
                },
                CoreEffect::WalletState(WalletState::Busy)
            ]
        ));
    }

    #[test]
    fn fido_approval_holds_runtime_busy_until_result_is_ready() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(false));
        init(&mut runtime);
        let outputs = fido(
            &mut runtime,
            42,
            FidoRequest::Confirm {
                operation: FidoOperation::Authenticate,
                rp_id: b"example.com",
                account: b"OSKey",
            },
        );
        let confirmation_id = outputs
            .iter()
            .find_map(|output| match output {
                CoreEffect::ConfirmationRequired(id) => Some(*id),
                _ => None,
            })
            .unwrap();
        confirm(&mut runtime, confirmation_id, ConfirmationChoice::Approve);
        assert_eq!(runtime.state(), WalletState::Busy);
        assert!(matches!(
            protocol(
                &mut runtime,
                Transport::Uart,
                &protocol_request(req_data::Payload::StatusRequest(proto::StatusRequest {})),
            )
            .as_slice(),
            [CoreEffect::Transport(
                _,
                proto::ResData {
                    payload: Some(res_data::Payload::ErrorResponse(proto::ErrorResponse {
                        code,
                        ..
                    }))
                }
            )] if *code == proto::AppError::Busy as i32
        ));
    }

    #[test]
    fn fido_register_and_authenticate_keep_one_confirmation_id() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(false));
        init(&mut runtime);
        runtime.platform.seed_read_fails = true;

        let first = fido(
            &mut runtime,
            10,
            FidoRequest::Confirm {
                operation: FidoOperation::Register,
                rp_id: b"ssh:",
                account: b"OSKey",
            },
        );
        let first_id = required_id(&first);
        assert!(matches!(
            runtime.confirmation(first_id),
            Some((ConfirmationDetails::Fido(_), None))
        ));
        assert!(matches!(
            confirm(&mut runtime, first_id, ConfirmationChoice::Approve).first(),
            Some(CoreEffect::Fido {
                id: 10,
                result: FidoOutput {
                    status: FidoStatus::Success,
                    ..
                }
            })
        ));

        runtime.platform.seed_read_fails = false;
        let registration = fido(
            &mut runtime,
            11,
            FidoRequest::Register {
                rp_id: "ssh:",
                cred_protect: 1,
            },
        );
        let registration_id = required_id(&registration);
        assert_eq!(registration_id, first_id);
        let Some((ConfirmationDetails::Fido(_), Some(prepared))) =
            runtime.confirmation(registration_id)
        else {
            panic!("expected prepared FIDO registration");
        };
        let credential_id = &prepared.credential_id;
        let public_key = &prepared.public_key;
        assert_eq!(credential_id.len(), oskey_chain::fido::CREDENTIAL_ID_SIZE);
        assert_eq!(public_key.len(), 65);
        let credential_id = credential_id.to_vec();
        runtime.platform.seed_read_fails = true;
        let registered = confirm(&mut runtime, registration_id, ConfirmationChoice::Approve);
        assert!(matches!(
            registered.first(),
            Some(CoreEffect::Fido {
                id: 11,
                result: FidoOutput {
                    status: FidoStatus::Success,
                    credential_id: result_id,
                    data,
                }
            }) if result_id == &credential_id && data.len() == 65
        ));

        runtime.platform.seed_read_fails = false;
        let rp_id_hash = crypto::Hash::sha256(b"ssh:").unwrap();
        let preflight = fido(
            &mut runtime,
            12,
            FidoRequest::Sign {
                credential_id: &credential_id,
                rp_id_hash: &rp_id_hash,
                hash: &[8; 32],
                preflight: true,
            },
        );
        assert!(matches!(
            preflight.as_slice(),
            [CoreEffect::Fido {
                id: 12,
                result: FidoOutput {
                    status: FidoStatus::Success,
                    data,
                    ..
                }
            }] if !data.is_empty()
        ));

        let presence = fido(
            &mut runtime,
            13,
            FidoRequest::Confirm {
                operation: FidoOperation::Authenticate,
                rp_id: b"ssh:",
                account: b"OSKey",
            },
        );
        let presence_id = required_id(&presence);
        confirm(&mut runtime, presence_id, ConfirmationChoice::Approve);

        let signing_hash = [9; 32];
        let signing = fido(
            &mut runtime,
            14,
            FidoRequest::Sign {
                credential_id: &credential_id,
                rp_id_hash: &rp_id_hash,
                hash: &signing_hash,
                preflight: false,
            },
        );
        let signing_id = required_id(&signing);
        assert_eq!(signing_id, presence_id);
        assert!(matches!(
            runtime.confirmation(signing_id),
            Some((ConfirmationDetails::Fido(_), Some(prepared)))
                if !prepared.signature.is_empty()
        ));
        runtime.platform.seed_read_fails = true;
        assert!(matches!(
            confirm(&mut runtime, signing_id, ConfirmationChoice::Approve).first(),
            Some(CoreEffect::Fido {
                id: 14,
                result: FidoOutput {
                    status: FidoStatus::Success,
                    data,
                    ..
                }
            }) if !data.is_empty()
        ));
    }

    #[test]
    fn fido_sign_rejects_a_service_different_from_the_confirmation() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(false));
        init(&mut runtime);
        let presence = fido(
            &mut runtime,
            20,
            FidoRequest::Confirm {
                operation: FidoOperation::Authenticate,
                rp_id: b"example.com",
                account: b"OSKey",
            },
        );
        let id = required_id(&presence);
        confirm(&mut runtime, id, ConfirmationChoice::Approve);

        let result = fido(
            &mut runtime,
            21,
            FidoRequest::Sign {
                credential_id: &[0; oskey_chain::fido::CREDENTIAL_ID_SIZE],
                rp_id_hash: &crypto::Hash::sha256(b"other.example").unwrap(),
                hash: &[0; 32],
                preflight: false,
            },
        );
        assert!(matches!(
            result.as_slice(),
            [
                CoreEffect::Fido {
                    id: 21,
                    result: FidoOutput {
                        status: FidoStatus::Failed,
                        ..
                    }
                },
                CoreEffect::ConfirmationCompleted {
                    id: completed_id,
                    outcome: ConfirmationOutcome::Cancelled
                },
                CoreEffect::WalletState(WalletState::Ready)
            ] if *completed_id == id
        ));
    }

    #[test]
    fn fido_rejection_never_releases_a_private_result() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(false));
        init(&mut runtime);
        let presence = fido(
            &mut runtime,
            30,
            FidoRequest::Confirm {
                operation: FidoOperation::Register,
                rp_id: b"ssh:",
                account: b"OSKey",
            },
        );
        let presence_id = required_id(&presence);
        confirm(&mut runtime, presence_id, ConfirmationChoice::Approve);

        let registration = fido(
            &mut runtime,
            31,
            FidoRequest::Register {
                rp_id: "ssh:",
                cred_protect: 1,
            },
        );
        let registration_id = required_id(&registration);
        let rejected = confirm(&mut runtime, registration_id, ConfirmationChoice::Reject);
        assert!(matches!(
            rejected.first(),
            Some(CoreEffect::Fido {
                id: 31,
                result: FidoOutput {
                    status: FidoStatus::Failed,
                    credential_id,
                    data,
                }
            }) if credential_id.is_empty() && data.is_empty()
        ));
        assert!(confirm(&mut runtime, registration_id, ConfirmationChoice::Approve).is_empty());
    }

    #[test]
    fn fido_cancel_does_not_cancel_wallet_confirmation() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(false));
        init(&mut runtime);
        let outputs = protocol(
            &mut runtime,
            Transport::Uart,
            &protocol_request(sign_request("hello".into())),
        );
        let id = outputs
            .iter()
            .find_map(|output| match output {
                CoreEffect::ConfirmationRequired(id) => Some(*id),
                _ => None,
            })
            .unwrap();

        assert!(fido(&mut runtime, 1, FidoRequest::CancelConfirmation).is_empty());
        assert!(runtime.confirmation(id).is_some());
        assert!(!confirm(&mut runtime, id, ConfirmationChoice::Approve).is_empty());
    }

    #[test]
    fn fido_cancel_completes_its_confirmation() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(false));
        init(&mut runtime);
        let outputs = fido(
            &mut runtime,
            77,
            FidoRequest::Confirm {
                operation: FidoOperation::Select,
                rp_id: b"",
                account: b"",
            },
        );
        let id = outputs
            .iter()
            .find_map(|output| match output {
                CoreEffect::ConfirmationRequired(id) => Some(*id),
                _ => None,
            })
            .unwrap();

        assert!(fido(&mut runtime, 78, FidoRequest::CancelConfirmation).is_empty());
        assert!(runtime.confirmation(id).is_some());

        let outputs = fido(&mut runtime, 77, FidoRequest::CancelConfirmation);
        assert!(matches!(
            outputs.as_slice(),
            [
                CoreEffect::Fido {
                    id: 77,
                    result: FidoOutput {
                        status: FidoStatus::Cancelled,
                        ..
                    }
                },
                CoreEffect::ConfirmationCompleted {
                    id: completed_id,
                    outcome: ConfirmationOutcome::Cancelled
                },
                CoreEffect::WalletState(WalletState::Ready)
            ] if *completed_id == id
        ));
        assert!(runtime.confirmation(id).is_none());
    }

    #[test]
    fn large_message_confirmation_is_bounded() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(false));
        init(&mut runtime);
        let outputs = protocol(
            &mut runtime,
            Transport::Uart,
            &protocol_request(sign_request("a".repeat(8192))),
        );
        let id = outputs
            .iter()
            .find_map(|output| match output {
                CoreEffect::ConfirmationRequired(id) => Some(*id),
                _ => None,
            })
            .unwrap();
        let Some((ConfirmationDetails::EthMessage(details), None)) = runtime.confirmation(id)
        else {
            panic!("expected message details");
        };
        assert_eq!(details.byte_length, 8192);
        assert_eq!(details.preview.len(), 256);
        assert!(details.truncated);
    }
}
