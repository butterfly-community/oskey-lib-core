#![no_std]

extern crate alloc;

mod confirmation;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use anyhow::{anyhow, Result};
use oskey_chain::eth::{Eip2930Transaction, OSKeyTxEip2930};
pub use oskey_chain::{ConfirmationDetails, FidoOperation};
use oskey_protocol::proto::{req_data, res_data};
pub use oskey_protocol::{proto, FrameParser, Message};
use oskey_wallet::alg::crypto;
use oskey_wallet::path::DerivationPath;
use oskey_wallet::{mnemonic, wallets};
use zeroize::{Zeroize, Zeroizing};

use confirmation::ConfirmationService;

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
    InitCustom { words: &'a str, pin: &'a str },
    GenerateMnemonic { words: u32, entropy: &'a [u8] },
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
        data: &'a [u8],
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
    fn reset_storage(&self) -> bool;
    fn restart(&self);
}

struct PendingSign {
    id: i32,
    path: DerivationPath,
    hash: [u8; 32],
    public_key: Vec<u8>,
    reply_to: TransportRoute,
}

#[allow(clippy::large_enum_variant)]
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

struct WalletApp<P> {
    platform: P,
    pin_cache: [u8; 32],
    locked: bool,
    failed_unlocks: u8,
    storage_failed: bool,
    confirmation: ConfirmationService<PendingAction>,
}

impl<P> Drop for WalletApp<P> {
    fn drop(&mut self) {
        self.pin_cache.zeroize();
    }
}

pub struct WalletRuntime<P> {
    uart_parser: FrameParser,
    bluetooth_parser: FrameParser,
    bluetooth_session: u32,
    uart_busy_notified: bool,
    bluetooth_busy_session: Option<u32>,
    app: WalletApp<P>,
}

impl<P: WalletPlatform> WalletRuntime<P> {
    pub fn new(platform: P) -> Self {
        Self {
            uart_parser: FrameParser::new(),
            bluetooth_parser: FrameParser::new(),
            bluetooth_session: 0,
            uart_busy_notified: false,
            bluetooth_busy_session: None,
            app: WalletApp::new(platform),
        }
    }

    pub fn state(&self) -> WalletState {
        self.app.state()
    }

    pub fn confirmation(&self, id: u32) -> Option<&ConfirmationDetails> {
        self.app.confirmation.details(id)
    }

    pub fn handle(&mut self, request: CoreRequest<'_>) -> Vec<CoreEffect> {
        let was_busy = self.app.is_busy();
        let effects = match request {
            CoreRequest::Protocol { route, data } => {
                let parser = match route.transport {
                    Transport::Uart => &mut self.uart_parser,
                    Transport::Bluetooth => {
                        if self.bluetooth_session != route.session_id {
                            self.bluetooth_parser.clear();
                            self.bluetooth_session = route.session_id;
                        }
                        &mut self.bluetooth_parser
                    }
                };

                if self.app.is_busy() {
                    parser.clear();
                    let notify = match route.transport {
                        Transport::Uart => {
                            let notify = !self.uart_busy_notified;
                            self.uart_busy_notified = true;
                            notify
                        }
                        Transport::Bluetooth => {
                            let notify = self.bluetooth_busy_session != Some(route.session_id);
                            self.bluetooth_busy_session = Some(route.session_id);
                            notify
                        }
                    };
                    if notify {
                        self.app
                            .transport_error_output(route, proto::AppError::Busy)
                    } else {
                        Vec::new()
                    }
                } else {
                    parser.push(data);
                    let mut effects = Vec::new();
                    while let Some(request) = parser.unpack() {
                        match request {
                            Ok(request) => effects.extend(self.app.handle_protocol(route, request)),
                            Err(_) => effects.push(WalletApp::<P>::transport_error(
                                route,
                                proto::AppError::Failed,
                            )),
                        }
                        if self.app.is_busy() {
                            parser.clear();
                            break;
                        }
                    }
                    effects
                }
            }
            CoreRequest::Local(request) => self.app.handle_local(request),
            CoreRequest::Fido { id, request } => self.app.handle_fido(id, request),
            CoreRequest::Confirm { id, choice } => self.app.handle_confirmation(id, choice),
        };

        if was_busy && !self.app.is_busy() {
            self.uart_busy_notified = false;
            self.bluetooth_busy_session = None;
        }
        effects
    }
}

impl<P: WalletPlatform> WalletApp<P> {
    fn new(platform: P) -> Self {
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
        }
    }

    fn is_busy(&self) -> bool {
        self.confirmation.is_waiting()
    }

    fn state(&self) -> WalletState {
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
            LocalRequest::InitCustom { words, pin } => self.handle_local_init_custom(words, pin),
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
            } => self.handle_fido_credential(id, credential_id, rp_id_hash, None),
            FidoRequest::Sign {
                credential_id,
                rp_id_hash,
                hash,
            } => self.handle_fido_credential(id, credential_id, rp_id_hash, Some(hash)),
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

        let mut outputs = match pending.action {
            PendingAction::Sign(pending) => match choice {
                ConfirmationChoice::Approve => {
                    let reply_to = pending.reply_to;
                    match self.sign(pending) {
                        Ok(payload) => vec![Self::transport(reply_to, payload)],
                        Err(_) => vec![Self::transport_error(reply_to, proto::AppError::Failed)],
                    }
                }
                ConfirmationChoice::Reject => vec![Self::transport_error(
                    pending.reply_to,
                    proto::AppError::Rejected,
                )],
            },
            PendingAction::Fido(request_id) => vec![Self::fido(
                request_id,
                FidoOutput {
                    status: if choice == ConfirmationChoice::Approve {
                        FidoStatus::Success
                    } else {
                        FidoStatus::Failed
                    },
                    credential_id: Vec::new(),
                    data: Vec::new(),
                },
            )],
        };

        outputs.push(CoreEffect::ConfirmationCompleted {
            id,
            outcome: match choice {
                ConfirmationChoice::Approve => ConfirmationOutcome::Approved,
                ConfirmationChoice::Reject => ConfirmationOutcome::Rejected,
            },
        });
        outputs.push(CoreEffect::WalletState(self.state()));
        outputs
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
                    Err(_) => self.transport_error_output(route, proto::AppError::Failed),
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
                vec![Self::local_error(
                    proto::AppError::UnlockFailed,
                    failures.into(),
                )]
            }
            Err(UnlockFailure::Reset) => vec![
                Self::local_error(proto::AppError::UnlockFailed, MAX_FAILED_UNLOCKS.into()),
                CoreEffect::WalletState(WalletState::Setup),
            ],
            Err(UnlockFailure::Storage) => {
                vec![Self::local_error(proto::AppError::Failed, 0)]
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
                    self.initialize_seed(&mnemonic, &request.password)?;
                    Ok(mnemonic.words.join(" "))
                })();
                self.external_init_result(route, result)
            }
        };
        request.password.zeroize();
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
                    self.initialize_seed(&mnemonic, &request.password)?;
                    Ok(mnemonic.words.join(" "))
                })();
                self.external_init_result(route, result)
            }
        };
        request.words.zeroize();
        request.password.zeroize();
        request.pin.zeroize();
        effects
    }

    fn handle_local_init_custom(&mut self, words: &str, pin: &str) -> Vec<CoreEffect> {
        match self.seed_exists() {
            Err(_) => return vec![Self::local_error(proto::AppError::Failed, 0)],
            Ok(true) => return vec![Self::local_error(proto::AppError::InvalidAction, 0)],
            Ok(false) => {}
        }

        let result = (|| {
            self.set_pin_text(pin)?;
            let mnemonic = mnemonic::Mnemonic::from_phrase(words)?;
            self.initialize_seed(&mnemonic, "")
        })();

        match result {
            Ok(()) => vec![
                Self::local(LocalAction::Ready, String::new()),
                CoreEffect::WalletState(WalletState::Ready),
            ],
            Err(_) => vec![Self::local_error(proto::AppError::Failed, 0)],
        }
    }

    fn initialize_seed(&mut self, mnemonic: &mnemonic::Mnemonic, password: &str) -> Result<()> {
        let mut seed = mnemonic.to_seed(password)?;
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

    fn handle_fido_register(&self, id: u32, rp_id: &str, cred_protect: u8) -> Vec<CoreEffect> {
        if self.locked {
            return vec![Self::fido(id, Self::fido_error())];
        }

        let result: Result<FidoOutput> = (|| {
            let nonce = self.platform.random(oskey_chain::fido::NONCE_SIZE);
            let credential = oskey_chain::fido::create(
                &self.load_seed()?,
                rp_id,
                nonce.as_slice().try_into()?,
                cred_protect,
            )?;
            Ok(FidoOutput {
                status: FidoStatus::Success,
                credential_id: credential.id.to_vec(),
                data: credential.public_key.to_vec(),
            })
        })();

        vec![Self::fido(
            id,
            result.unwrap_or_else(|_| Self::fido_error()),
        )]
    }

    fn handle_fido_credential(
        &self,
        id: u32,
        credential_id: &[u8],
        rp_id_hash: &[u8],
        hash: Option<&[u8]>,
    ) -> Vec<CoreEffect> {
        if self.locked {
            return vec![Self::fido(id, Self::fido_error())];
        }

        let result: Result<Vec<u8>> = self.load_seed().and_then(|seed| {
            if let Some(hash) = hash {
                oskey_chain::fido::sign(&seed, credential_id, rp_id_hash, hash)
                    .map(|signature| signature.to_vec())
            } else {
                oskey_chain::fido::validate(&seed, credential_id, rp_id_hash)
                    .map(|cred_protect| vec![cred_protect])
            }
        });

        vec![Self::fido(
            id,
            match result {
                Ok(data) => FidoOutput {
                    status: FidoStatus::Success,
                    credential_id: Vec::new(),
                    data,
                },
                Err(_) => Self::fido_error(),
            },
        )]
    }

    fn prepare_sign(
        &self,
        route: TransportRoute,
        request: proto::SignEthRequest,
    ) -> Result<(PendingSign, ConfirmationDetails)> {
        let proto::SignEthRequest { id, path, tx, .. } = request;
        let path: DerivationPath = path.parse()?;
        let tx = tx.ok_or_else(|| anyhow!("Transaction data is missing"))?;
        let public_key = wallets::ExtendedPrivKey::derive(
            &self.load_seed()?,
            path.clone(),
            wallets::Curve::K256,
        )?
        .export_pk()?
        .to_vec();
        let from = oskey_chain::eth::OSKeyTxEip191::address(&public_key)?;

        let (hash, details) = match tx {
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
                let hash = transaction.hash();
                let details =
                    ConfirmationDetails::EthTransaction(transaction.confirmation(&hash, from));
                (hash, details)
            }
            proto::sign_eth_request::Tx::Eip191(message) => {
                if message.is_personal == Some(false) {
                    return Err(anyhow!("Non-personal message signing is unsupported"));
                }
                let hash =
                    oskey_chain::eth::OSKeyTxEip191::hash_message(message.message.as_bytes());
                let details = ConfirmationDetails::EthMessage(
                    oskey_chain::eth::OSKeyTxEip191::confirmation(&message.message, &hash, from)?,
                );
                (hash, details)
            }
        };

        Ok((
            PendingSign {
                id,
                path,
                hash,
                public_key,
                reply_to: route,
            },
            details,
        ))
    }

    fn sign(&self, pending: PendingSign) -> Result<res_data::Payload> {
        let private_key = wallets::ExtendedPrivKey::derive(
            &self.load_seed()?,
            pending.path,
            wallets::Curve::K256,
        )?;
        let signature = private_key.sign(&pending.hash)?;

        Ok(res_data::Payload::SignResponse(proto::SignResponse {
            id: pending.id,
            message: Vec::new(),
            public_key: pending.public_key,
            pre_hash: pending.hash.to_vec(),
            signature: signature.to_vec(),
            recovery_id: None,
        }))
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
        let mut seed =
            crypto::ChaCha20Poly1305Cipher::decrypt(&self.pin_cache, &nonce, &stored[12..])
                .map_err(|_| SeedLoadError::Credentials)?;
        let result = Zeroizing::new(seed.as_slice().to_vec());
        seed.as_mut_slice().zeroize();
        Ok(result)
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

    fn frame(payload: req_data::Payload) -> Vec<u8> {
        FrameParser::pack(
            &proto::ReqData {
                payload: Some(payload),
            }
            .encode_to_vec(),
        )
    }

    fn init(runtime: &mut WalletRuntime<TestPlatform>) {
        let outputs = runtime.handle(CoreRequest::Local(LocalRequest::InitCustom {
            words: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            pin: "Password1!",
        }));
        assert!(outputs
            .iter()
            .any(|output| matches!(output, CoreEffect::WalletState(WalletState::Ready))));
    }

    fn protocol(
        runtime: &mut WalletRuntime<TestPlatform>,
        transport: Transport,
        data: &[u8],
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
            data,
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

    #[test]
    fn version_replies_to_origin() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(false));
        let request = frame(req_data::Payload::VersionRequest(proto::VersionRequest {}));
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
            &frame(req_data::Payload::VersionRequest(proto::VersionRequest {})),
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
                &frame(req_data::Payload::InitRequest(proto::InitWalletRequest {
                    length: 12,
                    password: String::new(),
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
                &frame(req_data::Payload::UnlockRequest(proto::UnlockRequest {
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
        assert_eq!(runtime.app.failed_unlocks, 0);
    }

    #[test]
    fn protocol_parser_keeps_fragment_state() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(false));
        let request = frame(req_data::Payload::VersionRequest(proto::VersionRequest {}));
        let (first, second) = request.split_at(3);

        assert!(protocol(&mut runtime, Transport::Uart, first).is_empty());
        assert!(matches!(
            protocol(&mut runtime, Transport::Bluetooth, &request).as_slice(),
            [CoreEffect::Transport(
                TransportRoute {
                    transport: Transport::Bluetooth,
                    session_id: 7
                },
                _
            )]
        ));
        assert!(matches!(
            protocol(&mut runtime, Transport::Uart, second).as_slice(),
            [CoreEffect::Transport(
                TransportRoute {
                    transport: Transport::Uart,
                    session_id: 0
                },
                _
            )]
        ));
    }

    #[test]
    fn bluetooth_parser_does_not_cross_sessions() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(false));
        let request = frame(req_data::Payload::VersionRequest(proto::VersionRequest {}));
        let (first, second) = request.split_at(3);

        assert!(runtime
            .handle(CoreRequest::Protocol {
                route: TransportRoute {
                    transport: Transport::Bluetooth,
                    session_id: 7,
                },
                data: first,
            })
            .is_empty());
        assert!(runtime
            .handle(CoreRequest::Protocol {
                route: TransportRoute {
                    transport: Transport::Bluetooth,
                    session_id: 8,
                },
                data: second,
            })
            .is_empty());
        assert!(matches!(
            runtime
                .handle(CoreRequest::Protocol {
                    route: TransportRoute {
                        transport: Transport::Bluetooth,
                        session_id: 8,
                    },
                    data: &request,
                })
                .as_slice(),
            [CoreEffect::Transport(
                TransportRoute {
                    transport: Transport::Bluetooth,
                    session_id: 8
                },
                _
            )]
        ));
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
                &frame(req_data::Payload::InitRequest(proto::InitWalletRequest {
                    length,
                    password: String::new(),
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
            &frame(req_data::Payload::InitRequest(proto::InitWalletRequest {
                length: 12,
                password: String::new(),
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
                password: String::new(),
                seed: None,
                pin: vec![0; 32],
            }),
            req_data::Payload::InitCustomRequest(proto::InitWalletCustomRequest {
                words:
                    "legal winner thank year wave sausage worth useful legal winner thank yellow"
                        .into(),
                password: String::new(),
                pin: vec![0; 32],
            }),
        ] {
            assert!(matches!(
                protocol(&mut runtime, Transport::Uart, &frame(payload)).as_slice(),
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
                &frame(req_data::Payload::UnlockRequest(proto::UnlockRequest {
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
                [CoreEffect::Local(LocalResult {
                    error: proto::AppError::Failed,
                    ..
                })]
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
            &frame(req_data::Payload::UnlockRequest(proto::UnlockRequest {
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
        let mut runtime = WalletRuntime::new(platform);
        let mut input = b"Password1!".to_vec();
        input.extend_from_slice(PIN_SALT);
        let hash = crypto::Hash::sha256(&input).unwrap();

        let outputs = protocol(
            &mut runtime,
            Transport::Uart,
            &frame(req_data::Payload::UnlockRequest(proto::UnlockRequest {
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
                })] if *value == expected
            ));
        }

        let mut restarted = WalletRuntime::new(platform.clone());
        assert_eq!(restarted.app.failed_unlocks, 3);
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
        assert!(!local.app.storage_failed);
        assert!(!local.app.locked);
        assert_eq!(local.app.failed_unlocks, 0);
        assert!(local_platform.seed.borrow().is_empty());

        let external_platform = TestPlatform::new(false);
        init(&mut WalletRuntime::new(external_platform.clone()));
        let mut external = WalletRuntime::new(external_platform.clone());
        let wrong_pin = frame(req_data::Payload::UnlockRequest(proto::UnlockRequest {
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
        assert!(!external.app.storage_failed);
        assert!(!external.app.locked);
        assert_eq!(external.app.failed_unlocks, 0);
        assert!(external_platform.seed.borrow().is_empty());
    }

    #[test]
    fn lock_and_reset_publish_the_resulting_state() {
        let mut setup = WalletRuntime::new(TestPlatform::new(false));
        assert!(matches!(
            protocol(
                &mut setup,
                Transport::Uart,
                &frame(req_data::Payload::LockRequest(proto::LockRequest {})),
            )
            .as_slice(),
            [
                CoreEffect::Transport(_, _),
                CoreEffect::WalletState(WalletState::Setup)
            ]
        ));

        let mut ready = WalletRuntime::new(TestPlatform::new(true));
        init(&mut ready);
        assert_ne!(ready.app.pin_cache, [0; 32]);
        ready.app.storage_failed = true;
        ready.app.locked = true;
        ready.app.failed_unlocks = 3;
        assert!(matches!(
            ready
                .handle(CoreRequest::Local(LocalRequest::ResetStorage))
                .as_slice(),
            [CoreEffect::WalletState(WalletState::Setup)]
        ));
        assert_eq!(ready.app.pin_cache, [0; 32]);
        assert!(!ready.app.storage_failed);
        assert!(!ready.app.locked);
        assert_eq!(ready.app.failed_unlocks, 0);

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
    fn signing_uses_id_only_event_and_native_details() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(false));
        init(&mut runtime);

        let outputs = protocol(
            &mut runtime,
            Transport::Bluetooth,
            &frame(sign_request("hello".into())),
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
        let Some(ConfirmationDetails::EthMessage(details)) = runtime.confirmation(id) else {
            panic!("expected Ethereum message confirmation");
        };
        let confirmation_from = details.from;
        let confirmation_hash = details.signing_hash;

        let completed = confirm(&mut runtime, id, ConfirmationChoice::Approve);
        assert!(matches!(
            completed.as_slice(),
            [
                CoreEffect::Transport(
                    TransportRoute {
                        transport: Transport::Bluetooth,
                        session_id: 7
                    },
                    _
                ),
                CoreEffect::ConfirmationCompleted {
                    id: completed_id,
                    outcome: ConfirmationOutcome::Approved
                },
                CoreEffect::WalletState(WalletState::Ready)
            ] if *completed_id == id
        ));
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
            &frame(req_data::Payload::SignEthRequest(request)),
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
    fn stale_and_duplicate_confirmation_decisions_are_ignored() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(false));
        init(&mut runtime);
        let outputs = protocol(
            &mut runtime,
            Transport::Uart,
            &frame(sign_request("hello".into())),
        );
        let id = outputs
            .iter()
            .find_map(|output| match output {
                CoreEffect::ConfirmationRequired(id) => Some(*id),
                _ => None,
            })
            .unwrap();

        assert!(confirm(&mut runtime, id + 1, ConfirmationChoice::Approve).is_empty());
        assert!(!confirm(&mut runtime, id, ConfirmationChoice::Reject).is_empty());
        assert!(confirm(&mut runtime, id, ConfirmationChoice::Approve).is_empty());
    }

    #[test]
    fn pending_confirmation_rejects_other_requests_as_busy() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(false));
        init(&mut runtime);
        let pending = protocol(
            &mut runtime,
            Transport::Uart,
            &frame(sign_request("hello".into())),
        );
        let confirmation_id = pending
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::ConfirmationRequired(id) => Some(*id),
                _ => None,
            })
            .unwrap();

        let status = frame(req_data::Payload::StatusRequest(proto::StatusRequest {}));
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
        assert!(protocol(&mut runtime, Transport::Uart, &status).is_empty());

        confirm(&mut runtime, confirmation_id, ConfirmationChoice::Reject);
        let pending = protocol(
            &mut runtime,
            Transport::Uart,
            &frame(sign_request("again".into())),
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
    fn entering_busy_discards_later_frames_in_the_same_chunk() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(false));
        init(&mut runtime);

        let mut requests = frame(sign_request("hello".into()));
        requests.extend(frame(req_data::Payload::LockRequest(proto::LockRequest {})));
        let outputs = protocol(&mut runtime, Transport::Uart, &requests);
        let confirmation_id = outputs
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::ConfirmationRequired(id) => Some(*id),
                _ => None,
            })
            .unwrap();

        assert_eq!(runtime.state(), WalletState::Busy);
        confirm(&mut runtime, confirmation_id, ConfirmationChoice::Reject);
        assert_eq!(runtime.state(), WalletState::Ready);
        assert!(matches!(
            protocol(
                &mut runtime,
                Transport::Uart,
                &frame(req_data::Payload::StatusRequest(proto::StatusRequest {})),
            )
            .as_slice(),
            [CoreEffect::Transport(
                _,
                proto::ResData {
                    payload: Some(res_data::Payload::StatusResponse(_))
                }
            )]
        ));
    }

    #[test]
    fn pending_confirmation_discards_partial_frames() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(false));
        init(&mut runtime);
        let outputs = protocol(
            &mut runtime,
            Transport::Uart,
            &frame(sign_request("hello".into())),
        );
        let id = outputs
            .iter()
            .find_map(|output| match output {
                CoreEffect::ConfirmationRequired(id) => Some(*id),
                _ => None,
            })
            .unwrap();
        let status = frame(req_data::Payload::StatusRequest(proto::StatusRequest {}));
        let middle = status.len() / 2;

        assert!(matches!(
            protocol(&mut runtime, Transport::Uart, &status[..middle]).as_slice(),
            [CoreEffect::Transport(
                _,
                proto::ResData {
                    payload: Some(res_data::Payload::ErrorResponse(_))
                }
            )]
        ));
        confirm(&mut runtime, id, ConfirmationChoice::Reject);
        assert!(protocol(&mut runtime, Transport::Uart, &status[middle..]).is_empty());
        assert!(matches!(
            protocol(&mut runtime, Transport::Uart, &status).as_slice(),
            [CoreEffect::Transport(
                _,
                proto::ResData {
                    payload: Some(res_data::Payload::StatusResponse(_))
                }
            )]
        ));
    }

    #[test]
    fn fido_uses_same_confirmation_service() {
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
            Some(ConfirmationDetails::Fido(_))
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
                CoreEffect::ConfirmationCompleted {
                    id: completed_id,
                    outcome: ConfirmationOutcome::Approved
                },
                CoreEffect::WalletState(WalletState::Ready)
            ] if *completed_id == id
        ));
    }

    #[test]
    fn fido_approval_does_not_hold_runtime_busy() {
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
        assert_eq!(runtime.state(), WalletState::Ready);
        assert!(matches!(
            protocol(
                &mut runtime,
                Transport::Uart,
                &frame(req_data::Payload::StatusRequest(proto::StatusRequest {})),
            )
            .as_slice(),
            [CoreEffect::Transport(
                _,
                proto::ResData {
                    payload: Some(res_data::Payload::StatusResponse(_))
                }
            )]
        ));
    }

    #[test]
    fn fido_cancel_does_not_cancel_wallet_confirmation() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(false));
        init(&mut runtime);
        let outputs = protocol(
            &mut runtime,
            Transport::Uart,
            &frame(sign_request("hello".into())),
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
    fn large_message_is_released_after_preparing_confirmation() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(false));
        init(&mut runtime);
        let outputs = protocol(
            &mut runtime,
            Transport::Uart,
            &frame(sign_request("a".repeat(8192))),
        );
        let id = outputs
            .iter()
            .find_map(|output| match output {
                CoreEffect::ConfirmationRequired(id) => Some(*id),
                _ => None,
            })
            .unwrap();
        let Some(ConfirmationDetails::EthMessage(details)) = runtime.confirmation(id) else {
            panic!("expected message details");
        };
        assert!(details.truncated);
        assert_eq!(details.preview.len(), 256);
        assert_eq!(details.byte_length, 8192);
    }
}
