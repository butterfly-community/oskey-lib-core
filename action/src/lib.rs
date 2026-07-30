#![no_std]

extern crate alloc;

mod confirmation;

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use anyhow::{anyhow, Result};
use oskey_bus::proto::{req_data, res_data};
pub use oskey_bus::{proto, FrameParser, Message};
use oskey_chain::eth::OSKeyTxEip2930;
use oskey_wallet::alg::crypto;
use oskey_wallet::{mnemonic, wallets};
use zeroize::{Zeroize, Zeroizing};

use confirmation::ConfirmationService;

const PIN_SALT: &[u8] = b"&%OSKey1$!@";

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppMessageSource {
    Uart = 0,
    Bluetooth = 1,
    Display = 2,
    Fido2 = 4,
    Confirmation = 5,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppMessageAction {
    External = 0,
    Unlock,
    InitCustom,
    GenerateMnemonic,
    Approve,
    Reject,
    Restart,
    ResetStorage,
    Fido2Register,
    Fido2Sign,
    Confirmation,
}

#[derive(Debug, PartialEq)]
pub struct WalletOutput {
    pub target: AppMessageSource,
    pub response: proto::ResData,
}

pub trait WalletPlatform {
    fn version(&self) -> String;
    fn serial_number(&self) -> String;
    fn support_mask(&self) -> Vec<u8>;
    fn storage_ready(&self) -> bool;
    fn seed_exists(&self) -> bool;
    fn random(&self, len: usize) -> Vec<u8>;
    fn read_seed(&self, data: &mut [u8]) -> Result<usize>;
    fn write_seed(&self, data: &[u8]) -> Result<()>;
    fn reset_storage(&self);
    fn restart(&self);
}

struct PendingSign {
    request: proto::SignEthRequest,
    reply_to: AppMessageSource,
}

#[allow(clippy::large_enum_variant)]
enum PendingAction {
    Sign(PendingSign),
    Fido2,
}

struct WalletApp<P> {
    platform: P,
    pin_cache: [u8; 32],
    locked: bool,
    failed_unlocks: u8,
    confirmation: ConfirmationService<PendingAction>,
}

pub struct WalletRuntime<P> {
    uart_parser: FrameParser,
    bluetooth_parser: FrameParser,
    app: WalletApp<P>,
}

impl<P: WalletPlatform> WalletRuntime<P> {
    pub fn new(platform: P) -> Self {
        Self {
            uart_parser: FrameParser::new(),
            bluetooth_parser: FrameParser::new(),
            app: WalletApp::new(platform),
        }
    }

    fn external(&mut self, source: AppMessageSource, data: &[u8]) -> Vec<WalletOutput> {
        let parser = match source {
            AppMessageSource::Uart => &mut self.uart_parser,
            AppMessageSource::Bluetooth => &mut self.bluetooth_parser,
            _ => return Vec::new(),
        };

        parser.push(data);
        let mut outputs = Vec::new();
        while let Some(request) = parser.unpack() {
            match request {
                Ok(request) => outputs.extend(self.app.handle(source, request)),
                Err(_) => outputs.push(WalletApp::<P>::error_output(
                    source,
                    proto::AppError::Failed,
                )),
            }
        }
        outputs
    }

    pub fn message(
        &mut self,
        source: AppMessageSource,
        action: AppMessageAction,
        value: u32,
        data: &[u8],
        auxiliary: &[u8],
    ) -> Vec<WalletOutput> {
        if action == AppMessageAction::External {
            return self.external(source, data);
        }

        if !matches!(
            source,
            AppMessageSource::Display | AppMessageSource::Fido2 | AppMessageSource::Confirmation
        ) {
            return Vec::new();
        }

        let request: Result<proto::ReqData> = (|| {
            let payload = match action {
                AppMessageAction::Unlock => {
                    req_data::Payload::UnlockRequest(proto::UnlockRequest {
                        hash: Vec::new(),
                        pin_text: Some(core::str::from_utf8(data)?.to_string()),
                    })
                }
                AppMessageAction::InitCustom => {
                    req_data::Payload::InitCustomRequest(proto::InitWalletCustomRequest {
                        words: core::str::from_utf8(data)?.to_string(),
                        password: String::new(),
                        pin: Vec::new(),
                        pin_text: Some(core::str::from_utf8(auxiliary)?.to_string()),
                    })
                }
                AppMessageAction::GenerateMnemonic => {
                    req_data::Payload::GenerateMnemonicRequest(proto::GenerateMnemonicRequest {
                        length: value,
                        entropy: (!data.is_empty()).then(|| data.to_vec()),
                    })
                }
                AppMessageAction::Approve | AppMessageAction::Reject => {
                    req_data::Payload::UserActionRequest(proto::UserActionRequest {
                        action: if action == AppMessageAction::Approve {
                            proto::UserAction::Approve as i32
                        } else {
                            proto::UserAction::Reject as i32
                        },
                    })
                }
                AppMessageAction::Restart | AppMessageAction::ResetStorage => {
                    req_data::Payload::DeviceRequest(proto::DeviceRequest {
                        action: if action == AppMessageAction::Restart {
                            proto::DeviceAction::Restart as i32
                        } else {
                            proto::DeviceAction::ResetStorage as i32
                        },
                    })
                }
                AppMessageAction::Fido2Register => {
                    req_data::Payload::Fido2RegisterRequest(proto::Fido2RegisterRequest {
                        rp_id: core::str::from_utf8(data)?.to_string(),
                        user_id: auxiliary.to_vec(),
                    })
                }
                AppMessageAction::Fido2Sign => {
                    if !matches!(auxiliary.len(), 32 | 64) {
                        return Err(anyhow!("Invalid FIDO2 signing request"));
                    }
                    req_data::Payload::Fido2SignRequest(proto::Fido2SignRequest {
                        credential_id: data.to_vec(),
                        rp_id_hash: auxiliary[..32].to_vec(),
                        hash: auxiliary.get(32..).unwrap_or_default().to_vec(),
                    })
                }
                AppMessageAction::Confirmation => {
                    req_data::Payload::ConfirmationControl(proto::ConfirmationControl {
                        active: value != 0,
                    })
                }
                AppMessageAction::External => return Err(anyhow!("Invalid local message action")),
            };
            Ok(proto::ReqData {
                payload: Some(payload),
            })
        })();

        match request {
            Ok(request) => self.app.handle(source, request),
            Err(_) if source == AppMessageSource::Display => {
                vec![WalletApp::<P>::display_error(proto::AppError::Failed, 0)]
            }
            Err(_) => vec![WalletApp::<P>::error_output(
                source,
                proto::AppError::Failed,
            )],
        }
    }
}

impl<P: WalletPlatform> WalletApp<P> {
    fn new(platform: P) -> Self {
        let locked = platform.seed_exists();

        Self {
            platform,
            pin_cache: [0; 32],
            locked,
            failed_unlocks: 0,
            confirmation: ConfirmationService::new(),
        }
    }

    fn handle(&mut self, source: AppMessageSource, request: proto::ReqData) -> Vec<WalletOutput> {
        if self.confirmation.is_waiting() {
            match request.payload {
                Some(req_data::Payload::UserActionRequest(request)) => {
                    return self.handle_user_action(source, request);
                }
                Some(req_data::Payload::ConfirmationControl(request))
                    if source == AppMessageSource::Fido2 && !request.active =>
                {
                    return self.handle_confirmation_control(source, request);
                }
                Some(req_data::Payload::ConfirmationControl(_))
                    if source == AppMessageSource::Fido2 =>
                {
                    return vec![Self::confirmation_result(AppMessageSource::Fido2, false)];
                }
                _ => {}
            }

            // TODO: Dispatch independent requests to a separate worker. Until then,
            // reject requests while user confirmation is pending.
            return self.error(source, proto::AppError::Busy);
        }

        let Some(payload) = request.payload else {
            return self.reply(source, res_data::Payload::Unknown(proto::Unknown {}));
        };

        match payload {
            req_data::Payload::Unknown(_) => {
                self.reply(source, res_data::Payload::Unknown(proto::Unknown {}))
            }
            req_data::Payload::VersionRequest(_) => {
                let features = proto::Features {
                    initialized: self.platform.seed_exists(),
                    support_mask: self.platform.support_mask(),
                };
                self.reply(
                    source,
                    res_data::Payload::VersionResponse(proto::VersionResponse {
                        version: self.platform.version(),
                        features: Some(features),
                        sn: self.platform.serial_number(),
                    }),
                )
            }
            req_data::Payload::StatusRequest(_) => self.reply(source, self.status_response()),
            req_data::Payload::LockRequest(_) => {
                self.locked = true;
                self.pin_cache.zeroize();
                self.reply(source, self.status_response())
            }
            req_data::Payload::UnlockRequest(request) => self.handle_unlock(source, request),
            req_data::Payload::GenerateMnemonicRequest(request) => {
                self.handle_generate_mnemonic(source, request)
            }
            req_data::Payload::InitRequest(request) => self.handle_init(source, request),
            req_data::Payload::InitCustomRequest(request) => {
                self.handle_init_custom(source, request)
            }
            req_data::Payload::DerivePublicKeyRequest(request) => {
                if self.locked {
                    return self.error(source, proto::AppError::Locked);
                }
                match self.derive_public_key(request) {
                    Ok(payload) => self.reply(source, payload),
                    Err(_) => self.error(source, proto::AppError::Failed),
                }
            }
            req_data::Payload::SignEthRequest(request) => self.handle_sign_request(source, request),
            req_data::Payload::UserActionRequest(_) => {
                self.error(source, proto::AppError::NoPendingAction)
            }
            req_data::Payload::DeviceRequest(request) => {
                self.handle_device_request(source, request)
            }
            req_data::Payload::Fido2RegisterRequest(request) => {
                self.handle_fido2_register(source, request)
            }
            req_data::Payload::Fido2SignRequest(request) => self.handle_fido2_sign(source, request),
            req_data::Payload::ConfirmationControl(request) => {
                self.handle_confirmation_control(source, request)
            }
        }
    }

    fn status_response(&self) -> res_data::Payload {
        let mut status_mask = vec![0; 16];
        status_mask[0] = self.platform.storage_ready() as u8;
        status_mask[1] = self.locked as u8;
        res_data::Payload::StatusResponse(proto::StatusResponse { status_mask })
    }

    fn handle_unlock(
        &mut self,
        source: AppMessageSource,
        request: proto::UnlockRequest,
    ) -> Vec<WalletOutput> {
        if self.external_display_operation(source) {
            return self.error(source, proto::AppError::DisplayRequired);
        }

        let result = self
            .set_request_pin(source, request.hash, request.pin_text)
            .and_then(|_| self.load_seed().map(|_| ()));

        match result {
            Ok(()) => {
                self.locked = false;
                self.failed_unlocks = 0;
                if source == AppMessageSource::Display {
                    vec![Self::display_output(proto::DisplayAction::Ready, "")]
                } else {
                    self.reply(source, self.status_response())
                }
            }
            Err(_) if source == AppMessageSource::Display => {
                self.failed_unlocks = self.failed_unlocks.saturating_add(1);
                if self.failed_unlocks >= 10 {
                    self.platform.reset_storage();
                }
                vec![Self::display_error(
                    proto::AppError::UnlockFailed,
                    self.failed_unlocks.into(),
                )]
            }
            Err(_) => self.error(source, proto::AppError::Failed),
        }
    }

    fn handle_generate_mnemonic(
        &self,
        source: AppMessageSource,
        request: proto::GenerateMnemonicRequest,
    ) -> Vec<WalletOutput> {
        if source != AppMessageSource::Display {
            return self.error(source, proto::AppError::DisplayRequired);
        }

        let result: Result<String> = (|| {
            let entropy = match request.entropy {
                Some(entropy) => entropy,
                None => self.platform.random(request.length as usize * 4 / 3),
            };
            let mnemonic = mnemonic::Mnemonic::from_entropy(&entropy)?;
            Ok(mnemonic.words.join(" "))
        })();

        match result {
            Ok(words) => vec![Self::display_output(proto::DisplayAction::Mnemonic, words)],
            Err(_) => self.error(source, proto::AppError::Failed),
        }
    }

    fn handle_init(
        &mut self,
        source: AppMessageSource,
        request: proto::InitWalletRequest,
    ) -> Vec<WalletOutput> {
        if self.external_display_operation(source) {
            return self.error(source, proto::AppError::DisplayRequired);
        }

        let result = (|| {
            self.set_request_pin(source, request.pin, request.pin_text)?;
            let entropy = self.platform.random(request.length as usize * 4 / 3);
            let mnemonic = mnemonic::Mnemonic::from_entropy(&entropy)?;
            let mut seed = mnemonic.to_seed(&request.password)?;
            let result = self.save_seed(&seed);
            seed.zeroize();
            result?;
            self.locked = false;
            Ok(mnemonic.words.join(" "))
        })();

        self.init_result(source, result)
    }

    fn handle_init_custom(
        &mut self,
        source: AppMessageSource,
        request: proto::InitWalletCustomRequest,
    ) -> Vec<WalletOutput> {
        if self.external_display_operation(source) {
            return self.error(source, proto::AppError::DisplayRequired);
        }

        let result = (|| {
            self.set_request_pin(source, request.pin, request.pin_text)?;
            let mnemonic = mnemonic::Mnemonic::from_phrase(&request.words)?;
            let mut seed = mnemonic.to_seed(&request.password)?;
            let result = self.save_seed(&seed);
            seed.zeroize();
            result?;
            self.locked = false;
            Ok(mnemonic.words.join(" "))
        })();

        self.init_result(source, result)
    }

    fn init_result(&self, source: AppMessageSource, result: Result<String>) -> Vec<WalletOutput> {
        match result {
            Ok(_) if source == AppMessageSource::Display => {
                vec![Self::display_output(proto::DisplayAction::Ready, "")]
            }
            Ok(words) => self.reply(
                source,
                res_data::Payload::InitWalletResponse(proto::InitWalletResponse {
                    mnemonic: Some(words),
                }),
            ),
            Err(_) => self.error(source, proto::AppError::Failed),
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
        source: AppMessageSource,
        request: proto::SignEthRequest,
    ) -> Vec<WalletOutput> {
        if self.locked {
            return self.error(source, proto::AppError::Locked);
        }

        if !matches!(source, AppMessageSource::Uart | AppMessageSource::Bluetooth) {
            return self.error(source, proto::AppError::ExternalRequestRequired);
        }

        let display_text = match Self::sign_display_text(&request) {
            Ok(text) => text,
            Err(_) => return self.error(source, proto::AppError::Failed),
        };

        if !self.confirmation.request(PendingAction::Sign(PendingSign {
            request,
            reply_to: source,
        })) {
            return self.error(source, proto::AppError::Busy);
        }

        vec![
            Self::output(
                source,
                res_data::Payload::WaitForUserActionResponse(proto::WaitForUserActionResponse {}),
            ),
            Self::confirmation_prompt(proto::ConfirmationKind::Sign, display_text),
        ]
    }

    fn handle_user_action(
        &mut self,
        source: AppMessageSource,
        request: proto::UserActionRequest,
    ) -> Vec<WalletOutput> {
        if source != AppMessageSource::Confirmation {
            return self.error(source, proto::AppError::TrustedActionRequired);
        }

        let Some(pending) = self.confirmation.finish() else {
            return self.error(source, proto::AppError::NoPendingAction);
        };

        let action =
            proto::UserAction::try_from(request.action).unwrap_or(proto::UserAction::Unspecified);

        let mut outputs = match pending {
            PendingAction::Sign(pending) => match action {
                proto::UserAction::Approve => match self.sign(pending.request) {
                    Ok(payload) => vec![Self::output(pending.reply_to, payload)],
                    Err(_) => vec![Self::error_output(
                        pending.reply_to,
                        proto::AppError::Failed,
                    )],
                },
                proto::UserAction::Reject => {
                    vec![Self::error_output(
                        pending.reply_to,
                        proto::AppError::Rejected,
                    )]
                }
                proto::UserAction::Unspecified => {
                    vec![Self::error_output(
                        pending.reply_to,
                        proto::AppError::InvalidAction,
                    )]
                }
            },
            PendingAction::Fido2 => {
                vec![Self::confirmation_result(
                    AppMessageSource::Fido2,
                    action == proto::UserAction::Approve,
                )]
            }
        };

        outputs.push(Self::confirmation_finished());
        outputs
    }

    fn handle_confirmation_control(
        &mut self,
        source: AppMessageSource,
        request: proto::ConfirmationControl,
    ) -> Vec<WalletOutput> {
        if source != AppMessageSource::Fido2 {
            return self.error(source, proto::AppError::TrustedActionRequired);
        }

        if request.active {
            if !self.confirmation.request(PendingAction::Fido2) {
                vec![Self::confirmation_result(source, false)]
            } else {
                vec![Self::confirmation_prompt(
                    proto::ConfirmationKind::Fido2,
                    "",
                )]
            }
        } else if matches!(self.confirmation.pending(), Some(PendingAction::Fido2)) {
            self.confirmation.finish();
            vec![Self::confirmation_finished()]
        } else {
            Vec::new()
        }
    }

    fn handle_device_request(
        &self,
        source: AppMessageSource,
        request: proto::DeviceRequest,
    ) -> Vec<WalletOutput> {
        if source != AppMessageSource::Display {
            return self.error(source, proto::AppError::DisplayRequired);
        }

        match proto::DeviceAction::try_from(request.action)
            .unwrap_or(proto::DeviceAction::Unspecified)
        {
            proto::DeviceAction::Restart => self.platform.restart(),
            proto::DeviceAction::ResetStorage => self.platform.reset_storage(),
            proto::DeviceAction::Unspecified => {
                return self.error(source, proto::AppError::InvalidAction);
            }
        }
        Vec::new()
    }

    fn handle_fido2_register(
        &self,
        source: AppMessageSource,
        request: proto::Fido2RegisterRequest,
    ) -> Vec<WalletOutput> {
        if source != AppMessageSource::Fido2 {
            return self.error(source, proto::AppError::TrustedActionRequired);
        }
        if self.locked {
            return self.error(source, proto::AppError::Locked);
        }

        let result: Result<res_data::Payload> = (|| {
            let credential =
                oskey_wallet::fido2::create(&self.load_seed()?, &request.rp_id, &request.user_id)?;
            Ok(res_data::Payload::Fido2Response(proto::Fido2Response {
                credential_id: credential.id.to_vec(),
                data: credential.public_key.to_vec(),
            }))
        })();

        match result {
            Ok(payload) => self.reply(source, payload),
            Err(_) => self.error(source, proto::AppError::Failed),
        }
    }

    fn handle_fido2_sign(
        &self,
        source: AppMessageSource,
        request: proto::Fido2SignRequest,
    ) -> Vec<WalletOutput> {
        if source != AppMessageSource::Fido2 {
            return self.error(source, proto::AppError::TrustedActionRequired);
        }
        if self.locked {
            return self.error(source, proto::AppError::Locked);
        }

        let result: Result<Vec<u8>> = self.load_seed().and_then(|seed| {
            if request.hash.is_empty() {
                oskey_wallet::fido2::validate(&seed, &request.credential_id, &request.rp_id_hash)
                    .map(|_| Vec::new())
            } else {
                oskey_wallet::fido2::sign(
                    &seed,
                    &request.credential_id,
                    &request.rp_id_hash,
                    &request.hash,
                )
                .map(|signature| signature.to_vec())
            }
        });

        match result {
            Ok(signature) => self.reply(
                source,
                res_data::Payload::Fido2Response(proto::Fido2Response {
                    credential_id: Vec::new(),
                    data: signature,
                }),
            ),
            Err(_) => self.error(source, proto::AppError::Failed),
        }
    }

    fn sign(&self, request: proto::SignEthRequest) -> Result<res_data::Payload> {
        let tx = request
            .tx
            .ok_or_else(|| anyhow!("Transaction data is missing"))?;
        let hash = match tx {
            proto::sign_eth_request::Tx::Eip2930(transaction) => {
                OSKeyTxEip2930::from_proto(transaction)?.hash()
            }
            proto::sign_eth_request::Tx::Eip191(message) => {
                oskey_chain::eth::OSKeyTxEip191::hash_message(message.message.as_bytes())
            }
        };

        let private_key = wallets::ExtendedPrivKey::derive(
            &self.load_seed()?,
            request.path.parse()?,
            wallets::Curve::K256,
        )?;
        let public_key = private_key.export_pk()?.to_vec();
        let signature = private_key.sign(&hash)?;

        Ok(res_data::Payload::SignResponse(proto::SignResponse {
            id: request.id,
            message: Vec::new(),
            public_key,
            pre_hash: hash.to_vec(),
            signature: signature.to_vec(),
            recovery_id: None,
        }))
    }

    fn sign_display_text(request: &proto::SignEthRequest) -> Result<String> {
        match request
            .tx
            .as_ref()
            .ok_or_else(|| anyhow!("Transaction data is missing"))?
        {
            proto::sign_eth_request::Tx::Eip2930(transaction) => {
                Ok(OSKeyTxEip2930::from_proto(transaction.clone())?.to_string())
            }
            proto::sign_eth_request::Tx::Eip191(message) => {
                let mut text: String = message.message.chars().take(512).collect();
                if text.len() < message.message.len() {
                    text.push_str("...");
                }
                Ok(text)
            }
        }
    }

    fn set_request_pin(
        &mut self,
        source: AppMessageSource,
        hash: Vec<u8>,
        pin_text: Option<String>,
    ) -> Result<()> {
        match source {
            AppMessageSource::Uart | AppMessageSource::Bluetooth => {
                if pin_text.is_some() {
                    return Err(anyhow!("Plaintext PIN is not allowed"));
                }
                self.set_pin_hash(&hash)
            }
            AppMessageSource::Display => {
                let pin = pin_text.ok_or_else(|| anyhow!("PIN is required"))?;
                let mut input = pin.into_bytes();
                input.extend_from_slice(PIN_SALT);
                let hash = crypto::Hash::sha256(&input);
                input.zeroize();
                let hash = hash?;
                self.set_pin_hash(&hash)
            }
            _ => Err(anyhow!("PIN request source is not allowed")),
        }
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

    fn load_seed(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut stored = vec![0; 128];
        let len = self.platform.read_seed(&mut stored)?;
        if !(12..=stored.len()).contains(&len) {
            return Err(anyhow!("Stored seed is invalid"));
        }
        stored.truncate(len);

        let mut nonce = [0; 12];
        nonce.copy_from_slice(&stored[..12]);
        crypto::ChaCha20Poly1305Cipher::decrypt(&self.pin_cache, &nonce, &stored[12..])
            .map(|seed| Zeroizing::new(seed.as_slice().to_vec()))
    }

    fn external_display_operation(&self, source: AppMessageSource) -> bool {
        matches!(source, AppMessageSource::Uart | AppMessageSource::Bluetooth)
            && self.platform.support_mask().get(5).copied() == Some(1)
    }

    fn reply(&self, source: AppMessageSource, payload: res_data::Payload) -> Vec<WalletOutput> {
        vec![Self::output(source, payload)]
    }

    fn error(&self, source: AppMessageSource, error: proto::AppError) -> Vec<WalletOutput> {
        if source == AppMessageSource::Display {
            return vec![Self::display_error(error, 0)];
        }

        vec![Self::error_output(source, error)]
    }

    fn output(target: AppMessageSource, payload: res_data::Payload) -> WalletOutput {
        WalletOutput {
            target,
            response: proto::ResData {
                payload: Some(payload),
            },
        }
    }

    fn error_output(target: AppMessageSource, error: proto::AppError) -> WalletOutput {
        Self::output(
            target,
            res_data::Payload::ErrorResponse(proto::ErrorResponse {
                code: error as i32,
                message: String::new(),
            }),
        )
    }

    fn display_output(action: proto::DisplayAction, text: impl Into<String>) -> WalletOutput {
        Self::output(
            AppMessageSource::Display,
            res_data::Payload::DisplayResponse(proto::DisplayResponse {
                action: action as i32,
                text: text.into(),
                error: proto::AppError::Unspecified as i32,
                value: 0,
            }),
        )
    }

    fn display_error(error: proto::AppError, value: u32) -> WalletOutput {
        Self::output(
            AppMessageSource::Display,
            res_data::Payload::DisplayResponse(proto::DisplayResponse {
                action: proto::DisplayAction::Error as i32,
                text: String::new(),
                error: error as i32,
                value,
            }),
        )
    }

    fn confirmation_prompt(kind: proto::ConfirmationKind, text: impl Into<String>) -> WalletOutput {
        Self::output(
            AppMessageSource::Confirmation,
            res_data::Payload::ConfirmationPrompt(proto::ConfirmationPrompt {
                active: true,
                kind: kind as i32,
                text: text.into(),
            }),
        )
    }

    fn confirmation_finished() -> WalletOutput {
        Self::output(
            AppMessageSource::Confirmation,
            res_data::Payload::ConfirmationPrompt(proto::ConfirmationPrompt {
                active: false,
                kind: proto::ConfirmationKind::Unspecified as i32,
                text: String::new(),
            }),
        )
    }

    fn confirmation_result(target: AppMessageSource, approved: bool) -> WalletOutput {
        Self::output(
            target,
            res_data::Payload::ConfirmationResult(proto::ConfirmationResult { approved }),
        )
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
        display: bool,
        device_action: Rc<RefCell<Option<proto::DeviceAction>>>,
    }

    impl TestPlatform {
        fn new(display: bool) -> Self {
            Self {
                seed: Rc::new(RefCell::new(Vec::new())),
                display,
                device_action: Rc::new(RefCell::new(None)),
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
            features[5] = self.display as u8;
            features
        }

        fn storage_ready(&self) -> bool {
            true
        }

        fn seed_exists(&self) -> bool {
            !self.seed.borrow().is_empty()
        }

        fn random(&self, len: usize) -> Vec<u8> {
            vec![0; len]
        }

        fn read_seed(&self, data: &mut [u8]) -> Result<usize> {
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

        fn reset_storage(&self) {
            self.seed.borrow_mut().clear();
            *self.device_action.borrow_mut() = Some(proto::DeviceAction::ResetStorage);
        }

        fn restart(&self) {
            *self.device_action.borrow_mut() = Some(proto::DeviceAction::Restart);
        }
    }

    fn request(
        app: &mut WalletApp<TestPlatform>,
        payload: req_data::Payload,
        source: AppMessageSource,
    ) -> Vec<WalletOutput> {
        app.handle(
            source,
            proto::ReqData {
                payload: Some(payload),
            },
        )
    }

    fn external(
        app: &mut WalletApp<TestPlatform>,
        payload: req_data::Payload,
    ) -> Vec<WalletOutput> {
        request(app, payload, AppMessageSource::Uart)
    }

    fn pin() -> Vec<u8> {
        vec![0; 32]
    }

    fn init_request() -> req_data::Payload {
        req_data::Payload::InitRequest(proto::InitWalletRequest {
            length: 12,
            password: String::new(),
            seed: None,
            pin: pin(),
            pin_text: None,
        })
    }

    fn sign_request() -> req_data::Payload {
        req_data::Payload::SignEthRequest(proto::SignEthRequest {
            id: 1,
            path: "m/44'/60'/0'/0/0".into(),
            tx: Some(proto::sign_eth_request::Tx::Eip191(proto::AppEthTxEip191 {
                message: "hello".into(),
                is_personal: None,
            })),
            debug_text: None,
        })
    }

    #[test]
    fn version_replies_to_origin() {
        let mut app = WalletApp::new(TestPlatform::new(false));
        let output = external(
            &mut app,
            req_data::Payload::VersionRequest(proto::VersionRequest {}),
        );

        assert_eq!(output.len(), 1);
        assert_eq!(output[0].target, AppMessageSource::Uart);
        assert!(matches!(
            output[0].response.payload,
            Some(res_data::Payload::VersionResponse(_))
        ));
    }

    #[test]
    fn external_plaintext_pin_is_rejected() {
        let mut app = WalletApp::new(TestPlatform::new(false));
        let payload = req_data::Payload::InitRequest(proto::InitWalletRequest {
            length: 12,
            password: String::new(),
            seed: None,
            pin: Vec::new(),
            pin_text: Some("Password1!".into()),
        });

        let output = external(&mut app, payload);
        assert!(matches!(
            output[0].response.payload,
            Some(res_data::Payload::ErrorResponse(_))
        ));
    }

    #[test]
    fn display_can_initialize_with_plaintext_pin() {
        let mut app = WalletApp::new(TestPlatform::new(true));
        let payload = req_data::Payload::InitCustomRequest(proto::InitWalletCustomRequest {
            words: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
            password: String::new(),
            pin: Vec::new(),
            pin_text: Some("Password1!".into()),
        });

        let output = request(&mut app, payload, AppMessageSource::Display);
        assert!(matches!(
            output[0].response.payload,
            Some(res_data::Payload::DisplayResponse(_))
        ));
    }

    #[test]
    fn sign_waits_for_a_trusted_user_action() {
        let mut app = WalletApp::new(TestPlatform::new(false));
        external(&mut app, init_request());

        let output = external(&mut app, sign_request());
        assert_eq!(output.len(), 2);
        assert!(matches!(
            output[0].response.payload,
            Some(res_data::Payload::WaitForUserActionResponse(_))
        ));
        assert_eq!(output[1].target, AppMessageSource::Confirmation);
        assert!(matches!(
            output[1].response.payload,
            Some(res_data::Payload::ConfirmationPrompt(
                proto::ConfirmationPrompt {
                    active: true,
                    kind,
                    ..
                }
            )) if kind == proto::ConfirmationKind::Sign as i32
        ));

        let untrusted = external(
            &mut app,
            req_data::Payload::UserActionRequest(proto::UserActionRequest {
                action: proto::UserAction::Approve as i32,
            }),
        );
        assert!(matches!(
            untrusted[0].response.payload,
            Some(res_data::Payload::ErrorResponse(_))
        ));

        let approved = request(
            &mut app,
            req_data::Payload::UserActionRequest(proto::UserActionRequest {
                action: proto::UserAction::Approve as i32,
            }),
            AppMessageSource::Confirmation,
        );
        assert!(matches!(
            approved[0].response.payload,
            Some(res_data::Payload::SignResponse(_))
        ));
    }

    #[test]
    fn pending_sign_rejects_another_request_as_busy() {
        let mut app = WalletApp::new(TestPlatform::new(false));
        external(&mut app, init_request());
        external(&mut app, sign_request());

        let output = external(
            &mut app,
            req_data::Payload::StatusRequest(proto::StatusRequest {}),
        );
        let Some(res_data::Payload::ErrorResponse(error)) = &output[0].response.payload else {
            panic!("expected busy error");
        };
        assert_eq!(error.code, proto::AppError::Busy as i32);
        assert!(error.message.is_empty());
    }

    #[test]
    fn fido2_uses_the_confirmation_service() {
        let mut app = WalletApp::new(TestPlatform::new(false));
        external(&mut app, init_request());

        let prompt = request(
            &mut app,
            req_data::Payload::ConfirmationControl(proto::ConfirmationControl { active: true }),
            AppMessageSource::Fido2,
        );
        assert!(matches!(
            prompt[0].response.payload,
            Some(res_data::Payload::ConfirmationPrompt(
                proto::ConfirmationPrompt {
                    active: true,
                    kind,
                    ..
                }
            )) if kind == proto::ConfirmationKind::Fido2 as i32
        ));

        let busy = external(&mut app, sign_request());
        assert!(matches!(
            busy[0].response.payload,
            Some(res_data::Payload::ErrorResponse(proto::ErrorResponse {
                code,
                ..
            })) if code == proto::AppError::Busy as i32
        ));

        let approved = request(
            &mut app,
            req_data::Payload::UserActionRequest(proto::UserActionRequest {
                action: proto::UserAction::Approve as i32,
            }),
            AppMessageSource::Confirmation,
        );
        assert!(matches!(
            approved[0].response.payload,
            Some(res_data::Payload::ConfirmationResult(
                proto::ConfirmationResult { approved: true }
            ))
        ));
    }

    #[test]
    fn fido2_cancellation_releases_the_confirmation_service() {
        let mut app = WalletApp::new(TestPlatform::new(false));

        request(
            &mut app,
            req_data::Payload::ConfirmationControl(proto::ConfirmationControl { active: true }),
            AppMessageSource::Fido2,
        );
        let output = request(
            &mut app,
            req_data::Payload::ConfirmationControl(proto::ConfirmationControl { active: false }),
            AppMessageSource::Fido2,
        );

        assert!(matches!(
            output[0].response.payload,
            Some(res_data::Payload::ConfirmationPrompt(
                proto::ConfirmationPrompt { active: false, .. }
            ))
        ));
        assert!(!app.confirmation.is_waiting());
    }

    #[test]
    fn malformed_fido2_message_returns_an_error() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(false));
        let output = runtime.message(
            AppMessageSource::Fido2,
            AppMessageAction::Fido2Register,
            0,
            &[0xff],
            &[],
        );

        assert!(matches!(
            output[0].response.payload,
            Some(res_data::Payload::ErrorResponse(_))
        ));
    }

    #[test]
    fn display_error_uses_a_typed_error_and_value() {
        let platform = TestPlatform::new(false);
        let mut first_boot = WalletApp::new(platform.clone());
        external(&mut first_boot, init_request());

        let mut second_boot = WalletApp::new(platform);
        let output = request(
            &mut second_boot,
            req_data::Payload::UnlockRequest(proto::UnlockRequest {
                hash: Vec::new(),
                pin_text: Some("wrong".into()),
            }),
            AppMessageSource::Display,
        );

        let Some(res_data::Payload::DisplayResponse(error)) = &output[0].response.payload else {
            panic!("expected display error");
        };
        assert_eq!(error.action, proto::DisplayAction::Error as i32);
        assert_eq!(error.error, proto::AppError::UnlockFailed as i32);
        assert_eq!(error.value, 1);
        assert!(error.text.is_empty());
    }

    #[test]
    fn confirmation_returns_to_original_transport() {
        let mut app = WalletApp::new(TestPlatform::new(false));
        external(&mut app, init_request());
        external(&mut app, sign_request());

        let output = request(
            &mut app,
            req_data::Payload::UserActionRequest(proto::UserActionRequest {
                action: proto::UserAction::Approve as i32,
            }),
            AppMessageSource::Confirmation,
        );

        assert_eq!(output[0].target, AppMessageSource::Uart);
        assert!(matches!(
            output[0].response.payload,
            Some(res_data::Payload::SignResponse(_))
        ));
        assert_eq!(output[1].target, AppMessageSource::Confirmation);
    }

    #[test]
    fn display_initialization_is_required_on_display_devices() {
        let mut app = WalletApp::new(TestPlatform::new(true));
        let output = external(&mut app, init_request());
        assert!(matches!(
            output[0].response.payload,
            Some(res_data::Payload::ErrorResponse(_))
        ));
    }

    #[test]
    fn display_unlock_cannot_be_bypassed_by_a_transport() {
        let platform = TestPlatform::new(true);
        let mut first_boot = WalletApp::new(platform.clone());
        request(
            &mut first_boot,
            req_data::Payload::InitCustomRequest(proto::InitWalletCustomRequest {
                words: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
                password: String::new(),
                pin: Vec::new(),
                pin_text: Some("Password1!".into()),
            }),
            AppMessageSource::Display,
        );

        let mut second_boot = WalletApp::new(platform);
        let output = external(
            &mut second_boot,
            req_data::Payload::UnlockRequest(proto::UnlockRequest {
                hash: pin(),
                pin_text: None,
            }),
        );

        assert!(matches!(
            output[0].response.payload,
            Some(res_data::Payload::ErrorResponse(_))
        ));
        assert!(second_boot.locked);
    }

    #[test]
    fn bluetooth_sign_response_returns_to_bluetooth() {
        let mut app = WalletApp::new(TestPlatform::new(false));
        external(&mut app, init_request());
        request(&mut app, sign_request(), AppMessageSource::Bluetooth);

        let output = request(
            &mut app,
            req_data::Payload::UserActionRequest(proto::UserActionRequest {
                action: proto::UserAction::Approve as i32,
            }),
            AppMessageSource::Confirmation,
        );
        assert_eq!(output[0].target, AppMessageSource::Bluetooth);
    }

    #[test]
    fn rejection_clears_pending_sign() {
        let mut app = WalletApp::new(TestPlatform::new(false));
        external(&mut app, init_request());
        external(&mut app, sign_request());

        let rejected = request(
            &mut app,
            req_data::Payload::UserActionRequest(proto::UserActionRequest {
                action: proto::UserAction::Reject as i32,
            }),
            AppMessageSource::Confirmation,
        );
        let Some(res_data::Payload::ErrorResponse(error)) = &rejected[0].response.payload else {
            panic!("expected rejection");
        };
        assert_eq!(error.code, proto::AppError::Rejected as i32);

        let status = external(
            &mut app,
            req_data::Payload::StatusRequest(proto::StatusRequest {}),
        );
        assert!(matches!(
            status[0].response.payload,
            Some(res_data::Payload::StatusResponse(_))
        ));
    }

    #[test]
    fn stored_wallet_starts_locked_and_can_be_unlocked() {
        let platform = TestPlatform::new(false);
        let mut first_boot = WalletApp::new(platform.clone());
        external(&mut first_boot, init_request());

        let mut second_boot = WalletApp::new(platform);
        let locked = external(
            &mut second_boot,
            req_data::Payload::DerivePublicKeyRequest(proto::DerivePublicKeyRequest {
                path: "m/44'/60'/0'/0/0".into(),
            }),
        );
        assert!(matches!(
            locked[0].response.payload,
            Some(res_data::Payload::ErrorResponse(_))
        ));

        let unlocked = external(
            &mut second_boot,
            req_data::Payload::UnlockRequest(proto::UnlockRequest {
                hash: pin(),
                pin_text: None,
            }),
        );
        let Some(res_data::Payload::StatusResponse(status)) = &unlocked[0].response.payload else {
            panic!("expected status");
        };
        assert_eq!(status.status_mask[1], 0);
    }

    #[test]
    fn lock_clears_the_pin_cache() {
        let mut app = WalletApp::new(TestPlatform::new(false));
        external(&mut app, init_request());
        assert_ne!(app.pin_cache, [0; 32]);

        let output = external(
            &mut app,
            req_data::Payload::LockRequest(proto::LockRequest {}),
        );
        let Some(res_data::Payload::StatusResponse(status)) = &output[0].response.payload else {
            panic!("expected status");
        };
        assert_eq!(status.status_mask[1], 1);
        assert_eq!(app.pin_cache, [0; 32]);
        assert!(app.load_seed().is_err());

        external(
            &mut app,
            req_data::Payload::UnlockRequest(proto::UnlockRequest {
                hash: pin(),
                pin_text: None,
            }),
        );
        assert!(app.load_seed().is_ok());
    }

    #[test]
    fn mnemonic_generation_is_a_display_message() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(true));
        let output = runtime.message(
            AppMessageSource::Display,
            AppMessageAction::GenerateMnemonic,
            12,
            &[0; 16],
            &[],
        );

        let Some(res_data::Payload::DisplayResponse(response)) = &output[0].response.payload else {
            panic!("expected display response");
        };
        assert_eq!(response.action, proto::DisplayAction::Mnemonic as i32);
        assert!(response.text.ends_with("about"));
    }

    #[test]
    fn device_actions_require_the_display() {
        let platform = TestPlatform::new(true);
        let mut app = WalletApp::new(platform.clone());
        let device_request = || {
            req_data::Payload::DeviceRequest(proto::DeviceRequest {
                action: proto::DeviceAction::Restart as i32,
            })
        };

        let rejected = external(&mut app, device_request());
        assert!(matches!(
            rejected[0].response.payload,
            Some(res_data::Payload::ErrorResponse(_))
        ));
        assert_eq!(*platform.device_action.borrow(), None);

        let output = request(&mut app, device_request(), AppMessageSource::Display);
        assert!(output.is_empty());
        assert_eq!(
            *platform.device_action.borrow(),
            Some(proto::DeviceAction::Restart)
        );
    }

    #[test]
    fn transport_parsers_keep_partial_frames_separate() {
        let mut runtime = WalletRuntime::new(TestPlatform::new(false));
        let uart_frame = FrameParser::pack(
            &proto::ReqData {
                payload: Some(req_data::Payload::VersionRequest(proto::VersionRequest {})),
            }
            .encode_to_vec(),
        );
        let bluetooth_frame = FrameParser::pack(
            &proto::ReqData {
                payload: Some(req_data::Payload::StatusRequest(proto::StatusRequest {})),
            }
            .encode_to_vec(),
        );

        assert!(runtime
            .external(AppMessageSource::Uart, &uart_frame[..2])
            .is_empty());

        let bluetooth = runtime.external(AppMessageSource::Bluetooth, &bluetooth_frame);
        assert_eq!(bluetooth[0].target, AppMessageSource::Bluetooth);
        assert!(matches!(
            bluetooth[0].response.payload,
            Some(res_data::Payload::StatusResponse(_))
        ));

        let uart = runtime.external(AppMessageSource::Uart, &uart_frame[2..]);
        assert_eq!(uart[0].target, AppMessageSource::Uart);
        assert!(matches!(
            uart[0].response.payload,
            Some(res_data::Payload::VersionResponse(_))
        ));
    }

    #[test]
    fn fido2_credential_survives_wallet_restore() {
        let platform = TestPlatform::new(false);
        let mut first_boot = WalletApp::new(platform.clone());
        external(&mut first_boot, init_request());

        let registered = request(
            &mut first_boot,
            req_data::Payload::Fido2RegisterRequest(proto::Fido2RegisterRequest {
                rp_id: "ssh:".into(),
                user_id: b"oskey".to_vec(),
            }),
            AppMessageSource::Fido2,
        );
        let Some(res_data::Payload::Fido2Response(credential)) = &registered[0].response.payload
        else {
            panic!("expected FIDO2 credential");
        };
        assert_eq!(credential.credential_id.len(), 64);
        assert_eq!(credential.data.len(), 65);

        let mut restored = WalletApp::new(platform);
        external(
            &mut restored,
            req_data::Payload::UnlockRequest(proto::UnlockRequest {
                hash: pin(),
                pin_text: None,
            }),
        );
        let signed = request(
            &mut restored,
            req_data::Payload::Fido2SignRequest(proto::Fido2SignRequest {
                credential_id: credential.credential_id.clone(),
                rp_id_hash: crypto::Hash::sha256(b"ssh:").unwrap().to_vec(),
                hash: vec![1; 32],
            }),
            AppMessageSource::Fido2,
        );
        let Some(res_data::Payload::Fido2Response(response)) = &signed[0].response.payload else {
            panic!("expected FIDO2 signature");
        };
        use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
        let public_key = VerifyingKey::from_sec1_bytes(&credential.data).unwrap();
        let signature = Signature::from_der(&response.data).unwrap();
        public_key.verify_prehash(&[1; 32], &signature).unwrap();
    }
}
