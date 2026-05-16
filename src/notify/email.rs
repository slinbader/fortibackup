//! SMTP email notification using lettre with STARTTLS over rustls.

use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::config::EmailConfig;
use crate::error::NotificationError;
use crate::notify::NotificationEvent;

/// Send an email notification.
///
/// # Errors
/// Returns [`NotificationError`] if the message cannot be built or the SMTP
/// transport rejects the message.
pub async fn send(cfg: &EmailConfig, event: &NotificationEvent) -> Result<(), NotificationError> {
    let password = std::env::var(&cfg.smtp_password_env).map_err(|_| {
        NotificationError::Smtp(format!("env var `{}` is not set", cfg.smtp_password_env))
    })?;

    let from_mbox = cfg
        .from
        .parse()
        .map_err(|e: lettre::address::AddressError| NotificationError::EmailBuild(e.to_string()))?;

    let mut builder = Message::builder()
        .from(from_mbox)
        .subject(event.subject())
        .header(ContentType::TEXT_PLAIN);

    for to in &cfg.to {
        let mbox = to.parse().map_err(|e: lettre::address::AddressError| {
            NotificationError::EmailBuild(format!("invalid `to` address `{to}`: {e}"))
        })?;
        builder = builder.to(mbox);
    }

    let message = builder
        .body(event.body())
        .map_err(|e| NotificationError::EmailBuild(e.to_string()))?;

    let tls = TlsParameters::new(cfg.smtp_host.clone())
        .map_err(|e| NotificationError::Smtp(e.to_string()))?;

    let mailer: AsyncSmtpTransport<Tokio1Executor> =
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.smtp_host)
            .map_err(|e| NotificationError::Smtp(e.to_string()))?
            .port(cfg.smtp_port)
            .tls(Tls::Required(tls))
            .credentials(Credentials::new(cfg.smtp_user.clone(), password))
            .build();

    mailer
        .send(message)
        .await
        .map_err(|e| NotificationError::Smtp(e.to_string()))?;
    Ok(())
}
