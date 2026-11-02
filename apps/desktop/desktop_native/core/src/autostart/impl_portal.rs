use anyhow::Result;
use ashpd::desktop::background::{Background, BackgroundProxy};
use tracing::{error, info};

pub async fn is_background_portal_available() -> bool {
    let Ok(proxy) = BackgroundProxy::new().await else {
        return false;
    };

    proxy.get_property::<u32>("version").await.is_ok()
}

pub async fn set_autostart(autostart: bool, params: Vec<String>) -> Result<()> {
    let request = if params.is_empty() {
        Background::request().auto_start(autostart)
    } else {
        Background::request().command(params).auto_start(autostart)
    };

    match request.send().await.and_then(|r| r.response()) {
        Ok(response) => {
            if autostart {
                info!(response = ?response, "[autostart] Successfully enabled autostart");
            } else {
                info!(response = ?response, "[autostart] Successfully disabled autostart");
            }
            Ok(())
        }
        Err(err) => {
            if autostart {
                error!(error = %err, "[autostart] Failed to enable autostart");
            } else {
                error!(error = %err, "[autostart] Failed to disable autostart");
            }
            Err(anyhow::anyhow!("error setting autostart {}", err))
        }
    }
}
