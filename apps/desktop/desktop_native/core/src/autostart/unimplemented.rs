use anyhow::Result;

/// Values supplied by the Electron main process. Unused on non-Linux platforms, where autostart is
/// handled directly through Electron's `app.setLoginItemSettings`.
pub struct AutostartConfig {
    pub exec_path: String,
    pub autostart_flag: String,
}

#[allow(clippy::unused_async)]
pub async fn is_background_portal_available() -> bool {
    false
}

#[allow(clippy::unused_async)]
pub async fn set_autostart(_enabled: bool, _config: AutostartConfig) -> Result<()> {
    unimplemented!();
}
