use tracing_subscriber::EnvFilter;

/// 初始化全局 `tracing` 日志订阅器（始终定向到 `stderr`，确保不污染 MCP stdio `stdout` 协议流）
///
/// - 优先读取环境变量 `RUST_LOG`；未设置时按 `default_level` 过滤（如 `warn` / `info` / `debug` / `off`）
/// - `format` 支持 `"compact"`（默认）、`"pretty"` 与 `"json"`（适合线上 RPC 接入 ELK/Loki）
pub fn init_logging(default_level: &str, format: &str) {
    if default_level.eq_ignore_ascii_case("off") && std::env::var("RUST_LOG").is_err() {
        return;
    }

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("runidbg={default_level},runidbg_arm64_emu_tracer={default_level}")));

    match format.to_ascii_lowercase().as_str() {
        "json" => {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .json()
                .try_init();
        }
        "pretty" => {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .pretty()
                .try_init();
        }
        _ => {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .compact()
                .try_init();
        }
    }
}
