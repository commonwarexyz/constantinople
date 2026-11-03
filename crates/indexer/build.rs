fn main() {
    let mut config = connectrpc_build::CodeGenConfig::default();
    config.generate_json = true;
    config.file_per_package = true;
    connectrpc_build::Config::new()
        .files(&["proto/constantinople/explorer/v1/explorer.proto"])
        .includes(&["proto"])
        .buffa_config(config)
        .emit_register_fn(false)
        .compile()
        .expect("compile explorer service protobuf");
}
