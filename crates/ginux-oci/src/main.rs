use std::env;
use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let arguments: Vec<OsString> = env::args_os().skip(1).collect();
    let Some((command, rest)) = arguments.split_first() else {
        eprintln!("usage: ginux-image materialize IMAGE CACHE_ROOT DESTINATION");
        eprintln!("       ginux-image import-layout CACHE_ROOT");
        eprintln!("       ginux-image export-tree ROOT MAX_BYTES MAX_MEMBERS MAX_PATH PATH...");
        eprintln!("       ginux-image inject-tree ROOT MAX_BYTES MAX_MEMBERS MAX_PATH PATH");
        return ExitCode::from(64);
    };
    match command.to_str() {
        Some("materialize") => materialize(rest),
        Some("import-layout") => ExitCode::from(ginux_oci::layout::run(rest)),
        Some("export-tree") => ExitCode::from(ginux_oci::export::run(rest)),
        Some("inject-tree") => ExitCode::from(ginux_oci::inject::run(rest)),
        _ => {
            eprintln!("ginux-image: unsupported private command");
            ExitCode::from(64)
        }
    }
}

fn materialize(arguments: &[OsString]) -> ExitCode {
    let [image, cache_root, destination] = arguments else {
        eprintln!("usage: ginux-image materialize IMAGE CACHE_ROOT DESTINATION");
        return ExitCode::from(64);
    };
    let Some(image) = image.to_str() else {
        eprintln!("ginux-image: image reference is not UTF-8");
        return ExitCode::from(64);
    };
    match ginux_oci::materialize(
        image,
        Path::new(cache_root),
        Path::new(destination),
        std::io::stderr(),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ginux-image: {error}");
            ExitCode::from(1)
        }
    }
}
