mod extract;
mod image;
mod inject;
mod sys;
mod wait;

use clap::{ArgAction, ArgGroup, Args, Parser, Subcommand, ValueEnum};
use ginux_contract::Action;
use ginux_instance::InstanceConfig;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_HELPER: &str = "/usr/libexec/ginux/ginux-helper";
const HELPER_PROTOCOL: &str = "1";
const MAX_ROOT_LENGTH: usize = 256;

#[derive(Debug, Parser)]
#[command(
    name = "ginux",
    bin_name = "ginux",
    version,
    about = "Manage Ginux userspace-kernel instances",
    subcommand_required = true,
    arg_required_else_help = true,
    disable_help_subcommand = false
)]
pub struct Cli {
    /// Keep persistent instance state under DIR instead of the system default.
    #[arg(long, global = true, value_name = "DIR", value_parser = parse_root)]
    pub state_root: Option<String>,
    /// Keep transient run state under DIR (default: STATE_ROOT/run).
    #[arg(
        long,
        global = true,
        value_name = "DIR",
        value_parser = parse_root,
        requires = "state_root"
    )]
    pub run_root: Option<String>,
    #[command(subcommand)]
    pub command: PublicCommand,
}

#[derive(Debug, Subcommand)]
pub enum PublicCommand {
    #[command(flatten, next_help_heading = "Configure instances")]
    Configure(ConfigureCommand),
    #[command(flatten, next_help_heading = "Inspect instances")]
    InspectInstance(InspectInstanceCommand),
    #[command(flatten, next_help_heading = "Run instances")]
    Run(RunCommand),
    #[command(flatten, next_help_heading = "Maintain instances")]
    Maintain(MaintainCommand),
    #[command(flatten, next_help_heading = "Manage images")]
    Image(ImageCommand),
    #[command(flatten, next_help_heading = "Inspect recipes")]
    Recipe(RecipeCommand),
}

#[derive(Debug, Subcommand)]
pub enum ConfigureCommand {
    /// Create an instance from the installed default recipe.
    Create(CreateArgs),
    /// Create or replace an instance from a recipe.
    Import(ImportArgs),
    /// Atomically change recipe overrides or host deployment settings.
    Set(SetArgs),
    /// Edit, validate, and atomically apply an instance recipe.
    Edit(NameArgs),
    /// Write an instance recipe to standard output.
    Export(NameArgs),
    /// Delete a stopped instance and all of its state.
    Delete(NameArgs),
    /// Unpack a tar archive into a directory of a stopped instance.
    Inject(InjectArgs),
}

#[derive(Debug, Subcommand)]
pub enum InspectInstanceCommand {
    /// List instances.
    List,
    /// Show instance state and paths.
    Status(StatusArgs),
    /// Write directories of a stopped instance to a tar archive.
    Extract(ExtractArgs),
}

#[derive(Debug, Subcommand)]
pub enum RunCommand {
    /// Start an instance.
    Start(StartArgs),
    /// Attach to a running instance console.
    Attach(NameArgs),
    /// Stop an instance.
    Stop(NameArgs),
}

#[derive(Debug, Subcommand)]
pub enum MaintainCommand {
    /// Enforce the configured contract for a stopped instance.
    Lock(NameArgs),
    /// Enable bounded maintenance access for a stopped instance.
    Unlock(NameArgs),
}

#[derive(Debug, Subcommand)]
pub enum ImageCommand {
    /// Add an OCI image layout to the image cache without network access.
    ImportImage(PathArgs),
}

#[derive(Debug, Subcommand)]
pub enum RecipeCommand {
    /// Validate and compile a recipe without changing state.
    Validate(FileArgs),
    /// Show a recipe's normalized effective contract.
    Inspect(FileArgs),
    /// Explain one operation's effective contract decision.
    Explain(ExplainArgs),
}

#[derive(Debug, Args)]
pub struct NameArgs {
    #[arg(value_parser = parse_name)]
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum StatusFormat {
    /// Line-oriented text.
    Text,
    /// One JSON object on one line.
    Json,
}

#[derive(Debug, Args)]
pub struct StatusArgs {
    #[arg(value_parser = parse_name)]
    pub name: String,
    /// Output format.
    #[arg(long, value_enum, default_value_t = StatusFormat::Text)]
    pub format: StatusFormat,
}

#[derive(Debug, Args)]
pub struct ExtractArgs {
    #[arg(value_parser = parse_name)]
    pub name: String,
    /// Archive to create; it must not exist.
    #[arg(long, value_name = "FILE")]
    pub output: PathBuf,
    /// Largest total size of regular-file contents.
    #[arg(long, value_name = "N", value_parser = extract::parse_bound, default_value_t = extract::DEFAULT_MAX_BYTES)]
    pub max_bytes: u64,
    /// Largest number of archive members.
    #[arg(long, value_name = "N", value_parser = extract::parse_bound, default_value_t = extract::DEFAULT_MAX_MEMBERS)]
    pub max_members: u64,
    /// Longest path, in bytes, of a requested path or an archive member.
    #[arg(long, value_name = "N", value_parser = extract::parse_bound, default_value_t = extract::DEFAULT_MAX_PATH)]
    pub max_path: u64,
    /// Absolute directory paths inside the instance.
    #[arg(required = true, value_name = "PATH", value_parser = extract::parse_instance_path)]
    pub paths: Vec<String>,
}

#[derive(Debug, Args)]
pub struct InjectArgs {
    #[arg(value_parser = parse_name)]
    pub name: String,
    /// Uncompressed tar archive to unpack; read with the caller's own rights.
    #[arg(long, value_name = "FILE")]
    pub input: PathBuf,
    /// Absolute directory path inside the instance to unpack into.
    #[arg(long, value_name = "PATH", value_parser = extract::parse_instance_path)]
    pub into: String,
    /// Largest total size of regular-file contents.
    #[arg(long, value_name = "N", value_parser = extract::parse_bound, default_value_t = extract::DEFAULT_MAX_BYTES)]
    pub max_bytes: u64,
    /// Largest number of archive members.
    #[arg(long, value_name = "N", value_parser = extract::parse_bound, default_value_t = extract::DEFAULT_MAX_MEMBERS)]
    pub max_members: u64,
    /// Longest path, in bytes, of the target path or an archive member.
    #[arg(long, value_name = "N", value_parser = extract::parse_bound, default_value_t = extract::DEFAULT_MAX_PATH)]
    pub max_path: u64,
}

#[derive(Debug, Args)]
pub struct PathArgs {
    /// OCI image-layout directory or uncompressed tar archive of one.
    pub path: PathBuf,
}

#[derive(Debug, Args)]
pub struct FileArgs {
    pub file: PathBuf,
}

#[derive(Debug, Args)]
pub struct ExplainArgs {
    pub file: PathBuf,
    pub operation: String,
}

#[derive(Debug, Args)]
pub struct CreateArgs {
    #[arg(value_parser = parse_name)]
    pub name: String,
    #[command(flatten)]
    pub deployment: DeploymentArgs,
}

#[derive(Debug, Args)]
pub struct ImportArgs {
    #[arg(value_parser = parse_name)]
    pub name: String,
    pub file: PathBuf,
    #[command(flatten)]
    pub deployment: DeploymentArgs,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("change")
        .required(true)
        .multiple(true)
        .args(["overrides", "network", "forwards"])
))]
pub struct SetArgs {
    #[arg(value_parser = parse_name)]
    pub name: String,
    #[command(flatten)]
    pub deployment: DeploymentArgs,
}

#[derive(Debug, Args, Default)]
pub struct DeploymentArgs {
    /// Override one recipe key with a TOML value.
    #[arg(long = "set", value_name = "KEY=TOML_VALUE", value_parser = parse_override, action = ArgAction::Append)]
    pub overrides: Vec<String>,
    /// Bind the instance to a host attachment, or use "default".
    #[arg(long, value_name = "ATTACHMENT", value_parser = parse_network)]
    pub network: Option<String>,
    /// Replace port forwarding; use "none" by itself to clear all forwards.
    #[arg(long = "forward", value_name = "SPEC", value_parser = parse_forward, action = ArgAction::Append)]
    pub forwards: Vec<String>,
}

#[derive(Debug, Args)]
pub struct StartArgs {
    #[arg(value_parser = parse_name)]
    pub name: String,
    /// Attach to the instance console after starting it.
    #[arg(long)]
    pub attach: bool,
    /// Enable detailed runtime audit output for this start.
    #[arg(long)]
    pub audit: bool,
    /// Stay in the foreground until the instance stops and exit with its
    /// workload status; stopping this command stops the instance.
    #[arg(long, conflicts_with = "attach")]
    pub wait: bool,
    /// With --wait: copy the instance console output to standard output as
    /// it appears; a run that does not exit 0 also prints the end of the
    /// audit log to standard error.
    #[arg(long, requires = "wait", conflicts_with = "attach")]
    pub stream_console: bool,
}

fn parse_name(value: &str) -> Result<String, String> {
    if value.is_empty()
        || value.starts_with('.')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    {
        return Err(
            "instance names may contain only letters, digits, '_', '.', and '-', and must not start with '.'"
                .into(),
        );
    }
    Ok(value.into())
}

fn parse_root(value: &str) -> Result<String, String> {
    if value.len() > MAX_ROOT_LENGTH {
        return Err(format!("roots may be at most {MAX_ROOT_LENGTH} bytes"));
    }
    if !value.starts_with('/')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_./-".contains(&byte))
    {
        return Err(
            "roots must be absolute and contain only letters, digits, '_', '.', '/', and '-'"
                .into(),
        );
    }
    if value[1..]
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err("roots must not contain empty, '.' or '..' components".into());
    }
    Ok(value.into())
}

fn parse_override(value: &str) -> Result<String, String> {
    let Some((key, toml)) = value.split_once('=') else {
        return Err("expected KEY=TOML_VALUE".into());
    };
    if key.is_empty() || toml.is_empty() {
        return Err("expected non-empty KEY=TOML_VALUE".into());
    }
    Ok(value.into())
}

fn parse_network(value: &str) -> Result<String, String> {
    if value == "default"
        || (!value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte)))
    {
        Ok(value.into())
    } else {
        Err("invalid network attachment".into())
    }
}

fn parse_forward(value: &str) -> Result<String, String> {
    if value == "none" {
        return Ok(value.into());
    }
    let mut protocol = None;
    let mut external = None;
    let mut instance = None;
    for field in value.split(',') {
        let Some((key, field_value)) = field.split_once('=') else {
            return Err("expected protocol=...,external_port=...,instance_port=...".into());
        };
        match key {
            "protocol" if protocol.is_none() && matches!(field_value, "tcp" | "udp") => {
                protocol = Some(field_value)
            }
            "external_port" if external.is_none() => external = Some(parse_port(field_value)?),
            "instance_port" if instance.is_none() => instance = Some(parse_port(field_value)?),
            _ => return Err("invalid or duplicate forwarding field".into()),
        }
    }
    if protocol.is_none() || external.is_none() || instance.is_none() {
        return Err("forwarding requires protocol, external_port, and instance_port".into());
    }
    Ok(value.into())
}

fn parse_port(value: &str) -> Result<u16, String> {
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| "ports must be integers from 1 through 65535".into())
}

fn validate_deployment(args: &DeploymentArgs) -> Result<(), String> {
    if args.forwards.len() > 1 && args.forwards.iter().any(|value| value == "none") {
        return Err("--forward none conflicts with every other --forward value".into());
    }
    Ok(())
}

pub fn validate_cli(cli: &Cli) -> Result<(), String> {
    if cli.run_root.is_none() {
        if let Some(state_root) = &cli.state_root {
            if state_root.len() + "/run".len() > MAX_ROOT_LENGTH {
                return Err(format!(
                    "--state-root without --run-root implies STATE_ROOT/run, which exceeds {MAX_ROOT_LENGTH} bytes"
                ));
            }
        }
    }
    match &cli.command {
        PublicCommand::Configure(ConfigureCommand::Create(args)) => {
            validate_deployment(&args.deployment)
        }
        PublicCommand::Configure(ConfigureCommand::Import(args)) => {
            validate_deployment(&args.deployment)
        }
        PublicCommand::Configure(ConfigureCommand::Set(args)) => {
            validate_deployment(&args.deployment)
        }
        PublicCommand::InspectInstance(InspectInstanceCommand::Extract(args)) => {
            extract::check_path_lengths(&args.paths, args.max_path)
        }
        PublicCommand::Configure(ConfigureCommand::Inject(args)) => {
            extract::check_path_lengths(std::slice::from_ref(&args.into), args.max_path)
        }
        _ => Ok(()),
    }
}

pub fn run(cli: Cli) -> Result<i32, String> {
    validate_cli(&cli)?;
    let helper = Helper::new(&cli);
    let helper = &helper;
    match cli.command {
        PublicCommand::Configure(ConfigureCommand::Create(args)) => helper_status(
            helper,
            "create",
            [OsString::from(args.name)],
            &args.deployment,
        ),
        PublicCommand::Configure(ConfigureCommand::Import(args)) => helper_status(
            helper,
            "import",
            [OsString::from(args.name), args.file.into_os_string()],
            &args.deployment,
        ),
        PublicCommand::Configure(ConfigureCommand::Set(args)) => {
            helper_status(helper, "set", [OsString::from(args.name)], &args.deployment)
        }
        PublicCommand::Configure(ConfigureCommand::Edit(args)) => edit_instance(helper, &args.name),
        PublicCommand::Configure(ConfigureCommand::Export(args)) => {
            privileged_helper_status(helper, "export", [args.name])
        }
        PublicCommand::Configure(ConfigureCommand::Delete(args)) => {
            let mut command = helper.helper_command(true, "delete");
            command.arg(args.name);
            feature_helper_status(&mut command, "delete")
        }
        PublicCommand::Configure(ConfigureCommand::Inject(args)) => inject_instance(helper, &args),
        PublicCommand::InspectInstance(InspectInstanceCommand::List) => {
            privileged_helper_status(helper, "list", std::iter::empty::<String>())
        }
        PublicCommand::InspectInstance(InspectInstanceCommand::Status(args)) => {
            status_instance(helper, args)
        }
        PublicCommand::InspectInstance(InspectInstanceCommand::Extract(args)) => {
            extract_instance(helper, args)
        }
        PublicCommand::Run(RunCommand::Start(args)) => start_instance(helper, args),
        PublicCommand::Run(RunCommand::Attach(args)) => attach_instance(helper, &args.name),
        PublicCommand::Run(RunCommand::Stop(args)) => {
            privileged_helper_status(helper, "stop", [args.name])
        }
        PublicCommand::Maintain(MaintainCommand::Lock(args)) => {
            privileged_helper_status(helper, "lock", [args.name])
        }
        PublicCommand::Maintain(MaintainCommand::Unlock(args)) => {
            privileged_helper_status(helper, "unlock", [args.name])
        }
        PublicCommand::Image(ImageCommand::ImportImage(args)) => import_image(helper, &args.path),
        PublicCommand::Recipe(RecipeCommand::Validate(args)) => validate_recipe(&args.file),
        PublicCommand::Recipe(RecipeCommand::Inspect(args)) => inspect_recipe(&args.file),
        PublicCommand::Recipe(RecipeCommand::Explain(args)) => {
            explain_recipe(&args.file, &args.operation)
        }
    }
}

/// Builds every helper invocation, so the optional state and run roots reach
/// each call in the same position (`--protocol 1 [--state-root DIR --run-root
/// DIR] VERB`). With no roots the argument vector is exactly the historical one.
struct Helper {
    roots: Vec<OsString>,
}

impl Helper {
    fn new(cli: &Cli) -> Self {
        let mut roots = Vec::new();
        if let Some(state_root) = &cli.state_root {
            let run_root = cli
                .run_root
                .clone()
                .unwrap_or_else(|| format!("{state_root}/run"));
            roots.extend(
                ["--state-root", state_root, "--run-root", &run_root]
                    .into_iter()
                    .map(OsString::from),
            );
        }
        Self { roots }
    }

    /// The helper invocation for `verb`: through `sudo` when `privileged`,
    /// otherwise the helper itself (the unprivileged attach transport).
    fn helper_command(&self, privileged: bool, verb: &str) -> Command {
        let mut command = if privileged {
            let mut command = Command::new("sudo");
            command.arg(helper_path());
            command
        } else {
            Command::new(helper_path())
        };
        command
            .args(["--protocol", HELPER_PROTOCOL])
            .args(&self.roots)
            .arg(verb);
        command
    }
}

/// Map a helper usage failure (64) for a command or option that older helpers
/// do not know to "unsupported" (69). A current helper also exits 64 when it
/// refuses a state or run root; that refusal, recognized from the helper's
/// own standard error, keeps its status and message.
fn feature_status(code: i32, feature: &str, helper_stderr: &[u8]) -> i32 {
    if code != 64 || refused_root(helper_stderr) {
        return code;
    }
    print_error(&format!("the installed helper does not support {feature}"));
    69
}

fn refused_root(helper_stderr: &[u8]) -> bool {
    let text = String::from_utf8_lossy(helper_stderr);
    text.lines().any(|line| {
        line.starts_with("untrusted state root: ") || line.starts_with("untrusted run root: ")
    })
}

/// Spawn `command` with its standard error relayed, as it arrives, to this
/// process's standard error; the join handle returns a copy of everything
/// relayed.
pub(crate) fn spawn_relaying_stderr(
    command: &mut Command,
) -> io::Result<(std::process::Child, std::thread::JoinHandle<Vec<u8>>)> {
    use std::io::Read;
    let mut child = command.stderr(Stdio::piped()).spawn()?;
    let mut pipe = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("helper standard error is unavailable"))?;
    let relay = std::thread::spawn(move || {
        let mut copy = Vec::new();
        let mut buffer = [0_u8; 4096];
        let mut stderr = io::stderr();
        let mut sanitizer = Sanitizer::default();
        let mut shown = String::new();
        loop {
            match pipe.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    shown.clear();
                    sanitizer.push(&buffer[..count], &mut shown);
                    let _ = stderr.write_all(shown.as_bytes());
                    if copy.len() < 65536 {
                        copy.extend_from_slice(&buffer[..count]);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        shown.clear();
        sanitizer.finish(&mut shown);
        let _ = stderr.write_all(shown.as_bytes());
        copy
    });
    Ok((child, relay))
}

/// Run a helper call that uses a command or option older helpers lack.
fn feature_helper_status(command: &mut Command, feature: &str) -> Result<i32, String> {
    let (mut child, relay) = spawn_relaying_stderr(command)
        .map_err(|error| format!("unable to run command: {error}"))?;
    let status = child
        .wait()
        .map_err(|error| format!("unable to run command: {error}"))?;
    let stderr = relay.join().unwrap_or_default();
    Ok(feature_status(status.code().unwrap_or(1), feature, &stderr))
}

fn helper_path() -> OsString {
    env::var_os("GINUX_INSTANCE_HELPER").unwrap_or_else(|| {
        if Path::new(DEFAULT_HELPER).exists() {
            DEFAULT_HELPER.into()
        } else {
            "/usr/local/libexec/ginux-instance-helper".into()
        }
    })
}

fn deployment_arguments(args: &DeploymentArgs) -> Vec<OsString> {
    let mut output = Vec::new();
    for value in &args.overrides {
        output.push("--set".into());
        output.push(value.into());
    }
    if let Some(network) = &args.network {
        output.push("--network".into());
        output.push(network.into());
    }
    for value in &args.forwards {
        output.push("--forward".into());
        output.push(value.into());
    }
    output
}

fn helper_status<I, S>(
    helper: &Helper,
    command: &str,
    leading: I,
    deployment: &DeploymentArgs,
) -> Result<i32, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut arguments: Vec<OsString> = leading
        .into_iter()
        .map(|value| value.as_ref().to_os_string())
        .collect();
    arguments.extend(deployment_arguments(deployment));
    privileged_helper_status(helper, command, arguments)
}

fn privileged_helper_status<I, S>(
    helper: &Helper,
    command: &str,
    arguments: I,
) -> Result<i32, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = helper.helper_command(true, command);
    command.args(arguments);
    rooted_status(helper, &mut command)
}

/// Run a helper call. When a state or run root is passed, a helper usage
/// failure (64) that is not a root refusal means the installed helper does not
/// know the root options: unsupported (69), whatever the verb.
fn rooted_status(helper: &Helper, command: &mut Command) -> Result<i32, String> {
    if helper.roots.is_empty() {
        status_code(command)
    } else {
        feature_helper_status(command, "--state-root")
    }
}

fn status_code(command: &mut Command) -> Result<i32, String> {
    command
        .status()
        .map(|status| status.code().unwrap_or(1))
        .map_err(|error| format!("unable to run command: {error}"))
}

fn start_instance(helper: &Helper, args: StartArgs) -> Result<i32, String> {
    if args.wait {
        return start_waiting(helper, &args);
    }
    let mut options = Vec::new();
    if args.attach {
        options.push("--attach");
    }
    if args.audit {
        options.push("--audit");
    }
    let status = privileged_helper_status(
        helper,
        "start",
        std::iter::once(args.name.as_str()).chain(options),
    )?;
    if status == 0 && args.attach {
        attach_instance(helper, &args.name)
    } else {
        Ok(status)
    }
}

/// `start --wait`: the helper's exit status is the workload's (or 128+signal,
/// or 70 for a supervisor error), so a helper usage status cannot be told
/// from a workload exit status and is passed through unchanged.
fn start_waiting(helper: &Helper, args: &StartArgs) -> Result<i32, String> {
    let (pid, start) = wait::caller_identity()
        .map_err(|error| format!("unable to determine caller process identity: {error}"))?;
    let mut command = helper.helper_command(true, "start");
    command.arg(&args.name);
    if args.audit {
        command.arg("--audit");
    }
    command.args(["--wait", &pid.to_string(), &start.to_string()]);
    if args.stream_console {
        command.arg("--stream-console");
    }
    // Standard output is inherited, so the console bytes reach the caller
    // unchanged and unbuffered; standard error then goes through the
    // sanitizing relay, because it may carry the audit log.
    wait::run_waiting(&mut command, args.stream_console)
        .map_err(|error| format!("unable to run command: {error}"))
}

fn status_instance(helper: &Helper, args: StatusArgs) -> Result<i32, String> {
    match args.format {
        StatusFormat::Text => privileged_helper_status(helper, "status", [args.name]),
        StatusFormat::Json => {
            let mut command = helper.helper_command(true, "status");
            command.args([args.name.as_str(), "--format", "json"]);
            feature_helper_status(&mut command, "status --format json")
        }
    }
}

fn extract_instance(helper: &Helper, args: ExtractArgs) -> Result<i32, String> {
    let paths = extract::normalize_paths(&args.paths);
    let mut command = helper.helper_command(true, "extract");
    command
        .arg(&args.name)
        .args(["--max-bytes", &args.max_bytes.to_string()])
        .args(["--max-members", &args.max_members.to_string()])
        .args(["--max-path", &args.max_path.to_string()])
        .args(paths);
    match extract::run(&mut command, &args.output) {
        extract::Outcome::Done => Ok(0),
        extract::Outcome::Failed(code, message) => {
            print_error(&message);
            Ok(code)
        }
        extract::Outcome::Helper(code, stderr) => Ok(feature_status(code, "extract", &stderr)),
    }
}

fn inject_instance(helper: &Helper, args: &InjectArgs) -> Result<i32, String> {
    let file = match inject::open_input(&args.input) {
        Ok(file) => file,
        Err((code, message)) => {
            print_error(&message);
            return Ok(code);
        }
    };
    let mut command = helper.helper_command(true, "inject");
    command
        .arg(&args.name)
        .args(["--max-bytes", &args.max_bytes.to_string()])
        .args(["--max-members", &args.max_members.to_string()])
        .args(["--max-path", &args.max_path.to_string()])
        .arg(&args.into);
    match inject::run(&mut command, &file) {
        (code, Some(message), _) => {
            print_error(&message);
            Ok(code)
        }
        (code, None, stderr) => Ok(feature_status(code, "inject", &stderr)),
    }
}

fn import_image(helper: &Helper, path: &Path) -> Result<i32, String> {
    let input = match image::prepare(path) {
        Ok(input) => input,
        Err(rejection) => {
            print_error(&rejection.message);
            return Ok(rejection.code);
        }
    };
    let mut command = helper.helper_command(true, "import-image");
    match image::run(&mut command, &input) {
        (code, Some(message), _) => {
            print_error(&message);
            Ok(code)
        }
        (code, None, stderr) => Ok(feature_status(code, "import-image", &stderr)),
    }
}

fn current_identity(flag: &str) -> Result<String, String> {
    let output = Command::new("id")
        .arg(flag)
        .output()
        .map_err(|error| format!("unable to determine caller identity: {error}"))?;
    if !output.status.success() {
        return Err("unable to determine caller identity".into());
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| "caller identity is not valid UTF-8".into())
}

fn attach_instance(helper: &Helper, name: &str) -> Result<i32, String> {
    let uid = current_identity("-u")?;
    let gid = current_identity("-g")?;
    let status = rooted_status(
        helper,
        helper
            .helper_command(true, "authorize-attach")
            .args([name, &uid, &gid])
            .stdout(Stdio::null()),
    )
    .map_err(|error| format!("unable to authorize console attachment: {error}"))?;
    if status != 0 {
        return Ok(status);
    }
    let error = helper.helper_command(false, "attach").arg(name).exec();
    Err(format!("unable to attach console: {error}"))
}

fn edit_instance(helper: &Helper, name: &str) -> Result<i32, String> {
    let mut path = env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_owned())?
        .as_nanos();
    path.push(format!("ginux-edit-{}-{nonce}.toml", std::process::id()));
    let result = edit_instance_at(helper, name, &path);
    let _ = fs::remove_file(&path);
    result
}

fn edit_instance_at(helper: &Helper, name: &str, path: &Path) -> Result<i32, String> {
    let file = fs::File::create_new(path)
        .map_err(|error| format!("unable to create temporary recipe: {error}"))?;
    let export = rooted_status(
        helper,
        helper
            .helper_command(true, "export")
            .arg(name)
            .stdout(Stdio::from(file)),
    )
    .map_err(|error| format!("unable to export instance recipe: {error}"))?;
    if export != 0 {
        return Ok(export);
    }
    let editor = env::var_os("VISUAL")
        .or_else(|| env::var_os("EDITOR"))
        .unwrap_or_else(|| "vi".into());
    let edited = Command::new(editor)
        .arg(path)
        .status()
        .map_err(|error| format!("unable to start editor: {error}"))?;
    if !edited.success() {
        return Ok(edited.code().unwrap_or(1));
    }
    privileged_helper_status(helper, "import", [OsStr::new(name), path.as_os_str()])
}

fn load_recipe(path: &Path) -> Result<(InstanceConfig, ginux_contract::EffectiveContract), String> {
    let source =
        fs::read(path).map_err(|error| format!("unable to read {}: {error}", path.display()))?;
    let config = InstanceConfig::parse(&source)
        .map_err(|error| format!("configuration rejected: {error}"))?;
    let contract = config
        .effective_contract()
        .map_err(|error| format!("configuration rejected: {error}"))?;
    Ok((config, contract))
}

fn validate_recipe(path: &Path) -> Result<i32, String> {
    let (config, contract) = load_recipe(path)?;
    println!(
        "Contract valid: instance={} catalog={} digest={} operations={}",
        text(config.id.as_bytes()),
        ginux_contract::CATALOG_VERSION,
        text(contract.digest()),
        contract.rules().len()
    );
    Ok(0)
}

fn inspect_recipe(path: &Path) -> Result<i32, String> {
    let (config, contract) = load_recipe(path)?;
    let mut emulate = 0;
    let mut mediate = 0;
    let mut deny = 0;
    for rule in contract.rules() {
        match rule.action {
            Action::Emulate => emulate += 1,
            Action::Mediate => mediate += 1,
            Action::Deny(_) => deny += 1,
        }
    }
    println!(
        "Contract: instance={} catalog={} digest={}",
        text(config.id.as_bytes()),
        ginux_contract::CATALOG_VERSION,
        text(contract.digest())
    );
    println!(
        "Decisions: emulate={emulate} mediate={mediate} deny={deny} total={}",
        contract.rules().len()
    );
    Ok(0)
}

fn explain_recipe(path: &Path, operation: &str) -> Result<i32, String> {
    let (_, contract) = load_recipe(path)?;
    let Some(rule) = contract.operation_rule(operation) else {
        eprintln!(
            "Contract operation is not present in catalog version {}.",
            ginux_contract::CATALOG_VERSION
        );
        return Ok(2);
    };
    println!("Operation: {}", rule.operation.id);
    println!("Decision: {}", rule.action.name());
    println!(
        "Rule: {} source={} index={}",
        rule.provenance.name(),
        rule.source,
        rule.source_rule
    );
    println!("Status: {}", rule.operation.status.name());
    println!("Constraint: {}", rule.operation.constraint);
    println!("Limitation: {}", rule.operation.limitation);
    Ok(0)
}

fn text(bytes: &[u8]) -> String {
    let mut sanitizer = Sanitizer::default();
    let mut output = String::new();
    sanitizer.push(bytes, &mut output);
    sanitizer.finish(&mut output);
    output
}

/// Makes text from outside this process safe to show on a terminal: valid
/// UTF-8 printable text, newlines and tabs pass through; every other control
/// character (C0, DEL, C1), bidirectional override and invalid byte becomes a
/// visible `\xNN` or `\u{N}` escape. A character split across two `push`
/// calls is held back until it is complete.
#[derive(Default)]
struct Sanitizer {
    pending: Vec<u8>,
}

impl Sanitizer {
    fn push(&mut self, bytes: &[u8], output: &mut String) {
        let mut buffer = std::mem::take(&mut self.pending);
        buffer.extend_from_slice(bytes);
        let mut rest = buffer.as_slice();
        while !rest.is_empty() {
            match std::str::from_utf8(rest) {
                Ok(valid) => {
                    escape_str(valid, output);
                    break;
                }
                Err(error) => {
                    let (valid, tail) = rest.split_at(error.valid_up_to());
                    escape_str(std::str::from_utf8(valid).unwrap_or_default(), output);
                    match error.error_len() {
                        Some(length) => {
                            escape_bytes(&tail[..length], output);
                            rest = &tail[length..];
                        }
                        None => {
                            self.pending = tail.to_vec();
                            break;
                        }
                    }
                }
            }
        }
    }

    fn finish(&mut self, output: &mut String) {
        escape_bytes(&std::mem::take(&mut self.pending), output);
    }
}

fn escape_str(value: &str, output: &mut String) {
    use std::fmt::Write as _;
    for character in value.chars() {
        let code = u32::from(character);
        if matches!(character, '\n' | '\t') {
            output.push(character);
        } else if character.is_control() {
            let _ = write!(output, "\\x{code:02x}");
        } else if matches!(code, 0x200e | 0x200f | 0x202a..=0x202e | 0x2066..=0x2069) {
            let _ = write!(output, "\\u{{{code:x}}}");
        } else {
            output.push(character);
        }
    }
}

fn escape_bytes(bytes: &[u8], output: &mut String) {
    use std::fmt::Write as _;
    for byte in bytes {
        let _ = write!(output, "\\x{byte:02x}");
    }
}

pub fn print_error(error: &str) {
    let _ = writeln!(io::stderr(), "ginux: {error}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    fn parse(arguments: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(arguments)
    }

    #[test]
    fn command_model_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn public_commands_are_exactly_the_approved_set() {
        let names: Vec<_> = Cli::command()
            .get_subcommands()
            .map(|command| command.get_name().to_owned())
            .collect();
        assert_eq!(
            names,
            [
                "create",
                "import",
                "set",
                "edit",
                "export",
                "delete",
                "inject",
                "list",
                "status",
                "extract",
                "start",
                "attach",
                "stop",
                "lock",
                "unlock",
                "import-image",
                "validate",
                "inspect",
                "explain"
            ]
        );
        assert!(!names.iter().any(|name| name == "diff" || name == "native"));
    }

    #[test]
    fn deployment_arguments_preserve_order() {
        let cli = parse(&[
            "ginux",
            "create",
            "rocky",
            "--set",
            "resources.vcpus=2",
            "--set",
            "resources.memory_mib=1024",
            "--forward",
            "protocol=tcp,external_port=8080,instance_port=80",
            "--forward",
            "protocol=udp,external_port=5353,instance_port=53",
        ])
        .unwrap();
        let PublicCommand::Configure(ConfigureCommand::Create(args)) = cli.command else {
            panic!("unexpected command")
        };
        assert_eq!(
            args.deployment.overrides,
            ["resources.vcpus=2", "resources.memory_mib=1024"]
        );
        assert_eq!(args.deployment.forwards.len(), 2);
        validate_deployment(&args.deployment).unwrap();
    }

    #[test]
    fn set_requires_at_least_one_change() {
        let error = parse(&["ginux", "set", "rocky"]).unwrap_err();
        assert_eq!(error.exit_code(), 2);
    }

    #[test]
    fn forwarding_none_conflicts_with_other_values() {
        let cli = parse(&[
            "ginux",
            "set",
            "rocky",
            "--forward",
            "none",
            "--forward",
            "protocol=tcp,external_port=8080,instance_port=80",
        ])
        .unwrap();
        assert!(validate_cli(&cli).is_err());
    }

    #[test]
    fn missing_extra_and_unknown_arguments_are_parse_errors() {
        for arguments in [
            &["ginux", "status"] as &[&str],
            &["ginux", "list", "extra"],
            &["ginux", "start", "rocky", "--unknown"],
            &["ginux", "diff", "left", "right"],
            &["ginux", "native", "config", "root"],
        ] {
            assert_eq!(parse(arguments).unwrap_err().exit_code(), 2);
        }
    }

    fn helper_arguments(cli: &Cli, privileged: bool, verb: &str) -> Vec<String> {
        let command = Helper::new(cli).helper_command(privileged, verb);
        let mut arguments = vec![command.get_program().to_string_lossy().into_owned()];
        arguments.extend(
            command
                .get_args()
                .map(|argument| argument.to_string_lossy().into_owned()),
        );
        arguments
    }

    #[test]
    fn helper_arguments_are_unchanged_without_roots() {
        let cli = parse(&["ginux", "list"]).unwrap();
        let arguments = helper_arguments(&cli, true, "list");
        assert_eq!(arguments[0], "sudo");
        assert_eq!(arguments[2..], ["--protocol", "1", "list"]);
        let arguments = helper_arguments(&cli, false, "attach");
        assert_eq!(arguments[1..], ["--protocol", "1", "attach"]);
    }

    #[test]
    fn roots_are_forwarded_after_the_protocol() {
        for (arguments, run_root) in [
            (
                &["ginux", "--state-root", "/var/lib/ginux-a", "list"] as &[&str],
                "/var/lib/ginux-a/run",
            ),
            (
                &["ginux", "list", "--state-root", "/var/lib/ginux-a"],
                "/var/lib/ginux-a/run",
            ),
            (
                &[
                    "ginux",
                    "--state-root",
                    "/var/lib/ginux-a",
                    "--run-root",
                    "/run/ginux-a",
                    "list",
                ],
                "/run/ginux-a",
            ),
        ] {
            let cli = parse(arguments).unwrap();
            validate_cli(&cli).unwrap();
            let helper = helper_arguments(&cli, true, "list");
            assert_eq!(
                helper[2..],
                [
                    "--protocol",
                    "1",
                    "--state-root",
                    "/var/lib/ginux-a",
                    "--run-root",
                    run_root,
                    "list"
                ]
            );
            let attach = helper_arguments(&cli, false, "attach");
            assert_eq!(attach[3], "--state-root");
        }
    }

    #[test]
    fn invalid_roots_are_parse_errors() {
        let long = format!("/{}", "a".repeat(MAX_ROOT_LENGTH));
        for arguments in [
            &["ginux", "--run-root", "/run/ginux-a", "list"] as &[&str],
            &["ginux", "--state-root", "var/lib/ginux", "list"],
            &["ginux", "--state-root", "/var/lib/ginux/", "list"],
            &["ginux", "--state-root", "/var//lib", "list"],
            &["ginux", "--state-root", "/var/lib/../tmp", "list"],
            &["ginux", "--state-root", "/var/./lib", "list"],
            &["ginux", "--state-root", "/var/lib/a b", "list"],
            &["ginux", "--state-root", "/var/lib/$x", "list"],
            &["ginux", "--state-root", "/", "list"],
            &["ginux", "--state-root", &long, "list"],
            &[
                "ginux",
                "--state-root",
                "/var/lib/a",
                "--run-root",
                "run",
                "list",
            ],
        ] {
            assert_eq!(
                parse(arguments).unwrap_err().exit_code(),
                2,
                "{arguments:?}"
            );
        }
        let near = format!("/{}", "a".repeat(MAX_ROOT_LENGTH - 2));
        let cli = parse(&["ginux", "--state-root", &near, "list"]).unwrap();
        assert!(validate_cli(&cli).is_err());
        let cli = parse(&[
            "ginux",
            "--state-root",
            &near,
            "--run-root",
            "/run/a",
            "list",
        ])
        .unwrap();
        assert!(validate_cli(&cli).is_ok());
    }

    #[test]
    fn usage_status_maps_to_unsupported_except_for_refused_roots() {
        assert_eq!(feature_status(0, "delete", b""), 0);
        assert_eq!(feature_status(66, "delete", b"rocky: not found\n"), 66);
        assert_eq!(
            feature_status(64, "delete", b"usage: ginux-helper ...\n"),
            69
        );
        assert_eq!(
            feature_status(64, "delete", b"untrusted state root: /tmp/x (writable)\n"),
            64
        );
        assert_eq!(
            feature_status(64, "extract", b"untrusted run root: /tmp/r (owner)\n"),
            64
        );
    }

    #[test]
    fn sanitizer_escapes_control_bytes_and_keeps_text() {
        assert_eq!(
            text(b"plain text\n\tkept \xc3\xa9"),
            "plain text\n\tkept \u{e9}"
        );
        assert_eq!(
            text(b"a\x1b[31mred\x1b]0;t\x07"),
            "a\\x1b[31mred\\x1b]0;t\\x07"
        );
        assert_eq!(text(b"cr\rdel\x7f nul\0"), "cr\\x0ddel\\x7f nul\\x00");
        // C1 controls (U+009B is CSI), invalid bytes and bidirectional overrides.
        assert_eq!(text("a\u{9b}b".as_bytes()), "a\\x9bb");
        assert_eq!(text(b"bad \xff\xc3("), "bad \\xff\\xc3(");
        assert_eq!(text("x\u{202e}y".as_bytes()), "x\\u{202e}y");
        assert_eq!(text(b"cut \xe2\x82"), "cut \\xe2\\x82");
    }

    #[test]
    fn sanitizer_joins_characters_split_across_reads() {
        let mut sanitizer = Sanitizer::default();
        let mut output = String::new();
        let euro = "\u{20ac}".as_bytes();
        sanitizer.push(&euro[..1], &mut output);
        assert_eq!(output, "");
        sanitizer.push(&euro[1..2], &mut output);
        sanitizer.push(&euro[2..], &mut output);
        sanitizer.push(b"\x1b", &mut output);
        sanitizer.finish(&mut output);
        assert_eq!(output, "\u{20ac}\\x1b");
    }

    #[test]
    fn names_may_not_start_with_a_dot() {
        for name in [".", "..", ".hidden", ".a.b"] {
            assert_eq!(
                parse(&["ginux", "start", name]).unwrap_err().exit_code(),
                2,
                "{name}"
            );
        }
        for name in ["rocky", "a.b", "a..b", "a.", "_x", "-x"] {
            // "-x" is read as an option by the parser, so give it after `--`.
            assert!(parse(&["ginux", "start", "--", name]).is_ok(), "{name}");
        }
    }

    #[test]
    fn start_wait_parses_and_conflicts_with_attach() {
        let cli = parse(&["ginux", "start", "rocky", "--wait", "--audit"]).unwrap();
        let PublicCommand::Run(RunCommand::Start(args)) = cli.command else {
            panic!("unexpected command")
        };
        assert!(args.wait && args.audit && !args.attach);
        let error = parse(&["ginux", "start", "rocky", "--wait", "--attach"]).unwrap_err();
        assert_eq!(error.exit_code(), 2);
        assert_eq!(
            parse(&["ginux", "start", "rocky", "--wait", "5"])
                .unwrap_err()
                .exit_code(),
            2
        );
    }

    #[test]
    fn stream_console_requires_wait() {
        let cli = parse(&["ginux", "start", "rocky", "--wait", "--stream-console"]).unwrap();
        let PublicCommand::Run(RunCommand::Start(args)) = cli.command else {
            panic!("unexpected command")
        };
        assert!(args.wait && args.stream_console && !args.attach);
        let cli = parse(&["ginux", "start", "rocky", "--wait"]).unwrap();
        let PublicCommand::Run(RunCommand::Start(args)) = cli.command else {
            panic!("unexpected command")
        };
        assert!(!args.stream_console);
        for arguments in [
            &["ginux", "start", "rocky", "--stream-console"] as &[&str],
            &["ginux", "start", "rocky", "--attach", "--stream-console"],
            &[
                "ginux",
                "start",
                "rocky",
                "--wait",
                "--attach",
                "--stream-console",
            ],
            &[
                "ginux",
                "start",
                "rocky",
                "--wait",
                "--stream-console",
                "--stream-console",
            ],
            &["ginux", "start", "rocky", "--wait", "--stream-console=yes"],
        ] {
            assert_eq!(
                parse(arguments).unwrap_err().exit_code(),
                2,
                "{arguments:?}"
            );
        }
    }

    #[test]
    fn status_format_defaults_to_text_and_accepts_json() {
        let cli = parse(&["ginux", "status", "rocky"]).unwrap();
        let PublicCommand::InspectInstance(InspectInstanceCommand::Status(args)) = cli.command
        else {
            panic!("unexpected command")
        };
        assert_eq!(args.format, StatusFormat::Text);
        let cli = parse(&["ginux", "status", "rocky", "--format", "json"]).unwrap();
        let PublicCommand::InspectInstance(InspectInstanceCommand::Status(args)) = cli.command
        else {
            panic!("unexpected command")
        };
        assert_eq!(args.format, StatusFormat::Json);
        for arguments in [
            &["ginux", "status", "rocky", "--format", "yaml"] as &[&str],
            &["ginux", "status", "rocky", "--format"],
            &["ginux", "status", "--format", "json"],
        ] {
            assert_eq!(parse(arguments).unwrap_err().exit_code(), 2);
        }
    }

    #[test]
    fn extract_parses_with_default_bounds() {
        let cli = parse(&[
            "ginux", "extract", "rocky", "--output", "out.tar", "/out", "/b",
        ])
        .unwrap();
        validate_cli(&cli).unwrap();
        let PublicCommand::InspectInstance(InspectInstanceCommand::Extract(args)) = cli.command
        else {
            panic!("unexpected command")
        };
        assert_eq!(args.output, PathBuf::from("out.tar"));
        assert_eq!(args.paths, ["/out", "/b"]);
        assert_eq!(args.max_bytes, 68_719_476_736);
        assert_eq!(args.max_members, 1_000_000);
        assert_eq!(args.max_path, 4096);
        let cli = parse(&[
            "ginux",
            "extract",
            "rocky",
            "--output",
            "o",
            "--max-bytes",
            "10",
            "--max-members",
            "2",
            "--max-path",
            "8",
            "/",
        ])
        .unwrap();
        let PublicCommand::InspectInstance(InspectInstanceCommand::Extract(args)) = cli.command
        else {
            panic!("unexpected command")
        };
        assert_eq!(
            (args.max_bytes, args.max_members, args.max_path),
            (10, 2, 8)
        );
    }

    #[test]
    fn invalid_extract_forms_are_rejected_before_any_helper_call() {
        for arguments in [
            &["ginux", "extract", "rocky", "/out"] as &[&str],
            &["ginux", "extract", "rocky", "--output", "o"],
            &["ginux", "extract", "rocky", "--output", "o", "out"],
            &["ginux", "extract", "rocky", "--output", "o", "/a/../b"],
            &["ginux", "extract", "rocky", "--output", "o", "/a/"],
            &[
                "ginux",
                "extract",
                "rocky",
                "--output",
                "o",
                "--max-bytes",
                "0",
                "/a",
            ],
            &[
                "ginux",
                "extract",
                "rocky",
                "--output",
                "o",
                "--max-path",
                "-1",
                "/a",
            ],
            &["ginux", "extract", "bad/name", "--output", "o", "/a"],
        ] {
            assert_eq!(
                parse(arguments).unwrap_err().exit_code(),
                2,
                "{arguments:?}"
            );
        }
        let cli = parse(&[
            "ginux",
            "extract",
            "rocky",
            "--output",
            "o",
            "--max-path",
            "3",
            "/abcd",
        ])
        .unwrap();
        assert!(validate_cli(&cli).is_err());
    }

    #[test]
    fn inject_parses_with_default_bounds() {
        let cli = parse(&[
            "ginux", "inject", "rocky", "--input", "in.tar", "--into", "/work",
        ])
        .unwrap();
        validate_cli(&cli).unwrap();
        let PublicCommand::Configure(ConfigureCommand::Inject(args)) = cli.command else {
            panic!("unexpected command")
        };
        assert_eq!(args.name, "rocky");
        assert_eq!(args.input, PathBuf::from("in.tar"));
        assert_eq!(args.into, "/work");
        assert_eq!(args.max_bytes, 68_719_476_736);
        assert_eq!(args.max_members, 1_000_000);
        assert_eq!(args.max_path, 4096);
        let cli = parse(&[
            "ginux",
            "inject",
            "rocky",
            "--into",
            "/",
            "--max-path",
            "8",
            "--max-members",
            "2",
            "--max-bytes",
            "10",
            "--input",
            "-",
        ])
        .unwrap();
        validate_cli(&cli).unwrap();
        let PublicCommand::Configure(ConfigureCommand::Inject(args)) = cli.command else {
            panic!("unexpected command")
        };
        assert_eq!(
            (
                args.max_bytes,
                args.max_members,
                args.max_path,
                &args.into[..]
            ),
            (10, 2, 8, "/")
        );
    }

    #[test]
    fn invalid_inject_forms_are_rejected_before_any_helper_call() {
        for arguments in [
            &["ginux", "inject", "rocky", "--into", "/a"] as &[&str],
            &["ginux", "inject", "rocky", "--input", "in.tar"],
            &["ginux", "inject", "rocky", "--input", "i", "--into", "a"],
            &["ginux", "inject", "rocky", "--input", "i", "--into", ""],
            &[
                "ginux", "inject", "rocky", "--input", "i", "--into", "/a/../b",
            ],
            &[
                "ginux", "inject", "rocky", "--input", "i", "--into", "/a/./b",
            ],
            &["ginux", "inject", "rocky", "--input", "i", "--into", "/a/"],
            &["ginux", "inject", "rocky", "--input", "i", "--into", "//a"],
            &[
                "ginux", "inject", "rocky", "--input", "i", "--into", "/a", "/b",
            ],
            &[
                "ginux", "inject", "rocky", "--input", "i", "--into", "/a", "--into",
            ],
            &["ginux", "inject", "--input", "i", "--into", "/a"],
            &[
                "ginux", "inject", "bad/name", "--input", "i", "--into", "/a",
            ],
            &["ginux", "inject", ".hidden", "--input", "i", "--into", "/a"],
            &["ginux", "inject", "a", "b", "--input", "i", "--into", "/a"],
            &[
                "ginux",
                "inject",
                "rocky",
                "--input",
                "i",
                "--into",
                "/a",
                "--max-bytes",
                "0",
            ],
            &[
                "ginux",
                "inject",
                "rocky",
                "--input",
                "i",
                "--into",
                "/a",
                "--max-members",
                "0",
            ],
            &[
                "ginux",
                "inject",
                "rocky",
                "--input",
                "i",
                "--into",
                "/a",
                "--max-path",
                "0",
            ],
            &[
                "ginux",
                "inject",
                "rocky",
                "--input",
                "i",
                "--into",
                "/a",
                "--max-path",
                "-1",
            ],
        ] {
            assert_eq!(
                parse(arguments).unwrap_err().exit_code(),
                2,
                "{arguments:?}"
            );
        }
        let cli = parse(&[
            "ginux",
            "inject",
            "rocky",
            "--input",
            "i",
            "--into",
            "/abcd",
            "--max-path",
            "4",
        ])
        .unwrap();
        assert!(validate_cli(&cli).is_err());
    }

    #[test]
    fn delete_and_import_image_take_exactly_one_operand() {
        let cli = parse(&["ginux", "delete", "rocky"]).unwrap();
        assert!(matches!(
            cli.command,
            PublicCommand::Configure(ConfigureCommand::Delete(_))
        ));
        let cli = parse(&["ginux", "import-image", "layout"]).unwrap();
        assert!(matches!(
            cli.command,
            PublicCommand::Image(ImageCommand::ImportImage(_))
        ));
        for arguments in [
            &["ginux", "delete"] as &[&str],
            &["ginux", "delete", "a", "b"],
            &["ginux", "delete", "a/b"],
            &["ginux", "delete", "rocky", "--force"],
            &["ginux", "import-image"],
            &["ginux", "import-image", "a", "b"],
        ] {
            assert_eq!(
                parse(arguments).unwrap_err().exit_code(),
                2,
                "{arguments:?}"
            );
        }
    }
}
