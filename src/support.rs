//use jwalk::WalkDir;
use anyhow::Result;
use chrono::{DateTime, Utc};
use clap::Parser;
use crypto_hash::{Algorithm, Hasher};
use crypto_hash::hex_digest;
use fern::colors::{Color, ColoredLevelConfig};
use humansize::{format_size, DECIMAL};
use indicatif::{ProgressBar, ProgressStyle};
use log::{info, warn};
use memmap::MmapOptions;
use normpath::PathExt;
use num_format::{SystemLocale, ToFormattedString};
use serde::Serialize;
use std::fmt::Debug;
use std::fs::{File, Metadata};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration,SystemTime};
use users::{get_group_by_gid, get_user_by_uid};
use walkdir::DirEntry;
use humantime::format_duration;

#[derive(Serialize, Debug, Clone)]
pub struct Record {
    pub path: String,
    pub record_type: RecordType,
    pub xattr: Option<String>,
    pub size: Option<u64>,
    pub modified: Option<DateTime<Utc>>,
    pub created: Option<DateTime<Utc>>,
    pub mode: Option<u32>,
    pub owner_id: Option<u32>,
    pub owner_name: Option<String>,
    pub group_id: Option<u32>,
    pub group_name: Option<String>,
    pub hash: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
pub enum RecordType {
    File,
    Directory,
    Symlink,
    Other,
    XAttr,
}

pub fn record(
    path: &std::path::Path,
    metadata: &Metadata,
    args: &Args,
    progress: &ProgressBar,
) -> Result<Record> {
    let filetype = if metadata.is_file() {
        RecordType::File
    } else if metadata.is_dir() {
        RecordType::Directory
    } else if metadata.is_symlink() {
        RecordType::Symlink
    } else {
        RecordType::Other
    };
    let mut record = Record {
        path: path.to_string_lossy().to_string(),
        xattr: None,
        record_type: filetype,
        size: Some(metadata.len()),
        mode: Some(metadata.permissions().mode()),
        modified: Some(DateTime::<Utc>::from(metadata.modified()?)),
        created: Some(DateTime::<Utc>::from(metadata.created()?)),
        hash: None,
        owner_id: Some(metadata.uid()),
        group_id: Some(metadata.gid()),
        owner_name: get_user_by_uid(metadata.uid())
            .map(|user| user.name().to_string_lossy().to_string()),
        group_name: get_group_by_gid(metadata.gid())
            .map(|user| user.name().to_string_lossy().to_string()),
    };
    if !args.skip_hashes && path.is_file() && metadata.len() > 0 {
        if metadata.len() > 1024 * 1024 * 1024 && args.verbose {
            progress.suspend(|| {
                let len = format_size(metadata.len(), DECIMAL);
                warn!(
                    "{} is very large ({}), may take some type to hash.",
                    path.display(),
                    len
                );
            });
        }
        let hash = hash(path, progress)?;
        record.hash = Some(hash);
    }
    Ok(record)
}

pub fn xattr_records(path: &Path) -> Result<Vec<Record>> {
    let xattrs = xattr::list(path)?;
    let mut records: Vec<Record> = Vec::new();
    for xattr in xattrs {
        let value = xattr::get(path, &xattr)?.unwrap_or_else(Vec::<u8>::new);

        // let hash = value.map(|value| );
        // let size = value.map(|value| value.len() as u64);
        let record = Record {
            path: path.to_string_lossy().to_string(),
            xattr: Some(xattr.into_string().unwrap()), // TODO: Unwrap
            record_type: RecordType::XAttr,
            size: Some(value.len() as u64),
            modified: None,
            created: None,
            mode: None,
            owner_id: None,
            group_id: None,
            hash: Some(hex_digest(Algorithm::SHA256, &value)),
            owner_name: None,
            group_name: None,
        };
        records.push(record);
    }
    Ok(records)
}

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
pub struct Args {
    pub source_path: PathBuf,

    #[clap(short, long = "output", default_value = "-")]
    pub output_path: PathBuf,

    #[clap(short, long)]
    pub verbose: bool,

    #[clap(short, long)]
    pub skip_hashes: bool,

    #[clap(short, long, value_enum, default_value_t=Format::Csv)]
    pub format: Format,
}

pub fn hash(path: &Path, progress: &ProgressBar) -> Result<String> {
    let file = File::open(path)?;
    let mmap = unsafe { MmapOptions::new().map(&file)? };
    let block_size = 8 * 1024 * 1024;
    let mut hasher = Hasher::new(Algorithm::SHA256);
    for block in mmap.chunks(block_size) {
        hasher.write_all(block)?;
        progress.inc(block.len() as u64);
    }
    let hash = hex::encode(hasher.finish());
    Ok(hash)
}

#[derive(clap::ValueEnum, Debug, Clone)]
pub enum Format {
    Csv,
    Json,
}

pub fn is_hidden(entry: &DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.starts_with('.'))
        .unwrap_or(false)
}

pub fn setup_logger(
    level_filter: log::LevelFilter,
    log_path: &Option<PathBuf>,
) -> anyhow::Result<()> {
    let colors = ColoredLevelConfig::new()
        .info(Color::Green)
        .debug(Color::Magenta);

    let mut base_logger = fern::Dispatch::new();

    let console_logger = fern::Dispatch::new()
        .level(level_filter)
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{:8.8} | {}",
                colors.color(record.level()),
                message
            ))
        })
        .chain(std::io::stderr());
    base_logger = base_logger.chain(console_logger);

    if let Some(log_path) = log_path {
        let file_logger = fern::Dispatch::new()
            .format(move |out, message, record| {
                out.finish(format_args!(
                    "[{} {} {}] {}",
                    humantime::format_rfc3339_seconds(SystemTime::now()),
                    record.level(),
                    record.target(),
                    message
                ))
            })
            .chain(fern::log_file(log_path)?);
        base_logger = base_logger.chain(file_logger);
    }

    base_logger.apply()?;

    Ok(())
}

pub fn make_progress(args: &Args) -> ProgressBar {
    let progress = ProgressBar::new(0);

    progress.set_style(
        if args.skip_hashes {
            ProgressStyle::with_template("{spinner:.yellow} {human_pos:10.green.bold} {human_len:10.magenta.bold} {per_sec:12.cyan.bold} {wide_msg}").expect("Unable to set progress style")
        }
        else {
            ProgressStyle::with_template("{spinner:.yellow} {bytes:10.green.bold} {total_bytes:10.magenta.bold} {bytes_per_sec:12.cyan.bold} {wide_msg}").expect("Unable to set progress style")
        }
    );
    progress
}

pub fn export_records(records: &Vec<Record>, args: &Args) {
    let mut records = records.clone();

    // Make all paths relative to the source path
    let root = args.source_path.normalize().unwrap().into_path_buf().to_string_lossy().into_owned();
    records = records
        .iter()
        .map(|record| {
            let mut record = record.clone();
            let relative_path = record
                .path
                .strip_prefix(&root)
                .unwrap_or_else(|| record.path.as_ref())
                .to_string();
            record.path = format!(".{}", relative_path);
            record
        })
        .collect();

    // Sort by path, then xattr
    records.sort_by(|a, b| {
        if a.path == b.path {
            a.xattr.cmp(&b.xattr)
        } else {
            a.path.cmp(&b.path)
        }
    });

    if args.output_path == PathBuf::from("-") {
        match args.format {
            Format::Csv => {
                let mut writer = csv::Writer::from_writer(std::io::stdout());
                for record in records {
                    writer
                        .serialize(record)
                        .expect("Unable to serialize record");
                }
                writer.flush().expect("Unable to flush");
            }
            Format::Json => {
                let json =
                    serde_json::to_string_pretty(&records).expect("Unable to serialize records");
                println!("{}", json);
            }
        }
    } else {
        match args.format {
            Format::Csv => {
                let file = File::create(&args.output_path).expect("Unable to serialize records");
                let mut writer = csv::Writer::from_writer(file);
                for record in records {
                    writer
                        .serialize(record)
                        .expect("Unable to serialize record");
                }
                writer.flush().expect("Unable to flush");
            }
            Format::Json => {
                let file = File::create(&args.output_path).expect("Unable to serialize records");
                let mut writer = std::io::BufWriter::new(file);
                let json =
                    serde_json::to_string_pretty(&records).expect("Unable to serialize records");
                writer
                    .write_all(json.as_bytes())
                    .expect("Unable to serialize records");
            }
        }
    };
}

pub fn print_result(args: &Args, records: &[Record], progress: &ProgressBar, elapsed: Duration) {
    if !args.skip_hashes {
        info!(
            "Scanned {} entries, {} in {}.",
            records
                .len()
                .to_formatted_string(&SystemLocale::default().unwrap()),
            format_size(progress.length().unwrap_or(0), DECIMAL),
            format_duration(elapsed).to_string()
        );
    } else {
        info!(
            "Scanned {} entries, in {}.",
            records
                .len()
                .to_formatted_string(&SystemLocale::default().unwrap()),
                format_duration(elapsed).to_string()
        );
    }
}
