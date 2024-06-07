use anyhow::anyhow;
use clap::Parser;
use log::{error, info};
use normpath::PathExt;
use std::sync::mpsc::channel;
use threadpool::ThreadPool;
use walkdir::WalkDir;
//use jwalk::WalkDir;
use indicatif::ProgressBar;
use std::path::PathBuf;
use std::sync::mpsc::Sender;

mod support;
use support::*;

fn main() {
    let args = Args::parse();
    setup_logger(log::LevelFilter::Info, &None).expect("Failed to setup logger.");
    let snapshot = TreeSnapshot::new(&args);
    snapshot.main();
}

#[derive(Clone)]

struct TreeSnapshot {
    args: Args,
    progress: ProgressBar,
}

impl TreeSnapshot {
    fn new(args: &Args) -> Self {
        Self {
            args: args.clone(),
            progress: make_progress(args),
        }
    }

    fn main(&self) {
        let worker_count = usize::from(std::thread::available_parallelism().unwrap());
        info!("Number of workers: {}", worker_count);
        let pool: ThreadPool = ThreadPool::new(worker_count);
        let (tx, rx) = channel();
        self.walk(&pool, &tx);
        drop(tx);
        if self.args.verbose {
            self.progress.suspend(|| {
                info!("Scan finished, waiting for workers to finish computing hashes.");
            });
        }
        let records = rx.iter().collect::<Vec<Record>>();
        self.progress.finish_and_clear();
        print_result(&self.args, &records, &self.progress);
        export_records(records, &self.args);
    }

    fn walk(&self, pool: &ThreadPool, tx: &Sender<Record>) {
        let root: PathBuf = self.args.source_path.normalize().unwrap().into_path_buf();
        let walker = WalkDir::new(root).into_iter();
        let walker_iter = walker.filter_entry(|e| !is_hidden(e));
        for entry in walker_iter {
            let result = entry.map_err(|error| anyhow!(error)).and_then(|entry| {
                let path = entry.path();
                let metadata = std::fs::symlink_metadata(path)?;
                self.progress
                    .set_message(format!("Scanning: {}", path.display()));
                self.progress.inc_length(if self.args.skip_hashes {
                    1
                } else {
                    metadata.len()
                });

                let copy = self.clone();
                let path = path.to_owned();
                let tx = tx.clone();
                pool.execute(move || {
                    copy.process_file(path, metadata, tx);
                });
                Ok(())
            });
            if let Err(e) = result {
                self.progress.suspend(|| {
                    error!("{:?}", e);
                });
            }
        }
    }

    fn process_file(&self, path: PathBuf, metadata: std::fs::Metadata, tx: Sender<Record>) {
        self.progress
            .set_message(format!("Processing: {}", path.display()));
        let record = record(&path, &metadata, &self.args, &self.progress);
        if self.args.skip_hashes {
            self.progress.inc(1);
        }
        let Ok(record) = record else {
            self.progress.suspend(|| {
                error!("{} Error: {:?}", path.display(), record.err().unwrap());
            });
            return;
        };
        tx.send(record).expect("Failed to send record from thread.");
        let Ok(xattr_records) = xattr_records(&path) else {
            self.progress.suspend(|| {
                error!("Error loading xattr: {} ", path.display());
            });
            return;
        };
        for record in xattr_records {
            tx.send(record).expect("Failed to send record from thread.");
        }
    }
}
