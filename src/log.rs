//! Buffered access-log writer.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::Duration;

pub struct Logger {
    tx: Option<Sender<(PathBuf, String)>>,
    handle: Option<JoinHandle<()>>,
}

impl Logger {
    pub fn new() -> std::io::Result<Self> {
        let (tx, rx) = channel::<(PathBuf, String)>();
        let handle = std::thread::Builder::new()
            .name("ngxrs-log".to_string())
            .spawn(move || {
                let mut files: HashMap<PathBuf, BufWriter<File>> = HashMap::new();
                loop {
                    match rx.recv_timeout(Duration::from_millis(50)) {
                        Ok((path, line)) => {
                            if !files.contains_key(&path) {
                                if let Some(parent) = path.parent() {
                                    if !parent.as_os_str().is_empty() {
                                        let _ = std::fs::create_dir_all(parent);
                                    }
                                }
                                match OpenOptions::new().create(true).append(true).open(&path) {
                                    Ok(f) => {
                                        files.insert(
                                            path.clone(),
                                            BufWriter::with_capacity(64 * 1024, f),
                                        );
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "ngxrs: [error] cannot open access log {}: {}",
                                            path.display(),
                                            e
                                        );
                                        continue;
                                    }
                                }
                            }
                            if let Some(w) = files.get_mut(&path) {
                                let _ = w.write_all(line.as_bytes());
                                let _ = w.write_all(b"\n");
                            }
                        }
                        Err(RecvTimeoutError::Timeout) => {
                            for w in files.values_mut() {
                                let _ = w.flush();
                            }
                        }
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                }
                for w in files.values_mut() {
                    let _ = w.flush();
                }
            })?;
        Ok(Logger {
            tx: Some(tx),
            handle: Some(handle),
        })
    }

    pub fn access(&self, path: &Path, line: String) {
        if let Some(tx) = &self.tx {
            let _ = tx.send((path.to_path_buf(), line));
        }
    }
}

impl Drop for Logger {
    fn drop(&mut self) {
        self.tx.take();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}
