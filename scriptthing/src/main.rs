use chrono::NaiveDateTime;
use std::cmp::Ordering;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

// Define a struct to hold log entries with their timestamp and origin (client or server).
#[derive(Debug, Clone)]
struct LogEntry {
    timestamp: NaiveDateTime,
    line: String,
    is_client: bool,
}

impl LogEntry {
    // Attempts to create a new LogEntry from a log line, returning None if parsing fails.
    fn new(line: &str, is_client: bool, last_timestamp: NaiveDateTime) -> Option<Self> {
        let (timestamp_str, rest) = line.split_once('Z')?;
        let timestamp =
            NaiveDateTime::parse_from_str(&format!("{}Z", timestamp_str), "%Y-%m-%dT%H:%M:%S%.fZ")
                .unwrap_or(last_timestamp);
        Some(LogEntry {
            timestamp,
            line: format!("{}Z {}", timestamp_str, rest),
            is_client,
        })
    }
}

// Reads a log file and returns a vector of LogEntry.
fn read_log_file(path: &Path, is_client: bool) -> io::Result<Vec<LogEntry>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    let mut last_timestamp = NaiveDateTime::from_timestamp(0, 0); // Fallback initial timestamp.

    for line in reader.lines() {
        let line = line?;
        if let Some(entry) = LogEntry::new(&line, is_client, last_timestamp) {
            last_timestamp = entry.timestamp;
            entries.push(entry);
        } else if let Some(last) = entries.last_mut() {
            // For lines that are part of the previous log entry, append them to the last entry.
            last.line.push('\n');
            last.line.push_str(&line);
        }
    }

    Ok(entries)
}

fn main() -> io::Result<()> {
    let client_logs = read_log_file(Path::new("600_client.log"), true)?;
    let server_logs = read_log_file(Path::new("600_server.log"), false)?;

    // Merge and sort the log entries by timestamp.
    let mut all_logs = [client_logs, server_logs].concat();
    all_logs.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    // Print the merged logs with coloring.
    for log in all_logs {
        if log.is_client {
            println!("\x1b[32m{}\x1b[0m", log.line); // Green for client
        } else {
            println!("\x1b[31m{}\x1b[0m", log.line); // Red for server
        }
    }

    Ok(())
}
