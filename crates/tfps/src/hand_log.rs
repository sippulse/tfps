//! The record of hand-placed bans and unbans.
//!
//! `tfps_ctl ban` and `tfps_ctl unban` change what the kernel drops, and until
//! this module they left no trace: `banned` showed a hand-placed block with no
//! reason, and an operator could not tell who placed it or why. Unbans went
//! unrecorded too, though an operator lifting a block is useful to know about.
//!
//! # Beside the database, not in it
//!
//! `tfps_ctl` opens the database read-only on purpose (the note on
//! [`crate::store::Store::open_readonly`]): a tool inspecting state must not be
//! able to corrupt what the daemon writes, and it must never run a migration
//! from a binary that is not the daemon. So the record is its own file, in the
//! database's directory, and the database is untouched.
//!
//! # One file per month, and no lock
//!
//! Every action is one line, written with one `write` to a file opened for
//! appending, so two `tfps_ctl` runs appending at once cannot interleave a
//! line. Retention deletes whole months that nobody writes to any more; it
//! never rewrites a file another process may be appending to. That is what
//! lets this work without a file lock, which would otherwise need either a
//! newer toolchain than the installer may find or an `unsafe` call this crate
//! forbids.

use std::collections::HashMap;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Longest `--source`, in bytes.
pub const MAX_SOURCE: usize = 64;
/// Longest `--reason`, in bytes.
pub const MAX_REASON: usize = 256;

/// File name prefix; the month and `.jsonl` follow.
const PREFIX: &str = "hand_actions-";
const SUFFIX: &str = ".jsonl";

/// What was done by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HandVerb {
    /// `tfps_ctl ban`, applied.
    Ban,
    /// `tfps_ctl unban`, applied.
    Unban,
}

/// One hand action that took effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandAction {
    /// When, in Unix seconds.
    pub ts: u32,
    /// Ban or unban.
    #[serde(rename = "action")]
    pub verb: HandVerb,
    /// The address.
    pub ip: Ipv4Addr,
    /// Who asked: `--source`, or `operator` when none was given.
    pub source: String,
    /// Why, in the asker's words: `--reason`, when given.
    pub reason: Option<String>,
    /// When a ban lapses, in Unix seconds; `None` for no expiry and for an unban.
    pub expires: Option<u32>,
}

/// The file holding actions taken at `ts`, beside the database at `db`.
#[must_use]
pub fn path_for(db: &Path, ts: u32) -> PathBuf {
    let (year, month) = year_month(ts);
    dir_of(db).join(format!("{PREFIX}{year:04}{month:02}{SUFFIX}"))
}

fn dir_of(db: &Path) -> PathBuf {
    db.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

/// Append `actions`, each as one line, to the month file of its own time.
///
/// A new file takes the database's permissions, so whoever may read the
/// database may read this and no one else; with no database yet, `0640`.
///
/// # Errors
///
/// A message naming the file when it cannot be opened or written.
pub fn append(db: &Path, actions: &[HandAction]) -> Result<(), String> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mode = std::fs::metadata(db)
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or(0o640);
    for action in actions {
        let path = path_for(db, action.ts);
        let mut line = serde_json::to_string(action).map_err(|e| format!("encoding: {e}"))?;
        line.push('\n');
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(mode)
            .open(&path)
            .map_err(|e| format!("opening {}: {e}", path.display()))?;
        // One write per line: an append of the whole line is what keeps two
        // writers from interleaving.
        file.write_all(line.as_bytes())
            .map_err(|e| format!("writing {}: {e}", path.display()))?;
    }
    Ok(())
}

/// Every recorded action beside `db`, oldest file first, and how many lines
/// could not be read.
///
/// A line that does not parse is counted rather than skipped silently, so a
/// caller can tell the operator the record is incomplete.
#[must_use]
pub fn read_all(db: &Path) -> (Vec<HandAction>, usize) {
    let mut files = month_files(db);
    files.sort();
    let mut actions = Vec::new();
    let mut unreadable = 0;
    for (_, path) in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            unreadable += 1;
            continue;
        };
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            match serde_json::from_str::<HandAction>(line) {
                Ok(a) => actions.push(a),
                Err(_) => unreadable += 1,
            }
        }
    }
    (actions, unreadable)
}

/// The latest action per address, by time.
#[must_use]
pub fn latest_by_ip(actions: &[HandAction]) -> HashMap<String, HandAction> {
    let mut latest: HashMap<String, HandAction> = HashMap::new();
    for a in actions {
        let key = a.ip.to_string();
        match latest.get(&key) {
            Some(held) if held.ts > a.ts => {}
            _ => {
                latest.insert(key, a.clone());
            }
        }
    }
    latest
}

/// The latest hand action for each address asked about, and how many lines
/// could not be read along the way.
#[derive(Debug, Default)]
pub struct Latest {
    /// The latest action per address, by time.
    pub by_ip: HashMap<Ipv4Addr, HandAction>,
    /// Lines read that could not be parsed.
    pub unreadable: usize,
}

/// The latest hand action for each address in `wanted`: what `banned` asks.
///
/// Cheaper than [`read_all`] followed by [`latest_by_ip`], and gives the same
/// answer (`latest_for_agrees_with_reading_everything` pins that):
///
/// * months are read newest first, and the scan stops after the first whole
///   file that leaves every address in `wanted` answered. A file holds the
///   actions of one month, so an older file cannot hold a newer action;
/// * a line's address is read without parsing the rest of it, and only a line
///   about an address still being asked about is parsed in full;
/// * within a file the latest is decided by time, not by line order, because
///   two runs may append slightly out of order.
///
/// Asked about nothing, it reads nothing.
#[must_use]
pub fn latest_for(db: &Path, wanted: &std::collections::HashSet<Ipv4Addr>) -> Latest {
    let mut out = Latest::default();
    if wanted.is_empty() {
        return out;
    }
    let mut files = month_files(db);
    files.sort();
    for (_, path) in files.iter().rev() {
        // Answered by a newer month: nothing in this one can be newer.
        let settled: std::collections::HashSet<Ipv4Addr> = out.by_ip.keys().copied().collect();
        let Ok(bytes) = std::fs::read(path) else {
            out.unreadable += 1;
            continue;
        };
        for line in bytes.split(|b| *b == b'\n') {
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let Some(ip) = quick_ip(line) else {
                out.unreadable += 1;
                continue;
            };
            if !wanted.contains(&ip) || settled.contains(&ip) {
                continue;
            }
            match serde_json::from_slice::<HandAction>(line) {
                Ok(a) => match out.by_ip.get(&ip) {
                    Some(held) if held.ts > a.ts => {}
                    _ => {
                        out.by_ip.insert(ip, a);
                    }
                },
                Err(_) => out.unreadable += 1,
            }
        }
        if out.by_ip.len() == wanted.len() {
            break;
        }
    }
    out
}

/// The address of a record line, read without parsing the rest of it.
///
/// Relies on the shape [`append`] writes, `"ip":"a.b.c.d"`; a line without it
/// is not one of ours and counts as unreadable.
fn quick_ip(line: &[u8]) -> Option<Ipv4Addr> {
    const KEY: &[u8] = b"\"ip\":\"";
    let start = line.windows(KEY.len()).position(|w| w == KEY)? + KEY.len();
    let len = line[start..].iter().position(|b| *b == b'"')?;
    std::str::from_utf8(&line[start..start + len])
        .ok()?
        .parse()
        .ok()
}

/// Check a `--source` value: a short plain name.
///
/// # Errors
///
/// A message naming `--source` and what is wrong with the value.
pub fn check_source(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > MAX_SOURCE {
        return Err(format!("--source must be 1 to {MAX_SOURCE} characters"));
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(format!(
            "--source {s:?}: use letters, digits, '.', '_' and '-' only"
        ));
    }
    Ok(())
}

/// Check a `--reason` value: bounded text with no control characters.
///
/// # Errors
///
/// A message naming `--reason` and what is wrong with the value.
pub fn check_reason(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > MAX_REASON {
        return Err(format!("--reason must be 1 to {MAX_REASON} bytes"));
    }
    if s.chars().any(char::is_control) {
        return Err("--reason may not contain control characters".to_string());
    }
    Ok(())
}

/// Delete month files wholly older than `window` seconds before `now`.
///
/// A month file goes only when its last possible second is older than the
/// window. The current month's last second is always later than `now`, so the
/// file still being appended to can never qualify: no separate guard is
/// needed, and `pruning_never_deletes_the_current_month` pins the property.
/// Returns how many files were deleted.
///
/// # Errors
///
/// A message naming the first file that could not be deleted.
pub fn prune(db: &Path, now: u32, window: u32) -> Result<usize, String> {
    let cutoff = now.saturating_sub(window);
    let mut removed = 0;
    for ((year, month), path) in month_files(db) {
        if month_end(year, month) < cutoff {
            std::fs::remove_file(&path).map_err(|e| format!("removing {}: {e}", path.display()))?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// The month files beside `db`, with their year and month.
fn month_files(db: &Path) -> Vec<((i64, u32), PathBuf)> {
    let Ok(entries) = std::fs::read_dir(dir_of(db)) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let ym = name.strip_prefix(PREFIX)?.strip_suffix(SUFFIX)?;
            if ym.len() != 6 || !ym.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let year: i64 = ym[..4].parse().ok()?;
            let month: u32 = ym[4..].parse().ok()?;
            (1..=12).contains(&month).then(|| ((year, month), e.path()))
        })
        .collect()
}

/// The last second of `month` in `year`, in Unix seconds.
fn month_end(year: i64, month: u32) -> u32 {
    let (ny, nm) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    let next = days_from_civil(ny, nm, 1) * 86_400;
    u32::try_from(next - 1).unwrap_or(u32::MAX)
}

/// The UTC year and month of Unix second `ts`.
fn year_month(ts: u32) -> (i64, u32) {
    let (y, m, _) = civil_from_days(i64::from(ts) / 86_400);
    (y, m)
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 to a UTC date.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Howard Hinnant's `days_from_civil`: a UTC date to days since 1970-01-01.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_round_trip_across_years_and_leap_days() {
        for (y, m, d) in [
            (1970, 1, 1),
            (2000, 2, 29),
            (2026, 9, 28),
            (2026, 12, 31),
            (2027, 1, 1),
            (2100, 3, 1),
        ] {
            let days = days_from_civil(y, m, d);
            assert_eq!(civil_from_days(days), (y, m, d), "{y}-{m}-{d}");
        }
    }

    #[test]
    fn a_month_ends_on_its_last_second() {
        // 2026-09-30 23:59:59 UTC.
        assert_eq!(month_end(2026, 9), 1_790_812_799);
        // December rolls into the next year.
        assert_eq!(month_end(2026, 12), 1_798_761_599);
    }
}
