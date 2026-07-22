use zeenome_core::errors::{Result, ZeenomeError};

/// Matches TypeScript `DIRECTORY_GENESIS_SENTINEL` when no public directory row exists.
pub const DIRECTORY_GENESIS_SENTINEL: i32 = -1;

/// Resolve the registry-route epoch number for the next publish (genomic or phenotype chain).
pub fn resolve_registry_epoch_number(
    next_registry_epoch_number: Option<i32>,
    directory_prev_epoch_number: Option<i32>,
    latest_epoch_number: Option<i32>,
) -> Result<i32> {
    if let Some(next) = next_registry_epoch_number {
        if let Some(prev) = directory_prev_epoch_number {
            let expected = if prev == DIRECTORY_GENESIS_SENTINEL {
                0
            } else {
                prev + 1
            };
            if next != expected {
                return Err(ZeenomeError::InvalidFormat(format!(
                    "next_registry_epoch_number {next} does not match directory_prev_epoch_number {prev} (expected {expected})"
                )));
            }
        }
        return Ok(next);
    }
    Ok(latest_epoch_number.map(|n| n + 1).unwrap_or(0))
}
