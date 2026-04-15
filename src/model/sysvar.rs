#[allow(deprecated)]
use solana_sysvar::{clock, epoch_rewards, epoch_schedule, fees, last_restart_slot,
                    recent_blockhashes, rent, slot_hashes, slot_history};
use solana_stake_interface::sysvar::stake_history as sysvar_stake_history;
use solana_sdk_ids::sysvar::instructions as sysvar_instructions;
use solana_pubkey::Pubkey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysvarKind {
    Clock,
    Rent,
    EpochSchedule,
    Fees,
    SlotHashes,
    StakeHistory,
    RecentBlockhashes,
    Instructions,
    LastRestartSlot,
    EpochRewards,
    SlotHistory,
}

/* All known sysvar IDs paired with their kind */
fn sysvar_ids() -> &'static [(Pubkey, SysvarKind)] {
    use SysvarKind::*;
    static IDS: std::sync::OnceLock<Vec<(Pubkey, SysvarKind)>> = std::sync::OnceLock::new();
    IDS.get_or_init(|| vec![
        (clock::ID, Clock),
        (rent::ID, Rent),
        (epoch_schedule::ID, EpochSchedule),
        (fees::ID, Fees),
        (slot_hashes::ID, SlotHashes),
        (sysvar_stake_history::ID, StakeHistory),
        (recent_blockhashes::ID, RecentBlockhashes),
        (sysvar_instructions::ID, Instructions),
        (last_restart_slot::ID, LastRestartSlot),
        (epoch_rewards::ID, EpochRewards),
        (slot_history::ID, SlotHistory),
    ])
}

pub fn identify_sysvar(key: &[u8; 32]) -> Option<SysvarKind> {
    sysvar_ids().iter()
        .find(|(id, _)| id.as_array() == key)
        .map(|(_, kind)| *kind)
}

pub fn sysvar_kind_name(kind: SysvarKind) -> &'static str {
    match kind {
        SysvarKind::Clock => "Clock",
        SysvarKind::Rent => "Rent",
        SysvarKind::EpochSchedule => "EpochSchedule",
        SysvarKind::Fees => "Fees",
        SysvarKind::SlotHashes => "SlotHashes",
        SysvarKind::StakeHistory => "StakeHistory",
        SysvarKind::RecentBlockhashes => "RecentBlockhashes",
        SysvarKind::Instructions => "Instructions",
        SysvarKind::LastRestartSlot => "LastRestartSlot",
        SysvarKind::EpochRewards => "EpochRewards",
        SysvarKind::SlotHistory => "SlotHistory",
    }
}

pub fn deserialize_sysvar(kind: SysvarKind, data: &[u8]) -> Vec<String> {
    let result = match kind {
        SysvarKind::Clock => deserialize_clock(data),
        SysvarKind::Rent => deserialize_rent(data),
        SysvarKind::EpochSchedule => deserialize_epoch_schedule(data),
        SysvarKind::Fees => deserialize_fees(data),
        SysvarKind::SlotHashes => deserialize_slot_hashes(data),
        SysvarKind::StakeHistory => deserialize_stake_history(data),
        SysvarKind::RecentBlockhashes => deserialize_recent_blockhashes(data),
        SysvarKind::Instructions => Ok(vec!["Runtime-only sysvar".to_string()]),
        SysvarKind::LastRestartSlot => deserialize_last_restart_slot(data),
        SysvarKind::EpochRewards => deserialize_epoch_rewards(data),
        SysvarKind::SlotHistory => deserialize_slot_history(data),
    };
    result.unwrap_or_else(|e| vec![format!("Failed to deserialize: {}", e)])
}

fn deserialize_clock(data: &[u8]) -> Result<Vec<String>, String> {
    let c: clock::Clock = bincode::deserialize(data)
        .map_err(|e| format!("bincode: {}", e))?;
    Ok(vec![
        format!("  Slot:                    {}", c.slot),
        format!("  Epoch:                   {}", c.epoch),
        format!("  Leader Schedule Epoch:   {}", c.leader_schedule_epoch),
        format!("  Unix Timestamp:          {}", c.unix_timestamp),
        format!("  Epoch Start Timestamp:   {}", c.epoch_start_timestamp),
    ])
}

#[allow(deprecated)]
fn deserialize_rent(data: &[u8]) -> Result<Vec<String>, String> {
    let r: rent::Rent = bincode::deserialize(data)
        .map_err(|e| format!("bincode: {}", e))?;
    Ok(vec![
        format!("  Lamports Per Byte:       {}", r.lamports_per_byte),
        format!("  Exemption Threshold:     {:?}", r.exemption_threshold),
        format!("  Burn Percent:            {}", r.burn_percent),
    ])
}

fn deserialize_epoch_schedule(data: &[u8]) -> Result<Vec<String>, String> {
    let es: epoch_schedule::EpochSchedule = bincode::deserialize(data)
        .map_err(|e| format!("bincode: {}", e))?;
    Ok(vec![
        format!("  Slots Per Epoch:               {}", es.slots_per_epoch),
        format!("  Leader Schedule Slot Offset:   {}", es.leader_schedule_slot_offset),
        format!("  Warmup:                        {}", es.warmup),
        format!("  First Normal Epoch:            {}", es.first_normal_epoch),
        format!("  First Normal Slot:             {}", es.first_normal_slot),
    ])
}

#[allow(deprecated)]
fn deserialize_fees(data: &[u8]) -> Result<Vec<String>, String> {
    let f: fees::Fees = bincode::deserialize(data)
        .map_err(|e| format!("bincode: {}", e))?;
    Ok(vec![
        format!("  Lamports Per Signature:  {}", f.fee_calculator.lamports_per_signature),
    ])
}

fn deserialize_slot_hashes(data: &[u8]) -> Result<Vec<String>, String> {
    let sh: slot_hashes::SlotHashes = bincode::deserialize(data)
        .map_err(|e| format!("bincode: {}", e))?;
    let entries: Vec<_> = sh.iter().collect();
    let count = entries.len();
    let mut lines = vec![format!("  Entries: {}", count)];

    let show_first = 10.min(count);
    let show_last = if count > 20 { 10 } else { 0 };
    let skip_middle = count > 20;

    for (i, (slot, hash)) in entries.iter().enumerate() {
        if i < show_first {
            lines.push(format!("  [{:>4}] Slot {:>12}: {}", i, slot, hash));
        } else if skip_middle && i == show_first {
            lines.push(format!("  ... ({} more entries) ...", count - show_first - show_last));
        }
        if skip_middle && i >= count - show_last {
            lines.push(format!("  [{:>4}] Slot {:>12}: {}", i, slot, hash));
        }
    }

    Ok(lines)
}

fn deserialize_last_restart_slot(data: &[u8]) -> Result<Vec<String>, String> {
    let lrs: last_restart_slot::LastRestartSlot = bincode::deserialize(data)
        .map_err(|e| format!("bincode: {}", e))?;
    Ok(vec![
        format!("  Last Restart Slot:  {}", lrs.last_restart_slot),
    ])
}

fn deserialize_epoch_rewards(data: &[u8]) -> Result<Vec<String>, String> {
    let er: epoch_rewards::EpochRewards = bincode::deserialize(data)
        .map_err(|e| format!("bincode: {}", e))?;
    Ok(vec![
        format!("  Distribution Block Height:  {}", er.distribution_starting_block_height),
        format!("  Num Partitions:             {}", er.num_partitions),
        format!("  Parent Blockhash:           {}", er.parent_blockhash),
        format!("  Total Points:               {}", er.total_points),
        format!("  Total Rewards:              {}", er.total_rewards),
        format!("  Distributed Rewards:        {}", er.distributed_rewards),
        format!("  Active:                     {}", er.active),
    ])
}

fn deserialize_slot_history(data: &[u8]) -> Result<Vec<String>, String> {
    let sh: slot_history::SlotHistory = bincode::deserialize(data)
        .map_err(|e| format!("bincode: {}", e))?;
    let newest = sh.newest();
    let mut set_count: u64 = 0;
    let check_range: u64 = 1024.min(newest);
    let start = newest - check_range + 1;
    for slot in start..=newest {
        if sh.check(slot) == solana_slot_history::Check::Found {
            set_count += 1;
        }
    }
    Ok(vec![
        format!("  Newest Slot:   {}", newest),
        format!("  Recent Hits:   {}/{} (last {} slots)", set_count, check_range, check_range),
    ])
}

fn deserialize_stake_history(data: &[u8]) -> Result<Vec<String>, String> {
    use solana_stake_interface::stake_history::StakeHistory;
    let sh: StakeHistory = bincode::deserialize(data)
        .map_err(|e| format!("bincode: {}", e))?;
    let count = sh.len();
    let mut lines = vec![format!("  Entries: {}", count)];

    let show_first = 10.min(count);
    let show_last = if count > 20 { 10 } else { 0 };
    let skip_middle = count > 20;

    for (i, (epoch, entry)) in sh.iter().enumerate() {
        if i < show_first {
            lines.push(format!(
                "  [{:>3}] Epoch {:>4}: eff={}, act={}, deact={}",
                i, epoch, entry.effective, entry.activating, entry.deactivating
            ));
        } else if skip_middle && i == show_first {
            lines.push(format!("  ... ({} more entries) ...", count - show_first - show_last));
        }

        if skip_middle && i >= count - show_last {
            lines.push(format!(
                "  [{:>3}] Epoch {:>4}: eff={}, act={}, deact={}",
                i, epoch, entry.effective, entry.activating, entry.deactivating
            ));
        }
    }

    Ok(lines)
}

#[allow(deprecated)]
fn deserialize_recent_blockhashes(data: &[u8]) -> Result<Vec<String>, String> {
    let rbh: recent_blockhashes::RecentBlockhashes = bincode::deserialize(data)
        .map_err(|e| format!("bincode: {}", e))?;
    let count = rbh.len();
    let mut lines = vec![format!("  Entries: {}", count)];

    let show_first = 10.min(count);
    let show_last = if count > 20 { 10 } else { 0 };
    let skip_middle = count > 20;

    for (i, entry) in rbh.iter().enumerate() {
        let hash = format!("{}", entry.blockhash);
        let fee = entry.fee_calculator.lamports_per_signature;

        if i < show_first {
            lines.push(format!("  [{:>4}] {:<44}  fee={}", i, hash, fee));
        } else if skip_middle && i == show_first {
            lines.push(format!("  ... ({} more entries) ...", count - show_first - show_last));
        }

        if skip_middle && i >= count - show_last {
            lines.push(format!("  [{:>4}] {:<44}  fee={}", i, hash, fee));
        }
    }

    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identify_all_sysvars() {
        assert_eq!(identify_sysvar(clock::ID.as_array()), Some(SysvarKind::Clock));
        assert_eq!(identify_sysvar(rent::ID.as_array()), Some(SysvarKind::Rent));
        assert_eq!(identify_sysvar(epoch_schedule::ID.as_array()), Some(SysvarKind::EpochSchedule));
        assert_eq!(identify_sysvar(fees::ID.as_array()), Some(SysvarKind::Fees));
        assert_eq!(identify_sysvar(slot_hashes::ID.as_array()), Some(SysvarKind::SlotHashes));
        assert_eq!(identify_sysvar(sysvar_stake_history::ID.as_array()), Some(SysvarKind::StakeHistory));
        assert_eq!(identify_sysvar(recent_blockhashes::ID.as_array()), Some(SysvarKind::RecentBlockhashes));
        assert_eq!(identify_sysvar(sysvar_instructions::ID.as_array()), Some(SysvarKind::Instructions));
        assert_eq!(identify_sysvar(last_restart_slot::ID.as_array()), Some(SysvarKind::LastRestartSlot));
        assert_eq!(identify_sysvar(epoch_rewards::ID.as_array()), Some(SysvarKind::EpochRewards));
        assert_eq!(identify_sysvar(slot_history::ID.as_array()), Some(SysvarKind::SlotHistory));
        assert_eq!(identify_sysvar(&[0u8; 32]), None);
    }

    #[test]
    fn test_sysvar_kind_name() {
        assert_eq!(sysvar_kind_name(SysvarKind::Clock), "Clock");
        assert_eq!(sysvar_kind_name(SysvarKind::SlotHashes), "SlotHashes");
        assert_eq!(sysvar_kind_name(SysvarKind::RecentBlockhashes), "RecentBlockhashes");
    }

    #[test]
    fn test_deserialize_clock() {
        let mut data = vec![0u8; 40];
        data[0..8].copy_from_slice(&100u64.to_le_bytes());
        data[8..16].copy_from_slice(&1678900000i64.to_le_bytes());
        data[16..24].copy_from_slice(&5u64.to_le_bytes());
        data[24..32].copy_from_slice(&6u64.to_le_bytes());
        data[32..40].copy_from_slice(&1678901234i64.to_le_bytes());

        let lines = deserialize_clock(&data).unwrap();
        assert_eq!(lines.len(), 5);
        assert!(lines[0].contains("100"));
        assert!(lines[1].contains("5"));
        assert!(lines[2].contains("6"));
        assert!(lines[3].contains("1678901234"));
        assert!(lines[4].contains("1678900000"));
    }

    #[test]
    fn test_deserialize_rent() {
        let mut data = vec![0u8; 17];
        data[0..8].copy_from_slice(&3480u64.to_le_bytes());
        data[8..16].copy_from_slice(&2.0f64.to_le_bytes());
        data[16] = 50;

        let lines = deserialize_rent(&data).unwrap();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("3480"));
    }

    #[test]
    fn test_deserialize_fees() {
        let mut data = vec![0u8; 8];
        data[0..8].copy_from_slice(&5000u64.to_le_bytes());

        let lines = deserialize_fees(&data).unwrap();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("5000"));
    }

    #[test]
    fn test_deserialize_last_restart_slot() {
        let mut data = vec![0u8; 8];
        data[0..8].copy_from_slice(&42u64.to_le_bytes());

        let lines = deserialize_last_restart_slot(&data).unwrap();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("42"));
    }

    #[test]
    fn test_deserialize_truncated_data() {
        let data = vec![0u8; 3];
        let lines = deserialize_sysvar(SysvarKind::Clock, &data);
        assert!(lines[0].contains("Failed to deserialize"));
    }

    #[test]
    fn test_deserialize_epoch_schedule() {
        let mut data = vec![0u8; 33];
        data[0..8].copy_from_slice(&432000u64.to_le_bytes());
        data[8..16].copy_from_slice(&432000u64.to_le_bytes());
        data[16] = 0;
        data[17..25].copy_from_slice(&0u64.to_le_bytes());
        data[25..33].copy_from_slice(&0u64.to_le_bytes());

        let lines = deserialize_epoch_schedule(&data).unwrap();
        assert_eq!(lines.len(), 5);
        assert!(lines[0].contains("432000"));
    }

    #[test]
    fn test_recent_blockhashes_id_matches_base58() {
        let expected = bs58::decode("SysvarRecentB1ockHashes11111111111111111111")
            .into_vec().unwrap();
        assert_eq!(recent_blockhashes::ID.as_array(), expected.as_slice());
    }
}
