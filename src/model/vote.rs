use solana_vote_interface::state::VoteStateVersions;
use solana_pubkey::Pubkey;

pub fn is_vote_program_owner(owner: &[u8; 32]) -> bool {
    owner == solana_sdk_ids::vote::ID.as_array()
}

pub fn deserialize_vote_account(data: &[u8]) -> Vec<String> {
    match VoteStateVersions::deserialize(data) {
        Ok(versioned) => format_vote_state(&versioned),
        Err(e) => vec![format!("Failed to deserialize vote state: {:?}", e)],
    }
}

fn format_vote_state(versioned: &VoteStateVersions) -> Vec<String> {
    match versioned {
        VoteStateVersions::Uninitialized => {
            vec!["  (Uninitialized)".to_string()]
        }
        VoteStateVersions::V1_14_11(state) => {
            let mut lines = vec![
                "  Version:                 V1_14_11".to_string(),
                format!("  Node Pubkey:             {}", state.node_pubkey),
                format!("  Authorized Withdrawer:   {}", state.authorized_withdrawer),
                format!("  Commission:              {}%", state.commission),
                format!("  Root Slot:               {}", fmt_option_slot(state.root_slot)),
            ];

            let count = state.votes.len();
            lines.push(format!("  Votes:                   {} entries", count));
            let show = 5.min(count);
            for (i, lockout) in state.votes.iter().rev().take(show).enumerate() {
                lines.push(format!(
                    "    [{:>2}] slot={:<12} conf={}",
                    i, lockout.slot(), lockout.confirmation_count()
                ));
            }
            if count > show {
                lines.push(format!("    ... ({} more)", count - show));
            }

            format_epoch_credits(&mut lines, &state.epoch_credits);
            format_authorized_voters(&mut lines, &state.authorized_voters);
            lines.push(format!("  Last Timestamp:          slot={} ts={}", state.last_timestamp.slot, state.last_timestamp.timestamp));

            lines
        }
        VoteStateVersions::V3(state) => {
            let mut lines = vec![
                "  Version:                 V3".to_string(),
                format!("  Node Pubkey:             {}", state.node_pubkey),
                format!("  Authorized Withdrawer:   {}", state.authorized_withdrawer),
                format!("  Commission:              {}%", state.commission),
                format!("  Root Slot:               {}", fmt_option_slot(state.root_slot)),
            ];

            let count = state.votes.len();
            lines.push(format!("  Votes:                   {} entries", count));
            let show = 5.min(count);
            for (i, vote) in state.votes.iter().rev().take(show).enumerate() {
                lines.push(format!(
                    "    [{:>2}] slot={:<12} conf={} latency={}",
                    i, vote.lockout.slot(), vote.lockout.confirmation_count(), vote.latency
                ));
            }
            if count > show {
                lines.push(format!("    ... ({} more)", count - show));
            }

            format_epoch_credits(&mut lines, &state.epoch_credits);
            format_authorized_voters(&mut lines, &state.authorized_voters);
            lines.push(format!("  Last Timestamp:          slot={} ts={}", state.last_timestamp.slot, state.last_timestamp.timestamp));

            lines
        }
        VoteStateVersions::V4(state) => {
            let mut lines = vec![
                "  Version:                 V4".to_string(),
                format!("  Node Pubkey:             {}", state.node_pubkey),
                format!("  Authorized Withdrawer:   {}", state.authorized_withdrawer),
                format!("  Inflation Collector:     {}", state.inflation_rewards_collector),
                format!("  Block Rev Collector:     {}", state.block_revenue_collector),
                format!("  Inflation Comm (bps):    {}", state.inflation_rewards_commission_bps),
                format!("  Block Rev Comm (bps):    {}", state.block_revenue_commission_bps),
                format!("  Pending Deleg Rewards:   {}", state.pending_delegator_rewards),
                format!("  BLS Pubkey:              {}", match &state.bls_pubkey_compressed {
                    Some(key) => hex::encode(key),
                    None => "None".to_string(),
                }),
                format!("  Root Slot:               {}", fmt_option_slot(state.root_slot)),
            ];

            let count = state.votes.len();
            lines.push(format!("  Votes:                   {} entries", count));
            let show = 5.min(count);
            for (i, vote) in state.votes.iter().rev().take(show).enumerate() {
                lines.push(format!(
                    "    [{:>2}] slot={:<12} conf={} latency={}",
                    i, vote.lockout.slot(), vote.lockout.confirmation_count(), vote.latency
                ));
            }
            if count > show {
                lines.push(format!("    ... ({} more)", count - show));
            }

            format_epoch_credits(&mut lines, &state.epoch_credits);
            format_authorized_voters(&mut lines, &state.authorized_voters);
            lines.push(format!("  Last Timestamp:          slot={} ts={}", state.last_timestamp.slot, state.last_timestamp.timestamp));

            lines
        }
    }
}

fn fmt_option_slot(slot: Option<u64>) -> String {
    match slot {
        Some(s) => s.to_string(),
        None => "None".to_string(),
    }
}

fn format_epoch_credits(lines: &mut Vec<String>, epoch_credits: &[(u64, u64, u64)]) {
    let count = epoch_credits.len();
    lines.push(format!("  Epoch Credits:           {} entries", count));
    let show = 5.min(count);
    for (i, (epoch, credits, prev_credits)) in epoch_credits.iter().rev().take(show).enumerate() {
        lines.push(format!(
            "    [{:>2}] epoch={:<6} credits={:<12} prev={}",
            i, epoch, credits, prev_credits
        ));
    }
    if count > show {
        lines.push(format!("    ... ({} more)", count - show));
    }
}

fn format_authorized_voters(lines: &mut Vec<String>, authorized_voters: &solana_vote_interface::authorized_voters::AuthorizedVoters) {
    let voters: Vec<_> = authorized_voters.iter().collect();
    lines.push(format!("  Authorized Voters:       {} entries", voters.len()));
    for (epoch, pubkey) in &voters {
        lines.push(format!("    epoch={}: {}", epoch, Pubkey::from(**pubkey)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vote_program_id() {
        let expected = bs58::decode("Vote111111111111111111111111111111111111111")
            .into_vec().unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&expected);
        assert!(is_vote_program_owner(&arr));
        assert!(!is_vote_program_owner(&[0u8; 32]));
    }

    #[test]
    fn test_deserialize_uninitialized() {
        /* Variant tag 0 = V0_23_5 which returns InstructionError */
        let data = vec![0u8; 64];
        let lines = deserialize_vote_account(&data);
        assert!(lines[0].contains("Failed to deserialize"));
    }
}
