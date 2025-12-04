/*! Block validation utilities shared across solcap tools.
    
    Provides functions to validate PCAP-NG blocks according to solcap format. */

use crate::model::structs::*;
use pcap_parser::PcapBlockOwned;
use std::mem;

/* ============================================================================
   Block Validation State
   ============================================================================ */

/// Tracks the state of required headers during block processing
#[derive(Debug, Default, Clone)]
pub struct HeaderState {
    pub section_header_found: bool,
    pub idb_found: bool,
    pub epb_seen: bool,
}

impl HeaderState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if all required headers have been found
    pub fn headers_complete(&self) -> bool {
        self.section_header_found && self.idb_found
    }
}

/* ============================================================================
   Block Validation Result
   ============================================================================ */

/// Result of validating a single block
#[derive(Debug)]
pub enum BlockValidation {
    /// Section Header Block validated successfully
    SectionHeader,
    /// Interface Description Block validated successfully  
    InterfaceDescription,
    /// Enhanced Packet Block validated successfully
    EnhancedPacket {
        block_type: u32,
        slot: u32,
        txn_idx: u64,
        payload_size: usize,
    },
    /// Other block type (allowed but not processed)
    Other,
}

/* ============================================================================
   Validation Functions
   ============================================================================ */

/// Validate a PCAP-NG block and update header state
/// 
/// Returns Ok(BlockValidation) on success, or Err((message, offset)) on failure
pub fn validate_block(
    block: &PcapBlockOwned,
    state: &mut HeaderState,
    current_offset: u64,
) -> Result<BlockValidation, (String, u64)> {
    match block {
        PcapBlockOwned::NG(ng_block) => {
            use pcap_parser::pcapng::Block;
            
            match ng_block {
                Block::SectionHeader(shb) => {
                    validate_section_header(shb, state, current_offset)
                }
                Block::InterfaceDescription(idb) => {
                    validate_interface_description(idb, state, current_offset)
                }
                Block::EnhancedPacket(epb) => {
                    validate_enhanced_packet(epb, state, current_offset)
                }
                _ => Ok(BlockValidation::Other),
            }
        }
        _ => Err(("Legacy PCAP format not supported".to_string(), current_offset)),
    }
}

/// Validate Section Header Block
fn validate_section_header(
    shb: &pcap_parser::pcapng::SectionHeaderBlock,
    state: &mut HeaderState,
    current_offset: u64,
) -> Result<BlockValidation, (String, u64)> {
    /* Check if we already have a section header */
    if state.section_header_found {
        return Err(("Multiple Section Header blocks found".to_string(), current_offset));
    }
    
    /* Validate magic number */
    if shb.block_type != FD_SOLCAP_V2_FILE_MAGIC {
        return Err((
            format!("Invalid Section Header magic number: 0x{:08x} (expected 0x{:08x})", 
                shb.block_type, FD_SOLCAP_V2_FILE_MAGIC),
            current_offset
        ));
    }
    
    state.section_header_found = true;
    Ok(BlockValidation::SectionHeader)
}

/// Validate Interface Description Block
fn validate_interface_description(
    idb: &pcap_parser::pcapng::InterfaceDescriptionBlock,
    state: &mut HeaderState,
    current_offset: u64,
) -> Result<BlockValidation, (String, u64)> {
    /* Check ordering - SHB must come first */
    if !state.section_header_found {
        return Err((
            "Interface Description Block found before Section Header".to_string(),
            current_offset
        ));
    }
    
    /* Check if we already have an IDB */
    if state.idb_found {
        return Err(("Multiple Interface Description blocks found".to_string(), current_offset));
    }
    
    /* Check ordering - IDB must come before EPBs */
    if state.epb_seen {
        return Err((
            "Interface Description Block found after Enhanced Packet Blocks".to_string(),
            current_offset
        ));
    }
    
    /* Validate link type */
    let linktype_value = idb.linktype.0;
    let expected_linktype = SOLCAP_IDB_HDR_LINK_TYPE as i32;
    if linktype_value != expected_linktype {
        return Err((
            format!("Invalid IDB link type: {} (expected {})", linktype_value, expected_linktype),
            current_offset
        ));
    }
    
    state.idb_found = true;
    Ok(BlockValidation::InterfaceDescription)
}

/// Validate Enhanced Packet Block
fn validate_enhanced_packet(
    epb: &pcap_parser::pcapng::EnhancedPacketBlock,
    state: &mut HeaderState,
    current_offset: u64,
) -> Result<BlockValidation, (String, u64)> {
    /* Check ordering - headers must come first */
    if !state.section_header_found || !state.idb_found {
        return Err((
            "Enhanced Packet Block found before required headers".to_string(),
            current_offset
        ));
    }
    
    state.epb_seen = true;
    
    /* Validate EPB has minimum data for internal header */
    let packet_data = epb.data;
    if packet_data.len() < mem::size_of::<SolcapChunkIntHdr>() {
        return Err((
            format!("EPB too small for internal header: {} bytes (need at least {})", 
                packet_data.len(), mem::size_of::<SolcapChunkIntHdr>()),
            current_offset
        ));
    }
    
    /* Read internal header */
    let int_hdr = unsafe {
        std::ptr::read_unaligned(packet_data.as_ptr() as *const SolcapChunkIntHdr)
    };
    
    let payload_size = packet_data.len() - mem::size_of::<SolcapChunkIntHdr>();
    
    Ok(BlockValidation::EnhancedPacket {
        block_type: int_hdr.block_type,
        slot: int_hdr.slot,
        txn_idx: int_hdr.txn_idx,
        payload_size,
    })
}

/// Validate the internal structure of an Enhanced Packet Block based on its type
/// 
/// This performs deeper validation of the EPB payload to ensure it matches
/// the expected structure for the given block type.
pub fn validate_epb_payload(
    block_type: u32,
    payload_size: usize,
    current_offset: u64,
) -> Result<(), (String, u64)> {
    let required_size = match block_type {
        SOLCAP_WRITE_ACCOUNT => mem::size_of::<SolcapAccountUpdateHdr>(),
        SOLCAP_WRITE_BANK_PREIMAGE => mem::size_of::<SolcapBankPreimage>(),
        SOLCAP_STAKE_ACCOUNT_PAYOUT => mem::size_of::<SolcapStakeAccountPayout>(),
        SOLCAP_STAKE_REWARD_EVENT => mem::size_of::<SolcapStakeRewardEvent>(),
        SOLCAP_STAKE_REWARDS_BEGIN => mem::size_of::<SolcapStakeRewardsBegin>(),
        _ => {
            return Err((
                format!("Unknown block type: {}", block_type),
                current_offset
            ));
        }
    };
    
    if payload_size < required_size {
        let type_name = match block_type {
            SOLCAP_WRITE_ACCOUNT => "Account update",
            SOLCAP_WRITE_BANK_PREIMAGE => "Bank preimage",
            SOLCAP_STAKE_ACCOUNT_PAYOUT => "Stake account payout",
            SOLCAP_STAKE_REWARD_EVENT => "Stake reward event",
            SOLCAP_STAKE_REWARDS_BEGIN => "Stake rewards begin",
            _ => "Unknown",
        };
        return Err((
            format!("{} payload too small: {} bytes (need at least {})", 
                type_name, payload_size, required_size),
            current_offset
        ));
    }
    
    Ok(())
}

/// Get a human-readable name for a solcap block type
pub fn block_type_name(block_type: u32) -> &'static str {
    match block_type {
        SOLCAP_WRITE_ACCOUNT => "Account Update",
        SOLCAP_WRITE_BANK_PREIMAGE => "Bank Preimage",
        SOLCAP_STAKE_ACCOUNT_PAYOUT => "Stake Account Payout",
        SOLCAP_STAKE_REWARD_EVENT => "Stake Reward Event",
        SOLCAP_STAKE_REWARDS_BEGIN => "Stake Rewards Begin",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_state_new() {
        let state = HeaderState::new();
        assert!(!state.section_header_found);
        assert!(!state.idb_found);
        assert!(!state.epb_seen);
    }

    #[test]
    fn test_headers_complete() {
        let mut state = HeaderState::new();
        assert!(!state.headers_complete());
        
        state.section_header_found = true;
        assert!(!state.headers_complete());
        
        state.idb_found = true;
        assert!(state.headers_complete());
    }

    #[test]
    fn test_block_type_name() {
        assert_eq!(block_type_name(SOLCAP_WRITE_ACCOUNT), "Account Update");
        assert_eq!(block_type_name(SOLCAP_WRITE_BANK_PREIMAGE), "Bank Preimage");
        assert_eq!(block_type_name(999), "Unknown");
    }
}

