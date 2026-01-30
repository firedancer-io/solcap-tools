use std::mem;

/* Solcap message type constants (must match fd_solcap_proto.h) */
pub const SOLCAP_WRITE_ACCOUNT: u32 = 1;
pub const SOLCAP_WRITE_BANK_PREIMAGE: u32 = 2;
pub const SOLCAP_STAKE_ACCOUNT_PAYOUT: u32 = 3;
pub const SOLCAP_STAKE_REWARD_EVENT: u32 = 4;
pub const SOLCAP_STAKE_REWARDS_BEGIN: u32 = 5;

/* File magic constants */
pub const FD_SOLCAP_V1_FILE_MAGIC: u64 = 0x806fe7581b1da4b7; /* deprecated */
pub const FD_SOLCAP_V2_FILE_MAGIC: u32 = 0x0A0D0D0A; /* used in pcapng */
pub const FD_SOLCAP_V2_BYTE_ORDER_MAGIC: u32 = 0x1A2B3C4D; /* used in pcapng */

/* PCAPng block type constants */
pub const SOLCAP_PCAPNG_BLOCK_TYPE_IDB: u32 = 1;
pub const SOLCAP_PCAPNG_BLOCK_TYPE_EPB: u32 = 6;
pub const SOLCAP_IDB_HDR_LINK_TYPE: u16 = 147; /* DLT_USER(0) */
pub const SOLCAP_IDB_HDR_SNAP_LEN: u32 = 0; /* unlimited */

/* Buffer configuration constants */
pub const FD_CAPCTX_BUF_ALIGN: usize = 128;
pub const FD_CAPCTX_BUF_CNT: usize = 64;
/* Note: FD_RUNTIME_ACC_SZ_MAX would need to be defined based on the actual runtime
   For now, using a reasonable default */
pub const FD_RUNTIME_ACC_SZ_MAX: usize = 10 * 1024 * 1024; /* 10MB */
pub const FD_CAPCTX_BUF_MTU: usize = FD_RUNTIME_ACC_SZ_MAX + 32 + mem::size_of::<SolanaAccountMeta>() + 8;

/* Pubkey type - 32 bytes for Solana public keys */
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pubkey {
    pub key: [u8; 32],
}

impl Pubkey {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }
}

/* Hash type - 32 bytes for Solana hashes */
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hash {
    pub hash: [u8; 32],
}

impl Hash {
    pub fn new(hash: [u8; 32]) -> Self {
        Self { hash }
    }
}

/* Solana account metadata structure */
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SolanaAccountMeta {
    pub lamports: u64,
    pub owner: Pubkey,
    pub executable: u8,
    pub padding: [u8; 3],
}

/* Solcap file header (Section Header Block in pcapng format) */
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SolcapFileHdr {
    pub block_type: u32,           /* 0x0A0D0D0A */
    pub block_len: u32,            /* length of the block */
    pub byte_order_magic: u32,     /* 0x1a2b3c4d */
    pub major_version: u32,        /* 0x00000001 */
    pub minor_version: u32,        /* 0x00000001 */
    pub section_len: u64,          /* (-1) length of the section */
    pub block_len_redundant: u32,  /* length of the block */
}

/* Interface Description Block header */
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SolcapChunkIdbHdr {
    pub block_type: u32,           /* pcap block type (1) */
    pub block_len: u32,            /* total block length */
    pub link_type: u16,            /* DLT_USER(0) = 147 */
    pub reserved: u16,             /* 0x0000 */
    pub snap_len: u32,             /* 0 = unlimited */
    pub block_len_redundant: u32,  /* length of the block */
}

/* Enhanced Packet Block header */
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SolcapChunkEpbHdr {
    pub block_type: u32,           /* pcap block type (6) */
    pub block_len: u32,            /* total block length including footer */
    pub interface_id: u32,         /* 0 */
    pub timestamp_upper: u32,      /* upper 32 bits of timestamp */
    pub timestamp_lower: u32,      /* lower 32 bits of timestamp */
    pub captured_packet_len: u32,  /* captured packet length */
    pub original_packet_len: u32,  /* original packet length */
}

/* Internal chunk header */
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SolcapChunkIntHdr {
    pub block_type: u32,           /* SOLCAP_BLOCK_TYPE_CHUNK */
    pub slot: u32,                 /* reference slot for the chunk */
    pub txn_idx: u64,              /* transaction index */
}

/* Chunk footer */
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SolcapChunkFtr {
    pub block_len_redundant: u32,  /* length of the block */
}

/* Account update header structure */
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SolcapAccountUpdateHdr {
    pub key: Pubkey,
    pub info: SolanaAccountMeta,
    pub data_sz: u64,
}

/* Bank preimage structure */
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SolcapBankPreimage {
    pub bank_hash: Hash,
    pub prev_bank_hash: Hash,
    pub accounts_lt_hash_checksum: Hash,
    pub poh_hash: Hash,
    pub signature_cnt: u64,
}

/* Stake rewards begin structure */
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SolcapStakeRewardsBegin {
    pub payout_epoch: u64,
    pub reward_epoch: u64,
    pub inflation_lamports: u64,
    pub total_points: u64,
}

/* Stake reward event structure */
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SolcapStakeRewardEvent {
    pub stake_acc_addr: Pubkey,
    pub vote_acc_addr: Pubkey,
    pub commission: u32,
    pub vote_rewards: i64,
    pub stake_rewards: i64,
    pub new_credits_observed: i64,
}

/* Stake account payout structure */
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SolcapStakeAccountPayout {
    pub stake_acc_addr: Pubkey,
    pub update_slot: u64,
    pub lamports: u64,
    pub lamports_delta: i64,
    pub credits_observed: u64,
    pub credits_observed_delta: i64,
    pub delegation_stake: u64,
    pub delegation_stake_delta: i64,
}

/* Utility functions for creating default instances */
impl Default for Pubkey {
    fn default() -> Self {
        Self { key: [0; 32] }
    }
}

impl Default for Hash {
    fn default() -> Self {
        Self { hash: [0; 32] }
    }
}

impl Default for SolanaAccountMeta {
    fn default() -> Self {
        Self {
            lamports: 0,
            owner: Pubkey::default(),
            executable: 0,
            padding: [0; 3],
        }
    }
}

impl Default for SolcapAccountUpdateHdr {
    fn default() -> Self {
        Self {
            key: Pubkey::default(),
            info: SolanaAccountMeta::default(),
            data_sz: 0,
        }
    }
}

impl Default for SolcapBankPreimage {
    fn default() -> Self {
        Self {
            bank_hash: Hash::default(),
            prev_bank_hash: Hash::default(),
            accounts_lt_hash_checksum: Hash::default(),
            poh_hash: Hash::default(),
            signature_cnt: 0,
        }
    }
}

/* Helper function to get timestamp from EPB header */
impl SolcapChunkEpbHdr {
    pub fn get_timestamp(&self) -> u64 {
        ((self.timestamp_upper as u64) << 32) | (self.timestamp_lower as u64)
    }
    
    pub fn set_timestamp(&mut self, timestamp: u64) {
        self.timestamp_upper = (timestamp >> 32) as u32;
        self.timestamp_lower = (timestamp & 0xFFFFFFFF) as u32;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn test_struct_sizes() {
        /* Verify that our Rust structs have the same size as the C structs */
        assert_eq!(mem::size_of::<Pubkey>(), 32);
        assert_eq!(mem::size_of::<Hash>(), 32);
        assert_eq!(mem::size_of::<SolanaAccountMeta>(), 44);
        assert_eq!(mem::size_of::<SolcapFileHdr>(), 32);
        assert_eq!(mem::size_of::<SolcapChunkIdbHdr>(), 20);
        assert_eq!(mem::size_of::<SolcapChunkEpbHdr>(), 28);
        assert_eq!(mem::size_of::<SolcapChunkIntHdr>(), 16);
        assert_eq!(mem::size_of::<SolcapChunkFtr>(), 4);
    }

    #[test]
    fn test_timestamp_operations() {
        let mut epb_hdr = SolcapChunkEpbHdr {
            block_type: SOLCAP_PCAPNG_BLOCK_TYPE_EPB,
            block_len: 0,
            interface_id: 0,
            timestamp_upper: 0,
            timestamp_lower: 0,
            captured_packet_len: 0,
            original_packet_len: 0,
        };

        let test_timestamp = 0x123456789ABCDEF0u64;
        epb_hdr.set_timestamp(test_timestamp);
        assert_eq!(epb_hdr.get_timestamp(), test_timestamp);
    }

    #[test]
    fn test_default_implementations() {
        let pubkey = Pubkey::default();
        assert_eq!(pubkey.key, [0; 32]);

        let hash = Hash::default();
        assert_eq!(hash.hash, [0; 32]);

        let account_meta = SolanaAccountMeta::default();
        /* Copy packed struct fields to local variables to avoid unaligned references */
        let lamports = account_meta.lamports;
        assert_eq!(lamports, 0);
    }
}
