use crate::model::sysvar::{identify_sysvar, sysvar_kind_name, deserialize_sysvar, SysvarKind};
use crate::model::vote::{is_vote_program_owner, deserialize_vote_account};
use crate::reader::{read_account_data, SolcapData, SolcapReaderError, read_account_data_from_bhd};
use crate::reader::agave_bhd_reader::AgaveBhdReaderError;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame, Terminal,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, BufReader, Seek, SeekFrom};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
enum ViewLevel {
    SlotLevel,
    AccountLevel { slot: u32 },
    UpdateLevel { slot: u32, account: [u8; 32] },
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Source {
    Both,
    SourceOne,
    SourceTwo,
}

#[derive(Debug, Clone)]
struct SlotInfo {
    slot: u32,
    bank_hash_1: Option<[u8; 32]>,
    bank_hash_2: Option<[u8; 32]>,
    account_count_1: usize,
    account_count_2: usize,
    source: Source,
    has_diff: bool,
}

#[derive(Debug, Clone)]
struct AccountInfo {
    account: [u8; 32],
    owner_1: Option<[u8; 32]>,
    owner_2: Option<[u8; 32]>,
    update_count_1: usize,
    update_count_2: usize,
    source: Source,
    has_diff: bool,
}

#[derive(Debug, Clone)]
struct UpdateComparison {
    txn_idx_1: Option<u64>,
    txn_idx_2: Option<u64>,
    lamports_1: Option<u64>,
    lamports_2: Option<u64>,
    owner_1: Option<[u8; 32]>,
    owner_2: Option<[u8; 32]>,
    data_size_1: Option<u64>,
    data_size_2: Option<u64>,
}

struct CircularCache<T> {
    capacity: usize,
    items: VecDeque<(String, T)>,
}

impl<T: Clone> CircularCache<T> {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            items: VecDeque::with_capacity(capacity),
        }
    }

    fn get(&self, key: &str) -> Option<&T> {
        self.items.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    fn insert(&mut self, key: String, value: T) {
        self.items.retain(|(k, _)| k != &key);
        self.items.push_front((key, value));
        if self.items.len() > self.capacity {
            self.items.pop_back();
        }
    }
}

struct App {
    data1: SolcapData,
    data2: SolcapData,
    path1: PathBuf,
    path2: PathBuf,
    name1: String,
    name2: String,
    level: ViewLevel,
    list_state: ListState,
    slots: Vec<SlotInfo>,
    should_quit: bool,
    page_size: usize,
    hex_scroll_offset: usize,

    saved_slot_selection: Option<usize>,
    saved_account_selection: Option<usize>,

    account_cache: CircularCache<Vec<AccountInfo>>,
    update_cache: CircularCache<Vec<UpdateComparison>>,
    data_cache: CircularCache<(Option<Vec<u8>>, Option<Vec<u8>>)>,
    current_cached_slot: Option<u32>,
    current_cached_account: Option<[u8; 32]>,

    data_comp: bool,
    show_owners: bool,

    search_mode: bool,
    search_query: String,
    search_matches: Vec<usize>,
    search_match_idx: Option<usize>,
    search_saved_selection: Option<usize>,
}

fn get_display_name(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| path.display().to_string())
}

impl App {
    fn new(data1: SolcapData, data2: SolcapData, path1: PathBuf, path2: PathBuf, start_slot: Option<u32>, end_slot: Option<u32>, data_comp: bool) -> Self {
        let name1 = get_display_name(&path1);
        let name2 = get_display_name(&path2);

        let mut slot_set = HashSet::new();
        for slot in data1.slot_account_updates_final.keys() {
            slot_set.insert(*slot);
        }
        for slot in data2.slot_account_updates_final.keys() {
            slot_set.insert(*slot);
        }

        if data1.lowest_slot <= data1.highest_slot {
            for slot in data1.lowest_slot..=data1.highest_slot {
                if data1.get_bank_preimage(slot).is_some() {
                    slot_set.insert(slot);
                }
            }
        }
        if data2.lowest_slot <= data2.highest_slot {
            for slot in data2.lowest_slot..=data2.highest_slot {
                if data2.get_bank_preimage(slot).is_some() {
                    slot_set.insert(slot);
                }
            }
        }

        let mut slots: Vec<SlotInfo> = slot_set.into_iter()
            .filter(|slot| {
                start_slot.map_or(true, |st| *slot >= st) && end_slot.map_or(true, |en| *slot <= en)
            })
            .map(|slot| {
            let preimage1 = data1.get_bank_preimage(slot);
            let preimage2 = data2.get_bank_preimage(slot);

            let bank_hash_1 = preimage1.map(|p| p.bank_hash.hash);
            let bank_hash_2 = preimage2.map(|p| p.bank_hash.hash);

            let account_count_1 = data1.get_account_updates_final(slot).map(|u| u.len()).unwrap_or(0);
            let account_count_2 = data2.get_account_updates_final(slot).map(|u| u.len()).unwrap_or(0);

            let source = match (preimage1.is_some() || account_count_1 > 0, preimage2.is_some() || account_count_2 > 0) {
                (true, true) => Source::Both,
                (true, false) => Source::SourceOne,
                (false, true) => Source::SourceTwo,
                (false, false) => Source::Both,
            };

            let has_diff = match (bank_hash_1, bank_hash_2) {
                (Some(h1), Some(h2)) => h1 != h2,
                _ => source != Source::Both,
            };

            SlotInfo {
                slot,
                bank_hash_1,
                bank_hash_2,
                account_count_1,
                account_count_2,
                source,
                has_diff,
            }
        }).collect();

        slots.sort_by_key(|s| s.slot);

        let mut list_state = ListState::default();
        if !slots.is_empty() {
            list_state.select(Some(0));
        }

        App {
            data1,
            data2,
            path1,
            path2,
            name1,
            name2,
            level: ViewLevel::SlotLevel,
            list_state,
            slots,
            should_quit: false,
            page_size: 20,
            hex_scroll_offset: 0,
            saved_slot_selection: None,
            saved_account_selection: None,
            account_cache: CircularCache::new(20),
            update_cache: CircularCache::new(20),
            data_cache: CircularCache::new(10),
            current_cached_slot: None,
            current_cached_account: None,
            data_comp,
            show_owners: false,
            search_mode: false,
            search_query: String::new(),
            search_matches: Vec::new(),
            search_match_idx: None,
            search_saved_selection: None,
        }
    }

    fn handle_key(&mut self, key: KeyCode, _modifiers: event::KeyModifiers) {
        if self.search_mode {
            self.handle_search_key(key);
            return;
        }

        match key {
            KeyCode::Char('q') => {
                match &self.level {
                    ViewLevel::SlotLevel => self.should_quit = true,
                    _ => self.go_back(),
                }
            }
            KeyCode::Char('b') => self.go_back(),
            KeyCode::Up => self.move_up(),
            KeyCode::Down => self.move_down(),
            KeyCode::Left => self.page_up(),
            KeyCode::Right => self.page_down(),
            KeyCode::Home => self.jump_to_start(),
            KeyCode::End => self.jump_to_end(),
            KeyCode::Enter => self.drill_down(),
            KeyCode::Char('/') => self.enter_search_mode(),
            KeyCode::Char('n') => self.search_next(),
            KeyCode::Char('N') => self.search_prev(),
            KeyCode::Char('m') => self.jump_to_first_divergence(),
            KeyCode::Char('o') => {
                if matches!(&self.level, ViewLevel::AccountLevel { .. }) {
                    self.show_owners = !self.show_owners;
                }
            }
            _ => {}
        }
    }

    fn go_back(&mut self) {
        match &self.level {
            ViewLevel::SlotLevel => {}
            ViewLevel::AccountLevel { .. } => {
                self.level = ViewLevel::SlotLevel;
                self.hex_scroll_offset = 0;
                if let Some(idx) = self.saved_slot_selection {
                    self.list_state.select(Some(idx));
                }
            }
            ViewLevel::UpdateLevel { slot, .. } => {
                self.level = ViewLevel::AccountLevel { slot: *slot };
                self.hex_scroll_offset = 0;
                if let Some(idx) = self.saved_account_selection {
                    self.list_state.select(Some(idx));
                }
            }
        }
    }

    fn move_up(&mut self) {
        match &self.level {
            ViewLevel::SlotLevel => {
                let i = match self.list_state.selected() {
                    Some(i) if i > 0 => i - 1,
                    Some(i) => i,
                    None => 0,
                };
                self.list_state.select(Some(i));
            }
            ViewLevel::AccountLevel { .. } => {
                let max_len = self.get_current_account_list_len();
                let i = match self.list_state.selected() {
                    Some(i) if i > 0 => i - 1,
                    Some(i) => i,
                    None => 0,
                };
                self.list_state.select(Some(i.min(max_len.saturating_sub(1))));
            }
            ViewLevel::UpdateLevel { .. } => {
                self.hex_scroll_offset = self.hex_scroll_offset.saturating_sub(1);
            }
        }
    }

    fn move_down(&mut self) {
        match &self.level {
            ViewLevel::SlotLevel => {
                let i = match self.list_state.selected() {
                    Some(i) if i < self.slots.len().saturating_sub(1) => i + 1,
                    Some(i) => i,
                    None => 0,
                };
                self.list_state.select(Some(i));
            }
            ViewLevel::AccountLevel { .. } => {
                let max_len = self.get_current_account_list_len();
                let i = match self.list_state.selected() {
                    Some(i) if i < max_len.saturating_sub(1) => i + 1,
                    Some(i) => i,
                    None => 0,
                };
                self.list_state.select(Some(i));
            }
            ViewLevel::UpdateLevel { .. } => {
                self.hex_scroll_offset += 1;
            }
        }
    }

    fn page_up(&mut self) {
        match &self.level {
            ViewLevel::SlotLevel => {
                let i = match self.list_state.selected() {
                    Some(i) => i.saturating_sub(self.page_size),
                    None => 0,
                };
                self.list_state.select(Some(i));
            }
            ViewLevel::AccountLevel { .. } => {
                let i = match self.list_state.selected() {
                    Some(i) => i.saturating_sub(self.page_size),
                    None => 0,
                };
                self.list_state.select(Some(i));
            }
            ViewLevel::UpdateLevel { .. } => {
                self.hex_scroll_offset = self.hex_scroll_offset.saturating_sub(self.page_size);
            }
        }
    }

    fn page_down(&mut self) {
        match &self.level {
            ViewLevel::SlotLevel => {
                let i = match self.list_state.selected() {
                    Some(i) => (i + self.page_size).min(self.slots.len().saturating_sub(1)),
                    None => 0,
                };
                self.list_state.select(Some(i));
            }
            ViewLevel::AccountLevel { .. } => {
                let max_len = self.get_current_account_list_len();
                let i = match self.list_state.selected() {
                    Some(i) => (i + self.page_size).min(max_len.saturating_sub(1)),
                    None => 0,
                };
                self.list_state.select(Some(i));
            }
            ViewLevel::UpdateLevel { .. } => {
                self.hex_scroll_offset += self.page_size;
            }
        }
    }

    fn get_current_account_list_len(&self) -> usize {
        match &self.level {
            ViewLevel::AccountLevel { slot } => {
                let cache_key = format!("slot_{}", slot);
                self.account_cache.get(&cache_key).map(|v| v.len()).unwrap_or(0)
            }
            _ => 0,
        }
    }

    fn drill_down(&mut self) {
        match &self.level {
            ViewLevel::SlotLevel => {
                if let Some(idx) = self.list_state.selected() {
                    if idx < self.slots.len() {
                        self.saved_slot_selection = Some(idx);
                        let slot = self.slots[idx].slot;
                        self.cache_accounts(slot);
                        self.level = ViewLevel::AccountLevel { slot };
                        self.list_state.select(Some(0));
                    }
                }
            }
            ViewLevel::AccountLevel { slot } => {
                let slot = *slot;
                if let Some(idx) = self.list_state.selected() {
                    let cache_key = format!("slot_{}", slot);
                    if let Some(accounts) = self.account_cache.get(&cache_key) {
                        if idx < accounts.len() {
                            self.saved_account_selection = Some(idx);
                            let account = accounts[idx].account;
                            self.cache_updates(slot, &account);
                            self.level = ViewLevel::UpdateLevel { slot, account };
                            self.hex_scroll_offset = 0;
                        }
                    }
                }
            }
            ViewLevel::UpdateLevel { .. } => {}
        }
    }

    fn jump_to_start(&mut self) {
        match &self.level {
            ViewLevel::SlotLevel | ViewLevel::AccountLevel { .. } => {
                self.list_state.select(Some(0));
            }
            ViewLevel::UpdateLevel { .. } => {
                self.hex_scroll_offset = 0;
            }
        }
    }

    fn jump_to_end(&mut self) {
        match &self.level {
            ViewLevel::SlotLevel => {
                self.list_state.select(Some(self.slots.len().saturating_sub(1)));
            }
            ViewLevel::AccountLevel { .. } => {
                let max_len = self.get_current_account_list_len();
                self.list_state.select(Some(max_len.saturating_sub(1)));
            }
            ViewLevel::UpdateLevel { .. } => {
                self.hex_scroll_offset = usize::MAX / 2;
            }
        }
    }

    /* Jump to the first divergence point: first mismatched slot after a matching one */
    fn jump_to_first_divergence(&mut self) {
        if !matches!(&self.level, ViewLevel::SlotLevel) {
            return;
        }
        let mut seen_good = false;
        for (i, slot_info) in self.slots.iter().enumerate() {
            let is_good = !slot_info.has_diff
                && slot_info.source == Source::Both
                && slot_info.bank_hash_1.is_some()
                && slot_info.bank_hash_2.is_some();
            if is_good {
                seen_good = true;
            } else if seen_good && slot_info.has_diff {
                self.list_state.select(Some(i));
                return;
            }
        }
        /* Fallback: jump to first mismatched slot */
        if !seen_good {
            for (i, slot_info) in self.slots.iter().enumerate() {
                if slot_info.has_diff {
                    self.list_state.select(Some(i));
                    return;
                }
            }
        }
    }

    fn enter_search_mode(&mut self) {
        match &self.level {
            ViewLevel::SlotLevel | ViewLevel::AccountLevel { .. } => {
                self.search_mode = true;
                self.search_query.clear();
                self.search_matches.clear();
                self.search_match_idx = None;
                self.search_saved_selection = self.list_state.selected();
            }
            _ => {}
        }
    }

    fn handle_search_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc => {
                self.search_mode = false;
                if let Some(idx) = self.search_saved_selection {
                    self.list_state.select(Some(idx));
                }
                self.search_query.clear();
                self.search_matches.clear();
                self.search_match_idx = None;
            }
            KeyCode::Enter => {
                self.search_mode = false;
            }
            KeyCode::Backspace => {
                self.search_query.pop();
                self.update_search_matches();
            }
            KeyCode::Char(c) => {
                self.search_query.push(c);
                self.update_search_matches();
            }
            _ => {}
        }
    }

    fn update_search_matches(&mut self) {
        self.search_matches.clear();
        self.search_match_idx = None;

        if self.search_query.is_empty() {
            return;
        }

        let query = self.search_query.to_lowercase();

        match &self.level {
            ViewLevel::SlotLevel => {
                for (i, slot_info) in self.slots.iter().enumerate() {
                    let slot_str = slot_info.slot.to_string();
                    let hash1 = slot_info.bank_hash_1
                        .map(|h| bs58::encode(&h).into_string().to_lowercase())
                        .unwrap_or_default();
                    let hash2 = slot_info.bank_hash_2
                        .map(|h| bs58::encode(&h).into_string().to_lowercase())
                        .unwrap_or_default();
                    if slot_str.contains(&query) || hash1.contains(&query) || hash2.contains(&query) {
                        self.search_matches.push(i);
                    }
                }
            }
            ViewLevel::AccountLevel { slot } => {
                let cache_key = format!("slot_{}", slot);
                if let Some(accounts) = self.account_cache.get(&cache_key) {
                    for (i, acc_info) in accounts.iter().enumerate() {
                        let key_str = if self.show_owners {
                            acc_info.owner_1.or(acc_info.owner_2)
                                .map(|o| bs58::encode(&o).into_string().to_lowercase())
                                .unwrap_or_default()
                        } else {
                            bs58::encode(&acc_info.account).into_string().to_lowercase()
                        };
                        let sysvar_label = identify_sysvar(&acc_info.account)
                            .map(|k| sysvar_kind_name(k).to_lowercase())
                            .unwrap_or_default();
                        if key_str.contains(&query) || sysvar_label.contains(&query) {
                            self.search_matches.push(i);
                        }
                    }
                }
            }
            _ => {}
        }

        if !self.search_matches.is_empty() {
            self.search_match_idx = Some(0);
            self.list_state.select(Some(self.search_matches[0]));
        }
    }

    fn search_next(&mut self) {
        if self.search_matches.is_empty() {
            return;
        }
        let next = match self.search_match_idx {
            Some(idx) => (idx + 1) % self.search_matches.len(),
            None => 0,
        };
        self.search_match_idx = Some(next);
        self.list_state.select(Some(self.search_matches[next]));
    }

    fn search_prev(&mut self) {
        if self.search_matches.is_empty() {
            return;
        }
        let prev = match self.search_match_idx {
            Some(idx) => {
                if idx == 0 { self.search_matches.len() - 1 } else { idx - 1 }
            }
            None => self.search_matches.len() - 1,
        };
        self.search_match_idx = Some(prev);
        self.list_state.select(Some(self.search_matches[prev]));
    }

    fn cache_accounts(&mut self, slot: u32) {
        let cache_key = format!("slot_{}", slot);
        if self.account_cache.get(&cache_key).is_some() {
            return;
        }

        let mut account_set = HashSet::new();
        if let Some(updates) = self.data1.get_account_updates_final(slot) {
            for key in updates.keys() {
                account_set.insert(*key);
            }
        }
        if let Some(updates) = self.data2.get_account_updates_final(slot) {
            for key in updates.keys() {
                account_set.insert(*key);
            }
        }

        let mut update_counts_1: HashMap<[u8; 32], usize> = HashMap::new();
        if let Some(all) = self.data1.get_account_updates_all(slot) {
            for up in all {
                *update_counts_1.entry(up.key.key).or_insert(0) += 1;
            }
        }
        let mut update_counts_2: HashMap<[u8; 32], usize> = HashMap::new();
        if let Some(all) = self.data2.get_account_updates_all(slot) {
            for up in all {
                *update_counts_2.entry(up.key.key).or_insert(0) += 1;
            }
        }

        let mut accounts: Vec<AccountInfo> = account_set.into_iter().map(|account| {
            let updates1 = self.data1.get_account_updates_final(slot)
                .and_then(|u| u.get(&account));
            let updates2 = self.data2.get_account_updates_final(slot)
                .and_then(|u| u.get(&account));

            let update_count_1 = update_counts_1.get(&account).copied().unwrap_or(0);
            let update_count_2 = update_counts_2.get(&account).copied().unwrap_or(0);

            let source = match (updates1.is_some(), updates2.is_some()) {
                (true, true) => Source::Both,
                (true, false) => Source::SourceOne,
                (false, true) => Source::SourceTwo,
                (false, false) => Source::Both,
            };

            let has_diff = match (updates1, updates2) {
                (Some(u1), Some(u2)) => {
                    u1.meta.lamports != u2.meta.lamports ||
                    u1.data_size != u2.data_size ||
                    u1.meta.owner.key != u2.meta.owner.key ||
                    u1.meta.executable != u2.meta.executable
                }
                _ => source != Source::Both,
            };

            AccountInfo {
                account,
                owner_1: updates1.map(|u| u.meta.owner.key),
                owner_2: updates2.map(|u| u.meta.owner.key),
                update_count_1,
                update_count_2,
                source,
                has_diff,
            }
        }).collect();

        if self.data_comp {
            let needs_data_check: Vec<usize> = accounts.iter().enumerate()
                .filter(|(_, a)| {
                    if a.has_diff || a.source != Source::Both { return false; }
                    let u1 = self.data1.get_account_updates_final(slot)
                        .and_then(|u| u.get(&a.account));
                    let u2 = self.data2.get_account_updates_final(slot)
                        .and_then(|u| u.get(&a.account));
                    match (u1, u2) {
                        (Some(u1), Some(u2)) => u1.data_size > 0 && u1.data_size == u2.data_size,
                        _ => false,
                    }
                })
                .map(|(i, _)| i)
                .collect();

            if !needs_data_check.is_empty() {
                let is_bhd_1 = self.data1.get_account_updates_final(slot)
                    .and_then(|u| u.values().next())
                    .map(|u| u.file.is_some())
                    .unwrap_or(false);
                let is_bhd_2 = self.data2.get_account_updates_final(slot)
                    .and_then(|u| u.values().next())
                    .map(|u| u.file.is_some())
                    .unwrap_or(false);

                let bhd_data_1: Option<HashMap<[u8; 32], Vec<u8>>> = if is_bhd_1 {
                    self.data1.get_account_updates_final(slot)
                        .and_then(|u| u.values().next())
                        .and_then(|u| u.file.as_ref())
                        .and_then(|f| parse_bhd_data_map(f).ok())
                } else {
                    None
                };
                let bhd_data_2: Option<HashMap<[u8; 32], Vec<u8>>> = if is_bhd_2 {
                    self.data2.get_account_updates_final(slot)
                        .and_then(|u| u.values().next())
                        .and_then(|u| u.file.as_ref())
                        .and_then(|f| parse_bhd_data_map(f).ok())
                } else {
                    None
                };

                let mut file1: Option<BufReader<File>> = if !is_bhd_1 {
                    File::open(&self.path1).ok().map(BufReader::new)
                } else {
                    None
                };
                let mut file2: Option<BufReader<File>> = if !is_bhd_2 {
                    File::open(&self.path2).ok().map(BufReader::new)
                } else {
                    None
                };

                for idx in needs_data_check {
                    let acct = accounts[idx].account;
                    let u1 = self.data1.get_account_updates_final(slot)
                        .and_then(|u| u.get(&acct));
                    let u2 = self.data2.get_account_updates_final(slot)
                        .and_then(|u| u.get(&acct));

                    if let (Some(u1), Some(u2)) = (u1, u2) {
                        let differs = match (&mut file1, &mut file2, &bhd_data_1, &bhd_data_2) {
                            (Some(f1), Some(f2), None, None) => {
                                files_differ(f1, u1.data_offset, f2, u2.data_offset, u1.data_size)
                                    .unwrap_or(false)
                            }
                            _ => {
                                /* Mixed or BHD sources: read + compare */
                                let d1 = if let Some(ref map) = bhd_data_1 {
                                    map.get(&acct).map(|v| v.as_slice())
                                } else {
                                    None
                                };
                                let d2 = if let Some(ref map) = bhd_data_2 {
                                    map.get(&acct).map(|v| v.as_slice())
                                } else {
                                    None
                                };

                                /* For solcap side in a mixed comparison, read into a buffer */
                                let buf1;
                                let slice1 = if let Some(s) = d1 { s } else if let Some(ref mut f) = file1 {
                                    buf1 = read_from_file(f, u1.data_offset, u1.data_size).ok();
                                    match buf1.as_deref() { Some(s) => s, None => continue }
                                } else { continue };

                                let buf2;
                                let slice2 = if let Some(s) = d2 { s } else if let Some(ref mut f) = file2 {
                                    buf2 = read_from_file(f, u2.data_offset, u2.data_size).ok();
                                    match buf2.as_deref() { Some(s) => s, None => continue }
                                } else { continue };

                                slice1 != slice2
                            }
                        };

                        if differs {
                            accounts[idx].has_diff = true;
                        }
                    }
                }
            }
        }

        /* Sort: differences first, then sysvars first, then by raw address bytes */
        accounts.sort_by(|a, b| {
            match (a.has_diff, b.has_diff) {
                (true, false) => return std::cmp::Ordering::Less,
                (false, true) => return std::cmp::Ordering::Greater,
                _ => {}
            }
            let a_sysvar = identify_sysvar(&a.account).is_some();
            let b_sysvar = identify_sysvar(&b.account).is_some();
            match (a_sysvar, b_sysvar) {
                (true, false) => return std::cmp::Ordering::Less,
                (false, true) => return std::cmp::Ordering::Greater,
                _ => {}
            }
            a.account.cmp(&b.account)
        });

        self.account_cache.insert(cache_key, accounts);
        self.current_cached_slot = Some(slot);
    }

    fn cache_updates(&mut self, slot: u32, account: &[u8; 32]) {
        let cache_key = format!("slot_{}_account_{}", slot, bs58::encode(account).into_string());

        /* Check if already cached */
        if self.update_cache.get(&cache_key).is_some() {
            return;
        }

        /* Get final updates from both sources */
        let update1 = self.data1.get_account_updates_final(slot)
            .and_then(|u| u.get(account));
        let update2 = self.data2.get_account_updates_final(slot)
            .and_then(|u| u.get(account));

        let comparison = UpdateComparison {
            txn_idx_1: update1.and_then(|u| u.txn_idx),
            txn_idx_2: update2.and_then(|u| u.txn_idx),
            lamports_1: update1.map(|u| u.meta.lamports),
            lamports_2: update2.map(|u| u.meta.lamports),
            owner_1: update1.map(|u| u.meta.owner.key),
            owner_2: update2.map(|u| u.meta.owner.key),
            data_size_1: update1.map(|u| u.data_size),
            data_size_2: update2.map(|u| u.data_size),
        };

        self.update_cache.insert(cache_key, vec![comparison]);
        self.current_cached_account = Some(*account);

        /* Also cache the actual account data for hex display */
        self.cache_account_data(slot, account);
    }

    fn cache_account_data(&mut self, slot: u32, account: &[u8; 32]) {
        let cache_key = format!("data_slot_{}_account_{}", slot, bs58::encode(account).into_string());

        /* Check if already cached */
        if self.data_cache.get(&cache_key).is_some() {
            return;
        }

        /* Get final updates from both sources */
        let update1 = self.data1.get_account_updates_final(slot)
            .and_then(|u| u.get(account));
        let update2 = self.data2.get_account_updates_final(slot)
            .and_then(|u| u.get(account));

        /* Read data from both sources */
        let data1 = update1.and_then(|u| {
            if u.file.is_some() {
                read_account_data_from_bhd(u).ok()
            } else {
                read_account_data(&self.path1, u).ok()
            }
        });

        let data2 = update2.and_then(|u| {
            if u.file.is_some() {
                read_account_data_from_bhd(u).ok()
            } else {
                read_account_data(&self.path2, u).ok()
            }
        });

        self.data_cache.insert(cache_key, (data1, data2));
    }
}

fn ui(f: &mut Frame, app: &mut App) {
    let footer_height = if app.search_mode { 2 } else { 1 };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),  
            Constraint::Min(0),  
            Constraint::Length(footer_height), 
        ])
        .split(f.size());

    let header_spans = match &app.level {
        ViewLevel::SlotLevel => {
            let diff_count = app.slots.iter().filter(|s| s.has_diff).count();
            vec![
                Span::styled(" Solcap Compare ", Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::raw("  "),
                Span::styled(format!("{}", app.name1), Style::default().fg(Color::Cyan)),
                Span::styled(" vs ", Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{}", app.name2), Style::default().fg(Color::Cyan)),
                Span::raw("  "),
                Span::styled(format!("{} slots", app.slots.len()), Style::default().fg(Color::White)),
                Span::raw(", "),
                Span::styled(
                    format!("{} mismatches", diff_count),
                    Style::default().fg(if diff_count > 0 { Color::Red } else { Color::Green }),
                ),
            ]
        }
        ViewLevel::AccountLevel { slot } => {
            let cache_key = format!("slot_{}", slot);
            let (total, diffs) = app.account_cache.get(&cache_key)
                .map(|accs| (accs.len(), accs.iter().filter(|a| a.has_diff).count()))
                .unwrap_or((0, 0));
            let mut spans = vec![
                Span::styled(" Accounts ", Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::raw("  "),
                Span::styled(format!("Slot {}", slot), Style::default().fg(Color::Cyan)),
                Span::raw("  "),
                Span::styled(format!("{} accounts", total), Style::default().fg(Color::White)),
                Span::raw(", "),
                Span::styled(
                    format!("{} diffs", diffs),
                    Style::default().fg(if diffs > 0 { Color::Red } else { Color::Green }),
                ),
            ];
            if app.show_owners {
                spans.push(Span::raw("  "));
                spans.push(Span::styled("[showing owners]", Style::default().fg(Color::Magenta)));
            }
            spans
        }
        ViewLevel::UpdateLevel { slot, account } => {
            let acct_str = bs58::encode(&account[..]).into_string();
            let short_acct = if acct_str.len() > 20 {
                format!("{}..{}", &acct_str[..8], &acct_str[acct_str.len()-8..])
            } else {
                acct_str.clone()
            };
            let sysvar_label = identify_sysvar(account)
                .map(|k| format!(" [{}]", sysvar_kind_name(k)))
                .unwrap_or_default();
            vec![
                Span::styled(" Update ", Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::raw("  "),
                Span::styled(format!("Slot {}", slot), Style::default().fg(Color::Cyan)),
                Span::raw("  "),
                Span::styled(short_acct, Style::default().fg(Color::White)),
                Span::styled(sysvar_label, Style::default().fg(Color::Yellow)),
            ]
        }
    };
    let header = Paragraph::new(Line::from(header_spans));
    f.render_widget(header, chunks[0]);

    /* Main content based on level */
    let level = app.level.clone();
    match level {
        ViewLevel::SlotLevel => render_slot_level(f, app, chunks[1]),
        ViewLevel::AccountLevel { slot } => render_account_level(f, app, slot, chunks[1]),
        ViewLevel::UpdateLevel { slot, account } => {
            render_update_level(f, app, slot, &account, chunks[1])
        }
    }

    let footer_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(if app.search_mode {
            vec![Constraint::Length(1), Constraint::Length(1)]
        } else {
            vec![Constraint::Length(1)]
        })
        .split(chunks[2]);

    let help_spans = match &app.level {
        ViewLevel::SlotLevel => vec![
            Span::styled(" q", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(" Quit ", Style::default().fg(Color::DarkGray)),
            Span::styled("Enter", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(" Drill ", Style::default().fg(Color::DarkGray)),
            Span::styled("/ ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled("Search ", Style::default().fg(Color::DarkGray)),
            Span::styled("n/N", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(" Next/Prev ", Style::default().fg(Color::DarkGray)),
            Span::styled("m", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(" Diverge ", Style::default().fg(Color::DarkGray)),
            Span::styled("←/→", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(" Page ", Style::default().fg(Color::DarkGray)),
            Span::styled("Home/End", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(" Jump", Style::default().fg(Color::DarkGray)),
        ],
        ViewLevel::AccountLevel { .. } => vec![
            Span::styled(" b", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(" Back ", Style::default().fg(Color::DarkGray)),
            Span::styled("Enter", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(" Drill ", Style::default().fg(Color::DarkGray)),
            Span::styled("o", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(if app.show_owners { " Keys " } else { " Owners " }, Style::default().fg(Color::DarkGray)),
            Span::styled("/ ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled("Search ", Style::default().fg(Color::DarkGray)),
            Span::styled("n/N", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(" Next/Prev ", Style::default().fg(Color::DarkGray)),
            Span::styled("←/→", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(" Page ", Style::default().fg(Color::DarkGray)),
            Span::styled("Home/End", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(" Jump", Style::default().fg(Color::DarkGray)),
        ],
        ViewLevel::UpdateLevel { .. } => vec![
            Span::styled(" b", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(" Back ", Style::default().fg(Color::DarkGray)),
            Span::styled("↑/↓", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(" Scroll ", Style::default().fg(Color::DarkGray)),
            Span::styled("←/→", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(" Page ", Style::default().fg(Color::DarkGray)),
            Span::styled("Home/End", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(" Jump", Style::default().fg(Color::DarkGray)),
        ],
    };
    let footer = Paragraph::new(Line::from(help_spans))
        .style(Style::default().bg(Color::DarkGray));
    f.render_widget(footer, footer_chunks[0]);

    if app.search_mode {
        let match_info = if app.search_query.is_empty() {
            String::new()
        } else if app.search_matches.is_empty() {
            " (no matches)".to_string()
        } else {
            format!(" ({}/{})",
                app.search_match_idx.map(|i| i + 1).unwrap_or(0),
                app.search_matches.len()
            )
        };
        let search_line = Line::from(vec![
            Span::styled("/", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(app.search_query.clone(), Style::default().fg(Color::White)),
            Span::styled("_", Style::default().fg(Color::DarkGray).add_modifier(Modifier::SLOW_BLINK)),
            Span::styled(match_info, Style::default().fg(Color::Cyan)),
        ]);
        let search_bar = Paragraph::new(search_line);
        f.render_widget(search_bar, footer_chunks[1]);
    }
}

fn render_slot_level(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(area);

    app.page_size = (chunks[1].height.saturating_sub(2)) as usize;

    /* Column header — "   " prefix matches the 3-char highlight symbol width */
    let name1_short = if app.name1.len() > 20 { &app.name1[..20] } else { &app.name1 };
    let name2_short = if app.name2.len() > 20 { &app.name2[..20] } else { &app.name2 };
    let header_line = Line::from(vec![
        Span::styled(format!("   {:>12}", "SLOT"), Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Span::styled("  │ ", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{:<44}", format!("BANK HASH ({})", name1_short)), Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Span::styled(" │ ", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{:<44}", format!("BANK HASH ({})", name2_short)), Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Span::styled(" │ ", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{:>6}", "ACCTS"), Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Span::styled(" │ ", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{:>6}", "ACCTS"), Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
    ]);
    f.render_widget(Paragraph::new(header_line), chunks[0]);

    let items: Vec<ListItem> = app.slots.iter().map(|slot_info| {
        let bank_hash_1 = slot_info.bank_hash_1
            .map(|h| bs58::encode(&h).into_string())
            .unwrap_or_else(|| "---".to_string());
        let bank_hash_2 = slot_info.bank_hash_2
            .map(|h| bs58::encode(&h).into_string())
            .unwrap_or_else(|| "---".to_string());

        let (slot_color, hash_color) = if slot_info.has_diff {
            (Color::Red, Color::Red)
        } else if slot_info.source != Source::Both {
            (Color::DarkGray, Color::DarkGray)
        } else {
            (Color::White, Color::Green)
        };

        let content = vec![
            Span::styled(format!("{:>12}", slot_info.slot), Style::default().fg(slot_color)),
            Span::raw("  │ "),
            Span::styled(format!("{:<44}", bank_hash_1), Style::default().fg(if slot_info.bank_hash_1.is_some() { hash_color } else { Color::DarkGray })),
            Span::raw(" │ "),
            Span::styled(format!("{:<44}", bank_hash_2), Style::default().fg(if slot_info.bank_hash_2.is_some() { hash_color } else { Color::DarkGray })),
            Span::raw(" │ "),
            Span::styled(format!("{:>6}", slot_info.account_count_1), Style::default().fg(if slot_info.account_count_1 > 0 { Color::Cyan } else { Color::DarkGray })),
            Span::raw(" │ "),
            Span::styled(format!("{:>6}", slot_info.account_count_2), Style::default().fg(if slot_info.account_count_2 > 0 { Color::Cyan } else { Color::DarkGray })),
        ];

        ListItem::new(Line::from(content))
    }).collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    f.render_stateful_widget(list, chunks[1], &mut app.list_state);
}

fn render_account_level(f: &mut Frame, app: &mut App, slot: u32, area: Rect) {
    /* Ensure accounts are cached */
    if app.current_cached_slot != Some(slot) {
        app.cache_accounts(slot);
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(area);

    app.page_size = (chunks[1].height.saturating_sub(2)) as usize;

    let name1_short = if app.name1.len() > 10 { &app.name1[..10] } else { &app.name1 };
    let name2_short = if app.name2.len() > 10 { &app.name2[..10] } else { &app.name2 };
    let col_label = if app.show_owners { "OWNER" } else { "ACCOUNT" };
    let header_line = Line::from(vec![
        Span::styled(format!("   {:<44}", col_label), Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Span::styled(format!("{:<16}", ""), Style::default().fg(Color::DarkGray)),
        Span::styled(" │ ", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{:>6}", name1_short), Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Span::styled(" │ ", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{:>6}", name2_short), Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
    ]);
    f.render_widget(Paragraph::new(header_line), chunks[0]);

    let cache_key = format!("slot_{}", slot);
    let show_owners = app.show_owners;
    let items: Vec<ListItem> = if let Some(accounts) = app.account_cache.get(&cache_key) {
        accounts.iter().map(|acc_info| {
            let display_key = if show_owners {
                acc_info.owner_1.or(acc_info.owner_2)
                    .map(|o| bs58::encode(&o).into_string())
                    .unwrap_or_else(|| "---".to_string())
            } else {
                bs58::encode(&acc_info.account).into_string()
            };
            let sysvar_label = identify_sysvar(&acc_info.account)
                .map(|k| format!(" [{}]", sysvar_kind_name(k)))
                .unwrap_or_default();

            let (account_color, count_color) = if acc_info.has_diff {
                (Color::Red, Color::Red)
            } else if acc_info.source != Source::Both {
                (Color::DarkGray, Color::DarkGray)
            } else {
                (Color::White, Color::Cyan)
            };

            let content = vec![
                Span::styled(format!("{:<44}", display_key), Style::default().fg(account_color)),
                Span::styled(format!("{:<16}", sysvar_label), Style::default().fg(Color::Yellow)),
                Span::raw(" │ "),
                Span::styled(format!("{:>6}", acc_info.update_count_1), Style::default().fg(if acc_info.update_count_1 > 0 { count_color } else { Color::DarkGray })),
                Span::raw(" │ "),
                Span::styled(format!("{:>6}", acc_info.update_count_2), Style::default().fg(if acc_info.update_count_2 > 0 { count_color } else { Color::DarkGray })),
            ];

            ListItem::new(Line::from(content))
        }).collect()
    } else {
        vec![ListItem::new(Line::from("Loading..."))]
    };

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    f.render_stateful_widget(list, chunks[1], &mut app.list_state);
}

fn render_update_level(f: &mut Frame, app: &mut App, slot: u32, account: &[u8; 32], area: Rect) {
    let sysvar_kind = identify_sysvar(account);

    let is_vote = if sysvar_kind.is_none() {
        let cache_key = format!("slot_{}_account_{}", slot, bs58::encode(account).into_string());
        app.update_cache.get(&cache_key)
            .and_then(|comps| comps.first())
            .map(|comp| {
                comp.owner_1.as_ref().map_or(false, |o| is_vote_program_owner(o))
                || comp.owner_2.as_ref().map_or(false, |o| is_vote_program_owner(o))
            })
            .unwrap_or(false)
    } else {
        false
    };

    let data_key = format!("data_slot_{}_account_{}", slot, bs58::encode(account).into_string());
    let deser_height = if let Some(kind) = sysvar_kind {
        let max_lines = if let Some((data1, data2)) = app.data_cache.get(&data_key) {
            let lines1 = data1.as_ref().map(|d| deserialize_sysvar(kind, d)).unwrap_or_default();
            let lines2 = data2.as_ref().map(|d| deserialize_sysvar(kind, d)).unwrap_or_default();
            lines1.len().max(lines2.len())
        } else {
            3
        };
        (max_lines as u16 + 2).min(area.height / 3).max(4)
    } else if is_vote {
        let max_lines = if let Some((data1, data2)) = app.data_cache.get(&data_key) {
            let lines1 = data1.as_ref().map(|d| deserialize_vote_account(d)).unwrap_or_default();
            let lines2 = data2.as_ref().map(|d| deserialize_vote_account(d)).unwrap_or_default();
            let snipped = snipped_line_count(&lines1, &lines2);
            snipped.max(lines1.len().max(lines2.len()).min(snipped + 4))
        } else {
            3
        };
        (max_lines as u16 + 2).min(area.height * 2 / 3).max(4)
    } else {
        0
    };

    let has_deser = sysvar_kind.is_some() || is_vote;

    let chunks = if has_deser {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(10),
                Constraint::Length(deser_height),
                Constraint::Min(0),
            ])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(10), Constraint::Min(0)])
            .split(area)
    };

    /* Get cached update comparison */
    let cache_key = format!("slot_{}_account_{}", slot, bs58::encode(account).into_string());

    let update_info = if let Some(comparisons) = app.update_cache.get(&cache_key) {
        if let Some(comp) = comparisons.first() {
            const W: usize = 44;
            let na = "N/A".to_string();

            let fmt_val = |v: Option<String>| -> String {
                format!("{:>w$}", v.unwrap_or_else(|| na.clone()), w = W)
            };

            let color_pair = |differs: bool, present: bool, ok_color: Color| -> Color {
                if !present { Color::DarkGray }
                else if differs { Color::Red }
                else { ok_color }
            };

            let name1_short = if app.name1.len() > W { &app.name1[..W] } else { &app.name1 };
            let name2_short = if app.name2.len() > W { &app.name2[..W] } else { &app.name2 };

            let mut lines = vec![
                Line::from(vec![
                    Span::styled(format!("{:<20}", ""), Style::default()),
                    Span::styled(format!("{:>w$}", name1_short, w = W), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Span::raw("  │  "),
                    Span::styled(format!("{:>w$}", name2_short, w = W), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                ]),
                Line::from(""),
            ];

            /* Transaction indices */
            let txn_diff = comp.txn_idx_1 != comp.txn_idx_2;
            lines.push(Line::from(vec![
                Span::styled(format!("{:<20}", "Transaction Idx:"), Style::default().fg(Color::DarkGray)),
                Span::styled(fmt_val(comp.txn_idx_1.map(|t| t.to_string())),
                    Style::default().fg(color_pair(txn_diff, comp.txn_idx_1.is_some(), Color::Green))),
                Span::raw("  │  "),
                Span::styled(fmt_val(comp.txn_idx_2.map(|t| t.to_string())),
                    Style::default().fg(color_pair(txn_diff, comp.txn_idx_2.is_some(), Color::Green))),
            ]));

            /* Lamports */
            let lamp_diff = comp.lamports_1 != comp.lamports_2;
            lines.push(Line::from(vec![
                Span::styled(format!("{:<20}", "Lamports:"), Style::default().fg(Color::DarkGray)),
                Span::styled(fmt_val(comp.lamports_1.map(|l| l.to_string())),
                    Style::default().fg(color_pair(lamp_diff, comp.lamports_1.is_some(), Color::Green))),
                Span::raw("  │  "),
                Span::styled(fmt_val(comp.lamports_2.map(|l| l.to_string())),
                    Style::default().fg(color_pair(lamp_diff, comp.lamports_2.is_some(), Color::Green))),
            ]));

            /* Owner */
            let owner_diff = comp.owner_1 != comp.owner_2;
            lines.push(Line::from(vec![
                Span::styled(format!("{:<20}", "Owner:"), Style::default().fg(Color::DarkGray)),
                Span::styled(fmt_val(comp.owner_1.map(|o| bs58::encode(&o).into_string())),
                    Style::default().fg(color_pair(owner_diff, comp.owner_1.is_some(), Color::Cyan))),
                Span::raw("  │  "),
                Span::styled(fmt_val(comp.owner_2.map(|o| bs58::encode(&o).into_string())),
                    Style::default().fg(color_pair(owner_diff, comp.owner_2.is_some(), Color::Cyan))),
            ]));

            /* Data size */
            let data_diff = comp.data_size_1 != comp.data_size_2;
            lines.push(Line::from(vec![
                Span::styled(format!("{:<20}", "Data Size:"), Style::default().fg(Color::DarkGray)),
                Span::styled(fmt_val(comp.data_size_1.map(|d| format!("{} bytes", d))),
                    Style::default().fg(color_pair(data_diff, comp.data_size_1.is_some(), Color::Magenta))),
                Span::raw("  │  "),
                Span::styled(fmt_val(comp.data_size_2.map(|d| format!("{} bytes", d))),
                    Style::default().fg(color_pair(data_diff, comp.data_size_2.is_some(), Color::Magenta))),
            ]));

            lines
        } else {
            vec![Line::from(Span::styled("No comparison data available", Style::default().fg(Color::Red)))]
        }
    } else {
        vec![Line::from(Span::styled("Loading...", Style::default().fg(Color::Yellow)))]
    };

    let info_widget = Paragraph::new(update_info)
        .block(Block::default().borders(Borders::ALL).title("Update Comparison"));
    f.render_widget(info_widget, chunks[0]);

    if let Some(kind) = sysvar_kind {
        render_sysvar_comparison(f, app, slot, account, kind, chunks[1]);
        render_hex_dump_comparison(f, app, slot, account, chunks[2]);
    } else if is_vote {
        render_vote_comparison(f, app, slot, account, chunks[1]);
        render_hex_dump_comparison(f, app, slot, account, chunks[2]);
    } else {
        render_hex_dump_comparison(f, app, slot, account, chunks[1]);
    }
}

fn build_sysvar_diff_lines(lines: &[String], other_lines: &[String]) -> Vec<Line<'static>> {
    let max_len = lines.len().max(other_lines.len());
    let mut result = Vec::new();

    for i in 0..max_len {
        let line = lines.get(i).map(|s| s.as_str()).unwrap_or("");
        let other = other_lines.get(i).map(|s| s.as_str()).unwrap_or("");

        let color = if line != other { Color::Red } else { Color::Green };
        result.push(Line::from(Span::styled(
            line.to_string(),
            Style::default().fg(color),
        )));
    }
    result
}

fn render_sysvar_comparison(
    f: &mut Frame,
    app: &App,
    slot: u32,
    account: &[u8; 32],
    kind: SysvarKind,
    area: Rect,
) {
    let cache_key = format!("data_slot_{}_account_{}", slot, bs58::encode(account).into_string());

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    if let Some((data1, data2)) = app.data_cache.get(&cache_key) {
        let lines1 = data1.as_ref()
            .map(|d| deserialize_sysvar(kind, d))
            .unwrap_or_else(|| vec!["No data".to_string()]);
        let lines2 = data2.as_ref()
            .map(|d| deserialize_sysvar(kind, d))
            .unwrap_or_else(|| vec!["No data".to_string()]);

        let display1 = build_sysvar_diff_lines(&lines1, &lines2);
        let display2 = build_sysvar_diff_lines(&lines2, &lines1);

        let title = sysvar_kind_name(kind);
        let widget1 = Paragraph::new(display1)
            .block(Block::default().borders(Borders::ALL)
                .title(format!("{} ({})", title, app.name1)));
        let widget2 = Paragraph::new(display2)
            .block(Block::default().borders(Borders::ALL)
                .title(format!("{} ({})", title, app.name2)));

        f.render_widget(widget1, columns[0]);
        f.render_widget(widget2, columns[1]);
    } else {
        let widget = Paragraph::new(Line::from("Loading sysvar data..."))
            .block(Block::default().borders(Borders::ALL).title(sysvar_kind_name(kind)));
        f.render_widget(widget, area);
    }
}

/* Count how many lines the snipped view will produce */
fn snipped_line_count(lines1: &[String], lines2: &[String]) -> usize {
    let max_len = lines1.len().max(lines2.len());
    if max_len == 0 { return 0; }

    let mut differs: Vec<bool> = Vec::with_capacity(max_len);
    for i in 0..max_len {
        let a = lines1.get(i).map(|s| s.as_str()).unwrap_or("");
        let b = lines2.get(i).map(|s| s.as_str()).unwrap_or("");
        differs.push(a != b);
    }

    /* Always show header lines */
    let header_count = 3.min(max_len);
    let mut count = header_count;

    let mut i = header_count;
    while i < max_len {
        let in_context = differs.get(i).copied().unwrap_or(false)
            || (i > 0 && differs.get(i - 1).copied().unwrap_or(false))
            || differs.get(i + 1).copied().unwrap_or(false);

        if in_context {
            count += 1;
            i += 1;
        } else {
            /* Count run of matching lines outside context */
            let run_start = i;
            while i < max_len {
                let near_diff = differs.get(i).copied().unwrap_or(false)
                    || differs.get(i + 1).copied().unwrap_or(false);
                if near_diff { break; }
                i += 1;
            }
            let run_len = i - run_start;
            if run_len > 3 {
                count += 1; /* collapsed "... (N matching) ..." */
            } else {
                count += run_len;
            }
        }
    }
    count
}

/* Build diff lines with snipping: collapses runs of >3 matching lines */
fn build_diff_lines_snipped(lines: &[String], other_lines: &[String]) -> Vec<Line<'static>> {
    let max_len = lines.len().max(other_lines.len());
    if max_len == 0 { return Vec::new(); }

    let mut differs: Vec<bool> = Vec::with_capacity(max_len);
    for i in 0..max_len {
        let a = lines.get(i).map(|s| s.as_str()).unwrap_or("");
        let b = other_lines.get(i).map(|s| s.as_str()).unwrap_or("");
        differs.push(a != b);
    }

    let mut result = Vec::new();
    let header_count = 3.min(max_len);

    /* Always show header lines */
    for i in 0..header_count {
        let line = lines.get(i).map(|s| s.as_str()).unwrap_or("");
        let color = if differs[i] { Color::Red } else { Color::Green };
        result.push(Line::from(Span::styled(line.to_string(), Style::default().fg(color))));
    }

    let mut i = header_count;
    while i < max_len {
        let in_context = differs.get(i).copied().unwrap_or(false)
            || (i > 0 && differs.get(i - 1).copied().unwrap_or(false))
            || differs.get(i + 1).copied().unwrap_or(false);

        if in_context {
            let line = lines.get(i).map(|s| s.as_str()).unwrap_or("");
            let color = if differs[i] { Color::Red } else { Color::Green };
            result.push(Line::from(Span::styled(line.to_string(), Style::default().fg(color))));
            i += 1;
        } else {
            let run_start = i;
            while i < max_len {
                let near_diff = differs.get(i).copied().unwrap_or(false)
                    || differs.get(i + 1).copied().unwrap_or(false);
                if near_diff { break; }
                i += 1;
            }
            let run_len = i - run_start;
            if run_len > 3 {
                result.push(Line::from(Span::styled(
                    format!("  ... ({} matching lines) ...", run_len),
                    Style::default().fg(Color::DarkGray),
                )));
            } else {
                for j in run_start..i {
                    let line = lines.get(j).map(|s| s.as_str()).unwrap_or("");
                    result.push(Line::from(Span::styled(line.to_string(), Style::default().fg(Color::Green))));
                }
            }
        }
    }
    result
}

fn render_vote_comparison(
    f: &mut Frame,
    app: &App,
    slot: u32,
    account: &[u8; 32],
    area: Rect,
) {
    let cache_key = format!("data_slot_{}_account_{}", slot, bs58::encode(account).into_string());

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    if let Some((data1, data2)) = app.data_cache.get(&cache_key) {
        let lines1 = data1.as_ref()
            .map(|d| deserialize_vote_account(d))
            .unwrap_or_else(|| vec!["No data".to_string()]);
        let lines2 = data2.as_ref()
            .map(|d| deserialize_vote_account(d))
            .unwrap_or_else(|| vec!["No data".to_string()]);

        let display1 = build_diff_lines_snipped(&lines1, &lines2);
        let display2 = build_diff_lines_snipped(&lines2, &lines1);

        let widget1 = Paragraph::new(display1)
            .block(Block::default().borders(Borders::ALL)
                .title(format!("Vote State ({})", app.name1)));
        let widget2 = Paragraph::new(display2)
            .block(Block::default().borders(Borders::ALL)
                .title(format!("Vote State ({})", app.name2)));

        f.render_widget(widget1, columns[0]);
        f.render_widget(widget2, columns[1]);
    } else {
        let widget = Paragraph::new(Line::from("Loading vote data..."))
            .block(Block::default().borders(Borders::ALL).title("Vote State"));
        f.render_widget(widget, area);
    }
}

fn render_hex_dump_comparison(f: &mut Frame, app: &mut App, slot: u32, account: &[u8; 32], area: Rect) {
    let cache_key = format!("data_slot_{}_account_{}", slot, bs58::encode(account).into_string());

    /* Split area into two columns */
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    app.page_size = (area.height.saturating_sub(2)) as usize;

    if let Some((data1, data2)) = app.data_cache.get(&cache_key) {
        /* Render left side with comparison highlighting */
        let lines1 = render_hex_data_with_diff(data1.as_ref(), data2.as_ref(), app.hex_scroll_offset, app.page_size, true);
        let hex_widget1 = Paragraph::new(lines1)
            .block(Block::default().borders(Borders::ALL).title(app.name1.clone()));
        f.render_widget(hex_widget1, columns[0]);

        /* Render right side with comparison highlighting */
        let lines2 = render_hex_data_with_diff(data2.as_ref(), data1.as_ref(), app.hex_scroll_offset, app.page_size, false);
        let hex_widget2 = Paragraph::new(lines2)
            .block(Block::default().borders(Borders::ALL).title(app.name2.clone()));
        f.render_widget(hex_widget2, columns[1]);
    } else {
        let loading_widget = Paragraph::new(Line::from("Loading..."))
            .block(Block::default().borders(Borders::ALL).title("Data Comparison"));
        f.render_widget(loading_widget, area);
    }
}

fn render_hex_data_with_diff(
    data: Option<&Vec<u8>>,
    other_data: Option<&Vec<u8>>,
    scroll_offset: usize,
    visible_rows: usize,
    _is_left: bool,
) -> Vec<Line<'static>> {
    let bytes_per_row = 16;

    match data {
        None => vec![Line::from(Span::styled(
            "No data available",
            Style::default().fg(Color::DarkGray)
        ))],
        Some(data) if data.is_empty() => vec![Line::from(Span::styled(
            "Empty data",
            Style::default().fg(Color::DarkGray)
        ))],
        Some(data) => {
            let total_rows = (data.len() + bytes_per_row - 1) / bytes_per_row;
            let start_row = scroll_offset.min(total_rows.saturating_sub(1));
            let end_row = (start_row + visible_rows).min(total_rows);

            let mut lines = Vec::new();

            for row in start_row..end_row {
                let offset = row * bytes_per_row;
                let row_end = (offset + bytes_per_row).min(data.len());
                let row_data = &data[offset..row_end];

                /* Build the line with colored spans for differences */
                let mut spans = vec![
                    Span::styled(
                        format!("{:08X}  ", offset),
                        Style::default().fg(Color::DarkGray)
                    )
                ];

                for (i, byte) in row_data.iter().enumerate() {
                    if i == 8 {
                        spans.push(Span::raw(" "));
                    }

                    /* Check if this byte differs from the other source */
                    let differs = if let Some(other) = other_data {
                        let other_idx = offset + i;
                        if other_idx < other.len() {
                            other[other_idx] != *byte
                        } else {
                            true /* Different if other data doesn't have this byte */
                        }
                    } else {
                        false /* No other data to compare with */
                    };

                    let color = if differs { Color::Red } else { Color::White };
                    spans.push(Span::styled(
                        format!("{:02X} ", byte),
                        Style::default().fg(color)
                    ));
                }

                lines.push(Line::from(spans));
            }

            if end_row < total_rows {
                lines.push(Line::from(Span::styled(
                    format!("... ({} more rows) ...", total_rows - end_row),
                    Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC)
                )));
            }

            lines
        }
    }
}

fn read_from_file<R: io::Read + Seek>(f: &mut R, offset: u64, size: u64) -> io::Result<Vec<u8>> {
    f.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; size as usize];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

fn files_differ<R1: io::Read + Seek, R2: io::Read + Seek>(
    f1: &mut R1, offset1: u64,
    f2: &mut R2, offset2: u64,
    size: u64,
) -> io::Result<bool> {
    const CHUNK: usize = 64 * 1024;
    f1.seek(SeekFrom::Start(offset1))?;
    f2.seek(SeekFrom::Start(offset2))?;

    let mut buf1 = [0u8; CHUNK];
    let mut buf2 = [0u8; CHUNK];
    let mut remaining = size as usize;

    while remaining > 0 {
        let n = remaining.min(CHUNK);
        f1.read_exact(&mut buf1[..n])?;
        f2.read_exact(&mut buf2[..n])?;
        if buf1[..n] != buf2[..n] {
            return Ok(true);
        }
        remaining -= n;
    }
    Ok(false)
}

fn parse_bhd_data_map(file_path: &str) -> Result<HashMap<[u8; 32], Vec<u8>>, String> {
    use crate::reader::agave_bhd_reader::AgaveBankHashDetails;
    use base64::{Engine as _, engine::general_purpose};

    let contents = std::fs::read_to_string(file_path)
        .map_err(|e| format!("read BHD: {}", e))?;
    let bhd: AgaveBankHashDetails = serde_json::from_str(&contents)
        .map_err(|e| format!("parse BHD: {}", e))?;

    let mut map = HashMap::new();
    for entry in &bhd.bank_hash_details {
        for account in &entry.accounts {
            if let Ok(key_bytes) = bs58::decode(&account.pubkey).into_vec() {
                if key_bytes.len() == 32 {
                    if let Ok(data) = general_purpose::STANDARD.decode(&account.data) {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&key_bytes);
                        map.insert(key, data);
                    }
                }
            }
        }
    }
    Ok(map)
}

/* Parse a path (either a file or directory) into SolcapData */
fn parse_path<P: AsRef<Path>>(path: P) -> Result<SolcapData, CompareError> {
    let path = path.as_ref();

    if !path.exists() {
        return Err(CompareError::PathNotFound(format!(
            "Path does not exist: {}",
            path.display()
        )));
    }

    let data = if path.is_dir() {
        use crate::reader::agave_bhd_reader::AgaveBhdReader;
        let reader = AgaveBhdReader::from_directory(path)?;
        reader.parse_directory()?
    } else {
        use crate::reader::solcap_reader::SolcapReader;
        let mut reader = SolcapReader::from_file(path)?;
        reader.parse_file()?
    };

    Ok(data)
}

/// Errors that can occur during comparison
#[derive(Debug)]
pub enum CompareError {
    SolcapError(SolcapReaderError),
    AgaveError(AgaveBhdReaderError),
    IoError(std::io::Error),
    PathNotFound(String),
}

impl From<SolcapReaderError> for CompareError {
    fn from(err: SolcapReaderError) -> Self {
        CompareError::SolcapError(err)
    }
}

impl From<AgaveBhdReaderError> for CompareError {
    fn from(err: AgaveBhdReaderError) -> Self {
        CompareError::AgaveError(err)
    }
}

impl From<std::io::Error> for CompareError {
    fn from(err: std::io::Error) -> Self {
        CompareError::IoError(err)
    }
}

/* Run the interactive comparison */
pub fn compare_solcap<P1: AsRef<Path>, P2: AsRef<Path>>(
    path1: P1,
    path2: P2,
    start_slot: Option<u32>,
    end_slot: Option<u32>,
    data_comp: bool,
) -> Result<(), CompareError> {
    let path1 = path1.as_ref();
    let path2 = path2.as_ref();

    /* Get display names for the sources */
    let name1 = get_display_name(path1);
    let name2 = get_display_name(path2);

    /* Read both paths */
    println!("Loading '{}': {}", name1, path1.display());
    let data1 = parse_path(path1)?;
    println!("  Slots: {} - {}", data1.lowest_slot, data1.highest_slot);

    println!("Loading '{}': {}", name2, path2.display());
    let data2 = parse_path(path2)?;
    println!("  Slots: {} - {}", data2.lowest_slot, data2.highest_slot);

    /* Setup terminal */
    enable_raw_mode().map_err(|e| {
        CompareError::IoError(e)
    })?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).map_err(|e| {
        CompareError::IoError(e)
    })?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(|e| {
        CompareError::IoError(e)
    })?;

    /* Create app and run */
    let mut app = App::new(data1, data2, path1.to_path_buf(), path2.to_path_buf(), start_slot, end_slot, data_comp);
    let res = run_app(&mut terminal, &mut app);

    /* Restore terminal */
    disable_raw_mode().map_err(|e| {
        CompareError::IoError(e)
    })?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen
    )
    .map_err(|e| {
        CompareError::IoError(e)
    })?;
    terminal.show_cursor().map_err(|e| {
        CompareError::IoError(e)
    })?;

    res
}

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> Result<(), CompareError> {
    loop {
        terminal.draw(|f| ui(f, app)).map_err(|e| {
            CompareError::IoError(io::Error::new(io::ErrorKind::Other, e.to_string()))
        })?;

        /* Block for the first event */
        let first_event = event::read().map_err(|e| {
            CompareError::IoError(e)
        })?;

        /* Collect this event and drain any pending events to avoid input lag.
           This prevents scroll buffering where touchpad/SSH input queues up
           many key events faster than we can redraw. */
        let mut events = vec![first_event];
        while event::poll(Duration::ZERO).unwrap_or(false) {
            if let Ok(ev) = event::read() {
                events.push(ev);
            }
        }

        /* Coalesce directional events: count net Up/Down movement */
        let mut up_count: i32 = 0;
        let mut down_count: i32 = 0;
        let mut other_keys: Vec<(KeyCode, event::KeyModifiers)> = Vec::new();

        for ev in events {
            if let Event::Key(key) = ev {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Up => up_count += 1,
                        KeyCode::Down => down_count += 1,
                        code => other_keys.push((code, key.modifiers)),
                    }
                }
            }
        }

        /* Apply net directional movement (coalesced) */
        let net_move = down_count - up_count;
        if net_move > 0 {
            for _ in 0..net_move {
                app.handle_key(KeyCode::Down, event::KeyModifiers::NONE);
            }
        } else if net_move < 0 {
            for _ in 0..(-net_move) {
                app.handle_key(KeyCode::Up, event::KeyModifiers::NONE);
            }
        }

        /* Process non-directional keys */
        for (code, modifiers) in other_keys {
            match code {
                KeyCode::Char('c') if modifiers.contains(event::KeyModifiers::CONTROL) => {
                    return Ok(());
                }
                _ => app.handle_key(code, modifiers),
            }
        }

        if app.should_quit {
            return Ok(());
        }
    }
}

