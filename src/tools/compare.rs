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
use std::collections::{HashSet, VecDeque};
use std::io;
use std::path::{Path, PathBuf};

/// Navigation level in the scanner
#[derive(Debug, Clone, PartialEq)]
enum ViewLevel {
    SlotLevel,
    AccountLevel { slot: u32 },
    UpdateLevel { slot: u32, account: [u8; 32] },
}

/// Which source a slot/account comes from
#[derive(Debug, Clone, Copy, PartialEq)]
enum Source {
    Both,
    SourceOne,
    SourceTwo,
}

/// Cached slot information
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

/// Cached account information for a slot
#[derive(Debug, Clone)]
struct AccountInfo {
    account: [u8; 32],
    update_count_1: usize,
    update_count_2: usize,
    source: Source,
    has_diff: bool,
}

/// Cached account update comparison
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
    has_diff: bool,
}

/// Circular buffer for caching
struct CircularCache<T> {
    capacity: usize,
    items: VecDeque<(String, T)>, /* (key, value) */
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
        /* Remove if already exists */
        self.items.retain(|(k, _)| k != &key);

        /* Add new item */
        self.items.push_front((key, value));

        /* Trim if over capacity */
        if self.items.len() > self.capacity {
            self.items.pop_back();
        }
    }
}

/// Application state
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

    /* Saved selection positions for navigation */
    saved_slot_selection: Option<usize>,
    saved_account_selection: Option<usize>,

    /* Circular caches */
    account_cache: CircularCache<Vec<AccountInfo>>,
    update_cache: CircularCache<Vec<UpdateComparison>>,
    data_cache: CircularCache<(Option<Vec<u8>>, Option<Vec<u8>>)>,

    current_cached_slot: Option<u32>,
    current_cached_account: Option<[u8; 32]>,

    /* Options */
    data_comp: bool, /* Whether to compare actual account data bytes */
}

/// Extract display name from a path (file name or folder name)
fn get_display_name(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| path.display().to_string())
}

impl App {
    fn new(data1: SolcapData, data2: SolcapData, path1: PathBuf, path2: PathBuf, start_slot: Option<u32>, end_slot: Option<u32>, data_comp: bool) -> Self {
        /* Get display names from paths */
        let name1 = get_display_name(&path1);
        let name2 = get_display_name(&path2);

        /* Build slot info list */
        let mut slot_set = HashSet::new();

        /* Collect all slots from both sources - include slots with account updates */
        for slot in data1.slot_account_updates_final.keys() {
            slot_set.insert(*slot);
        }
        for slot in data2.slot_account_updates_final.keys() {
            slot_set.insert(*slot);
        }

        /* Also include slots that have bank preimages (even if no account updates) */
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

        /* Convert to sorted vec with metadata, filtering by slot range */
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
                (false, false) => Source::Both, /* Shouldn't happen */
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
        }
    }

    fn handle_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('b') | KeyCode::Char('q') => self.go_back(),
            KeyCode::Up => self.move_up(),
            KeyCode::Down => self.move_down(),
            KeyCode::Left => self.page_up(),
            KeyCode::Right => self.page_down(),
            KeyCode::Enter => self.drill_down(),
            _ => {}
        }
    }

    fn go_back(&mut self) {
        match &self.level {
            ViewLevel::SlotLevel => {
                /* At top level, do nothing (or could quit) */
            }
            ViewLevel::AccountLevel { .. } => {
                self.level = ViewLevel::SlotLevel;
                self.hex_scroll_offset = 0;
                /* Restore slot selection */
                if let Some(idx) = self.saved_slot_selection {
                    self.list_state.select(Some(idx));
                }
            }
            ViewLevel::UpdateLevel { slot, .. } => {
                self.level = ViewLevel::AccountLevel { slot: *slot };
                self.hex_scroll_offset = 0;
                /* Restore account selection */
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
                        /* Save slot selection before drilling down */
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
                            /* Save account selection before drilling down */
                            self.saved_account_selection = Some(idx);
                            let account = accounts[idx].account;
                            self.cache_updates(slot, &account);
                            self.level = ViewLevel::UpdateLevel { slot, account };
                            self.hex_scroll_offset = 0;
                        }
                    }
                }
            }
            ViewLevel::UpdateLevel { .. } => {
                /* At deepest level, nothing to drill down to */
            }
        }
    }

    fn cache_accounts(&mut self, slot: u32) {
        let cache_key = format!("slot_{}", slot);

        /* Check if already cached */
        if self.account_cache.get(&cache_key).is_some() {
            return;
        }

        let mut account_set = HashSet::new();

        /* Collect accounts from both sources */
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

        /* Convert to sorted vec with metadata */
        let mut accounts: Vec<AccountInfo> = account_set.into_iter().map(|account| {
            let updates1 = self.data1.get_account_updates_final(slot)
                .and_then(|u| u.get(&account));
            let updates2 = self.data2.get_account_updates_final(slot)
                .and_then(|u| u.get(&account));

            let update_count_1 = self.data1.get_account_updates_all(slot)
                .map(|u| u.iter().filter(|up| &up.key.key == &account).count())
                .unwrap_or(0);
            let update_count_2 = self.data2.get_account_updates_all(slot)
                .map(|u| u.iter().filter(|up| &up.key.key == &account).count())
                .unwrap_or(0);

            let source = match (updates1.is_some(), updates2.is_some()) {
                (true, true) => Source::Both,
                (true, false) => Source::SourceOne,
                (false, true) => Source::SourceTwo,
                (false, false) => Source::Both, /* Shouldn't happen */
            };

            /* Check if there's a difference in final values */
            let has_diff = match (updates1, updates2) {
                (Some(u1), Some(u2)) => {
                    /* Check metadata differences */
                    let metadata_diff = u1.meta.lamports != u2.meta.lamports ||
                        u1.data_size != u2.data_size ||
                        u1.meta.owner.key != u2.meta.owner.key ||
                        u1.meta.executable != u2.meta.executable;

                    /* If metadata matches and data_comp is enabled, check actual account data bytes */
                    if !metadata_diff && self.data_comp && u1.data_size > 0 && u2.data_size > 0 && u1.data_size == u2.data_size {
                        /* Compare account data bytes */
                        let data1 = if u1.file.is_some() {
                            read_account_data_from_bhd(u1).ok()
                        } else {
                            read_account_data(&self.path1, u1).ok()
                        };
                        let data2 = if u2.file.is_some() {
                            read_account_data_from_bhd(u2).ok()
                        } else {
                            read_account_data(&self.path2, u2).ok()
                        };

                        match (data1, data2) {
                            (Some(d1), Some(d2)) => d1 != d2,
                            _ => false, /* If we can't read data, assume no diff (metadata already matched) */
                        }
                    } else {
                        metadata_diff
                    }
                }
                _ => source != Source::Both,
            };

            AccountInfo {
                account,
                update_count_1,
                update_count_2,
                source,
                has_diff,
            }
        }).collect();

        /* Sort: differences first, then by base58 address */
        accounts.sort_by(|a, b| {
            /* First sort by has_diff (true comes before false) */
            match (a.has_diff, b.has_diff) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                /* If both have same diff status, sort by base58 address */
                _ => {
                    let a_str = bs58::encode(&a.account).into_string();
                    let b_str = bs58::encode(&b.account).into_string();
                    a_str.cmp(&b_str)
                }
            }
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

        /* Check for differences including account data bytes if data_comp is enabled */
        let has_diff = match (update1, update2) {
            (Some(u1), Some(u2)) => {
                /* Check metadata differences */
                let metadata_diff = u1.meta.lamports != u2.meta.lamports ||
                    u1.data_size != u2.data_size ||
                    u1.meta.owner.key != u2.meta.owner.key ||
                    u1.meta.executable != u2.meta.executable;

                /* If metadata matches and data_comp is enabled, check actual account data bytes */
                if !metadata_diff && self.data_comp && u1.data_size > 0 && u2.data_size > 0 && u1.data_size == u2.data_size {
                    /* Compare account data bytes */
                    let data1 = if u1.file.is_some() {
                        read_account_data_from_bhd(u1).ok()
                    } else {
                        read_account_data(&self.path1, u1).ok()
                    };
                    let data2 = if u2.file.is_some() {
                        read_account_data_from_bhd(u2).ok()
                    } else {
                        read_account_data(&self.path2, u2).ok()
                    };

                    match (data1, data2) {
                        (Some(d1), Some(d2)) => d1 != d2,
                        _ => false, /* If we can't read data, assume no diff (metadata already matched) */
                    }
                } else {
                    metadata_diff
                }
            }
            (Some(_), None) | (None, Some(_)) => true,
            (None, None) => false,
        };

        let comparison = UpdateComparison {
            txn_idx_1: update1.and_then(|u| u.txn_idx),
            txn_idx_2: update2.and_then(|u| u.txn_idx),
            lamports_1: update1.map(|u| u.meta.lamports),
            lamports_2: update2.map(|u| u.meta.lamports),
            owner_1: update1.map(|u| u.meta.owner.key),
            owner_2: update2.map(|u| u.meta.owner.key),
            data_size_1: update1.map(|u| u.data_size),
            data_size_2: update2.map(|u| u.data_size),
            has_diff,
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
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(f.size());

    /* Header based on current level */
    let header = match &app.level {
        ViewLevel::SlotLevel => {
            let text = format!(
                "Solcap Comparison - Total Slots: {} | Press ↑/↓ to navigate, ←/→ for page jump, Enter to drill down, 'b' to go back, Ctrl+C to quit",
                app.slots.len()
            );
            Paragraph::new(text)
                .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
                .block(Block::default().borders(Borders::ALL).title("Comparison"))
        }
        ViewLevel::AccountLevel { slot } => {
            let text = format!(
                "Slot {} - Accounts View | Press ↑/↓ to navigate, ←/→ for page jump, Enter to view updates, 'b' to go back",
                slot
            );
            Paragraph::new(text)
                .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
                .block(Block::default().borders(Borders::ALL).title("Account Comparison"))
        }
        ViewLevel::UpdateLevel { slot, account } => {
            let text = format!(
                "Slot {} | Account: {} | Press ↑/↓ to scroll, ←/→ for page jump, 'b' to go back",
                slot,
                bs58::encode(&account[..]).into_string()
            );
            Paragraph::new(text)
                .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
                .block(Block::default().borders(Borders::ALL).title("Update Comparison"))
        }
    };
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
}

fn render_slot_level(f: &mut Frame, app: &mut App, area: Rect) {
    app.page_size = (area.height.saturating_sub(5)) as usize;

    /* Truncate names to fit in column headers */
    let name1_short = if app.name1.len() > 20 { &app.name1[..20] } else { &app.name1 };
    let name2_short = if app.name2.len() > 20 { &app.name2[..20] } else { &app.name2 };
    let header_text = format!(
        "SLOT             │ BANK HASH ({:20})             │ BANK HASH ({:20})             │ ACCTS({}) │ ACCTS({})",
        name1_short, name2_short, name1_short, name2_short
    );

    let items: Vec<ListItem> = app.slots.iter().map(|slot_info| {
        let bank_hash_1 = slot_info.bank_hash_1
            .map(|h| bs58::encode(&h).into_string())
            .unwrap_or_else(|| "N/A".to_string());
        let bank_hash_2 = slot_info.bank_hash_2
            .map(|h| bs58::encode(&h).into_string())
            .unwrap_or_else(|| "N/A".to_string());

        let slot_str = format!("{:>12}", slot_info.slot);
        let acct_1_str = format!("{:>6}", slot_info.account_count_1);
        let acct_2_str = format!("{:>6}", slot_info.account_count_2);

        /* Color based on source and differences */
        let (slot_color, hash_color) = if slot_info.has_diff {
            (Color::Red, Color::Red)
        } else if slot_info.source != Source::Both {
            (Color::DarkGray, Color::DarkGray)
        } else {
            (Color::White, Color::Green)
        };

        let content = vec![
            Span::styled(slot_str, Style::default().fg(slot_color)),
            Span::raw("  │ "),
            Span::styled(format!("{:44}", bank_hash_1), Style::default().fg(if slot_info.bank_hash_1.is_some() { hash_color } else { Color::DarkGray })),
            Span::raw(" │ "),
            Span::styled(format!("{:44}", bank_hash_2), Style::default().fg(if slot_info.bank_hash_2.is_some() { hash_color } else { Color::DarkGray })),
            Span::raw(" │ "),
            Span::styled(acct_1_str, Style::default().fg(if slot_info.account_count_1 > 0 { Color::Cyan } else { Color::DarkGray })),
            Span::raw(" │ "),
            Span::styled(acct_2_str, Style::default().fg(if slot_info.account_count_2 > 0 { Color::Cyan } else { Color::DarkGray })),
        ];

        ListItem::new(Line::from(content))
    }).collect();

    let list = List::new(items)
        .block(Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(
                header_text.clone(),
                Style::default().add_modifier(Modifier::BOLD)
            )))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    f.render_stateful_widget(list, area, &mut app.list_state);
}

fn render_account_level(f: &mut Frame, app: &mut App, slot: u32, area: Rect) {
    /* Ensure accounts are cached */
    if app.current_cached_slot != Some(slot) {
        app.cache_accounts(slot);
    }

    app.page_size = (area.height.saturating_sub(3)) as usize;

    /* Truncate names to fit in column headers */
    let name1_short = if app.name1.len() > 10 { &app.name1[..10] } else { &app.name1 };
    let name2_short = if app.name2.len() > 10 { &app.name2[..10] } else { &app.name2 };
    let header_text = format!(
        "ACCOUNT                                       │ ({}) │ ({})",
        name1_short, name2_short
    );

    let cache_key = format!("slot_{}", slot);
    let items: Vec<ListItem> = if let Some(accounts) = app.account_cache.get(&cache_key) {
        accounts.iter().map(|acc_info| {
            let account_str = bs58::encode(&acc_info.account).into_string();
            let upd_1_str = format!("{:>6}", acc_info.update_count_1);
            let upd_2_str = format!("{:>6}", acc_info.update_count_2);

            let (account_color, count_color) = if acc_info.has_diff {
                (Color::Red, Color::Red)
            } else if acc_info.source != Source::Both {
                (Color::DarkGray, Color::DarkGray)
            } else {
                (Color::White, Color::Cyan)
            };

            let content = vec![
                Span::styled(format!("{:44}", account_str), Style::default().fg(account_color)),
                Span::raw(" │ "),
                Span::styled(upd_1_str, Style::default().fg(if acc_info.update_count_1 > 0 { count_color } else { Color::DarkGray })),
                Span::raw(" │ "),
                Span::styled(upd_2_str, Style::default().fg(if acc_info.update_count_2 > 0 { count_color } else { Color::DarkGray })),
            ];

            ListItem::new(Line::from(content))
        }).collect()
    } else {
        vec![ListItem::new(Line::from("Loading..."))]
    };

    let list = List::new(items)
        .block(Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(
                header_text.clone(),
                Style::default().add_modifier(Modifier::BOLD)
            )))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    f.render_stateful_widget(list, area, &mut app.list_state);
}

fn render_update_level(f: &mut Frame, app: &mut App, slot: u32, account: &[u8; 32], area: Rect) {
    /* Split into info section and data comparison */
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(10), Constraint::Min(0)])
        .split(area);

    /* Get cached update comparison */
    let cache_key = format!("slot_{}_account_{}", slot, bs58::encode(account).into_string());

    let update_info = if let Some(comparisons) = app.update_cache.get(&cache_key) {
        if let Some(comp) = comparisons.first() {
            let mut lines = vec![
                Line::from(Span::styled("Comparison of Final Account States", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
                Line::from(""),
            ];

            /* Transaction indices */
            let txn_color = if comp.has_diff { Color::Red } else { Color::Green };
            lines.push(Line::from(vec![
                Span::raw("Transaction Index:  "),
                Span::styled(
                    format!("{:>16}", comp.txn_idx_1.map(|t| t.to_string()).unwrap_or_else(|| "N/A".to_string())),
                    Style::default().fg(if comp.txn_idx_1.is_some() { txn_color } else { Color::DarkGray })
                ),
                Span::raw("  │  "),
                Span::styled(
                    format!("{:>16}", comp.txn_idx_2.map(|t| t.to_string()).unwrap_or_else(|| "N/A".to_string())),
                    Style::default().fg(if comp.txn_idx_2.is_some() { txn_color } else { Color::DarkGray })
                ),
            ]));

            /* Lamports */
            let lamp_diff = match (comp.lamports_1, comp.lamports_2) {
                (Some(l1), Some(l2)) => l1 != l2,
                _ => true,
            };
            lines.push(Line::from(vec![
                Span::raw("Lamports:           "),
                Span::styled(
                    format!("{:>16}", comp.lamports_1.map(|l| l.to_string()).unwrap_or_else(|| "N/A".to_string())),
                    Style::default().fg(if lamp_diff && comp.lamports_1.is_some() { Color::Red } else if comp.lamports_1.is_some() { Color::Green } else { Color::DarkGray })
                ),
                Span::raw("  │  "),
                Span::styled(
                    format!("{:>16}", comp.lamports_2.map(|l| l.to_string()).unwrap_or_else(|| "N/A".to_string())),
                    Style::default().fg(if lamp_diff && comp.lamports_2.is_some() { Color::Red } else if comp.lamports_2.is_some() { Color::Green } else { Color::DarkGray })
                ),
            ]));

            /* Owner */
            let owner_diff = match (comp.owner_1, comp.owner_2) {
                (Some(o1), Some(o2)) => o1 != o2,
                _ => true,
            };
            lines.push(Line::from(vec![
                Span::raw("Owner:              "),
                Span::styled(
                    format!("{:44}", comp.owner_1.map(|o| bs58::encode(&o).into_string()).unwrap_or_else(|| "N/A".to_string())),
                    Style::default().fg(if owner_diff && comp.owner_1.is_some() { Color::Red } else if comp.owner_1.is_some() { Color::Cyan } else { Color::DarkGray })
                ),
                Span::raw("  │  "),
                Span::styled(
                    format!("{:44}", comp.owner_2.map(|o| bs58::encode(&o).into_string()).unwrap_or_else(|| "N/A".to_string())),
                    Style::default().fg(if owner_diff && comp.owner_2.is_some() { Color::Red } else if comp.owner_2.is_some() { Color::Cyan } else { Color::DarkGray })
                ),
            ]));

            /* Data size */
            let data_diff = match (comp.data_size_1, comp.data_size_2) {
                (Some(d1), Some(d2)) => d1 != d2,
                _ => true,
            };
            lines.push(Line::from(vec![
                Span::raw("Data Size:          "),
                Span::styled(
                    format!("{:>16}", comp.data_size_1.map(|d| format!("{} bytes", d)).unwrap_or_else(|| "N/A".to_string())),
                    Style::default().fg(if data_diff && comp.data_size_1.is_some() { Color::Red } else if comp.data_size_1.is_some() { Color::Magenta } else { Color::DarkGray })
                ),
                Span::raw("  │  "),
                Span::styled(
                    format!("{:>16}", comp.data_size_2.map(|d| format!("{} bytes", d)).unwrap_or_else(|| "N/A".to_string())),
                    Style::default().fg(if data_diff && comp.data_size_2.is_some() { Color::Red } else if comp.data_size_2.is_some() { Color::Magenta } else { Color::DarkGray })
                ),
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

    /* Render hex dump comparison */
    render_hex_dump_comparison(f, app, slot, account, chunks[1]);
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

        if let Event::Key(key) = event::read().map_err(|e| {
            CompareError::IoError(e)
        })? {
            if key.kind == KeyEventKind::Press {
                match key.code {
                    KeyCode::Char('c') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                        return Ok(());
                    }
                    code => app.handle_key(code),
                }
            }
        }

        if app.should_quit {
            return Ok(());
        }
    }
}

