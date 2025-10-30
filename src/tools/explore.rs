use crate::reader::{read_solcap_file, read_account_data, SolcapData, SolcapReaderError, AccountUpdate};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
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
use std::io;
use std::path::{Path, PathBuf};

/// Navigation level in the explorer
#[derive(Debug, Clone, PartialEq)]
enum ViewLevel {
    FileLevel,
    SlotLevel { slot: u32 },
    AccountLevel { slot: u32, account: [u8; 32] },
    UpdateLevel { slot: u32, account: [u8; 32], txn_idx: u64 },
}

/// Application state
struct App {
    data: SolcapData,
    level: ViewLevel,
    file_path: PathBuf,
    file_list_state: ListState,
    slot_list_state: ListState,
    account_list_state: ListState,
    slots: Vec<u32>,
    should_quit: bool,
    // Cached data for current view
    cached_slot_accounts: Vec<([u8; 32], usize)>, // (account, update_count)
    cached_account_updates: Vec<AccountUpdate>,
    current_cached_slot: Option<u32>,
    current_cached_account: Option<[u8; 32]>,
    // Page size for navigation
    page_size: usize,
    // Hex dump scrolling for UpdateLevel
    hex_scroll_offset: usize,
    // Cached account data for current update
    cached_account_data: Option<Vec<u8>>,
    current_cached_txn_idx: Option<u64>,
}

impl App {
    fn new(data: SolcapData, file_path: PathBuf) -> Self {
        // Get sorted list of slots
        let mut slots: Vec<u32> = data
            .bank_preimages
            .iter()
            .enumerate()
            .filter_map(|(idx, p)| {
                if p.is_some() {
                    Some(data.lowest_slot + idx as u32)
                } else {
                    None
                }
            })
            .collect();
        
        // Also include slots with account updates
        for slot in data.slot_account_updates_final.keys() {
            if !slots.contains(slot) {
                slots.push(*slot);
            }
        }
        slots.sort();

        let mut file_list_state = ListState::default();
        if !slots.is_empty() {
            file_list_state.select(Some(0));
        }

        App {
            data,
            level: ViewLevel::FileLevel,
            file_path,
            file_list_state,
            slot_list_state: ListState::default(),
            account_list_state: ListState::default(),
            slots,
            should_quit: false,
            cached_slot_accounts: Vec::new(),
            cached_account_updates: Vec::new(),
            current_cached_slot: None,
            current_cached_account: None,
            page_size: 20, // Default page size, will be updated based on terminal size
            hex_scroll_offset: 0,
            cached_account_data: None,
            current_cached_txn_idx: None,
        }
    }

    fn handle_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('b') => self.go_back(),
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
            ViewLevel::FileLevel => {
                // Already at top level, do nothing
            }
            ViewLevel::SlotLevel { .. } => {
                self.level = ViewLevel::FileLevel;
            }
            ViewLevel::AccountLevel { slot, .. } => {
                self.level = ViewLevel::SlotLevel { slot: *slot };
            }
            ViewLevel::UpdateLevel { slot, account, .. } => {
                self.level = ViewLevel::AccountLevel { slot: *slot, account: *account };
                self.hex_scroll_offset = 0; // Reset scroll when going back
            }
        }
    }

    fn move_up(&mut self) {
        match &self.level {
            ViewLevel::FileLevel => {
                let i = match self.file_list_state.selected() {
                    Some(i) => {
                        if i > 0 {
                            i - 1
                        } else {
                            i
                        }
                    }
                    None => 0,
                };
                self.file_list_state.select(Some(i));
            }
            ViewLevel::SlotLevel { .. } => {
                let i = match self.slot_list_state.selected() {
                    Some(i) => {
                        if i > 0 {
                            i - 1
                        } else {
                            i
                        }
                    }
                    None => 0,
                };
                self.slot_list_state.select(Some(i));
            }
            ViewLevel::AccountLevel { .. } => {
                let i = match self.account_list_state.selected() {
                    Some(i) => {
                        if i > 0 {
                            i - 1
                        } else {
                            i
                        }
                    }
                    None => 0,
                };
                self.account_list_state.select(Some(i));
            }
            ViewLevel::UpdateLevel { .. } => {
                // Scroll up in hex dump
                self.hex_scroll_offset = self.hex_scroll_offset.saturating_sub(1);
            }
        }
    }

    fn move_down(&mut self) {
        match &self.level {
            ViewLevel::FileLevel => {
                let i = match self.file_list_state.selected() {
                    Some(i) => {
                        if i < self.slots.len().saturating_sub(1) {
                            i + 1
                        } else {
                            i
                        }
                    }
                    None => 0,
                };
                self.file_list_state.select(Some(i));
            }
            ViewLevel::SlotLevel { .. } => {
                let i = match self.slot_list_state.selected() {
                    Some(i) => {
                        if i < self.cached_slot_accounts.len().saturating_sub(1) {
                            i + 1
                        } else {
                            i
                        }
                    }
                    None => 0,
                };
                self.slot_list_state.select(Some(i));
            }
            ViewLevel::AccountLevel { .. } => {
                let i = match self.account_list_state.selected() {
                    Some(i) => {
                        if i < self.cached_account_updates.len().saturating_sub(1) {
                            i + 1
                        } else {
                            i
                        }
                    }
                    None => 0,
                };
                self.account_list_state.select(Some(i));
            }
            ViewLevel::UpdateLevel { .. } => {
                // Scroll down in hex dump (will be clamped in render function)
                self.hex_scroll_offset += 1;
            }
        }
    }

    fn page_up(&mut self) {
        match &self.level {
            ViewLevel::FileLevel => {
                let i = match self.file_list_state.selected() {
                    Some(i) => i.saturating_sub(self.page_size),
                    None => 0,
                };
                self.file_list_state.select(Some(i));
            }
            ViewLevel::SlotLevel { .. } => {
                let i = match self.slot_list_state.selected() {
                    Some(i) => i.saturating_sub(self.page_size),
                    None => 0,
                };
                self.slot_list_state.select(Some(i));
            }
            ViewLevel::AccountLevel { .. } => {
                let i = match self.account_list_state.selected() {
                    Some(i) => i.saturating_sub(self.page_size),
                    None => 0,
                };
                self.account_list_state.select(Some(i));
            }
            ViewLevel::UpdateLevel { .. } => {
                // Page up in hex dump
                self.hex_scroll_offset = self.hex_scroll_offset.saturating_sub(self.page_size);
            }
        }
    }

    fn page_down(&mut self) {
        match &self.level {
            ViewLevel::FileLevel => {
                let i = match self.file_list_state.selected() {
                    Some(i) => {
                        let new_i = i + self.page_size;
                        if new_i < self.slots.len() {
                            new_i
                        } else {
                            self.slots.len().saturating_sub(1)
                        }
                    }
                    None => 0,
                };
                self.file_list_state.select(Some(i));
            }
            ViewLevel::SlotLevel { .. } => {
                let i = match self.slot_list_state.selected() {
                    Some(i) => {
                        let new_i = i + self.page_size;
                        if new_i < self.cached_slot_accounts.len() {
                            new_i
                        } else {
                            self.cached_slot_accounts.len().saturating_sub(1)
                        }
                    }
                    None => 0,
                };
                self.slot_list_state.select(Some(i));
            }
            ViewLevel::AccountLevel { .. } => {
                let i = match self.account_list_state.selected() {
                    Some(i) => {
                        let new_i = i + self.page_size;
                        if new_i < self.cached_account_updates.len() {
                            new_i
                        } else {
                            self.cached_account_updates.len().saturating_sub(1)
                        }
                    }
                    None => 0,
                };
                self.account_list_state.select(Some(i));
            }
            ViewLevel::UpdateLevel { .. } => {
                // Page down in hex dump (will be clamped in render)
                self.hex_scroll_offset += self.page_size;
            }
        }
    }

    fn drill_down(&mut self) {
        match &self.level {
            ViewLevel::FileLevel => {
                if let Some(idx) = self.file_list_state.selected() {
                    if idx < self.slots.len() {
                        let slot = self.slots[idx];
                        self.cache_slot_accounts(slot);
                        self.level = ViewLevel::SlotLevel { slot };
                        self.slot_list_state.select(Some(0));
                    }
                }
            }
            ViewLevel::SlotLevel { slot } => {
                let slot = *slot; // Copy to avoid borrow issues
                if let Some(idx) = self.slot_list_state.selected() {
                    if idx < self.cached_slot_accounts.len() {
                        let account = self.cached_slot_accounts[idx].0;
                        self.cache_account_updates(slot, &account);
                        self.level = ViewLevel::AccountLevel {
                            slot,
                            account,
                        };
                        self.account_list_state.select(Some(0));
                    }
                }
            }
            ViewLevel::AccountLevel { slot, account } => {
                let slot = *slot;
                let account = *account;
                if let Some(idx) = self.account_list_state.selected() {
                    if idx < self.cached_account_updates.len() {
                        let txn_idx = self.cached_account_updates[idx].txn_idx;
                        self.cache_update_data(slot, &account, txn_idx);
                        self.level = ViewLevel::UpdateLevel {
                            slot,
                            account,
                            txn_idx,
                        };
                        self.hex_scroll_offset = 0;
                    }
                }
            }
            ViewLevel::UpdateLevel { .. } => {
                // At deepest level, nothing to drill down to
            }
        }
    }

    fn cache_slot_accounts(&mut self, slot: u32) {
        if self.current_cached_slot == Some(slot) {
            return; // Already cached
        }

        self.cached_slot_accounts.clear();
        
        if let Some(updates) = self.data.get_account_updates_final(slot) {
            let mut accounts: Vec<[u8; 32]> = updates.keys().copied().collect();
            accounts.sort();
            
            // Pre-compute update counts
            let all_updates = self.data.get_account_updates_all(slot);
            for account in accounts {
                let update_count = all_updates
                    .as_ref()
                    .map(|u| u.iter().filter(|up| &up.key.key == &account).count())
                    .unwrap_or(0);
                self.cached_slot_accounts.push((account, update_count));
            }
        }
        
        self.current_cached_slot = Some(slot);
    }

    fn cache_account_updates(&mut self, slot: u32, account: &[u8; 32]) {
        if self.current_cached_account == Some(*account) && self.current_cached_slot == Some(slot) {
            return; // Already cached
        }

        self.cached_account_updates.clear();
        
        if let Some(updates) = self.data.get_account_updates_all(slot) {
            for u in updates.iter().filter(|u| &u.key.key == account) {
                self.cached_account_updates.push(u.clone());
            }
        }
        
        self.current_cached_account = Some(*account);
    }
    
    fn cache_update_data(&mut self, slot: u32, account: &[u8; 32], txn_idx: u64) {
        // Check if already cached
        if self.current_cached_txn_idx == Some(txn_idx) 
            && self.current_cached_account == Some(*account)
            && self.current_cached_slot == Some(slot) {
            return;
        }
        
        // Find the specific account update
        if let Some(updates) = self.data.get_account_updates_all(slot) {
            for update in updates.iter() {
                if &update.key.key == account && update.txn_idx == txn_idx {
                    // Try to read the account data from the file
                    match read_account_data(&self.file_path, update) {
                        Ok(data) => {
                            self.cached_account_data = Some(data);
                            self.current_cached_txn_idx = Some(txn_idx);
                            return;
                        }
                        Err(e) => {
                            eprintln!("Failed to read account data: {:?}", e);
                            self.cached_account_data = None;
                            self.current_cached_txn_idx = Some(txn_idx);
                            return;
                        }
                    }
                }
            }
        }
        
        // If we get here, the update wasn't found
        self.cached_account_data = None;
        self.current_cached_txn_idx = Some(txn_idx);
    }

}

fn ui(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(f.size());

    // Header based on current level
    let header = match &app.level {
        ViewLevel::FileLevel => {
            let text = format!(
                "Solcap Explorer - Slots: {} - {} | Total Slots: {} | Press ↑/↓ to navigate, ←/→ for page jump, Enter to drill down, Ctrl+C to quit",
                app.data.lowest_slot, app.data.highest_slot, app.slots.len()
            );
            Paragraph::new(text)
                .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
                .block(Block::default().borders(Borders::ALL).title("File Info"))
        }
        ViewLevel::SlotLevel { slot } => {
            let preimage = app.data.get_bank_preimage(*slot);
            let text = if let Some(p) = preimage {
                let sig_cnt = p.signature_cnt;  // Copy packed field
                let bank_hash = bs58::encode(&p.bank_hash.hash).into_string();
                format!(
                    "Slot {} | Bank Hash: {} | Sig Count: {} | Press ↑/↓, ←/→ for page jump, Enter to view account, 'b' to go back",
                    slot,
                    bank_hash,
                    sig_cnt
                )
            } else {
                format!("Slot {} | Press 'b' to go back", slot)
            };
            Paragraph::new(text)
                .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
                .block(Block::default().borders(Borders::ALL).title("Slot Info"))
        }
        ViewLevel::AccountLevel { slot, account } => {
            let text = format!(
                "Slot {} | Account: {} | Press ↑/↓ to navigate, ←/→ for page jump, Enter to view update, 'b' to go back",
                slot,
                bs58::encode(&account[..]).into_string()
            );
            Paragraph::new(text)
                .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
                .block(Block::default().borders(Borders::ALL).title("Account Updates"))
        }
        ViewLevel::UpdateLevel { slot, account, txn_idx } => {
            let text = format!(
                "Slot {} | Account: {} | Txn {} | Press ↑/↓ to scroll, ←/→ for page jump, 'b' to go back",
                slot,
                bs58::encode(&account[..]).into_string(),
                txn_idx
            );
            Paragraph::new(text)
                .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
                .block(Block::default().borders(Borders::ALL).title("Account Update Detail"))
        }
    };
    f.render_widget(header, chunks[0]);

    // Main content based on level
    // Clone the level to avoid borrow checker issues
    let level = app.level.clone();
    match level {
        ViewLevel::FileLevel => render_file_level(f, app, chunks[1]),
        ViewLevel::SlotLevel { slot } => render_slot_level(f, app, slot, chunks[1]),
        ViewLevel::AccountLevel { slot, account } => {
            render_account_level(f, app, slot, &account, chunks[1])
        }
        ViewLevel::UpdateLevel { slot, account, txn_idx } => {
            render_update_level(f, app, slot, &account, txn_idx, chunks[1])
        }
    }
}

fn render_file_level(f: &mut Frame, app: &mut App, area: Rect) {
    // Update page size based on visible area (subtract header area and borders)
    app.page_size = (area.height.saturating_sub(5)) as usize;

    // Table header as the title
    let header_text = format!(
        "SLOT             │ BANK HASH                                    │ ACCOUNTS"
    );

    // Table rows
    let items: Vec<ListItem> = app
        .slots
        .iter()
        .map(|slot| {
            let preimage = app.data.get_bank_preimage(*slot);
            let bank_hash = if let Some(p) = preimage {
                bs58::encode(&p.bank_hash.hash).into_string()
            } else {
                "N/A".to_string()
            };
            let account_count = app
                .data
                .get_account_updates_final(*slot)
                .map(|u| u.len())
                .unwrap_or(0);

            let content = format!(
                "{:>12}  │ {}  │ {:>6}",
                slot, bank_hash, account_count
            );
            ListItem::new(Line::from(content))
        })
        .collect();

    let list = List::new(items)
        .block(Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(
                header_text,
                Style::default().add_modifier(Modifier::BOLD)
            )))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    f.render_stateful_widget(list, area, &mut app.file_list_state);
}

fn render_slot_level(f: &mut Frame, app: &mut App, slot: u32, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(0)])
        .split(area);

    // Bank preimage details
    if let Some(preimage) = app.data.get_bank_preimage(slot) {
        let preimage_text = vec![
            Line::from(vec![
                Span::raw("Bank Hash:        "),
                Span::styled(
                    bs58::encode(&preimage.bank_hash.hash).into_string(),
                    Style::default().fg(Color::Cyan),
                ),
            ]),
            Line::from(vec![
                Span::raw("Parent Bank Hash: "),
                Span::styled(
                    bs58::encode(&preimage.prev_bank_hash.hash).into_string(),
                    Style::default().fg(Color::Cyan),
                ),
            ]),
            Line::from(vec![
                Span::raw("Accts LT Hash:    "),
                Span::styled(
                    bs58::encode(&preimage.accounts_lt_hash_checksum.hash).into_string(),
                    Style::default().fg(Color::Cyan),
                ),
            ]),
            Line::from(vec![
                Span::raw("PoH Hash:         "),
                Span::styled(
                    bs58::encode(&preimage.poh_hash.hash).into_string(),
                    Style::default().fg(Color::Cyan),
                ),
            ]),
            Line::from(vec![
                Span::raw("Signature Count:  "),
                Span::styled(
                    {
                        let sig_cnt = preimage.signature_cnt;  // Copy packed field
                        sig_cnt.to_string()
                    },
                    Style::default().fg(Color::Green),
                ),
            ]),
        ];
        let preimage_widget = Paragraph::new(preimage_text)
            .block(Block::default().borders(Borders::ALL).title("Bank Preimage"));
        f.render_widget(preimage_widget, chunks[0]);
    }

    // Ensure accounts are cached
    if app.current_cached_slot != Some(slot) {
        app.cache_slot_accounts(slot);
    }

    // Update page size based on visible area
    app.page_size = (chunks[1].height.saturating_sub(3)) as usize;

    // Account list with header as title - use cached data
    let header_text = "ACCOUNT                                       │ UPDATES";
    let items: Vec<ListItem> = app.cached_slot_accounts
        .iter()
        .map(|(account, update_count)| {
            let content = format!(
                "{} │ {}",
                bs58::encode(account).into_string(),
                update_count
            );
            ListItem::new(Line::from(content))
        })
        .collect();

    let list = List::new(items)
        .block(Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(
                header_text,
                Style::default().add_modifier(Modifier::BOLD)
            )))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    f.render_stateful_widget(list, chunks[1], &mut app.slot_list_state);
}

fn render_account_level(f: &mut Frame, app: &mut App, slot: u32, account: &[u8; 32], area: Rect) {
    // Ensure updates are cached
    if app.current_cached_account != Some(*account) || app.current_cached_slot != Some(slot) {
        app.cache_account_updates(slot, account);
    }

    // Update page size based on visible area
    app.page_size = (area.height.saturating_sub(3)) as usize;

    // Table header as title
    let header_text = "TXN #    │     LAMPORTS     │     DATA SIZE";

    // Use cached updates
    let items: Vec<ListItem> = app.cached_account_updates
        .iter()
        .map(|update| {
            let lamports = update.meta.lamports;  // Copy packed field
            let content = format!(
                "{:>5} │ {:>16} │ {:>9} bytes",
                update.txn_idx, lamports, update.data_size
            );
            ListItem::new(Line::from(content))
        })
        .collect();

    let list = List::new(items)
        .block(Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(
                header_text,
                Style::default().add_modifier(Modifier::BOLD)
            )))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    f.render_stateful_widget(list, area, &mut app.account_list_state);
}

fn render_update_level(f: &mut Frame, app: &mut App, slot: u32, account: &[u8; 32], txn_idx: u64, area: Rect) {
    // Ensure update data is cached
    if app.current_cached_txn_idx != Some(txn_idx) 
        || app.current_cached_account != Some(*account)
        || app.current_cached_slot != Some(slot) {
        app.cache_update_data(slot, account, txn_idx);
    }
    
    // Split area: top for account info, bottom for hex dump
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(10), Constraint::Min(0)])
        .split(area);
    
    // Find the account update to display metadata
    let mut update_info = vec![
        Line::from(Span::styled("Account update not found", Style::default().fg(Color::Red)))
    ];
    
    if let Some(updates) = app.data.get_account_updates_all(slot) {
        for update in updates.iter() {
            if &update.key.key == account && update.txn_idx == txn_idx {
                // Copy packed fields to avoid unaligned reference
                let lamports = update.meta.lamports;
                let owner = update.meta.owner;
                let executable = update.meta.executable;
                
                let owner_str = bs58::encode(&owner.key).into_string();
                update_info = vec![
                    Line::from(vec![
                        Span::raw("Transaction Index: "),
                        Span::styled(
                            txn_idx.to_string(),
                            Style::default().fg(Color::Cyan),
                        ),
                    ]),
                    Line::from(vec![
                        Span::raw("Lamports:          "),
                        Span::styled(
                            format!("{}", lamports),
                            Style::default().fg(Color::Green),
                        ),
                    ]),
                    Line::from(vec![
                        Span::raw("Owner:             "),
                        Span::styled(
                            owner_str,
                            Style::default().fg(Color::Cyan),
                        ),
                    ]),
                    Line::from(vec![
                        Span::raw("Executable:        "),
                        Span::styled(
                            if executable != 0 { "Yes" } else { "No" },
                            Style::default().fg(if executable != 0 { Color::Yellow } else { Color::White }),
                        ),
                    ]),
                    Line::from(vec![
                        Span::raw("Data Size:         "),
                        Span::styled(
                            format!("{} bytes", update.data_size),
                            Style::default().fg(Color::Magenta),
                        ),
                    ]),
                    Line::from(vec![
                        Span::raw("Data Offset:       "),
                        Span::styled(
                            format!("0x{:X}", update.data_offset),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]),
                ];
                break;
            }
        }
    }
    
    let info_widget = Paragraph::new(update_info)
        .block(Block::default().borders(Borders::ALL).title("Account Update Info"));
    f.render_widget(info_widget, chunks[0]);
    
    // Hex dump rendering
    render_hex_dump(f, app, chunks[1]);
}

fn render_hex_dump(f: &mut Frame, app: &mut App, area: Rect) {
    let bytes_per_row = 16;
    let visible_rows = (area.height.saturating_sub(2)) as usize; // Subtract border
    
    app.page_size = visible_rows.saturating_sub(1); // Update page size for scrolling
    
    let lines = if let Some(data) = &app.cached_account_data {
        if data.is_empty() {
            vec![Line::from(Span::styled(
                "No account data (empty)",
                Style::default().fg(Color::DarkGray)
            ))]
        } else {
            let total_rows = (data.len() + bytes_per_row - 1) / bytes_per_row;
            
            // Clamp scroll offset
            if app.hex_scroll_offset >= total_rows {
                app.hex_scroll_offset = total_rows.saturating_sub(1);
            }
            
            let start_row = app.hex_scroll_offset;
            let end_row = (start_row + visible_rows).min(total_rows);
            
            let mut lines = Vec::new();
            
            for row in start_row..end_row {
                let offset = row * bytes_per_row;
                let row_end = (offset + bytes_per_row).min(data.len());
                let row_data = &data[offset..row_end];
                
                // Format: "00000000  48 65 6C 6C 6F 20 57 6F  72 6C 64 21 00 00 00 00"
                let mut hex_part = String::new();
                
                for (i, byte) in row_data.iter().enumerate() {
                    if i == 8 {
                        hex_part.push(' '); // Extra space in the middle for readability
                    }
                    hex_part.push_str(&format!("{:02X} ", byte));
                }
                
                let line_content = format!(
                    "{:08X}  {}",
                    offset,
                    hex_part.trim_end()
                );
                
                lines.push(Line::from(line_content));
            }
            
            // Add scroll indicator if there's more data
            if end_row < total_rows {
                lines.push(Line::from(Span::styled(
                    format!("... ({} more rows) ...", total_rows - end_row),
                    Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC)
                )));
            }
            
            lines
        }
    } else {
        vec![Line::from(Span::styled(
            "Failed to load account data",
            Style::default().fg(Color::Red)
        ))]
    };
    
    let hex_widget = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Account Data (Hex Dump)"));
    f.render_widget(hex_widget, area);
}

/// Run the interactive explorer
pub fn explore_solcap<P: AsRef<Path>>(file_path: P) -> Result<(), SolcapReaderError> {
    // Read the solcap file
    let file_path = file_path.as_ref();
    let data = read_solcap_file(file_path)?;

    // Setup terminal
    enable_raw_mode().map_err(|e| {
        SolcapReaderError::InvalidFormat(format!("Failed to enable raw mode: {}", e))
    })?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture).map_err(|e| {
        SolcapReaderError::InvalidFormat(format!("Failed to setup terminal: {}", e))
    })?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(|e| {
        SolcapReaderError::InvalidFormat(format!("Failed to create terminal: {}", e))
    })?;

    // Create app and run
    let mut app = App::new(data, file_path.to_path_buf());
    let res = run_app(&mut terminal, &mut app);

    // Restore terminal
    disable_raw_mode().map_err(|e| {
        SolcapReaderError::InvalidFormat(format!("Failed to disable raw mode: {}", e))
    })?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .map_err(|e| {
        SolcapReaderError::InvalidFormat(format!("Failed to restore terminal: {}", e))
    })?;
    terminal.show_cursor().map_err(|e| {
        SolcapReaderError::InvalidFormat(format!("Failed to show cursor: {}", e))
    })?;

    res
}

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> Result<(), SolcapReaderError> {
    loop {
        terminal.draw(|f| ui(f, app)).map_err(|e| {
            SolcapReaderError::InvalidFormat(format!("Failed to draw: {}", e))
        })?;

        if let Event::Key(key) = event::read().map_err(|e| {
            SolcapReaderError::InvalidFormat(format!("Failed to read event: {}", e))
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

