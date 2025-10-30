use indicatif::{ProgressBar, ProgressStyle};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// A multithreaded spinner that displays progress without blocking the main thread
pub struct Spinner {
    should_stop: Arc<AtomicBool>,
    progress_bar: Arc<Mutex<ProgressBar>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Spinner {
    /// Create and start a new spinner with a given message
    pub fn new(message: &str) -> Self {
        let should_stop = Arc::new(AtomicBool::new(false));
        let should_stop_clone = Arc::clone(&should_stop);
        let message = message.to_string();

        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
                .template("{spinner:.white} {msg}")
                .unwrap(),
        );
        pb.set_message(message);
        pb.enable_steady_tick(Duration::from_millis(80));

        let progress_bar = Arc::new(Mutex::new(pb));

        let handle = thread::spawn(move || {
            while !should_stop_clone.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(100));
            }
        });

        Spinner {
            should_stop,
            progress_bar,
            handle: Some(handle),
        }
    }

     /* Stop the spinner, clear it, and print follow-up lines
        The original message line stays (without spinner), and
        additional lines are printed below
        
        Example:
        ```
        let spinner = Spinner::new("Loading data");
        // Shows: "Loading data ⠋"
        // ... do work ...
        spinner.finish_with_lines(vec!["  Complete!", "  Done in 5s"]);
        // Shows: "Loading data"
        //        "  Complete!"
        //        "  Done in 5s"
        ```
    */
    pub fn finish_with_lines(mut self, follow_up_lines: Vec<&str>) {
        self.should_stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        if let Ok(pb) = self.progress_bar.lock() {
            // Get the original message to reprint it with a checkmark
            let message = pb.message();
            pb.finish_and_clear();
            // Print original message with green checkmark instead of spinner
            println!("✓ {}", message);
            // Print follow-up lines
            for line in follow_up_lines {
                println!("{}", line);
            }
        }
    }

    /// Stop the spinner and clear the entire line
    pub fn finish_and_clear(mut self) {
        self.should_stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        if let Ok(pb) = self.progress_bar.lock() {
            pb.finish_and_clear();
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.should_stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        if let Ok(pb) = self.progress_bar.lock() {
            pb.finish_and_clear();
        }
    }
}

