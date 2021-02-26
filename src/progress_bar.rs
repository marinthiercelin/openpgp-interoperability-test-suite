//! Progress bar support
//!
//! This is a bit awkward, we cannot use indicatif's rayon support
//! directly, because we nest par_iter().

use std::sync::Mutex;
use std::sync::mpsc::{channel, Sender};
use std::thread;

pub struct ProgressBarHandle {
    ch: Mutex<Sender<Option<String>>>,
}

impl ProgressBarHandle {
    pub fn new(length: u64) -> ProgressBarHandle {
        let pb = indicatif::ProgressBar::new(length);
        let (sender, receiver) = channel();

        thread::spawn(move || {
            eprintln!("Running tests:");
            for msg in receiver.iter() {
                if let Some(m) = msg {
                    pb.println(format!("  - {}", m));
                } else {
                    pb.inc(1);
                }
            }
        });

        ProgressBarHandle {
            ch: Mutex::new(sender),
        }
    }

    pub fn start_test(&self, title: String) {
        self.ch.lock().unwrap().send(Some(title)).unwrap();
    }

    pub fn end_test(&self) {
        self.ch.lock().unwrap().send(None).unwrap();
    }
}
