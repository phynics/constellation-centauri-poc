use heapless::Deque;
use crate::config::SEEN_MESSAGES_CAPACITY;

pub struct SeenMessages {
    ring: Deque<[u8; 8], SEEN_MESSAGES_CAPACITY>,
}

impl SeenMessages {
    pub const fn new() -> Self {
        Self {
            ring: Deque::new(),
        }
    }

    /// Returns `true` if the message was already seen. Inserts it if not.
    pub fn check_and_insert(&mut self, id: &[u8; 8]) -> bool {
        for existing in self.ring.iter() {
            if existing == id {
                return true;
            }
        }
        if self.ring.is_full() {
            let _ = self.ring.pop_front();
        }
        let _ = self.ring.push_back(*id);
        false
    }
}
