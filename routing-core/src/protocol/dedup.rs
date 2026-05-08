use crate::config::SEEN_MESSAGES_CAPACITY;
use heapless::Deque;

pub struct SeenMessages {
    ring: Deque<[u8; 8], SEEN_MESSAGES_CAPACITY>,
}

impl SeenMessages {
    pub const fn new() -> Self {
        Self { ring: Deque::new() }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_insert_is_not_seen_but_second_is() {
        let mut seen = SeenMessages::new();
        let id = [0x11; 8];

        assert!(!seen.check_and_insert(&id));
        assert!(seen.check_and_insert(&id));
    }

    #[test]
    fn oldest_id_is_evicted_when_capacity_is_exceeded() {
        let mut seen = SeenMessages::new();
        let oldest = [0u8; 8];

        assert!(!seen.check_and_insert(&oldest));
        for i in 1..=SEEN_MESSAGES_CAPACITY {
            let id = [i as u8; 8];
            assert!(!seen.check_and_insert(&id));
        }

        assert!(!seen.check_and_insert(&oldest));
    }
}
