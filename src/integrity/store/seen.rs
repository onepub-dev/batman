#[derive(Clone, Debug)]
pub struct SeenSet {
    bits: Vec<u8>,
}

impl SeenSet {
    pub fn new(records: u64) -> Self {
        let bytes = records.div_ceil(8) as usize;
        Self {
            bits: vec![0; bytes],
        }
    }

    pub fn mark(&mut self, ordinal: u64) {
        let byte = (ordinal / 8) as usize;
        let bit = (ordinal % 8) as u8;
        if let Some(slot) = self.bits.get_mut(byte) {
            *slot |= 1 << bit;
        }
    }

    pub fn contains(&self, ordinal: u64) -> bool {
        let byte = (ordinal / 8) as usize;
        let bit = (ordinal % 8) as u8;
        self.bits
            .get(byte)
            .map(|slot| (*slot & (1 << bit)) != 0)
            .unwrap_or(false)
    }
}
