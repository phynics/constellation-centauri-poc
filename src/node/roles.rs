/// Node capabilities as a bitfield.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities(pub u16);

impl Capabilities {
    pub const ROUTE: u16 = 0b0000_0001;
    pub const STORE: u16 = 0b0000_0010;
    pub const BRIDGE: u16 = 0b0000_0100;
    pub const APPLICATION: u16 = 0b0000_1000;
    pub const LOW_ENERGY: u16 = 0b0001_0000;
    pub const MOBILE: u16 = 0b0010_0000;

    pub const fn new(bits: u16) -> Self {
        Self(bits)
    }

    pub const fn contains(&self, flag: u16) -> bool {
        self.0 & flag != 0
    }

    pub const fn is_knot(&self) -> bool {
        self.0 & Self::ROUTE != 0
    }

    pub const fn is_low_energy(&self) -> bool {
        self.0 & Self::LOW_ENERGY != 0
    }

    pub fn to_bytes(&self) -> [u8; 2] {
        self.0.to_le_bytes()
    }

    pub fn from_bytes(bytes: [u8; 2]) -> Self {
        Self(u16::from_le_bytes(bytes))
    }
}
