//! A thin `NorFlash` wrapper that adds a fixed base offset to all operations.
//!
//! Used to address the `constellation` data partition without changing the
//! storage API (which expects partition-relative offsets).

use embedded_storage::nor_flash::{NorFlash, ReadNorFlash};

/// NOR flash wrapper that translates partition-relative offsets to absolute
/// flash offsets by adding a fixed base.
pub struct PartitionedFlash<F> {
    pub inner: F,
    pub base: u32,
}

impl<F> embedded_storage::nor_flash::ErrorType for PartitionedFlash<F>
where
    F: embedded_storage::nor_flash::ErrorType,
{
    type Error = F::Error;
}

impl<F> ReadNorFlash for PartitionedFlash<F>
where
    F: ReadNorFlash,
{
    const READ_SIZE: usize = F::READ_SIZE;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.inner.read(self.base + offset, bytes)
    }

    fn capacity(&self) -> usize {
        self.inner.capacity() - self.base as usize
    }
}

impl<F> NorFlash for PartitionedFlash<F>
where
    F: NorFlash,
{
    const WRITE_SIZE: usize = F::WRITE_SIZE;
    const ERASE_SIZE: usize = F::ERASE_SIZE;

    fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        self.inner.erase(self.base + from, self.base + to)
    }

    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        self.inner.write(self.base + offset, bytes)
    }
}

impl<F> embedded_storage::nor_flash::MultiwriteNorFlash for PartitionedFlash<F> where
    F: embedded_storage::nor_flash::MultiwriteNorFlash
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::Infallible;

    const SECTOR_SIZE: usize = 4096;
    const TOTAL_SIZE: usize = SECTOR_SIZE * 4;
    const BASE: u32 = SECTOR_SIZE as u32 * 2; // partition starts at sector 2

    struct MockFlash {
        data: [u8; TOTAL_SIZE],
    }

    impl MockFlash {
        fn new() -> Self {
            Self {
                data: [0xFF; TOTAL_SIZE],
            }
        }
    }

    impl embedded_storage::nor_flash::ErrorType for MockFlash {
        type Error = Infallible;
    }

    impl ReadNorFlash for MockFlash {
        const READ_SIZE: usize = 1;

        fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
            let offset = offset as usize;
            bytes.copy_from_slice(&self.data[offset..offset + bytes.len()]);
            Ok(())
        }

        fn capacity(&self) -> usize {
            TOTAL_SIZE
        }
    }

    impl NorFlash for MockFlash {
        const WRITE_SIZE: usize = 1;
        const ERASE_SIZE: usize = SECTOR_SIZE;

        fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
            let from = from as usize;
            let to = to as usize;
            self.data[from..to].fill(0xFF);
            Ok(())
        }

        fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
            let offset = offset as usize;
            self.data[offset..offset + bytes.len()].copy_from_slice(bytes);
            Ok(())
        }
    }

    #[test]
    fn partitioned_flash_write_read_roundtrip() {
        let mut flash = PartitionedFlash {
            inner: MockFlash::new(),
            base: BASE,
        };
        let data = [0xAA, 0xBB, 0xCC, 0xDD];
        flash.write(0, &data).unwrap();

        let mut readback = [0u8; 4];
        flash.read(0, &mut readback).unwrap();
        assert_eq!(readback, data);
    }

    #[test]
    fn partitioned_flash_erases_partition_region() {
        let mut flash = PartitionedFlash {
            inner: MockFlash::new(),
            base: BASE,
        };
        flash.write(0, &[0x11; 8]).unwrap();
        flash.erase(0, SECTOR_SIZE as u32).unwrap();

        let mut readback = [0u8; 8];
        flash.read(0, &mut readback).unwrap();
        assert_eq!(readback, [0xFF; 8]);
    }

    #[test]
    fn partitioned_flash_address_translation() {
        let mut inner = MockFlash::new();
        // Write directly at the absolute offset that PartitionedFlash should target
        inner.write(BASE, &[0x42]).unwrap();

        let mut flash = PartitionedFlash { inner, base: BASE };
        let mut byte = [0u8; 1];
        flash.read(0, &mut byte).unwrap();
        assert_eq!(byte[0], 0x42);
    }

    #[test]
    fn partitioned_flash_capacity_excludes_base() {
        let flash = PartitionedFlash {
            inner: MockFlash::new(),
            base: BASE,
        };
        assert_eq!(flash.capacity(), TOTAL_SIZE - BASE as usize);
    }
}
