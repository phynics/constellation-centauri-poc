#![no_std]
#![no_main]

use embassy_executor::Spawner;
use esp_hal::{clock::CpuClock, timer::timg::TimerGroup};
use esp_wifi::ble::controller::BleConnector;
use trouble_host::prelude::ExternalController;
use {esp_alloc as _, esp_backtrace as _};

#[esp_hal_embassy::main]
async fn main(_s: Spawner) {
    esp_println::logger::init_logger_from_env();
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    esp_alloc::heap_allocator!(size: 72 * 1024);
    let timg0 = TimerGroup::new(peripherals.TIMG0);

    let mut rng = esp_hal::rng::Trng::new(peripherals.RNG, peripherals.ADC1);
    
    // create a SpiInterface from SpiDevice, a DC pin and a buffer
    let mut buffer = [0u8; 512];
    let di = SpiInterface::new(spi, dc, &mut buffer);
    // create the ILI9486 display driver in rgb666 color mode from the display interface and use a HW reset pin during init
    let mut display = Builder::new(ILI9486Rgb666, di)
        .reset_pin(rst)
        .init(&mut delay)?; // delay provider from your MCU
                            // clear the display to black
    display.clear(Rgb666::BLACK)?;
}
