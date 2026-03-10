# Hardware Integration Tests

How do you know RAPTOR is working? well why not make some basic rudimentary tests with hardware so you can see? 
This ain't pretty, but it kinda works. 

## Quick start

```bash
# Check Glasgow is detected (no hardware target needed), you probably installed via venv so ensure you have that activated 
python3 test/hardware/test_glasgow_applets.py --dry-run

# Test UART only (Arduino with uart_target.ino)
python3 test/hardware/test_glasgow_applets.py --test uart

# Test I2C only (Arduino with i2c_target.ino)
python3 test/hardware/test_glasgow_applets.py --test i2c

# Test SWD (Pi Pico or STM32 Blue Pill)
python3 test/hardware/test_glasgow_applets.py --test swd

# Run everything
python3 test/hardware/test_glasgow_applets.py
```

## What you need

### For UART + I2C tests
- Arduino Uno, Nano, or any 3.3V/5V board
- Glasgow Interface Explorer
- Jumper wires

### For SWD test
- **Raspberry Pi Pico** (SWD pins labelled, no protection)
- OR STM32 Blue Pill (STM32F103, SWD via 4-pin header)
- OR Arduino Due (SAM3X8E, ARM Cortex-M3)

### For JTAG test
- Arduino Due, STM32, or any FPGA dev board with exposed JTAG

---

## Wiring

### UART (uart_target.ino)

```
Glasgow A0 (RX) → Arduino pin 3 (SoftwareSerial TX)
Glasgow A1 (TX) → Arduino pin 2 (SoftwareSerial RX)
Glasgow GND     → Arduino GND
Voltage: 3.3V (Glasgow output)
```

Upload `arduino_sketches/uart_target/uart_target.ino` first.

### I2C (i2c_target.ino)

```
Glasgow A0 (SCL) → Arduino A5 (SCL) + 4.7kΩ to 3.3V
Glasgow A1 (SDA) → Arduino A4 (SDA) + 4.7kΩ to 3.3V
Glasgow GND      → Arduino GND
```

Pull-ups must go to 3.3V (Glasgow VCC), not 5V.
Add 1kΩ series resistor if Arduino runs at 5V.

Upload `arduino_sketches/i2c_target/i2c_target.ino` first.

### SWD (Pi Pico)

```
Glasgow A0 (SWCLK) → Pico SWCLK (pin 3 on debug header)
Glasgow A1 (SWDIO) → Pico SWDIO (pin 2 on debug header)
Glasgow GND        → Pico GND   (pin 1 on debug header)
Voltage: 3.3V
```

No firmware needed — Pico SWD is always accessible.

### SPI Flash (memory-25x)

```
Glasgow A0 (CS#)   → Flash pin 1 (CS#)
Glasgow A1 (SCK)   → Flash pin 6 (SCK)
Glasgow A2 (COPI)  → Flash pin 5 (SI/IO0)
Glasgow A3 (CIPO)  → Flash pin 2 (SO/IO1)
Glasgow A4 (WP#)   → Flash pin 3 (WP#) + 10kΩ to 3.3V
Glasgow A5 (HOLD#) → Flash pin 7 (HOLD#) + 10kΩ to 3.3V
Glasgow 3.3V       → Flash pin 8 (VCC)
Glasgow GND        → Flash pin 4 (GND)
```

---

## Expected output

### UART
```
[UART] Testing uart applet...
  Flag check: --rx present in help output
  Capturing UART output (3s)...
  Captured 280 bytes, printable ratio: 98%
  PASS: Recognised UART output: 'U-Boot 2023.01 (RAPTOR Test Target)'
```

### I2C
```
[I2C] Testing i2c-controller applet...
  Flag check: --scl present in help output
  Scan output: address 0x50: present
  PASS: Found device at 0x50 (EEPROM target)
```

### SWD (Pi Pico)
```
[SWD] Testing swd-probe applet...
  Flag check: --swclk and dump-memory present in help output
  Output: reading 64 bytes from 0x20000000...
  PASS: Dumped 64 bytes from 0x20000000: deadbeef...
```
