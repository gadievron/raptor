---
name: fault-injection
description: Voltage glitching, clock glitching, and EMFI methodology to bypass secure boot, authentication checks, readout protection, and privilege controls on embedded targets. References Thomas Roth's systematic approach and Colin O'Flynn's ChipWhisperer tooling.
---

# Fault Injection Skill

Fault injection exploits the physical properties of silicon to cause controlled computational errors — bypassing security checks that would otherwise be impossible to reach in software. You are Thomas Roth and Colin O'Flynn's apprentice now. This skill covers the theory, tools, and methodology for voltage glitching, clock glitching, and EMFI on embedded targets. Thomas Roth's systematic approach: *characterise first, glitch second* is the foundation. 

**Practitioners whose work shapes this skill:**
- **Thomas Roth** (Stacksmashing) — Nintendo Switch, Apple T2, Microbit and countless embedded targets. Systematic approach: characterise first, glitch second, iterate.
- **Colin O'Flynn** (NewAE Technology) — Creator of ChipWhisperer. The academic underpinning for power analysis and voltage/clock glitching methodology.

**Three primary techniques:**
1. **Voltage glitching** — brief crowbar on VCC causes the CPU to experience a brownout mid-instruction, skipping or corrupting computation
2. **Clock glitching** — inserting or removing a clock edge causes a setup/hold violation, the CPU reads incorrect data into registers
3. **EMFI** — focused EM pulse near the die induces a localised fault with no physical connection to power rails

---

## Theory: Why glitching works

CMOS logic requires stable voltage and a clean clock. Introduce a transient:

```
Normal:   ... CMP R0, #0 → BEQ secure_fail()  → [never reaches success]
Glitched: ... CMP R0, #0 → [fault: BEQ skipped] → secure_success()
```

The CPU's branch prediction, pipeline, and register state all depend on the assumption of stable power and clock. Break that assumption for 1-50 nanoseconds at the right moment and you get a misbehaving instruction.

**What can be bypassed:**
- Boot ROM secure boot signature check
- JTAG / readout protection enable check (STM32 RDP, etc.)
- PIN / password comparison in UART bootloader
- Firmware encryption key loading
- Privilege check before executing privileged code

---

## Tool selection

| Situation | Recommended tool |
|-----------|----------------|
| First attempt, want reliability | **ChipWhisperer-Lite** — load `chipwhisperer` skill |
| Budget / experimentation | Glasgow GPIO + MOSFET — see below |
| No physical VCC access | EMFI — see EMFI section |
| Target requires clock control | CW-Lite with CLKOUT — load `chipwhisperer` skill |
| Production / research | CW-Pro or CW-Husky |

**Load the `chipwhisperer` skill for full CW API coverage and campaign automation.**

---

## Phase 1: Target characterisation (Thomas Roth approach)

Before touching the glitcher, understand what you are trying to bypass. Thomas Roth's methodology: *characterise first, glitch second*.

### Step 1 — Identify the security check

```bash
# Capture UART output at each stage
glasgow run uart -V 3.3 --baud 115200 --pins-tx 0 --pins-rx 1 record boot.log

# Look for the check:
# "Verifying signature..."  → secure boot verification
# "Reading protection bits..." → RDP or fuse check
# "Enter PIN:"              → authentication comparison
# "Loading encrypted firmware..." → decryption before exec
```

### Step 2 — Measure timing to the check

Use Glasgow logic analyser or CW to measure time from reset-release to the security check:

```bash
# Glasgow: capture reset line (pin 0) and UART TX (pin 1) simultaneously
glasgow run logic-analyzer --pins 0,1 --sample-rate 100e6 record boot-timing.vcd

# Open in PulseView + UART decoder
# Measure: reset release → first UART character → "Verifying" message
# This gives you the rough ext_offset range to target
```

```python
import serial
import time

def measure_check_timing(uart_port: str, baud: int = 115200,
                          check_string: bytes = b"Verifying") -> float:
    """
    Measure time from power-on to the security check message.
    Power-cycle the device and watch for the string.
    """
    ser = serial.Serial(uart_port, baud, timeout=3)
    buf = b""
    t_start = time.perf_counter()

    while time.perf_counter() - t_start < 3:
        data = ser.read(64)
        buf += data
        if check_string in buf:
            elapsed = time.perf_counter() - t_start
            print(f"[+] '{check_string.decode()}' at {elapsed * 1000:.1f}ms")
            return elapsed

    print(f"[-] '{check_string.decode()}' not seen within 3s")
    return -1
```

### Step 3 — Identify power delivery topology

```
Single VCC rail (3.3V to SoC directly):
  → Simplest. Glitch directly on VCC.

Separate core voltage (1.0V-1.2V from PMIC):
  → More effective. Smaller voltage = smaller glitch needed.
  → Find the PMIC output capacitor, glitch there.

VCC through decoupling capacitors close to SoC:
  → Best glitch point. Caps are the primary energy reservoir.
  → Probe with oscilloscope first to find lowest-impedance point.
```

### Step 4 — Identify clock source

```
Crystal oscillator:
  → Can be removed and replaced with CW CLKOUT (enables clock glitching)
  → Most common on microcontrollers

PLL fed by external reference:
  → Control the reference clock

Internal RC oscillator (e.g. STM32 with HSI):
  → Clock glitching much harder (no external clock to control)
  → Voltage glitching more reliable
```

---

## Phase 2: Voltage glitching with ChipWhisperer (recommended)

**Load the `chipwhisperer` skill.** The CW-Lite has a dedicated crowbar MOSFET (GLITCH output) with sub-nanosecond control from an FPGA — far more reliable than Python-controlled GPIO.

Key parameters:
- `scope.glitch.ext_offset` — clock cycles from trigger to glitch
- `scope.glitch.width` — crowbar duration (% of clock period for CW-Lite)
- `scope.glitch.repeat` — consecutive pulses

See `.claude/skills/hardware-research/chipwhisperer/SKILL.md` for full campaign code.

---

## Phase 3: Voltage glitching without CW (budget option — Glasgow + MOSFET)

If you do not have a ChipWhisperer, use Glasgow GPIO to control a crowbar MOSFET. This gives microsecond-level precision (not nanosecond), which is sufficient for some targets.

### Circuit

```
Target VCC ──┬────────────── SoC VCC pin
             │
           10Ω resistor (shunt)
             │
         Drain of P-channel MOSFET (e.g. SI2305DS)
         Source → Target VCC (above 10Ω)
         Gate  → Glasgow GPIO pin 4 (via 100Ω series resistor)
             │
           GND
```

The MOSFET normally stays on (gate pulled low). Pulsing the gate HIGH briefly disconnects VCC.

### Glasgow glitch campaign

```python
import subprocess
import time
import serial
import random
import csv
from datetime import datetime

class GlasgowGlitcher:
    """
    Budget voltage glitcher using Glasgow GPIO + external MOSFET.
    Microsecond precision (limited by Python GIL + USB latency).
    Use ChipWhisperer for sub-microsecond work.
    """

    def __init__(self, power_pin: int = 4, reset_pin: int = 5,
                 voltage: float = 3.3):
        self.power_pin = power_pin
        self.reset_pin = reset_pin
        self.voltage = voltage

    def _gpio(self, **settings):
        pins = ",".join(str(k) for k in settings)
        vals = [f"{k}={v}" for k, v in settings.items()]
        subprocess.run(
            ["glasgow", "run", "gpio", "-V", str(self.voltage),
             "--pins", pins, "set"] + vals,
            capture_output=True
        )

    def reset_target(self, hold_ms: int = 100):
        self._gpio(**{self.reset_pin: 0})
        time.sleep(hold_ms / 1000)
        self._gpio(**{self.reset_pin: 1})

    def glitch(self, delay_s: float, width_s: float):
        """Voltage glitch: wait delay_s, cut power for width_s."""
        self._gpio(**{self.reset_pin: 0})
        time.sleep(0.1)
        self._gpio(**{self.reset_pin: 1, self.power_pin: 1})
        time.sleep(delay_s)
        self._gpio(**{self.power_pin: 0})   # Cut power
        time.sleep(width_s)
        self._gpio(**{self.power_pin: 1})   # Restore power

    def campaign(self, uart_port: str, baud: int = 115200,
                  delay_range: tuple = (0.001, 0.1),
                  width_range: tuple = (0.000_001, 0.000_050),
                  n_attempts: int = 2000,
                  success_strings: list = None) -> list[dict]:
        """
        Randomised glitch campaign. Returns list of successes.
        """
        if success_strings is None:
            success_strings = ['#', '$ ', 'shell', 'root', 'bypass']

        ser = serial.Serial(uart_port, baud, timeout=0.3)
        log = []
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_path = f".out/hardware/glitch-log-{ts}.csv"

        with open(log_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["attempt", "delay_ms", "width_us", "result", "response"])

            for i in range(n_attempts):
                delay = random.uniform(*delay_range)
                width = random.uniform(*width_range)

                self.glitch(delay, width)
                time.sleep(0.15)

                response = ser.read(256).decode("utf-8", errors="replace")

                if any(s in response for s in success_strings):
                    result = "success"
                elif response and len(response) > 5:
                    result = "interesting" if len(response) > 20 else "normal"
                else:
                    result = "reset"

                entry = {
                    "attempt": i,
                    "delay_ms": delay * 1000,
                    "width_us": width * 1_000_000,
                    "result": result,
                    "response": response[:80]
                }
                log.append(entry)
                writer.writerow([i, f"{delay*1000:.3f}", f"{width*1e6:.3f}",
                                  result, response[:40]])

                print(f"[{i:4d}] delay={delay*1000:.1f}ms "
                      f"width={width*1e6:.1f}µs → {result}")

                if result == "success":
                    print(f"\n[!!!] SUCCESS: delay={delay*1000:.1f}ms "
                          f"width={width*1e6:.1f}µs")
                    print(f"      Response: {repr(response[:100])}")

        return [e for e in log if e["result"] == "success"]
```

---

## Phase 4: Clock glitching

Clock glitching is most effective when you control the target's clock source. Remove the crystal oscillator and replace it with CW CLKOUT.

```
Crystal out → CW CLKOUT (via 22Ω series resistor)
```

The ChipWhisperer FPGA generates the clock and can inject a precisely-timed extra half-cycle or remove a rising edge. See the `chipwhisperer` skill for `scope.glitch.output = "clock_xor"` configuration.

**When to prefer clock glitching:**
- Target has internal VCC decoupling that absorbs voltage glitches
- Target has voltage monitoring / brown-out detector (blocks voltage glitch)
- Target uses internal RC oscillator fed through external PLL (you can control the PLL reference)

---

## Phase 5: EMFI

Electromagnetic Fault Injection uses a coil pressed near the chip to induce localised faults without any physical modification to power rails.

**Advantages over voltage/clock glitching:**
- No board modification — works on production hardware
- Can target a specific area of the die (useful if only one functional block needs faulting)
- Effective through PCB substrate and mould compound

**Equipment:**
- EM probe (hand-wound coil or commercial, ~2-5mm diameter)
- Pulse generator: 100V+ into the coil (NewAE ChipSHOUTER, or DIY)
- XY positioning stage (manual or automated)
- Oscilloscope to monitor target behaviour during scan

```python
# ChipSHOUTER (NewAE EMFI tool) Python API
# pip install chipshouterpython

from chipshouter import ChipSHOUTER

cs = ChipSHOUTER("/dev/ttyUSB0")
cs.voltage = 150      # Volts into coil
cs.pulse.width = 80   # Nanoseconds
cs.armed = True

# Fire a single pulse
cs.pulse = True

# Integrate with glitch campaign loop:
# Move XY stage to position, fire pulse, check UART response, repeat
```

**Positioning strategy (Thomas Roth):**
1. Start with a coarse grid scan (5mm steps) across the entire chip
2. When a response changes, refine to 1mm steps around that area
3. When consistent faults appear, refine to 0.5mm

---

## Phase 6: Result classification and iteration

```
Result          Interpretation                    Action
──────────────────────────────────────────────────────────────────────
Crash / reset   Glitch too wide or too early      Reduce width, check delay
No response     Missed window entirely             Widen delay sweep range
Normal output   No effect                         Continue sweep
Interesting     Different output, not success      Investigate — narrow around this
Success         Security check bypassed            Record, refine, reproduce 20x
```

### Refinement after first success

```python
def refine_parameters(controller, uart_port: str,
                        coarse_delay_ms: float, coarse_width_us: float,
                        n: int = 500) -> list[dict]:
    """
    Narrow parameter sweep ±10% around a known-good point.
    """
    delay_s = coarse_delay_ms / 1000
    width_s = coarse_width_us / 1_000_000

    return controller.campaign(
        uart_port,
        delay_range=(delay_s * 0.90, delay_s * 1.10),
        width_range=(width_s * 0.90, width_s * 1.10),
        n_attempts=n
    )
```

**Reproducibility target:** >10% success rate in the refined window before reporting.

---

## Safety

- Some devices permanently blow a fuse on glitch detection — check the datasheet for anti-tamper behaviour before starting
- Keep a spare target in case of damage
- Voltage glitching with a crowbar can destroy the target if width is too large — start with width < 1µs
- EMFI pulse into adjacent components can destroy them — shield or desolder what you can

---

## Output artefacts

```
fault-injection/
├── boot-timing.vcd        # Logic analyser trace, boot sequence
├── glitch-log-<ts>.csv    # All attempts (delay, width, result)
├── successes.json         # Successful parameter sets
├── refined-log-<ts>.csv   # Refined sweep around success
└── target-response.txt    # Device output after bypass
```

---

## References

- Colin O'Flynn — ChipWhisperer documentation and original papers (Fault Attack on AES, 2010)
- Thomas Roth (Stacksmashing) — YouTube: Nintendo Switch fault injection, Apple T2 research
- Colin O'Flynn — "A Survey of Fault Injection Countermeasures" (IACR 2022)
- Jasper van Woudenberg, Marc Witteman, Bram Bakker — "Improving Differential Fault Analysis"
