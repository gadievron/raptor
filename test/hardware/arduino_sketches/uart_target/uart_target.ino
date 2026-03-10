/*
 * RAPTOR Hardware Test Target — UART
 *
 * Simulates a device with an active UART console.
 * Glasgow wiring:
 *   Glasgow A0 (RX) → Arduino TX (pin 1, or pin 3 if using SoftwareSerial)
 *   Glasgow A1 (TX) → Arduino RX (pin 0, or pin 2 if using SoftwareSerial)
 *   Glasgow GND     → Arduino GND
 *
 * On Uno: hardware UART (pins 0/1) is shared with USB.
 * Prefer SoftwareSerial on pins 2/3 so USB stays available for programming.
 *
 * Expected Glasgow detection:
 *   glasgow run uart --voltage 3.3 --baud 115200 --rx A0 tty
 *   → Should see boot log + periodic heartbeat
 *
 * Test baud rates:
 *   115200 (primary), 57600, 9600 (also enabled via menu comment)
 */

#include <SoftwareSerial.h>

// SoftwareSerial: Glasgow A0 → pin 3 (RX), Glasgow A1 → pin 2 (TX)
SoftwareSerial targetSerial(3, 2);  // RX=3, TX=2

const char* BOOT_LOG[] = {
  "U-Boot 2023.01 (RAPTOR Test Target)",
  "CPU: ATmega328P @ 16MHz",
  "DRAM: 2 KiB",
  "Loading environment from EEP...",
  "Hit any key to stop autoboot: 3",
  "## Starting application at 0x00000000",
  "BusyBox v1.33.0 built-in shell (ash)",
  "/ # "
};

const int BOOT_LOG_LEN = sizeof(BOOT_LOG) / sizeof(BOOT_LOG[0]);

bool booted = false;
unsigned long lastHeartbeat = 0;
int bootStep = 0;

void setup() {
  targetSerial.begin(115200);
  delay(200);
  // Print boot log with realistic delays
}

void loop() {
  // Stream boot log on startup
  if (!booted) {
    if (bootStep < BOOT_LOG_LEN) {
      targetSerial.println(BOOT_LOG[bootStep]);
      bootStep++;
      delay(bootStep == 4 ? 3000 : 150);  // Pause on autoboot countdown
    } else {
      booted = true;
    }
    return;
  }

  // After boot: heartbeat + respond to input
  if (millis() - lastHeartbeat > 5000) {
    targetSerial.println("raptor-test:~# ");
    lastHeartbeat = millis();
  }

  if (targetSerial.available()) {
    String cmd = targetSerial.readStringUntil('\n');
    cmd.trim();
    if (cmd == "id") {
      targetSerial.println("uid=0(root) gid=0(root) groups=0(root)");
    } else if (cmd == "uname -a") {
      targetSerial.println("Linux raptor-test 5.15.0 #1 SMP PREEMPT Fri Jan 1 00:00:00 UTC 2023 armv7l GNU/Linux");
    } else if (cmd.length() > 0) {
      targetSerial.print("sh: ");
      targetSerial.print(cmd);
      targetSerial.println(": not found");
    }
    targetSerial.println("raptor-test:~# ");
  }
}
