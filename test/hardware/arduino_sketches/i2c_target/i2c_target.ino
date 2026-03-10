/*
 * RAPTOR Hardware Test Target — I2C Slave
 *
 * Simulates a device with I2C EEPROM + sensor combo.
 * Responds at addresses 0x50 (EEPROM-style) and 0x48 (sensor-style).
 *
 * Glasgow wiring:
 *   Glasgow A0 → Arduino A5 (SCL)  [with 4.7kΩ pull-up to 3.3V]
 *   Glasgow A1 → Arduino A4 (SDA)  [with 4.7kΩ pull-up to 3.3V]
 *   Glasgow GND → Arduino GND
 *
 * IMPORTANT: Arduino runs at 5V logic but I2C is open-drain.
 *   Pull-ups should go to 3.3V (Glasgow's VCC), not 5V.
 *   Add a 1kΩ series resistor on SDA/SCL to protect Glasgow inputs.
 *
 * Expected Glasgow detection:
 *   glasgow run i2c-controller --voltage 3.3 --scl A0 --sda A1 scan
 *   → Should find: 0x50 (EEPROM), 0x48 (sensor)
 *
 * Note: Arduino Wire library only supports one slave address.
 * This sketch uses 0x50. Uncomment the second block for 0x48.
 */

#include <Wire.h>

#define SLAVE_ADDR 0x50   // EEPROM-style address

// Simulated EEPROM contents — includes strings, a "MAC address", version info
byte eeprom[32] = {
  0x01, 0x00,             // Version: 1.0
  0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE,  // "MAC address" at offset 2
  'R', 'A', 'P', 'T', 'O', 'R', 0x00,  // Device name
  '-', 'T', 'E', 'S', 'T', 0x00,       // continued
  0x42, 0x00,             // Feature flags
  0xFF, 0xFF, 0xFF, 0xFF, // Unwritten / erased
  0xFF, 0xFF
};

byte regAddr = 0;

void setup() {
  Wire.begin(SLAVE_ADDR);
  Wire.onReceive(receiveEvent);
  Wire.onRequest(requestEvent);
  Serial.begin(115200);
  Serial.println("[I2C target] Listening at 0x50");
}

void loop() {
  delay(100);
}

// Called when master writes to us
void receiveEvent(int bytes) {
  if (Wire.available()) {
    regAddr = Wire.read();   // First byte = register/address
  }
  // If more bytes follow, it's a write — store them
  int i = regAddr;
  while (Wire.available() && i < 32) {
    eeprom[i++] = Wire.read();
  }
}

// Called when master reads from us
void requestEvent() {
  Wire.write(&eeprom[regAddr], min(8, 32 - regAddr));
}
