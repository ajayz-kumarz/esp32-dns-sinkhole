# Flashing guide (macOS)

Plug the board into your Mac with a **data** USB cable. A charge-only cable will power the board but the Mac won't see it.

## 1. Install Arduino IDE and ESP32 support

1. Download **Arduino IDE 2.x** from arduino.cc/en/software and move it to Applications.
2. Open **Arduino IDE → Settings**. In **Additional boards manager URLs**, add:
   ```
   https://espressif.github.io/arduino-esp32/package_esp32_index.json
   ```
3. Open **Tools → Board → Boards Manager**, search for **esp32**, and install **esp32 by Espressif Systems**.

## 2. Install the LittleFS upload plugin

1. Download the latest `.vsix` from the Releases page of `earlephilhower/arduino-littlefs-upload` on GitHub.
2. In Finder, press **Cmd+Shift+G** and go to `~/.arduinoIDE/`.
3. Create a `plugins` folder if it doesn't exist and put the `.vsix` file inside.
4. Quit and reopen Arduino IDE.

## 3. Connect the board

1. Plug in the ESP32.
2. Check **Tools → Port** for `/dev/cu.usbserial-XXXX` or `/dev/cu.SLAB_USBtoUART`.
3. If neither appears, try another cable. If it still doesn't appear, install the Silicon Labs CP210x VCP driver, approve it in **System Settings → Privacy & Security**, and replug the board.

## 4. Build the blocklist

```
cd esp32_dns_sinkhole
python3 build_blocklist.py
```

- If macOS asks to install Command Line Tools, accept and run the command again.
- If you see `SSL: CERTIFICATE_VERIFY_FAILED`, run **Applications → Python 3.x → Install Certificates.command**.

You should see `reading ...` lines followed by something like `131862 domains -> data/blocklist.bin`.

## 5. Find your router IP

```
route -n get default | grep gateway
```

## 6. Edit the sketch

Open `esp32_dns_sinkhole.ino` and set:

```cpp
const char* WIFI_SSID      = "YourWiFiName";      // 2.4 GHz only
const char* WIFI_PASS      = "YourWiFiPassword";
const char* UI_PASS        = "a-strong-password";
const char* DASHBOARD_NAME = "My Home";

IPAddress LOCAL_IP(192, 168, 1, 53);   // same first three numbers as your router
IPAddress GATEWAY (192, 168, 1, 1);    // your router IP
```

## 7. Upload the sketch

1. Under **Tools**, set:
   - **Board:** ESP32 Dev Module
   - **Partition Scheme:** No OTA (1MB APP/3MB SPIFFS)
   - **Port:** the port from step 3
2. Click **Upload**.
3. If it stays on `Connecting.....`, hold the **BOOT** button on the board until writing starts.

## 8. Upload the blocklist

1. Close the **Serial Monitor** tab completely (click its ×). An open monitor causes `Resource busy` errors.
2. Press **Cmd+Shift+P** and run **Upload LittleFS to Pico/ESP8266/ESP32**.
3. Hold **BOOT** again if it stays on `Connecting`.

## 9. Check it's running

Open **Tools → Serial Monitor** at **115200** baud and press **EN** on the board. You should see:

```
Blocklist: 131862 domains, custom block: 0, allow: 0
Sinkhole running at 192.168.1.53
Dashboard: http://sinkhole.local or http://192.168.1.53
```

## 10. Test

```
nslookup doubleclick.net 192.168.1.53   # should return 0.0.0.0
nslookup google.com 192.168.1.53        # should return a real IP
```

## 11. Point your network at it

**Whole network (recommended):** in your router's LAN/DHCP settings, set Primary DNS to the ESP32's IP and leave Secondary DNS empty. Make sure the ESP32's IP is outside the DHCP range or reserved for it.

**Per device (if the router doesn't allow it):**
- **macOS:** System Settings → Wi-Fi → Details → DNS → replace entries with the ESP32's IP
- **iPhone:** Settings → Wi-Fi → ⓘ → Configure DNS → Manual
- **Android:** Wi-Fi network → IP settings: Static → DNS 1

## 12. Turn off DNS bypasses

- Chrome / Edge: Settings → Privacy and security → Use secure DNS → Off
- Firefox: Settings → Privacy & Security → DNS over HTTPS → Off
- Apple devices: iCloud Private Relay → Off
- Android: Private DNS → Off

## 13. Move it to its permanent spot

Unplug from the Mac and power it from a 5V USB adapter near the router. It reconnects on its own within a few seconds.

## Troubleshooting

| Problem | Fix |
|---|---|
| `Resource busy` on upload | Close the Serial Monitor tab, or run `lsof \| grep usbserial` and quit the process |
| Stuck on `Connecting.....` | Hold BOOT until writing starts |
| `Blocklist: 0 domains` | Repeat step 8 |
| Dots in Serial Monitor never stop | Wrong Wi-Fi name/password, or a 5 GHz-only network |
| `sinkhole.local` doesn't open | Use the IP address directly |
| Old ads still showing | Flush DNS: `sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder` |
