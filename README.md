# XIAOMI BLE Yeelight YLYK01L proof-of-concept for ESP32

Proof-of-concept application for ESP32 to auth & decode YLYK01L (and maybe other contorls dimmers, etc). 


Scans for XIAOMI BLE device with productID specifed in `requiredProductId`, authenticates, receives beacon key and stores it in the EEPROM.


After successfull auth process, application subscribes for encrypted notifications and just prints pressed keys.


It's ugly, probably have a lot of bugs, but can be used as the starting point.



It uses Arduino structure to support ArduinoIDE, but can be easily ported to IDF.
All you need to do (I think) to compile it in Arduion IDE is to rename cpp->ino.


Example output log:
```
Remote control address not defined.
Scannig for remote, press OFF+M ...
Found! [yee-rc], RSSI:-56, Address:f8:24:41:ed:01:1d

 -- FrameControl: 0x3251
    Has data fields
 -- ProductID:    0x0153
 -- FrameCounter: 0x1020001
 -- MAC address:  F8:24:41:ED:01:1D

Scan done!
Paired remote control address: f8:24:41:ed:01:1d
Connecting to remote
Obtaining chracteristics
Connected to the remote, waiting for auth notification
Auth start notify:
Decrypted token
00000000: A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB              ............
Should be token
00000000: A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB              ............
Countinue auth
Auth done
FW version:
00000000: 31 2E 30 2E 31 5F 31 00 00 00                    1.0.1_1...
Beacon key:
00000000: F0 9B BE B9 8C 08 43 8B 8E 84 69 5B              ..C...i[
ON
OFF
DAY/NIGHT
HOLD ON
DAY/NIGHT
HOLD M
HOLD M
-
+
+
OFF
```