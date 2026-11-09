# Simarine STRx for Home Assistant

Home Assistant integration for the SIMARINE STRx radar tank level meter. It reads the tank level from
the meter's Bluetooth broadcast, so Home Assistant never connects to the meter. Every STRx in range is
discovered on its own, and an encrypted broadcast is read with the key from the Simarine Connect app.

## Requirements

- Home Assistant 2025.3 or newer, with Bluetooth set up through a local adapter or an ESPHome
  Bluetooth proxy. It has to scan actively, part of the broadcast only comes in the scan response.
- STRx firmware with broadcast protocol 1.x.
- Broadcast Mode on in the Simarine Connect app, under Device Management → Broadcast Settings.

## Installation

### HACS

1. In HACS open the menu ⋮ → **Custom repositories**, add `https://github.com/Simarine/ha-simarine-strx`
   with the type **Integration**.
2. Download **Simarine STRx** and restart Home Assistant.

### Manual

Copy `custom_components/simarine_strx` into the `custom_components` folder of the Home Assistant
configuration and restart Home Assistant.

## Setup

Each STRx in range shows up as discovered under **Settings → Devices & services**. It can also be added
by hand with **Add integration → Simarine STRx**.

In a Security mode Home Assistant asks for the encryption key. In the Simarine Connect app open
Device Management → Broadcast Settings → Show Encryption Key and enter the 32 hexadecimal digits.

| Broadcast mode  | Key | Home Assistant gets                                                                  |
|-----------------|-----|--------------------------------------------------------------------------------------|
| Open            | No  | Level and tank description                                                           |
| Low Security    | Yes | Level and tank description                                                           |
| Medium Security | Yes | Level. The tank description only for one minute after it changes, it is kept then   |
| High Security   | Yes | Level. Volume, Tank volume and Tank type stay unknown                                |
| Off             | -   | Nothing, Broadcast status shows Broadcast off                                        |

### Entities

| Entity           | Description                                                                 |
|------------------|-----------------------------------------------------------------------------|
| Level            | Tank level in %                                                             |
| Volume           | Liquid in the tank in L, level × tank volume                                |
| Tank volume      | Tank volume set in the app (diagnostic)                                     |
| Tank type        | Fresh water, gray water, black water, fuel or other (diagnostic)            |
| Broadcast mode   | Off, High, Medium or Low security, or Open (diagnostic)                     |
| Broadcast status | OK, or why there is no level, like Encryption key needed (diagnostic)       |
| Signal strength  | RSSI in dBm (diagnostic, disabled by default)                               |

### Changing the mode or the key

- **Switching to a Security mode, Regenerate Encryption Key, factory reset:** Home Assistant asks for
  the key again.
- **Switching to Open while a key is set:** the level is ignored, since an unencrypted broadcast can
  be forged, and a repair issue is raised. If Open is intended, open the device's ⋮ menu →
  **Reconfigure** and clear the key.
- **Entering a different key:** ⋮ → **Reconfigure**.

## Troubleshooting

- **"No scan response received"**: the adapter or proxy scans passively. For a local adapter open
  Settings → Devices & services → Bluetooth → the adapter → Configure and turn passive scanning off.
  For an ESPHome proxy set `bluetooth_proxy: active: true`. The meter also stops broadcasting while
  the app is connected to it.
- **Debug log:**

  ```yaml
  logger:
    logs:
      custom_components.simarine_strx: debug
  ```

## Protocol

The broadcast is described in [strx-ble-broadcast-protocol](https://github.com/Simarine/strx-ble-broadcast-protocol).
`custom_components/simarine_strx/strx/broadcast.py` is a copy of the reference parser from there.

## Development

```sh
python -m pytest                          # protocol tests, needs pytest and cryptography
pip install -r requirements_test.txt      # Home Assistant test harness, Python 3.14
python -m pytest                          # also runs the Home Assistant tests in tests/ha
```

To release, set `version` in `custom_components/simarine_strx/manifest.json` and publish a GitHub
release with the tag `v<version>`. HACS shows the tag of the latest release.

## License

MIT, see [LICENSE](LICENSE).
