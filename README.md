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
Disconnect the app before submitting the key: the meter does not broadcast while the app is
connected, so the key cannot be checked.

| Broadcast mode  | Key | Home Assistant gets                                                     |
|-----------------|-----|-------------------------------------------------------------------------|
| Open            | No  | Level and tank description                                              |
| Low Security    | Yes | Level and tank description                                              |
| Medium Security | Yes | Level, and the tank description it sends for 6 minutes after a change   |
| High Security   | Yes | Level. Volume, Tank volume and Tank type stay unknown                   |
| Off             | -   | Nothing, Broadcast status shows Broadcast off                           |

The tank description is stored, so Tank volume and Tank type keep their values while the meter is out
of range and across restarts of Home Assistant.

### Entering the tank description by hand

In High Security the meter never sends its tank volume and tank type, and in Medium Security only for a
while after a change. To have them anyway, or to use other values than the ones set in the app, open
the device's entry under **Settings → Devices & services → Simarine STRx → Configure**, turn on
**Enter the tank description by hand** and enter the tank volume and tank type.

- While turned on, the values entered by hand replace what the meter sends. A field left empty keeps
  the meter's value.
- The `source` attribute of Tank volume and Tank type says which one is shown: `manual` or `meter`.
- Turning it off goes back to what the meter sends and keeps the entered values for later.

### Entities

| Entity           | Description                                                           |
|------------------|-----------------------------------------------------------------------|
| Level            | Tank level in %                                                       |
| Volume           | Liquid in the tank in L, level × tank volume                          |
| Tank volume      | Tank volume set in the app (diagnostic)                               |
| Tank type        | Fresh water, gray water, black water, fuel or other (diagnostic)      |
| Broadcast mode   | Off, High, Medium or Low security, or Open (diagnostic)               |
| Broadcast status | OK, or why there is no level, like Encryption key needed (diagnostic) |
| Signal strength  | RSSI in dBm (diagnostic, disabled by default)                         |

### Dashboard card

The integration brings a **Simarine tank** card. The tank is the display: filled to its level, colored
by tank type, with the level in % and the volume in liters written inside it and a liter scale along
its side. A dot in the corner shows the broadcast status.

The card does not appear by itself: the automatic Overview dashboard and the device page only use the
cards of Home Assistant. Add it to a dashboard you edit, for example a new one from **Settings →
Dashboards → Add dashboard**. Edit the dashboard, add a card and search for *Simarine tank*, or add it
in YAML:

```yaml
type: custom:simarine-tank-card
entity: sensor.str2_8179_level   # Level sensor of the meter
name: Fresh water                # optional, the device name otherwise
```

The fill colors come from the theme variables `simarine-tank-fresh-water`, `simarine-tank-gray-water`,
`simarine-tank-black-water`, `simarine-tank-fuel` and `simarine-tank-other`. After updating the
integration, reload the browser page to get the new card.

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
- **"Not broadcasting right now" when entering the key**: the app is still connected to the meter.
  Disconnect it and submit again.
- **Medium Security, Tank volume stays unknown**: the meter sends the tank description only for six
  minutes of broadcasting after the volume, the tank type or the mode changes. Home Assistant scans
  for it as soon as it notices the change, and its regular scan every five minutes falls into that
  window too. A meter switched to Medium Security before Home
  Assistant knew it has nothing to send until the next change: in the app switch to another
  broadcast mode and back to Medium Security while Home Assistant is running. Saving unchanged
  settings does not count as a change.
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

Testing on a Home Assistant instance, releasing and publishing are described in
[MAINTAINING.md](MAINTAINING.md).

## License

MIT, see [LICENSE](LICENSE).
