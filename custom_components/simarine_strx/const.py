"""Constants of the Simarine STRx integration."""

DOMAIN = "simarine_strx"
MANUFACTURER = "Simarine"

# Config entry data
CONF_ENCRYPTION_KEY = "encryption_key"
CONF_PRODUCT_TYPE = "product_type"
CONF_TANK = "tank"

# Options: tank description entered by hand, used while the meter sends none
CONF_MANUAL = "manual_tank"
CONF_MANUAL_VOLUME = "tank_volume"
CONF_MANUAL_TYPE = "tank_type"
MANUAL_VOLUME_MAX = 65534

# Seconds the config flow waits for a scan response
SCAN_RESPONSE_TIMEOUT = 10

# Seconds since the last advertisement after which the device counts as not broadcasting,
# it advertises at least every 250 ms unless the app is connected to it
BROADCAST_STALE_SECONDS = 5

# Active scan asked for when the scan response is out of date: duration and minimum spacing, seconds
ACTIVE_SCAN_DURATION = 10
ACTIVE_SCAN_INTERVAL = 30

# Repair issue ids, suffixed with the device address
ISSUE_DOWNGRADE = "encryption_downgrade"
ISSUE_UNSUPPORTED = "unsupported_protocol"
