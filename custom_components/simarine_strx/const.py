"""Constants of the Simarine STRx integration."""

DOMAIN = "simarine_strx"
MANUFACTURER = "Simarine"

# Config entry data
CONF_ENCRYPTION_KEY = "encryption_key"
CONF_PRODUCT_TYPE = "product_type"
CONF_TANK = "tank"

# Seconds the config flow waits for a scan response
SCAN_RESPONSE_TIMEOUT = 10

# Active scan asked for when the scan response is out of date: duration and minimum spacing, seconds
ACTIVE_SCAN_DURATION = 10
ACTIVE_SCAN_INTERVAL = 30

# Repair issue ids, suffixed with the device address
ISSUE_DOWNGRADE = "encryption_downgrade"
ISSUE_UNSUPPORTED = "unsupported_protocol"
