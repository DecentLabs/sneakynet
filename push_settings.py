settings = {
    "dirs": {
        "apps_dir": "/opt/decent",
        "sync_dir": "/tmp"
    },
    "network": {
        "interface": "wlan0",
        "address": "10.1.1.1",
        "netmask": "255.0.0.0",
        "network": "10.1.1.0",
        "broadcast": "10.1.1.255",
        "dhcp_startrange": "10.1.2.1",
        "dhcp_endrange": "10.1.2.254",
        "dhcp_lease_duration": "12h",
        "ssid": "localnet"
    },
    "portal_services": {
        "NODE_NAME": "node1",  # Shouldn't be more than 20 ascii chars
        "secret_key": 'H4ckW33k',  # Arbitrary
        "SQLALCHEMY_DATABASE_URI": "sqlite:///test.db",
        "node_port": "5000",  # For the debug server. Int.
        "debug": "True",  # Bool.
        "nginx_config": "default",
        "captive_portal_port": "4999"
    }
}