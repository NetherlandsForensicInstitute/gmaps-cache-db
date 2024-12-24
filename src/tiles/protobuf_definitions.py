TILE_KEY_TYPE = {
    "1": {"type": "bytes", "name": "layer_id"},
    "2": {"type": "bytes", "name": "locale"},
    "5": {
        "type": "message",
        "message_typedef": {
            "1": {"type": "int", "name": "zoom"},
            "2": {"type": "int", "name": "x"},
            "3": {"type": "int", "name": "y"},
        },
        "name": "coordinate",
    },
    "6": {"type": "bytes", "name": "unknown1"},
    "7": {"type": "bytes", "name": "country"},
    "10": {"type": "bytes", "name": "unknown2"},
}

TILE_METADATA_TYPE = {
    "1": {
        "type": "message",
        "message_typedef": TILE_KEY_TYPE,
        "name": "TileKey",
    },
    "3": {"type": "int", "name": ""},
    "6": {"type": "int", "name": ""},
    "7": {"type": "int", "name": ""},
    "8": {"type": "int", "name": ""},
    "9": {"type": "int", "name": ""},
    "10": {"type": "bytes", "name": ""},
    "11": {"type": "int", "name": ""},
}
