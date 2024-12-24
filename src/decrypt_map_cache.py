import sqlite3
from datetime import datetime
from pathlib import Path

import blackboxprotobuf as bbpb
import shapely
import typer
from Crypto.Cipher import AES
from geopandas import GeoDataFrame
from typing_extensions import Annotated

from tiles.globalmaptiles import GlobalMercator
from tiles.protobuf_definitions import TILE_KEY_TYPE, TILE_METADATA_TYPE

GM = GlobalMercator()


KEYSIZE = 0x10


def key_derivation(key: bytes) -> bytes:
    key = bytearray(key)
    assert len(key) == KEYSIZE, "Invalid key length"
    for i in range(0, KEYSIZE - 1):
        key[i] = (key[i] + key[i + 1]) & 0xFF
    return bytes(key)


def get_aes_key(key_path: Path) -> bytes:
    m, _ = bbpb.decode_message(key_path.read_bytes())
    return key_derivation(m["1"])


def calc_tile_shape(z: int, x: int, y: int):
    # Google counts tiles differently than TMS, so we normalize to TMS
    gx, gy = GM.GoogleTile(x, y, z)
    (minLat, minLon, maxLat, maxLon) = GM.TileLatLonBounds(gx, gy, z)
    return shapely.geometry.box(minLon, minLat, maxLon, maxLat)


def decrypt(aes_key, nonce, data, ad=None, tag=None):
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    if ad is None and tag is None:
        return cipher.decrypt(data)
    cipher.update(ad)
    return cipher.decrypt_and_verify(data, tag)


def decrypt_and_verify_tile(aes_key, metadata_nonce, metadata, data_nonce, data):
    # Prepare data for processing
    metadata_nonce = metadata_nonce.ljust(12, b"\x00")
    metadata, metadata_tag = metadata[:-16], metadata[-16:]

    data_nonce = data_nonce.ljust(12, b"\x00")
    data, data_tag = data[:-16], data[-16:]

    plain = decrypt(aes_key, data_nonce, data)
    plain_meta = decrypt(aes_key, metadata_nonce, metadata)

    # Fix zero padding at the end of metadata
    end_idx = -1
    num_pad_bytes = plain_meta[end_idx]
    if num_pad_bytes in (1, 2):
        # No idea why but seems to work
        end_idx = -2
        num_pad_bytes = plain_meta[end_idx]
    assert (
        plain_meta[-num_pad_bytes + end_idx : end_idx] == num_pad_bytes * b"\x00"
    ), "Time to reconsider this padding observation"
    plain_meta = plain_meta[: -num_pad_bytes + end_idx]

    metadata_msg, _ = bbpb.decode_message(plain_meta, TILE_METADATA_TYPE)

    # Sanity check and verify
    # Will raise a ValueError if unable to verify tag
    ad = bbpb.encode_message(metadata_msg["TileKey"], TILE_KEY_TYPE)
    _ = decrypt(aes_key, metadata_nonce, metadata, ad=ad, tag=metadata_tag)
    _ = decrypt(aes_key, data_nonce, data, ad=ad, tag=data_tag)

    return metadata_msg, plain


def get_tiles(db_path: Path, aes_key: bytes):
    with sqlite3.connect(db_path) as con:
        for row in con.execute(
            "select layer_id, metadata_nonce, metadata, data_nonce, data, priority from tiles"
        ).fetchall():
            layer_id, metadata_nonce, metadata, data_nonce, data, priority = row

            # plain_data is not investigated further here
            metadata_msg, plain_data = decrypt_and_verify_tile(aes_key, metadata_nonce, metadata, data_nonce, data)

            z, x, y = [metadata_msg["TileKey"]["coordinate"][k] for k in ("zoom", "x", "y")]
            timestamp = datetime.fromtimestamp(priority / 1e3)
            shape = calc_tile_shape(z, x, y)
            yield (timestamp, layer_id.decode("ascii"), shape)


def get_tile_dataframe(key_path: Path, db_path: Path) -> GeoDataFrame:
    aes_key = get_aes_key(key_path)
    df = GeoDataFrame(get_tiles(db_path, aes_key), columns=["timestamp", "layer_id", "shape"], geometry="shape")
    return df


def main(
    key_path: Annotated[Path, typer.Argument(help="Path to 'map_cache.key'")],
    db_path: Annotated[Path, typer.Argument(help="Path to 'map_cache.db'")],
    out_path: Annotated[Path, typer.Argument(help="Path to output .geojson file")],
):
    """
    Decrypts a 'map_cache.db' with its corresponding 'map_cache.key' file and output to a '.geojson' file for further analysis.
    """
    if not key_path.is_file():
        print(f"Key file {key_path} not found, exiting")
        exit(-1)
    if not db_path.is_file():
        print(f"Database path {db_path} not found, exiting")
        exit(-1)
    if not out_path.name.endswith(".geojson"):
        print(f"Output file must end with .geojson, exiting")
        exit(-1)

    df = get_tile_dataframe(key_path, db_path)
    print(f"Succesfully decrypted tiles, storing to: {out_path}")
    df.to_file(f"{out_path}", driver="GeoJSON", engine="fiona")
    print("Done.")
    return df


if __name__ == "__main__":
    typer.run(main)
