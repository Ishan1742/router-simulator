"""
class for handling packets
"""

import json
import logger

LOG = logger.get_logger('root')


class Packet:

    @staticmethod
    def json_encoding(json_dict: dict) -> str:
        # convert to string from json
        json_str = json.dumps(json_dict)
        return json_str

    @staticmethod
    def json_decoding(json_str: str) -> dict:
        # conver to json dict
        try:
            json_dict = json.loads(json_str)
        except json.JSONDecodeError as err:
            LOG.error(f"JSON error: {err}")
            raise
        LOG.debug(
            f"Packet: json_decoding():\n{json.dumps(json_dict, indent=2, sort_keys=True)}")
        return json_dict

    @staticmethod
    def to_struct(json_str: str) -> bytes:
        # convert to byte string to transport
        data = bytes(json_str, 'ascii')
        return data

    @staticmethod
    def to_string(data: bytes) -> str:
        # convert byte string to json string
        json_str = data.decode('ascii')
        LOG.debug(
            f"Packet to_string(): \n{json.dumps(json.loads(json_str), indent=2, sort_keys=True)}")
        return json_str
