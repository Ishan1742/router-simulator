"""
Classes for different types of messages
which are allowed in the simulator
"""

import json

import logger

LOG = logger.get_logger('root')


class Message:
    """
    General message class template
    """
    __src: str = None
    __dest: str = None
    __type: str = None

    def __init__(self, src: str, dest: str, msg_type: str) -> None:
        """
        initialise the Message class obeject
        :param src: source addr
        :param dest: destination addr
        :param msg_type: type of the message
        """
        LOG.debug(
            f"New Message Object. source: {src}, destination: {dest}, message type: {msg_type}")
        LOG.debug(
            f"Types: in order: {type(src)}, {type(dest)}, {type(msg_type)}")
        self.__src = src
        self.__dest = dest
        self.__type = msg_type

    def to_dict(self) -> dict:
        """
        Returns class object in dict format
        """
        LOG.debug(
            f"Message to_dict(). source: {self.__src}, destination: {self.__dest}, message type: {self.__type}")
        d = dict()
        d["type"] = self.__type
        d["source"] = self.__src
        d["destination"] = self.__dest
        return d

    def get_destination(self) -> str:
        """
        return the destination of the message
        """
        return self.__dest

    def get_source(self) -> str:
        """
        return the source of the message
        """
        return self.__src

    def get_type(self) -> str:
        """
        return the type of the message
        """
        return self.__type


class Data(Message):
    """
    Data message type
    """
    __payload: str = None

    def __init__(self, src: str, dest: str, msg_type: str, payload: str) -> None:
        """
        create a Data Message object
        :param payload: payload of the data message
        """
        Message.__init__(self, src, dest, msg_type)
        self.__payload = payload
        LOG.debug(f"Data message: payload: {payload}")
        LOG.debug(f"Type: payload: {type(payload)}")

    def to_dict(self) -> dict:
        """
        return dict of Data Message
        """
        d = super().to_dict()
        d["payload"] = self.__payload
        LOG.debug(f"Data to_dict(): payload: {self.__payload}")
        return d

    def get_payload(self) -> str:
        """
        return Data message payload
        """
        return self.__payload


class Update(Message):
    """
    Update message type. Update weights between router links
    """
    __distances: dict = None

    def __init__(self, src: str, dest: str, msg_type: str, distances: dict) -> None:
        """
        create a Update message object.

        :param distances: dict containing all the weights to other nodes
        """
        Message.__init__(self, src, dest, msg_type)
        self.__distances = distances
        LOG.debug(f"Update message: distances: {distances}")
        LOG.debug(f"Type: distances: {type(distances)}")

    def to_dict(self) -> dict:
        """
        convert to dictionary
        """
        d = super().to_dict()
        d["distances"] = self.__distances
        LOG.debug(f"Update to_dict(): {self.__distances}")
        return d

    def get_distances(self) -> list:
        """
        return distances data
        """
        return self.__distances


class Trace(Message):
    """
    Trace message type
    """
    __hops = None

    def __init__(self, src: str, dest: str, msg_type: str, hops: list) -> None:
        """
        create a Trace type object

        :param hops: routers passed to get to that destination
        """
        Message.__init__(self, src, dest, msg_type)
        self.__hops = hops
        LOG.debug(f"Trace message: hops: {hops}")
        LOG.debug(f"Type: hops: {type(hops)}")

    def to_dict(self) -> dict:
        """
        convert to dictionary
        """
        d = super().to_dict()
        d["hops"] = self.__hops
        LOG.debug(f"Trace to_dict(): {self.__hops}")
        return d

    def get_hops(self) -> list:
        """
        return hops list
        """
        return self.__hops
