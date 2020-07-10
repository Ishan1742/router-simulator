import re
import sys
import json
import shlex
import random
import socket
import selectors
from typing import Tuple, Union
from threading import Lock, Timer
from collections import defaultdict

# import user defined modules
import logger
from packet import Packet
from message import Data, Trace, Update

DEFAULT_PORT: int = 60799  # tcp/udp
DEFAULT_PERIOD: int = 15
MAX_UDP_SIZE: int = 65507  # IPv4 max size
MAX_WEIGHT: int = sys.maxsize

LOG = logger.get_logger('root')


class Router:
    """
    router class main class for nodes
    """

    def __init__(self, addr: str, period: str, startcmd=None) -> None:
        # create logs for each address
        self.__log = logger.get_logger(addr)
        self.__log.debug("init(): Start")

        # ip address of the router
        self.__addr = addr
        self.__log.debug(f"node address: {self.__addr}")

        # period after update messages sent
        if (period == None):
            self.__period = DEFAULT_PERIOD
        else:
            self.__period = period
        self.__log.debug(f"update period: {self.__period}")

        # set port
        self.__port = DEFAULT_PORT
        # AF_NET refers to the family of IPv4 protocol
        # SOCK_DGRAM refers to the datagram based protocol UDP
        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__sock.bind((self.__addr, self.__port))
        self.__routes = defaultdict()
        self.__links = dict()
        self.__routes_timer = dict()

        # selector for input (stdin and udp)
        # high level IO multiplexing
        # allows to specify which events to look for in a socket
        self.__selector = selectors.DefaultSelector()
        # both input from terminal and socket
        self.__selector.register(
            sys.stdin, selectors.EVENT_READ, self.__handle_command)
        self.__selector.register(
            self.__sock, selectors.EVENT_READ, self.__handle_message)

        # Setting the locks to critical sessions
        self.__routes_lock = Lock()
        self.__links_lock = Lock()
        self.__routes_timer_lock = Lock()

        # setting the timer for updating routes information
        self.__timer = Timer(self.__period, self.__send_update)
        self.__timer.start()

        # initialization with commands in files
        if startcmd:
            self.__startup_command(startcmd)
        self.__log.debug("init(): End")

    def __startup_command(self, input_file: str) -> None:
        """
        load startup commands

        :param input_file: path of file contaning startup commands
        """
        self.__log.debug("startup_command(): Start")
        try:
            with open(input_file) as fp:
                for line in fp:
                    self.__handle_command(line)
        except FileNotFoundError as err:
            self.__log.error(f"file not found error: {err}")
        self.__log.debug("startup_command(): End")

    def run(self) -> None:
        """
        simulate router from runner.py
        """
        # infinite loop
        while True:
            # read events from selector
            evts = self.__selector.select()
            for key, mask in evts:
                callback_function = key.data
                if key.fileobj == sys.stdin:
                    # read input from console
                    cmd = input()
                    self.__log.debug(f"command input from stdin: {cmd}")
                    # this implies the function to be called when an event is caught
                    callback_function(cmd)

                    # print some additional data
                    self.__log.info(f"Input Command: {cmd}")
                    self.__log.info(f"Links:")
                    self.__log.info(json.dumps(
                        self.__links, indent=2, sort_keys=True))
                    self.__log.info(f"Routes:")
                    self.__log.info(json.dumps(
                        dict(self.__routes), indent=2, sort_keys=True))
                elif key.fileobj == self.__sock:
                    # handle messages from socket
                    self.__handle_message()
                else:
                    self.__log.exception("Unknown Selector Event")
                    raise ("Unknown Selector Event")

    def __handle_command(self, cmd_input: str) -> None:
        """
        handle commands input in stdin

        :param cmd_input: command string
        """
        self.__log.debug("handle_command(): Start")
        cmd = shlex.split(cmd_input)
        length = len(cmd)

        if length == 3 and cmd[0] == 'add':
            try:
                self.add_link(cmd[1], int(cmd[2]))
            except Exception as exc:
                self.__log.exception(f"Exception handle_command(): {exc}")
                raise
        elif length == 2 and cmd[0] == 'del':
            self.remove_link(cmd[1])
        elif length == 2 and cmd[0] == 'trace':
            self.send_trace(cmd[1])
        elif length == 3 and cmd[0] == 'data':
            payload = json.dumps({'type': 'data', 'data': cmd[2]})
            message = Data(self.__addr, cmd[1], 'data', payload)
            self.send_message(message)
            print("")
        elif length == 2 and cmd[0] == 'see':
            if cmd[1] == 'routes':
                print(json.dumps(dict(self.__routes), indent=2, sort_keys=True))
                print("")
            elif cmd[1] == 'links':
                print(json.dumps(self.__links, indent=2, sort_keys=True))
                print("")
        else:
            print(f"Allowed commands:")
            print(f"add ip weight")
            print(f"del ip")
            print(f"trace ip")
            print(f"data ip 'payload'")
            print(f"see routes")
            print(f"see links")
            print(f"")
        self.__log.debug("handle_command(): End")

    def add_link(self, addr: str, weight: int) -> None:
        """
        add a new link in the router

        :param addr: destination address of the link
        :param weight: weight of the link
        """
        self.__log.debug("add_link(): Start")
        print(f"Add Link: Address: {addr}, Weight: {weight}")
        # check for valid ip address
        if not self.__check_addr(addr):
            self.__log.error(f"Error: Invalid IP address: {addr}")
            self.__logexit(f"Error: Invalid IP. address: {addr}")

        if addr == self.__addr:
            self.__log.warning(
                f"Error: Unable to add link to itself: src: {addr}, dest: {self.__addr}")
            print(
                f"Error: Unable to add link to itself: src: {addr}, dest: {self.__addr}")
            print("")
            return
        self.__links_lock.acquire()
        self.__links[addr] = weight
        self.__log.debug(f"Link added: Address: {addr}, Weight: {weight}")
        self.__links_lock.release()
        print(f"Link added: Address: {addr}, Weight; {weight}")
        print(f"")
        self.__log.debug("add_link(): End")

    def remove_link(self, addr: str) -> None:
        """
        remove a link in the router

        :param addr: destination address of the link
        """
        self.__log.debug("remove_link(): Start")
        print(f"Remove Link: Address: {addr}")
        # check for valid ip address
        if not self.__check_addr(addr):
            self.__log.error(f"Error: Invalid IP address: {addr}")
            self.__logexit(f"Error: Invalid IP. address: {addr}")

        # remove the address from the routing table
        self.__remove_routes(addr)

        # remove the address from the link table
        self.__links_lock.acquire()
        try:
            del self.__links[addr]
        except KeyError as err:
            self.__log.exception(f"KeyError: {err}")
            print(
                f"Unknown Link: Unable to remove or Link doesn't exist: Address: {addr}")
            print(f"")
            return
        self.__links_lock.release()
        print(f"Link removed: Address: {addr}")
        print(f"")
        self.__log.debug("remove_link(): End")

    def send_trace(self, addr: str) -> None:
        """
        trace the path to a address

        :param addr: destination address
        """
        self.__log.debug("send_trace(): Start")
        print(f"Trace: Address: {addr}")
        hops = []
        hops.append(self.__addr)
        message = Trace(self.__addr, addr, "trace", hops)
        if self.__addr != addr:
            self.send_message(message)
        print(f"Trace sent: Address: {addr}")
        print(f"")
        self.__log.debug("send_trace(): End")

    def send_message(self, message: Union[Data, Update, Trace]) -> None:
        """
        Forward Messages

        :param message: class object
        """
        self.__log.debug("send_message(): Start")
        self.__routes_lock.acquire()
        self.__links_lock.acquire()

        routes = self.__get_routes(message.get_destination())

        self.__routes_lock.release()
        self.__links_lock.release()

        self.__log.info(
            f"send_message(): Message:\n{json.dumps(message.to_dict(), indent=2, sort_keys=True)}")
        self.__log.info(
            f"Routes:\n{json.dumps(routes, indent=2, sort_keys=True)}")

        if(len(routes) == 0):
            self.__log.error(
                f"Unknown route: Destination: {str(message.get_destination())}")
            self.__log.error(
                f"Routes:\n{json.dumps(dict(self.__routes), indent=2, sort_keys=True)}")
            if 'type' in message.to_dict() and message.to_dict()['type'] == 'trace':
                print(
                    f"Unknown route: Destination: {str(message.get_destination())}")
                print("")
        else:
            data = Packet.to_struct(Packet.json_encoding(message.to_dict()))
            self.__log.info(f"Type of data: {type(data)}")
            self.__sock.sendto(data, (random.choice(routes), DEFAULT_PORT))
        self.__log.debug("send_message(): End")

    def __send_update(self) -> None:
        self.__log.debug(f"send_update(): Start")

        self.__log.info(
            f"Routing Table:\n{json.dumps(dict(self.__routes), indent=2, sort_keys=True)}")

        self.__routes_lock.acquire()
        self.__links_lock.acquire()

        for link in self.__links:
            self.__log.info(f"Iterating over links: Link: {link}")
            distances = {}

            # Get links weight
            for dest in self.__links:
                if (dest != link):
                    distances[dest] = self.__links[dest]

            # Get routes min weight
            for dest in self.__routes:
                self.__log.info(f"Iterating over routes: Destination: {dest}")
                if (dest != link):
                    # removes all entries received from link
                    gateways = list(
                        filter(lambda x: x[0] != link, self.__routes[dest]))
                    if (len(gateways) == 0):
                        continue
                    min_weight, _ = self.__get_min_route(gateways)
                    if (dest not in distances):
                        distances[dest] = min_weight
                    if (dest in distances and distances[dest] > min_weight):
                        distances[dest] = min_weight
                    self.__log.info(
                        f"Update minimum weight: Destination: {dest}, Weight: {min_weight}")

            self.__routes_lock.release()
            self.__links_lock.release()

            message = Update(self.__addr, link, 'update', distances)
            self.__log.info(
                f"Send update message:\nDestination: {link}\nWeights: {distances}")
            self.send_message(message)
            self.__log.info("Send update message done")

            self.__routes_lock.acquire()
            self.__links_lock.acquire()

        self.__routes_lock.release()
        self.__links_lock.release()

        # Resetting the timer
        self.__timer.cancel()
        self.__timer = Timer(self.__period, self.__send_update)
        self.__timer.start()
        self.__log.debug(f"send_update(): End")

    def __handle_message(self) -> None:
        """
        Sort messages and create their respective objects
        """
        self.__log.debug(f"handle_message(): Start")
        message, _ = self.__sock.recvfrom(MAX_UDP_SIZE)
        message_dict = Packet.json_decoding(Packet.to_string(message))

        if (message_dict['type'] == 'data'):
            data_message = Data(
                message_dict['source'], message_dict['destination'], message_dict['type'], message_dict['payload'])
            self.__handle_data_message(data_message)

        elif (message_dict['type'] == 'update'):
            update_message = Update(
                message_dict['source'], message_dict['destination'], message_dict['type'], message_dict['distances'])
            self.__handle_update_message(update_message)

        elif (message_dict['type'] == 'trace'):
            trace_message = Trace(
                message_dict['source'], message_dict['destination'], message_dict['type'], message_dict['hops'])
            self.__handle_trace_message(trace_message)
        self.__log.debug(f"handle_message(): End")

    def __handle_data_message(self, message: Data) -> None:
        """
        handle all Data type messages from the router

        :param message: Data class object
        """
        self.__log.debug("handle_data_message(): Start")
        if (message.get_destination() != self.__addr):
            self.__log.info(
                f"handle_data_message(): Travelling: Destination: {message.get_destination()}")
            self.__log.info(
                f"Payload: {json.dumps(json.loads(message.get_payload()), indent=2, sort_keys=True)}")
            self.send_message(message)
        else:
            self.__log.info(
                f"handle_data_message(): Reached: Destination: {message.get_destination()}")
            self.__log.info(
                f"Payload: {json.dumps(json.loads(message.get_payload()), indent=2, sort_keys=True)}")
            try:
                jsonresp = json.loads(message.get_payload())
                if jsonresp['type'] == 'trace':
                    print(f"Trace complete: ")
                    print(json.dumps(jsonresp, indent=2, sort_keys=True))
                    print(f"")
                elif jsonresp['type'] == 'data':
                    print(f"Received Data: Source: {message.get_source()}")
                    print(jsonresp['data'])
                    print(f"")
            except (json.JSONDecodeError, KeyError) as err:
                self.__log.warning(f"handle_data_message(): Error: {err}")
        self.__log.debug(f"handle_data_message(): End")

    def __handle_update_message(self, message: Update) -> None:
        """
        update messages for routing tables

        :param message: update message type
        """
        self.__log.debug(f"handle_update_message(): Start")
        self.__log.info(
            f"Packet: {json.dumps(message.to_dict(), indent=2, sort_keys=True)}")
        if (message.get_destination() == self.__addr):
            self.__routes_lock.acquire()
            self.__links_lock.acquire()

            if (message.get_source() not in self.__links):
                self.__routes_lock.release()
                self.__links_lock.release()
                return

            # remove old entries from source
            self.__routes_lock.release()
            self.__remove_routes(message.get_source())
            self.__routes_lock.acquire()

            # insert new entries
            link_weight = self.__links[message.get_source()]
            for dest in message.get_distances().keys():
                if (dest not in self.__routes):
                    self.__routes[dest] = []
                self.__routes[dest].append(
                    (message.get_source(), message.get_distances()[dest] + link_weight))

            self.__log.info(f"Source: {message.get_source()}")
            self.__log.info(f"Weights:\n{message.get_distances()}")
            self.__log.info(
                f"Routing Table:\n{json.dumps(dict(self.__routes), indent=2, sort_keys=True)}")

            # update routes timer
            self.__routes_timer_lock.acquire()
            if (message.get_source() in self.__routes_timer):
                self.__routes_timer[message.get_source()].cancel()
            self.__routes_timer[message.get_source()] = Timer(
                4*self.__period, self.__remove_routes, [message.get_source()])
            self.__routes_timer[message.get_source()].start()
            self.__routes_timer_lock.release()

            self.__routes_lock.release()
            self.__links_lock.release()

        else:
            self.send_message(message)
        self.__log.debug(f"handle_update_message(): End")

    def __handle_trace_message(self, message: Trace) -> None:
        """
        handle all Trace packets

        :param message: trace message packet
        """
        self.__log.debug(f"handle_trace_message(): Start")
        # add current address to hops in Trace message
        message.get_hops().append(self.__addr)
        self.__log.info(f"handle_trace_message():")
        self.__log.info(
            f"Packet:\n{json.dumps(message.to_dict(), indent=2, sort_keys=True)}")
        if message.get_destination() == self.__addr:
            # if the destination is found
            trace = Packet.json_encoding(message.to_dict())
            message = Data(self.__addr, message.get_source(), "data", trace)

        self.send_message(message)
        self.__log.debug(f"handle_trace_message(): End")

    def __get_routes(self, dest: str) -> list:
        """
        get routes to the destination

        :param dest: destination IP
        :return: route list
        """
        m = MAX_WEIGHT
        routes = list()

        if (dest in self.__routes):
            m, routes = self.__get_min_route(self.__routes[dest])

        if (dest in self.__links):
            if (self.__links[dest] < m):
                m = self.__links[dest]
                routes = [dest]
            elif (self.__links[dest] == m):
                routes.append(dest)
        self.__log.debug(f"get_routes()\nRoutes: {routes}")
        return routes

    def __get_min_route(self, routes: list) -> Tuple[int, list]:
        """
        Fetch minimum routes from a list

        :param routes: list of all routes in the routing table
        :return: weight and minimum routes
        """
        if (len(routes) == 0):
            self.__log.debug(
                f"get_min_route(): Weight: {MAX_WEIGHT}, Routes: {routes}")
            return MAX_WEIGHT, routes
        min_weight = min(routes, key=lambda x: x[1])[1]
        # acts as a function
        min_routes = list(map(lambda x: x[0], filter(
            lambda x: x[1] == min_weight, routes)))
        self.__log.debug(
            f"get_min_route(): Weight: {min_weight}, Routes: {min_routes}")
        return min_weight, min_routes

    def __check_addr(self, ip_str: str) -> bool:
        """
        check ip address for valid ip

        :param ip: ip address of the router
        :return: boolean true or false
        """
        ip_list = ip_str.split('.')
        if len(ip_list) != 4:
            return False
        for elem in ip_list:
            try:
                if int(elem) < 0 or int(elem) > 255:
                    return False
            except ValueError as err:
                self.__log.error(
                    f"ValueError: Invalid IP {ip_str} Error: {err}")
                LOG.error(f"ValueError: IP: {ip_str}, Error: {err}")
                return False
        return True

    def __reset_timer(self) -> None:
        """
        reset timer
        """
        timer = Timer(self.__period, self.__send_update)
        self.__timer.cancel()
        self.__timer = timer
        self.__timer.start()

    def __remove_routes(self, addr: str) -> None:
        """
        removes routes from routing table

        :param addr: router IP address
        """
        self.__routes_lock.acquire()

        for dest in self.__routes.keys():
            # Removes all old entries from addr
            routes = list(filter(lambda x: x[0] != addr, self.__routes[dest]))
            self.__routes[dest] = routes
            self.__log.debug(f"Remove routes:")
            self.__log.debug(f"Destination: {dest}\nRoutes: {routes}")

        self.__routes_lock.release()

    def __logexit(self, msg: str) -> None:
        """
        exit from program by raising exception

        :param msg: exception message
        """
        raise Exception(f"Exception: {msg}")
