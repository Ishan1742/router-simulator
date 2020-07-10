"""
Creates a logger object
"""

import logging


def get_logger(name: str) -> logging.Logger:
    """
    Creates a logger object of the provided name

    :param name: name of the logger object
    ip specific logging and root logging
    """
    logger = logging.getLogger(name)
    logger.setLevel(level=logging.DEBUG)

    formatter = logging.Formatter(
        '%(asctime)s: %(threadName)s: %(module)s: [%(levelname)s]: %(message)s')

    file_handler = logging.FileHandler('../logs/' + name + '.log')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    return logger
