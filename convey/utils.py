# The file is not sourced from __init__ like decorators.py (where we hunt every ms)
# so there is no problem if put here many functions that would cause a bottleneck
import logging
import sys
from threading import Thread, Event, current_thread
from time import sleep
from typing import Callable

logger = logging.getLogger(__name__)


def print_atomic(s):
    """ print not atomic, \n trailed when threading
        If in thread, prints its name.
    """
    n = current_thread().name
    t = "" if n == "MainThread" else "/" + n + "/ "
    sys.stdout.write(t + s + "\n")


def timeout(seconds: int, function: Callable, *args, **kwargs):
    """
    Launch the function in a new thread. If function stops before timeout, returns output or re-raise an exception received.
    If timeout reached, raises TimeoutError and let the thread hang indefinitely, ignoring any successive output or exception.
    However, thread can print to stdout even after TimeoutError has been reached because there is no safe option to kill a thread.
    :param seconds: int
    :param function:
    :param args: Any positional arguments the function receives.
    :param kwargs: Any keyword arguments the function receives.
    :return:
    """
    result = []
    exception = []

    def wrapper(*args, **kwargs):
        try:
            result.append(function(*args, **kwargs))
        except Exception as e:
            exception.append(e)

    thread = Thread(target=wrapper, args=args, kwargs=kwargs)
    thread.daemon = True  # will not block the program exit if hung
    thread.start()
    thread.join(seconds)
    if thread.is_alive():
        raise TimeoutError(f'Timeout {seconds} of {function}')
    else:
        if exception:
            raise exception[0] from None
        return result[0]


def _lazy_print(timeout, msg, done):
    sleep(timeout)
    if not done.is_set():
        logger.info(msg)


def lazy_print(msg: str, timeout: float = 1) -> Event:
    """
    Print message only if time out reached and Event not marked with .set().
    Example:
        l = lazy_print(1, "... still loading")
        l.set() # will not print anything if called under 1 sec
    """
    event = Event()
    Thread(target=_lazy_print, args=(timeout, msg, event)).start()
    return event
