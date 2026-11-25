import select
from collections.abc import Callable

EventHandler = Callable[[int, int], None]
TickCallback = Callable[[], None]


class EventLoop:
    def __init__(self) -> None:
        self._epoll = select.epoll()
        self._handlers: dict[int, EventHandler] = {}
        self._tick_callbacks: list[TickCallback] = []

    def register(self, fd: int, events: int, handler: EventHandler) -> None:
        self._handlers[fd] = handler
        self._epoll.register(fd, events)

    def modify(self, fd: int, events: int) -> None:
        self._epoll.modify(fd, events)

    def unregister(self, fd: int) -> None:
        if fd in self._handlers:
            del self._handlers[fd]
        try:
            self._epoll.unregister(fd)
        except OSError:
            pass

    def add_tick_callback(self, callback: TickCallback) -> None:
        if callback not in self._tick_callbacks:
            self._tick_callbacks.append(callback)

    def remove_tick_callback(self, callback: TickCallback) -> None:
        if callback in self._tick_callbacks:
            self._tick_callbacks.remove(callback)

    @property
    def has_handlers(self) -> bool:
        return bool(self._handlers)

    def run(self, poll_interval: float = 0.05) -> None:
        try:
            while self._handlers:
                for callback in list(self._tick_callbacks):
                    callback()

                if not self._handlers:
                    break

                events = self._epoll.poll(poll_interval)
                for fd, event in events:
                    if fd in self._handlers:
                        self._handlers[fd](fd, event)
        finally:
            self.close()

    def close(self) -> None:
        try:
            self._epoll.close()
        except OSError:
            pass
