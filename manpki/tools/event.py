from time import time

class EventEmitter:
    __CBKEY = "__callbacks"

    def __init__(self):
        """ EventEmitter
        The EventEmitter class.
        """

        self.__delimiter = "."
        self.__tree = self.__new_branch()

    @property
    def delimiter(self):
        """
        *delimiter* getter.
        """
        return self.__delimiter

    @classmethod
    def __new_branch(cls):
        """
        Returns a new branch. Basically, a branch is just a dictionary with
        a special item *__CBKEY* that holds registered functions. All other
        items are used to build a tree structure.
        """
        return {cls.__CBKEY: []}

    def __find_branch(self, event):
        """
        Returns a branch of the tree stucture that matches *event*.
        """
        parts = event.split(self.delimiter)

        if self.__CBKEY in parts:
            return None

        branch = self.__tree
        for p in parts:
            if p not in branch:
                return None
            branch = branch[p]

        return branch

    @classmethod
    def __remove_listener(cls, branch, func):
        """
        Removes a listener given by its function from a branch.
        """
        listeners = branch[cls.__CBKEY]

        indexes = [i for i, l in enumerate(listeners) if l.func == func]
        indexes.reverse()

        for i in indexes:
            listeners.pop(i)

    def on(self, event, func=None):
        """
        Registers a function to an event. When *func* is *None*, decorator
        usage is assumed.
        Returns the function.
        """

        def _on(func):
            if not hasattr(func, "__call__"):
                return func

            parts = event.split(self.delimiter)

            if self.__CBKEY in parts:
                return func

            branch = self.__tree
            for p in parts:
                branch = branch.setdefault(p, self.__new_branch())

            listeners = branch[self.__CBKEY]

            listener = Listener(func, event)
            listeners.append(listener)

            return func

        if func is not None:
            return _on(func)
        else:
            return _on

    def on_any(self, func=None):
        """
        Registers a function that is called every time an event is emitted.
        When *func* is *None*, decorator usage is assumed. Returns the function.
        """

        def _on_any(func):
            if not hasattr(func, "__call__"):
                return func

            listeners = self.__tree[self.__CBKEY]

            listener = Listener(func, None)
            listeners.append(listener)

            return func

        if func is not None:
            return _on_any(func)
        else:
            return _on_any

    def off(self, event, func=None):
        """
        Removes a function that is registered to an event. When *func* is
        *None*, decorator usage is assumed. Returns the function.
        """

        def _off(func):
            branch = self.__find_branch(event)
            if branch is None:
                return func

            self.__remove_listener(branch, func)

            return func

        if func is not None:
            return _off(func)
        else:
            return _off

    def off_any(self, func=None):
        """
        Removes a function that was registered via *on_any*. When *func* is
        *None*, decorator usage is assumed. Returns the function.
        """

        def _off_any(func):
            self.__remove_listener(self.__tree, func)

            return func

        if func is not None:
            return _off_any(func)
        else:
            return _off_any

    def off_all(self):
        """
        Removes all registerd functions.
        """
        del self.__tree
        self.__tree = self.__new_branch()

    def listeners(self, event):
        """
        Returns all functions that are registered to an event.
        """
        branch = self.__find_branch(event)
        if branch is None:
            return []

        return [l.func for l in branch[self.__CBKEY]]

    def listeners_any(self):
        """
        Returns all functions that were registered using *on_any*.
        """
        return [l.func for l in self.__tree[self.__CBKEY]]

    def listeners_all(self):
        """
        Returns all registered functions.
        """
        listeners = self.__tree[self.__CBKEY][:]

        branches = list(self.__tree.values())
        for b in branches:
            if not isinstance(b, dict):
                continue

            branches.extend(list(b.values()))

            listeners.extend(b[self.__CBKEY])

        listeners.sort(key=lambda l: l.time)

        return [l.func for l in listeners]

    def emit(self, event, *args, **kwargs):
        """
        Emits an event. All functions of events that match *event* are invoked
        with *args* and *kwargs* in the exact order of their registration.
        """
        parts = event.split(self.delimiter)

        if self.__CBKEY in parts:
            return False

        listeners = self.__tree[self.__CBKEY][:]

        branches = [self.__tree]

        for p in parts:
            _branches = []
            for branch in branches:
                for k, b in branch.items():
                    if k == self.__CBKEY:
                        continue
                    if k == p:
                        _branches.append(b)
            branches = _branches

        for b in branches:
            listeners.extend(b[self.__CBKEY])

        listeners.sort(key=lambda l: l.time)

        remove = [l for l in listeners if not l(*args, **kwargs)]

        for l in remove:
            if l.event:
                self.off(l.event, func=l.func)


class Listener:
    def __init__(self, func, event):
        """
        The Listener class.
        Listener instances are simple structs to handle functions
        """

        self.func = func
        self.event = event
        self.time = time()

    def __call__(self, *args, **kwargs):
        """
        Invokes the wrapped function.
        """
        return self.func(*args, **kwargs)


event = EventEmitter()
