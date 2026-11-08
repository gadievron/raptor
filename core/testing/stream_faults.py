"""Real stream contexts with owned read/write and teardown fault injection."""


class FaultingStream:
    """Delegate stream behavior, close the real resource, then inject a fault."""
    def __init__(self, stream, *, primary=None, cleanup=None, operation='read'):
        self.stream = stream
        self.primary = primary
        self.cleanup = cleanup
        self.operation = operation
        self.exits = []

    def __enter__(self):
        self.stream.__enter__()
        return self

    def __exit__(self, *details):
        self.exits.append(details)
        result = self.stream.__exit__(*details)
        if self.cleanup is not None:
            raise self.cleanup
        return result

    def __getattr__(self, name):
        return getattr(self.stream, name)

    def read(self, *args):
        if self.operation == 'read' and self.primary is not None:
            raise self.primary
        return self.stream.read(*args)

    def write(self, value):
        result = self.stream.write(value)
        if self.operation == 'write' and self.primary is not None:
            raise self.primary
        return result
