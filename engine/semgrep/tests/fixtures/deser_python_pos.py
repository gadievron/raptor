import jsonpickle
import dill


def restore(payload):
    return jsonpickle.decode(payload)


def restore_blob(blob):
    return dill.loads(blob)
