import yaml


def bare_load(data):
    return yaml.load(data)


def explicit_unsafe(data):
    return yaml.load(data, Loader=yaml.UnsafeLoader)
