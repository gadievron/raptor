import yaml
from yaml import SafeLoader


def positional_qualified(data):
    return yaml.load(data, yaml.SafeLoader)


def positional_unqualified(data):
    return yaml.load(data, SafeLoader)


def positional_cloader(data):
    return yaml.load(data, yaml.CSafeLoader)


def positional_base(data):
    return yaml.load(data, yaml.BaseLoader)


def kwarg_qualified(data):
    return yaml.load(data, Loader=yaml.SafeLoader)


def kwarg_unqualified(data):
    return yaml.load(data, Loader=SafeLoader)


def helper(data):
    return yaml.safe_load(data)
