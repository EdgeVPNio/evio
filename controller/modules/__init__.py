
def to_repr(obj):
    return "{{{}}}".format(", ".join((f"\"{k}\": {obj.__dict__[k]!r}" for k in
                                        (obj._REFLECT if hasattr(obj, "_REFLECT") else obj.__dict__.keys()))))
