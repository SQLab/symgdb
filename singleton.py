class Singleton(object):
    """
    To be compatible with peda, have to use class way of singleton.
    Neither decorator nor metaclass.
    """
    _instance = None
    _initialized = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(Singleton, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def reset(cls, *args, **kwargs):
        cls._initialized = False
        cls.__init__()
