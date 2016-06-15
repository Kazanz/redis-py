def cmd_execution_wrapper(f, cmd):
    """
    Wraps redis class' `execute_command` so that it can be decorated by
    namepace_format.  This is necesary when the func calling `execute_commad`
    has kwargs that are turned into regular args inside of the method before
    being passed to `execute_command`.
    """
    def execute_command(self, *args, **kwargs):
        args = (cmd,) + args
        return f(*args, **kwargs)
    return execute_command


def namespace_format(arg_format=True, resp_format=False, multi=False,
                     arg_start=0, method=None, skip=[], resp_keys=[]):
    """Decorator to format args and responses of redis funcs with namespaces.

    :param arg_format: If True add namespace to args passed to the func.
    :param resp_format: If True remove namespace from response values of func.
    :param multi: Should be True if function takes an arbitrary # of variables.
    :param arg_start: Index of where the arguments passed to redis start.
    :param method: Func called on arg and arg index that returns True when the
        arg is a value that should receive the namespace.
    :param skip: List of indexes of args to not append namespace to.
    :param resp_keys: List of keys in the response where the values need
        namespace removal.
    """
    def decorator(f):
        def wrapper(self, *args, **kwargs):
            if self.namespace:
                args = list(args or f.__defaults__)
                if arg_format and args:
                    args = format_args(self.namespace, args, multi, arg_start,
                                       method, skip)
            response = f(self, *args, **kwargs)
            if self.namespace and resp_format:
                response = remove_namespace(self.namespace, response, resp_keys)
            return response
        return wrapper
    return decorator


def format_args(namespace, args, multi=False, arg_start=0, method=None,
                skip=[]):
    """Append namespace to applicaple args before returning to send to redis."""
    l = len(args) if multi else 1
    for i in range(arg_start, l):
        arg = args[i]
        if i in skip:
            continue
        elif isinstance(arg, (list, tuple)):
            args[i] = format_args(namespace, arg, multi=True)
        elif not isinstance(arg, (str, bytes)):
            continue
        elif method and not method(arg_start, l, i):
            continue
        else:
            args[i] = format_arg(namespace, arg)
    return args


def format_arg(namespace, arg):
    """Appends the namespace to the arg."""
    try:
        return namespace + arg
    except:
        return str.encode(namespace) + arg


def remove_namespace(namespace, response, resp_keys=[]):
    """Removes any namespace from a redis response."""
    if isinstance(namespace, str):
        namespace = str.encode(namespace)
    for key in resp_keys:
        response[key] = remove_namespace(namespace, response[key])
    if isinstance(response, (int, float, bool)):
        pass
    elif isinstance(response, bytes):
        response = response.replace(namespace, b'', 1)
    elif isinstance(response, (tuple, list)):
        response = tuple([remove_namespace(namespace, x) for x in response])
    return response


def every_other(arg_start, l, i):
    return arg_start % 2 == i % 2


def ignore_last(arg_start, l, i):
    return l - 1 != i
