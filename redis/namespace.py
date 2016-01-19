class NamespaceWrapper():
    FORMAT_METHODS = {
        "every other": lambda arg_start, l, i: arg_start % 2 == i % 2,
        "ignore last": lambda arg_start, l, i: l - 1 != i,
    }
    RESP_METHODS = {
        "mapped_tuple": lambda res: [
            tuple(x) if isinstance(x, list) else x for x in res
        ],
        "tuple": lambda res: tuple(res),
        "recursive": lambda res: NamespaceWrapper.recursive(res)
    }

    def __init__(self, namespace, args):
        self.namespace = namespace
        self.args = list(args)
        self.command_name = args[0]
        self.cmd = CMDS.get(self.command_name, {})
        self.l = len(args) if self.cmd.get('multi', False) else 2
        self.arg_start = self.cmd.get('arg_start', 1)
        self.method = self.FORMAT_METHODS.get(self.cmd.get('method'))
        self.skip = self.cmd.get('skip', [])

    def format_args(self):
        """Appends namespace to applicaple args before sending to redis."""
        if self.cmd.get('format_args', True) and len(self.args) > 1:
            for i in range(self.arg_start, self.l):
                arg = self.args[i]
                if self.should_format(i, arg):
                    self.args[i] = self.format_arg(arg)
        print(self.args)
        return self.args

    def should_format(self, i, arg):
        return all([
            not self.arg_reserved(arg),
            self.can_format(arg),
            self.valid_method(i),
            i not in self.skip,
        ])

    def can_format(self, arg):
        return isinstance(arg, (str, bytes))

    def valid_method(self, i):
        if self.method:
            return self.method(self.arg_start, self.l, i)
        return True

    def arg_reserved(self, arg):
        if arg in ['-', '+', "*", "#", "sorted_values"]:
            return True
        if self.cmd_contains("SCAN") and (arg == "MATCH" or arg == '0'):
            return True
        if self.cmd_contains('STORE') and arg in ['AGGREGATE', 'MAX', 'MIN']:
            return True
        return False

    def cmd_contains(self, x):
        return self.command_name.find(x) > -1

    def format_arg(self, arg):
        if not isinstance(arg, str):
            arg = arg.decode()
        if self.command_name.find('LEX') > -1:
            return self.format_lex_arg(arg)
        return (self.namespace + arg).encode()

    def format_lex_arg(self, arg):
        for v in ['[', '(']:
            if arg.startswith(v):
                return arg.replace(v, v + self.namespace)
        return (self.namespace + arg).encode()

    def format_response(self, response):
        """Removes namespace from responses."""
        print(response)
        if self.cmd.get('format_response', True):
            return self.clean_response(self.remove_namespace(response))
        return response

    def remove_namespace(self, response, keys=[]):
        if isinstance(response, dict) and self.command_name == "SLOWLOG GET":
            response['command'] = self.remove_namespace(response['command'])
        if isinstance(response, (tuple, list)):
            response = [self.remove_namespace(x) for x in response]
        try:
            if isinstance(response, str):
                return response.replace(self.namespace, '', 1)
            else:
                response = response.decode().replace(self.namespace, '', 1)
                return response.encode()
        except (AttributeError, TypeError, UnicodeDecodeError):
            return response

    def clean_response(self, response):
        tuple_method = self.RESP_METHODS.get(self.cmd.get('response_method'))
        if tuple_method and hasattr(response, '__iter__'):
            return tuple_method(response)
        return response

    @staticmethod
    def recursive(l):
        if isinstance(l, (list, tuple)):
            return tuple(map(NamespaceWrapper.recursive, l))
        return l


CMDS = {
    'BITOP': {
        "multi": True,
        "arg_start": 2,
    },
    'BLPOP': {
        "multi": True,
        "method": "ignore last",
        "response_method": "tuple",
    },
    'BRPOP': {
        "multi": True,
        "method": "ignore last",
        "response_method": "tuple",
    },
    'BRPOPLPUSH': {
        "multi": True,
        "method": "ignore last",
    },
    'CLIENT GETNAME': {
        'format_args': False,
    },
    'CONFIG GET': {
        'format_args': False,
    },
    'CONFIG SET': {
        'format_args': False,
    },
    'DEL': {
        'multi': True,
        'format_response': False,
    },
    'FLUSHDB': {
        'format_args': False,
        'format_response': False,
    },
    'INFO': {
        'format_args': False,
    },
    'MGET': {
        "multi": True,
    },
    'MSET': {
        "multi": True,
        "method": "every other",
    },
    'MSETNX': {
        "multi": True,
        "method": "every other",
    },
    'OBJECT': {
        'multi': True,
        'format_response': False,
        'arg_start': 2,
    },
    'PFCOUNT': {
        "multi": True,
    },
    'PFMERGE': {
        "multi": True,
    },
    'RENAME': {
        "multi": True,
        "format_response": False,
    },
    'RENAMENX': {
        "multi": True,
        "format_response": False,
    },
    'RPOPLPUSH': {
        "multi": True,
    },
    'SCAN': {
        "multi": True,
        "skip": [1],
        "response_method": "recursive",
    },
    'SDIFF': {
        "multi": True,
    },
    'SDIFFSTORE': {
        "multi": True,
    },
    'SINTER': {
        'multi': True,
    },
    'SINTERSTORE': {
        "multi": True,
    },
    'SLOWLOG GET': {
        "format_args": False,
        "resp_keys": ["command"],
    },
    'SMOVE': {
        "multi": True,
        "method": "ignore last",
    },
    'SORT': {
        'multi': True,
        "response_method": "mapped_tuple",
    },
    'SUNION': {
        'multi': True,
    },
    'SUNIONSTORE': {
        "multi": True,
    },
    'ZADD': {
        "multi": True,
        "method": "every other",
    },
    'ZINCRBY': {
        "multi": True,
    },
    'ZINTERSTORE': {
        "multi": True,
        "skip": [2],
    },
    'ZLEXCOUNT': {
        "multi": True,
    },
    'ZRANGE': {
        "response_method": "mapped_tuple",
    },
    'ZRANGEBYLEX': {
        "multi": True,
    },
    'ZRANGEBYSCORE': {
        "response_method": "mapped_tuple",
    },
    'ZRANK': {
        "multi": True,
    },
    'ZREM': {
        "multi": True,
    },
    'ZREMRANGEBYLEX': {
        "multi": True,
    },
    'ZREMRANGEBYRANK': {
        "multi": True,
    },
    'ZREMRANGEBYSCORE': {
        "multi": True,
    },
    'ZREVRANGE': {
        "response_method": "mapped_tuple",
    },
    'ZREVRANGEBYLEX': {
        "multi": True,
    },
    'ZREVRANGEBYSCORE': {
        "response_method": "mapped_tuple",
    },
    'ZREVRANK': {
        "multi": True,
    },
    'ZSCAN': {
        "multi": True,
        "response_method": "recursive",
    },
    'ZSCORE': {
        "multi": True,
    },
    'ZUNIONSTORE': {
        "multi": True,
        "skip": [2],
    },
}
