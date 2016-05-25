from __future__ import with_statement
import pytest

from redis.namespace import (
    every_other,
    format_arg,
    format_args,
    ignore_last,
    remove_namespace,
)


def dummy_func(*args, **kwargs):
    ns = kwargs.pop('namespace', None)
    return ns + args[0] + kwargs.get('name')


class TestNamespaceFuncs(object):

    def test_every_other(self):
        assert not every_other(1, 4, 0)
        assert every_other(1, 4, 1)
        assert not every_other(1, 4, 2)
        assert every_other(1, 4, 3)

    def test_ignore_last(self):
        assert ignore_last(1, 2, 0)
        assert not ignore_last(1, 2, 1)

    def test_format_args(self):
        keys = format_args(
            "namespace:", ["arg1"], False, 0, None, [], False)
        assert keys == ["namespace:arg1"]

    def test_format_is_recursive(self):
        keys = format_args(
            "namespace:", ["arg1", ["arg2", "arg3"]], True, 0, None, [], False)
        assert keys == ["namespace:arg1", ["namespace:arg2", "namespace:arg3"]]

    def test_format_args_with_skip(self):
        keys = format_args(
            "namespace:", ["arg1", "arg2"], True, 0, None, [0], False
        )
        assert keys == ["arg1", "namespace:arg2"]

    def test_format_args_with_non_string(self):
        keys = format_args(
            "namespace:", [1, "arg2"], True, 0, None, [], False)
        assert keys == [1, "namespace:arg2"]

    def test_format_args_with_method(self):
        keys = format_args(
            "namespace:", ["arg1", "arg2", "arg3"], True, 0, every_other, [],
            False)
        assert keys == ["namespace:arg1", "arg2", "namespace:arg3"]

    def test_format_arg_with_lex(self):
        assert format_arg("namespace:", "arg", True) == "namespace:arg"
        assert format_arg("namespace:", "(arg)", True) == "(namespace:arg)"
        assert format_arg("namespace:", "[arg]", True) == "[namespace:arg]"

    def test_remove_namespace_with_int_float_bool(self):
        assert remove_namespace("namespace:", 1) == 1
        assert remove_namespace("namespace:", 1.1) == 1.1
        assert remove_namespace("namespace:", False) is False

    def test_remove_namespace_with_bytes(self):
        assert remove_namespace("namespace:", b"namespace:val") == b"val"

    def test_remove_namespace_with_bytes_only_removes_first_instance(self):
        assert remove_namespace(
            "namespace:", b"namespace:namespace:val") == b"namespace:val"

    def test_remove_namespace_with_iterable(self):
        resp = remove_namespace(
            "namespace:", [b"namespace:val1", b"namespace:val2"])
        assert resp == (b"val1", b"val2")

    def test_remove_namespace_with_resp_keys(self):
        resp = remove_namespace("namespace:", {
            b"key1": b"namespace:val1",
            b"key2": b"namespace:val2",
            b"key3": b"namespace:val3",
        }, [b"key1", b"key3"])
        assert resp == {
            b"key1": b"val1",
            b"key2": b"namespace:val2",
            b"key3": b"val3",
        }

    def test_namespace_arg_format_gets_namespace(self, nr, monkeypatch):
        def func(namespace, *args):
            raise Exception(namespace)

        key, value = (b'key', b'value')
        monkeypatch.setattr("redis.namespace.format_args", func)
        with pytest.raises(Exception) as e:
            nr.set(key, value)
        assert nr.namespace in str(e.value)

    def test_namespace_resp_format_gets_namespace(self, nr, monkeypatch):
        def func(namespace, *args):
            raise Exception(namespace)

        key, value = (b'key', b'value')
        nr.set(key, value)
        monkeypatch.setattr("redis.namespace.remove_namespace", func)
        with pytest.raises(Exception) as e:
            nr.keys()
        assert nr.namespace in str(e.value)

    def test_namespace_format_with_namespace(self, nr):
        key, value = (b'key', b'value')
        nr.set(key, value)
        assert nr.get(key) == value
