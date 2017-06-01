from __future__ import with_statement
import pytest

import redis
from redis._compat import b, u, unichr, unicode

from .conftest import add_namespace


class TestPipeline(object):
    def test_pipeline(self, nr):
        with nr.pipeline() as pipe:
            pipe.set('a', 'a1').get('a').zadd('z', z1=1).zadd('z', z2=4)
            pipe.zincrby('z', 'z1').zrange('z', 0, 5, withscores=True)
            assert pipe.execute() == \
                [
                    True,
                    b('a1'),
                    True,
                    True,
                    2.0,
                    [(b('z1'), 2.0), (b('z2'), 4)],
                ]

    def test_pipeline_length(self, nr):
        with nr.pipeline() as pipe:
            # Initially empty.
            assert len(pipe) == 0
            assert not pipe

            # Fill 'er up!
            pipe.set('a', 'a1').set('b', 'b1').set('c', 'c1')
            assert len(pipe) == 3
            assert pipe

            # Execute calls reset(), so empty once again.
            pipe.execute()
            assert len(pipe) == 0
            assert not pipe

    def test_pipeline_no_transaction(self, nr):
        with nr.pipeline(transaction=False) as pipe:
            pipe.set('a', 'a1').set('b', 'b1').set('c', 'c1')
            assert pipe.execute() == [True, True, True]
            assert nr['a'] == b('a1')
            assert nr['b'] == b('b1')
            assert nr['c'] == b('c1')

    def test_pipeline_no_transaction_watch(self, nr):
        nr['a'] = 0

        with nr.pipeline(transaction=False) as pipe:
            pipe.watch('a')
            a = pipe.get('a')

            pipe.multi()
            pipe.set('a', int(a) + 1)
            assert pipe.execute() == [True]

    def test_pipeline_no_transaction_watch_failure(self, nr):
        nr['a'] = 0

        with nr.pipeline(transaction=False) as pipe:
            pipe.watch('a')
            a = pipe.get('a')

            nr['a'] = 'bad'

            pipe.multi()
            pipe.set('a', int(a) + 1)

            with pytest.raises(redis.WatchError):
                pipe.execute()

            assert nr['a'] == b('bad')

    def test_exec_error_in_response(self, nr):
        """
        an invalid pipeline command at exec time adds the exception instance
        to the list of returned values
        """
        nr['c'] = 'a'
        with nr.pipeline() as pipe:
            pipe.set('a', 1).set('b', 2).lpush('c', 3).set('d', 4)
            result = pipe.execute(raise_on_error=False)

            assert result[0]
            assert nr['a'] == b('1')
            assert result[1]
            assert nr['b'] == b('2')

            # we can't lpush to a key that's a string value, so this should
            # be a ResponseError exception
            assert isinstance(result[2], redis.ResponseError)
            assert nr['c'] == b('a')

            # since this isn't a transaction, the other commands after the
            # error are still executed
            assert result[3]
            assert nr['d'] == b('4')

            # make sure the pipe was restored to a working state
            assert pipe.set('z', 'zzz').execute() == [True]
            assert nr['z'] == b('zzz')

    def test_exec_error_raised(self, nr):
        nr['c'] = 'a'
        with nr.pipeline() as pipe:
            pipe.set('a', 1).set('b', 2).lpush('c', 3).set('d', 4)
            with pytest.raises(redis.ResponseError) as ex:
                pipe.execute()
            v = 'Command # 3 (LPUSH {0} 3) of pipeline caused error: '.format(
                add_namespace('c'))
            assert unicode(ex.value).startswith(v)

            # make sure the pipe was restored to a working state
            assert pipe.set('z', 'zzz').execute() == [True]
            assert nr['z'] == b('zzz')

    def test_parse_error_raised(self, nr):
        with nr.pipeline() as pipe:
            # the zrem is invalid because we don't pass any keys to it
            pipe.set('a', 1).zrem('b').set('b', 2)
            with pytest.raises(redis.ResponseError) as ex:
                pipe.execute()

            v = 'Command # 2 (ZREM {0}) of pipeline caused error: '.format(
                add_namespace('b'))
            assert unicode(ex.value).startswith(v)

            # make sure the pipe was restored to a working state
            assert pipe.set('z', 'zzz').execute() == [True]
            assert nr['z'] == b('zzz')

    def test_watch_succeed(self, nr):
        nr['a'] = 1
        nr['b'] = 2

        with nr.pipeline() as pipe:
            pipe.watch('a', 'b')
            assert pipe.watching
            a_value = pipe.get('a')
            b_value = pipe.get('b')
            assert a_value == b('1')
            assert b_value == b('2')
            pipe.multi()

            pipe.set('c', 3)
            assert pipe.execute() == [True]
            assert not pipe.watching

    def test_watch_failure(self, nr):
        nr['a'] = 1
        nr['b'] = 2

        with nr.pipeline() as pipe:
            pipe.watch('a', 'b')
            nr['b'] = 3
            pipe.multi()
            pipe.get('a')
            with pytest.raises(redis.WatchError):
                pipe.execute()

            assert not pipe.watching

    def test_unwatch(self, nr):
        nr['a'] = 1
        nr['b'] = 2

        with nr.pipeline() as pipe:
            pipe.watch('a', 'b')
            nr['b'] = 3
            pipe.unwatch()
            assert not pipe.watching
            pipe.get('a')
            assert pipe.execute() == [b('1')]

    def test_transaction_callable(self, nr):
        nr['a'] = 1
        nr['b'] = 2
        has_run = []

        def my_transaction(pipe):
            a_value = pipe.get('a')
            assert a_value in (b('1'), b('2'))
            b_value = pipe.get('b')
            assert b_value == b('2')

            # silly run-once code... incr's "a" so WatchError should be raised
            # forcing this all to run again. this should incr "a" once to "2"
            if not has_run:
                nr.incr('a')
                has_run.append('it has')

            pipe.multi()
            pipe.set('c', int(a_value) + int(b_value))

        result = nr.transaction(my_transaction, 'a', 'b')
        assert result == [True]
        assert nr['c'] == b('4')

    def test_exec_error_in_no_transaction_pipeline(self, nr):
        nr['a'] = 1
        with nr.pipeline(transaction=False) as pipe:
            pipe.llen('a')
            pipe.expire('a', 100)

            with pytest.raises(redis.ResponseError) as ex:
                pipe.execute()

            v = 'Command # 1 (LLEN {0}) of pipeline caused error: '.format(
                add_namespace('a'))
            assert unicode(ex.value).startswith(v)

        assert nr['a'] == b('1')

    def test_exec_error_in_no_transaction_pipeline_unicode_command(self, nr):
        key = unichr(3456) + u('abcd') + unichr(3421)
        nr[key] = 1
        with nr.pipeline(transaction=False) as pipe:
            pipe.llen(key)
            pipe.expire(key, 100)

            with pytest.raises(redis.ResponseError) as ex:
                pipe.execute()

            expected = unicode('Command # 1 (LLEN %s) of pipeline caused '
                               'error: ') % add_namespace(key)
            assert unicode(ex.value).startswith(expected)

        assert nr[key] == b('1')