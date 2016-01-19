from __future__ import with_statement
import binascii
import datetime
import pytest
import redis
import time

from redis._compat import (unichr, u, b, ascii_letters, iteritems, iterkeys,
                           itervalues)
from redis.client import parse_info
from redis import exceptions

from .conftest import skip_if_server_version_lt


@pytest.fixture()
def slowlog(request, nsr):
    current_config = nsr.config_get()
    old_slower_than_value = current_config['slowlog-log-slower-than']
    old_max_legnth_value = current_config['slowlog-max-len']

    def cleanup():
        nsr.config_set('slowlog-log-slower-than', old_slower_than_value)
        nsr.config_set('slowlog-max-len', old_max_legnth_value)
    request.addfinalizer(cleanup)

    nsr.config_set('slowlog-log-slower-than', 0)
    nsr.config_set('slowlog-max-len', 128)


def redis_server_time(client):
    seconds, milliseconds = client.time()
    timestamp = float('%s.%s' % (seconds, milliseconds))
    return datetime.datetime.fromtimestamp(timestamp)


class TestRedisCommands(object):

    def test_nsr_command_on_invalid_key_type(self, nsr):
        nsr.lpush('a', '1')
        with pytest.raises(redis.ResponseError):
            nsr['a']

    # SERVER INFORMATION
    def test_nsr_client_list(self, nsr):
        clients = nsr.client_list()
        assert isinstance(clients[0], dict)
        assert 'addr' in clients[0]

    @skip_if_server_version_lt('2.6.9')
    def test_nsr_client_getname(self, nsr):
        assert nsr.client_getname() is None

    @skip_if_server_version_lt('2.6.9')
    def test_nsr_client_setname(self, nsr):
        assert nsr.client_setname('redis_py_test')
        assert nsr.client_getname() == 'redis_py_test'

    def test_nsr_config_get(self, nsr):
        data = nsr.config_get()
        assert 'maxmemory' in data
        assert data['maxmemory'].isdigit()

    def test_nsr_config_resetstat(self, nsr):
        nsr.ping()
        prior_commands_processed = int(nsr.info()['total_commands_processed'])
        assert prior_commands_processed >= 1
        nsr.config_resetstat()
        reset_commands_processed = int(nsr.info()['total_commands_processed'])
        assert reset_commands_processed < prior_commands_processed

    def test_nsr_config_set(self, nsr):
        data = nsr.config_get()
        rdbname = data['dbfilename']
        try:
            assert nsr.config_set('dbfilename', 'redis_py_test.rdb')
            assert nsr.config_get()['dbfilename'] == 'redis_py_test.rdb'
        finally:
            assert nsr.config_set('dbfilename', rdbname)

    def test_nsr_dbsize(self, nsr):
        nsr['a'] = 'foo'
        nsr['b'] = 'bar'
        assert nsr.dbsize() == 2

    def test_nsr_echo(self, nsr):
        assert nsr.echo('foo bar') == b('foo bar')

    def test_nsr_info(self, nsr):
        nsr['a'] = 'foo'
        nsr['b'] = 'bar'
        info = nsr.info()
        assert isinstance(info, dict)
        assert info['db9']['keys'] == 2

    def test_nsr_lastsave(self, nsr):
        assert isinstance(nsr.lastsave(), datetime.datetime)

    def test_nsr_object(self, nsr):
        nsr['a'] = 'foo'
        assert isinstance(nsr.object('refcount', 'a'), int)
        assert isinstance(nsr.object('idletime', 'a'), int)
        assert nsr.object('encoding', 'a') in (b('raw'), b('embstr'))
        assert nsr.object('idletime', 'invalid-key') is None

    def test_nsr_ping(self, nsr):
        assert nsr.ping()

    def test_nsr_slowlog_get(self, nsr, slowlog):
        assert nsr.slowlog_reset()
        unicode_string = unichr(3456) + u('abcd') + unichr(3421)
        nsr.get(unicode_string)
        slowlog = nsr.slowlog_get()
        assert isinstance(slowlog, list)
        commands = [log['command'] for log in slowlog]

        get_command = b(' ').join((b('GET'), unicode_string.encode('utf-8')))
        assert get_command in commands
        assert b('SLOWLOG RESET') in commands
        # the order should be ['GET <uni string>', 'SLOWLOG RESET'],
        # but if other clients are executing commands at the same time, there
        # could be commands, before, between, or after, so just check that
        # the two we care about are in the appropriate ordensr.
        assert commands.index(get_command) < commands.index(b('SLOWLOG RESET'))

        # make sure other attributes are typed correctly
        assert isinstance(slowlog[0]['start_time'], int)
        assert isinstance(slowlog[0]['duration'], int)

    def test_nsr_slowlog_get_limit(self, nsr, slowlog):
        assert nsr.slowlog_reset()
        nsr.get('foo')
        nsr.get('bar')
        slowlog = nsr.slowlog_get(1)
        assert isinstance(slowlog, list)
        commands = [log['command'] for log in slowlog]
        assert b('GET foo') not in commands
        assert b('GET bar') in commands

    def test_nsr_slowlog_length(self, nsr, slowlog):
        nsr.get('foo')
        assert isinstance(nsr.slowlog_len(), int)

    @skip_if_server_version_lt('2.6.0')
    def test_nsr_time(self, nsr):
        t = nsr.time()
        assert len(t) == 2
        assert isinstance(t[0], int)
        assert isinstance(t[1], int)

    # BASIC KEY COMMANDS
    def test_nsr_append(self, nsr):
        assert nsr.append('a', 'a1') == 2
        assert nsr['a'] == b('a1')
        assert nsr.append('a', 'a2') == 4
        assert nsr['a'] == b('a1a2')

    @skip_if_server_version_lt('2.6.0')
    def test_nsr_bitcount(self, nsr):
        nsr.setbit('a', 5, True)
        assert nsr.bitcount('a') == 1
        nsr.setbit('a', 6, True)
        assert nsr.bitcount('a') == 2
        nsr.setbit('a', 5, False)
        assert nsr.bitcount('a') == 1
        nsr.setbit('a', 9, True)
        nsr.setbit('a', 17, True)
        nsr.setbit('a', 25, True)
        nsr.setbit('a', 33, True)
        assert nsr.bitcount('a') == 5
        assert nsr.bitcount('a', 0, -1) == 5
        assert nsr.bitcount('a', 2, 3) == 2
        assert nsr.bitcount('a', 2, -1) == 3
        assert nsr.bitcount('a', -2, -1) == 2
        assert nsr.bitcount('a', 1, 1) == 1

    @skip_if_server_version_lt('2.6.0')
    def test_nsr_bitop_not_empty_string(self, nsr):
        nsr['a'] = ''
        nsr.bitop('not', 'r', 'a')
        assert nsr.get('r') is None

    @skip_if_server_version_lt('2.6.0')
    def test_nsr_bitop_not(self, nsr):
        test_str = b('\xAA\x00\xFF\x55')
        correct = ~0xAA00FF55 & 0xFFFFFFFF
        nsr['a'] = test_str
        nsr.bitop('not', 'r', 'a')
        assert int(binascii.hexlify(nsr['r']), 16) == correct

    @skip_if_server_version_lt('2.6.0')
    def test_nsr_bitop_not_in_place(self, nsr):
        test_str = b('\xAA\x00\xFF\x55')
        correct = ~0xAA00FF55 & 0xFFFFFFFF
        nsr['a'] = test_str
        nsr.bitop('not', 'a', 'a')
        assert int(binascii.hexlify(nsr['a']), 16) == correct

    @skip_if_server_version_lt('2.6.0')
    def test_nsr_bitop_single_string(self, nsr):
        test_str = b('\x01\x02\xFF')
        nsr['a'] = test_str
        nsr.bitop('and', 'res1', 'a')
        nsr.bitop('or', 'res2', 'a')
        nsr.bitop('xor', 'res3', 'a')
        assert nsr['res1'] == test_str
        assert nsr['res2'] == test_str
        assert nsr['res3'] == test_str

    @skip_if_server_version_lt('2.6.0')
    def test_nsr_bitop_string_operands(self, nsr):
        nsr['a'] = b('\x01\x02\xFF\xFF')
        nsr['b'] = b('\x01\x02\xFF')
        nsr.bitop('and', 'res1', 'a', 'b')
        nsr.bitop('or', 'res2', 'a', 'b')
        nsr.bitop('xor', 'res3', 'a', 'b')
        assert int(binascii.hexlify(nsr['res1']), 16) == 0x0102FF00
        assert int(binascii.hexlify(nsr['res2']), 16) == 0x0102FFFF
        assert int(binascii.hexlify(nsr['res3']), 16) == 0x000000FF

    @skip_if_server_version_lt('2.8.7')
    def test_nsr_bitpos(self, nsr):
        key = 'key:bitpos'
        nsr.set(key, b('\xff\xf0\x00'))
        assert nsr.bitpos(key, 0) == 12
        assert nsr.bitpos(key, 0, 2, -1) == 16
        assert nsr.bitpos(key, 0, -2, -1) == 12
        nsr.set(key, b('\x00\xff\xf0'))
        assert nsr.bitpos(key, 1, 0) == 8
        assert nsr.bitpos(key, 1, 1) == 8
        nsr.set(key, b('\x00\x00\x00'))
        assert nsr.bitpos(key, 1) == -1

    @skip_if_server_version_lt('2.8.7')
    def test_nsr_bitpos_wrong_arguments(self, nsr):
        key = 'key:bitpos:wrong:args'
        nsr.set(key, b('\xff\xf0\x00'))
        with pytest.raises(exceptions.RedisError):
            nsr.bitpos(key, 0, end=1) == 12
        with pytest.raises(exceptions.RedisError):
            nsr.bitpos(key, 7) == 12

    def test_nsr_decr(self, nsr):
        assert nsr.decr('a') == -1
        assert nsr['a'] == b('-1')
        assert nsr.decr('a') == -2
        assert nsr['a'] == b('-2')
        assert nsr.decr('a', amount=5) == -7
        assert nsr['a'] == b('-7')

    def test_nsr_delete(self, nsr):
        assert nsr.delete('a') == 0
        nsr['a'] = 'foo'
        assert nsr.delete('a') == 1

    def test_nsr_delete_with_multiple_keys(self, nsr):
        nsr['a'] = 'foo'
        nsr['b'] = 'bar'
        assert nsr.delete('a', 'b') == 2
        assert nsr.get('a') is None
        assert nsr.get('b') is None

    def test_nsr_delitem(self, nsr):
        nsr['a'] = 'foo'
        del nsr['a']
        assert nsr.get('a') is None

    @skip_if_server_version_lt('2.6.0')
    def test_nsr_dump_and_restore(self, nsr):
        nsr['a'] = 'foo'
        dumped = nsr.dump('a')
        del nsr['a']
        nsr.restore('a', 0, dumped)
        assert nsr['a'] == b('foo')

    def test_nsr_exists(self, nsr):
        assert not nsr.exists('a')
        nsr['a'] = 'foo'
        assert nsr.exists('a')

    def test_nsr_exists_contains(self, nsr):
        assert 'a' not in nsr
        nsr['a'] = 'foo'
        assert 'a' in nsr

    def test_nsr_expire(self, nsr):
        assert not nsr.expire('a', 10)
        nsr['a'] = 'foo'
        assert nsr.expire('a', 10)
        assert 0 < nsr.ttl('a') <= 10
        assert nsr.persist('a')
        assert not nsr.ttl('a')

    def test_nsr_expireat_datetime(self, nsr):
        expire_at = redis_server_time(nsr) + datetime.timedelta(minutes=1)
        nsr['a'] = 'foo'
        assert nsr.expireat('a', expire_at)
        assert 0 < nsr.ttl('a') <= 61

    def test_nsr_expireat_no_key(self, nsr):
        expire_at = redis_server_time(nsr) + datetime.timedelta(minutes=1)
        assert not nsr.expireat('a', expire_at)

    def test_nsr_expireat_unixtime(self, nsr):
        expire_at = redis_server_time(nsr) + datetime.timedelta(minutes=1)
        nsr['a'] = 'foo'
        expire_at_seconds = int(time.mktime(expire_at.timetuple()))
        assert nsr.expireat('a', expire_at_seconds)
        assert 0 < nsr.ttl('a') <= 61

    def test_nsr_get_and_set(self, nsr):
        # get and set can't be tested independently of each other
        assert nsr.get('a') is None
        byte_string = b('value')
        integer = 5
        unicode_string = unichr(3456) + u('abcd') + unichr(3421)
        assert nsr.set('byte_string', byte_string)
        assert nsr.set('integer', 5)
        assert nsr.set('unicode_string', unicode_string)
        assert nsr.get('byte_string') == byte_string
        assert nsr.get('integer') == b(str(integer))
        assert nsr.get('unicode_string').decode('utf-8') == unicode_string

    def test_nsr_getitem_and_setitem(self, nsr):
        nsr['a'] = 'bar'
        assert nsr['a'] == b('bar')

    def test_nsr_getitem_raises_keyerror_for_missing_key(self, nsr):
        with pytest.raises(KeyError):
            nsr['a']

    def test_nsr_getitem_does_not_raise_keyerror_for_empty_string(self, nsr):
        nsr['a'] = b("")
        assert nsr['a'] == b("")

    def test_nsr_get_set_bit(self, nsr):
        # no value
        assert not nsr.getbit('a', 5)
        # set bit 5
        assert not nsr.setbit('a', 5, True)
        assert nsr.getbit('a', 5)
        # unset bit 4
        assert not nsr.setbit('a', 4, False)
        assert not nsr.getbit('a', 4)
        # set bit 4
        assert not nsr.setbit('a', 4, True)
        assert nsr.getbit('a', 4)
        # set bit 5 again
        assert nsr.setbit('a', 5, True)
        assert nsr.getbit('a', 5)

    def test_nsr_getrange(self, nsr):
        nsr['a'] = 'foo'
        assert nsr.getrange('a', 0, 0) == b('f')
        assert nsr.getrange('a', 0, 2) == b('foo')
        assert nsr.getrange('a', 3, 4) == b('')

    def test_nsr_getset(self, nsr):
        assert nsr.getset('a', 'foo') is None
        assert nsr.getset('a', 'bar') == b('foo')
        assert nsr.get('a') == b('bar')

    def test_nsr_incr(self, nsr):
        assert nsr.incr('a') == 1
        assert nsr['a'] == b('1')
        assert nsr.incr('a') == 2
        assert nsr['a'] == b('2')
        assert nsr.incr('a', amount=5) == 7
        assert nsr['a'] == b('7')

    def test_nsr_incrby(self, nsr):
        assert nsr.incrby('a') == 1
        assert nsr.incrby('a', 4) == 5
        assert nsr['a'] == b('5')

    @skip_if_server_version_lt('2.6.0')
    def test_nsr_incrbyfloat(self, nsr):
        assert nsr.incrbyfloat('a') == 1.0
        assert nsr['a'] == b('1')
        assert nsr.incrbyfloat('a', 1.1) == 2.1
        assert float(nsr['a']) == float(2.1)

    def test_nsr_keys(self, nsr):
        assert nsr.keys() == []
        keys_with_underscores = set([b('test_a'), b('test_b')])
        keys = keys_with_underscores.union(set([b('testc')]))
        for key in keys:
            nsr[key] = 1
        assert set(nsr.keys(pattern='test_*')) == keys_with_underscores
        assert set(nsr.keys(pattern='test*')) == keys

    def test_nsr_mget(self, nsr):
        assert nsr.mget(['a', 'b']) == [None, None]
        nsr['a'] = '1'
        nsr['b'] = '2'
        nsr['c'] = '3'
        val = nsr.mget('a', 'other', 'b', 'c')
        assert val == [b('1'), None, b('2'), b('3')]

    def test_nsr_mset(self, nsr):
        d = {'a': b('1'), 'b': b('2'), 'c': b('3')}
        assert nsr.mset(d)
        for k, v in iteritems(d):
            assert nsr[k] == v

    def test_nsr_mset_kwargs(self, nsr):
        d = {'a': b('1'), 'b': b('2'), 'c': b('3')}
        assert nsr.mset(**d)
        for k, v in iteritems(d):
            assert nsr[k] == v

    def test_nsr_msetnx(self, nsr):
        d = {'a': b('1'), 'b': b('2'), 'c': b('3')}
        assert nsr.msetnx(d)
        d2 = {'a': b('x'), 'd': b('4')}
        assert not nsr.msetnx(d2)
        for k, v in iteritems(d):
            assert nsr[k] == v
        assert nsr.get('d') is None

    def test_nsr_msetnx_kwargs(self, nsr):
        d = {'a': b('1'), 'b': b('2'), 'c': b('3')}
        assert nsr.msetnx(**d)
        d2 = {'a': b('x'), 'd': b('4')}
        assert not nsr.msetnx(**d2)
        for k, v in iteritems(d):
            assert nsr[k] == v
        assert nsr.get('d') is None

    @skip_if_server_version_lt('2.6.0')
    def test_nsr_pexpire(self, nsr):
        assert not nsr.pexpire('a', 60000)
        nsr['a'] = 'foo'
        assert nsr.pexpire('a', 60000)
        assert 0 < nsr.pttl('a') <= 60000
        assert nsr.persist('a')
        assert nsr.pttl('a') is None

    @skip_if_server_version_lt('2.6.0')
    def test_nsr_pexpireat_datetime(self, nsr):
        expire_at = redis_server_time(nsr) + datetime.timedelta(minutes=1)
        nsr['a'] = 'foo'
        assert nsr.pexpireat('a', expire_at)
        assert 0 < nsr.pttl('a') <= 61000

    @skip_if_server_version_lt('2.6.0')
    def test_nsr_pexpireat_no_key(self, nsr):
        expire_at = redis_server_time(nsr) + datetime.timedelta(minutes=1)
        assert not nsr.pexpireat('a', expire_at)

    @skip_if_server_version_lt('2.6.0')
    def test_nsr_pexpireat_unixtime(self, nsr):
        expire_at = redis_server_time(nsr) + datetime.timedelta(minutes=1)
        nsr['a'] = 'foo'
        expire_at_seconds = int(time.mktime(expire_at.timetuple())) * 1000
        assert nsr.pexpireat('a', expire_at_seconds)
        assert 0 < nsr.pttl('a') <= 61000

    @skip_if_server_version_lt('2.6.0')
    def test_nsr_psetex(self, nsr):
        assert nsr.psetex('a', 1000, 'value')
        assert nsr['a'] == b('value')
        assert 0 < nsr.pttl('a') <= 1000

    @skip_if_server_version_lt('2.6.0')
    def test_nsr_psetex_timedelta(self, nsr):
        expire_at = datetime.timedelta(milliseconds=1000)
        assert nsr.psetex('a', expire_at, 'value')
        assert nsr['a'] == b('value')
        assert 0 < nsr.pttl('a') <= 1000

    def test_nsr_randomkey(self, nsr):
        assert nsr.randomkey() is None
        for key in ('a', 'b', 'c'):
            nsr[key] = 1
        assert nsr.randomkey() in (b('a'), b('b'), b('c'))

    def test_nsr_rename(self, nsr):
        nsr['a'] = '1'
        assert nsr.rename('a', 'b')
        assert nsr.get('a') is None
        assert nsr['b'] == b('1')

    def test_nsr_renamenx(self, nsr):
        nsr['a'] = '1'
        nsr['b'] = '2'
        assert not nsr.renamenx('a', 'b')
        assert nsr['a'] == b('1')
        assert nsr['b'] == b('2')

    @skip_if_server_version_lt('2.6.0')
    def test_nsr_set_nx(self, nsr):
        assert nsr.set('a', '1', nx=True)
        assert not nsr.set('a', '2', nx=True)
        assert nsr['a'] == b('1')

    @skip_if_server_version_lt('2.6.0')
    def test_nsr_set_xx(self, nsr):
        assert not nsr.set('a', '1', xx=True)
        assert nsr.get('a') is None
        nsr['a'] = 'bar'
        assert nsr.set('a', '2', xx=True)
        assert nsr.get('a') == b('2')

    @skip_if_server_version_lt('2.6.0')
    def test_nsr_set_px(self, nsr):
        assert nsr.set('a', '1', px=10000)
        assert nsr['a'] == b('1')
        assert 0 < nsr.pttl('a') <= 10000
        assert 0 < nsr.ttl('a') <= 10

    @skip_if_server_version_lt('2.6.0')
    def test_nsr_set_px_timedelta(self, nsr):
        expire_at = datetime.timedelta(milliseconds=1000)
        assert nsr.set('a', '1', px=expire_at)
        assert 0 < nsr.pttl('a') <= 1000
        assert 0 < nsr.ttl('a') <= 1

    @skip_if_server_version_lt('2.6.0')
    def test_nsr_set_ex(self, nsr):
        assert nsr.set('a', '1', ex=10)
        assert 0 < nsr.ttl('a') <= 10

    @skip_if_server_version_lt('2.6.0')
    def test_nsr_set_ex_timedelta(self, nsr):
        expire_at = datetime.timedelta(seconds=60)
        assert nsr.set('a', '1', ex=expire_at)
        assert 0 < nsr.ttl('a') <= 60

    @skip_if_server_version_lt('2.6.0')
    def test_nsr_set_multipleoptions(self, nsr):
        nsr['a'] = 'val'
        assert nsr.set('a', '1', xx=True, px=10000)
        assert 0 < nsr.ttl('a') <= 10

    def test_nsr_setex(self, nsr):
        assert nsr.setex('a', '1', 60)
        assert nsr['a'] == b('1')
        assert 0 < nsr.ttl('a') <= 60

    def test_nsr_setnx(self, nsr):
        assert nsr.setnx('a', '1')
        assert nsr['a'] == b('1')
        assert not nsr.setnx('a', '2')
        assert nsr['a'] == b('1')

    def test_nsr_setrange(self, nsr):
        assert nsr.setrange('a', 5, 'foo') == 8
        assert nsr['a'] == b('\0\0\0\0\0foo')
        nsr['a'] = 'abcdefghijh'
        assert nsr.setrange('a', 6, '12345') == 11
        assert nsr['a'] == b('abcdef12345')

    def test_nsr_strlen(self, nsr):
        nsr['a'] = 'foo'
        assert nsr.strlen('a') == 3

    def test_nsr_substr(self, nsr):
        nsr['a'] = '0123456789'
        assert nsr.substr('a', 0) == b('0123456789')
        assert nsr.substr('a', 2) == b('23456789')
        assert nsr.substr('a', 3, 5) == b('345')
        assert nsr.substr('a', 3, -2) == b('345678')

    def test_nsr_type(self, nsr):
        assert nsr.type('a') == b('none')
        nsr['a'] = '1'
        assert nsr.type('a') == b('string')
        del nsr['a']
        nsr.lpush('a', '1')
        assert nsr.type('a') == b('list')
        del nsr['a']
        nsr.sadd('a', '1')
        assert nsr.type('a') == b('set')
        del nsr['a']
        nsr.zadd('a', **{'1': 1})
        assert nsr.type('a') == b('zset')

    # LIST COMMANDS
    def test_nsr_blpop(self, nsr):
        nsr.rpush('a', '1', '2')
        nsr.rpush('b', '3', '4')
        assert nsr.blpop(['b', 'a'], timeout=1) == (b('b'), b('3'))
        assert nsr.blpop(['b', 'a'], timeout=1) == (b('b'), b('4'))
        assert nsr.blpop(['b', 'a'], timeout=1) == (b('a'), b('1'))
        assert nsr.blpop(['b', 'a'], timeout=1) == (b('a'), b('2'))
        assert nsr.blpop(['b', 'a'], timeout=1) is None
        nsr.rpush('c', '1')
        assert nsr.blpop('c', timeout=1) == (b('c'), b('1'))

    def test_nsr_brpop(self, nsr):
        nsr.rpush('a', '1', '2')
        nsr.rpush('b', '3', '4')
        assert nsr.brpop(['b', 'a'], timeout=1) == (b('b'), b('4'))
        assert nsr.brpop(['b', 'a'], timeout=1) == (b('b'), b('3'))
        assert nsr.brpop(['b', 'a'], timeout=1) == (b('a'), b('2'))
        assert nsr.brpop(['b', 'a'], timeout=1) == (b('a'), b('1'))
        assert nsr.brpop(['b', 'a'], timeout=1) is None
        nsr.rpush('c', '1')
        assert nsr.brpop('c', timeout=1) == (b('c'), b('1'))

    def test_nsr_brpoplpush(self, nsr):
        nsr.rpush('a', '1', '2')
        nsr.rpush('b', '3', '4')
        assert nsr.brpoplpush('a', 'b') == b('2')
        assert nsr.brpoplpush('a', 'b') == b('1')
        assert nsr.brpoplpush('a', 'b', timeout=1) is None
        assert nsr.lrange('a', 0, -1) == []
        assert nsr.lrange('b', 0, -1) == [b('1'), b('2'), b('3'), b('4')]

    def test_nsr_brpoplpush_empty_string(self, nsr):
        nsr.rpush('a', '')
        assert nsr.brpoplpush('a', 'b') == b('')

    def test_nsr_lindex(self, nsr):
        nsr.rpush('a', '1', '2', '3')
        assert nsr.lindex('a', '0') == b('1')
        assert nsr.lindex('a', '1') == b('2')
        assert nsr.lindex('a', '2') == b('3')

    def test_nsr_linsert(self, nsr):
        nsr.rpush('a', '1', '2', '3')
        assert nsr.linsert('a', 'after', '2', '2.5') == 4
        assert nsr.lrange('a', 0, -1) == [b('1'), b('2'), b('2.5'), b('3')]
        assert nsr.linsert('a', 'before', '2', '1.5') == 5
        assert nsr.lrange('a', 0, -1) == \
            [b('1'), b('1.5'), b('2'), b('2.5'), b('3')]

    def test_nsr_llen(self, nsr):
        nsr.rpush('a', '1', '2', '3')
        assert nsr.llen('a') == 3

    def test_nsr_lpop(self, nsr):
        nsr.rpush('a', '1', '2', '3')
        assert nsr.lpop('a') == b('1')
        assert nsr.lpop('a') == b('2')
        assert nsr.lpop('a') == b('3')
        assert nsr.lpop('a') is None

    def test_nsr_lpush(self, nsr):
        assert nsr.lpush('a', '1') == 1
        assert nsr.lpush('a', '2') == 2
        assert nsr.lpush('a', '3', '4') == 4
        assert nsr.lrange('a', 0, -1) == [b('4'), b('3'), b('2'), b('1')]

    def test_nsr_lpushx(self, nsr):
        assert nsr.lpushx('a', '1') == 0
        assert nsr.lrange('a', 0, -1) == []
        nsr.rpush('a', '1', '2', '3')
        assert nsr.lpushx('a', '4') == 4
        assert nsr.lrange('a', 0, -1) == [b('4'), b('1'), b('2'), b('3')]

    def test_nsr_lrange(self, nsr):
        nsr.rpush('a', '1', '2', '3', '4', '5')
        assert nsr.lrange('a', 0, 2) == [b('1'), b('2'), b('3')]
        assert nsr.lrange('a', 2, 10) == [b('3'), b('4'), b('5')]
        val = nsr.lrange('a', 0, -1)
        assert val == [b('1'), b('2'), b('3'), b('4'), b('5')]

    def test_nsr_lrem(self, nsr):
        nsr.rpush('a', '1', '1', '1', '1')
        assert nsr.lrem('a', '1', 1) == 1
        assert nsr.lrange('a', 0, -1) == [b('1'), b('1'), b('1')]
        assert nsr.lrem('a', '1') == 3
        assert nsr.lrange('a', 0, -1) == []

    def test_nsr_lset(self, nsr):
        nsr.rpush('a', '1', '2', '3')
        assert nsr.lrange('a', 0, -1) == [b('1'), b('2'), b('3')]
        assert nsr.lset('a', 1, '4')
        assert nsr.lrange('a', 0, 2) == [b('1'), b('4'), b('3')]

    def test_nsr_ltrim(self, nsr):
        nsr.rpush('a', '1', '2', '3')
        assert nsr.ltrim('a', 0, 1)
        assert nsr.lrange('a', 0, -1) == [b('1'), b('2')]

    def test_nsr_rpop(self, nsr):
        nsr.rpush('a', '1', '2', '3')
        assert nsr.rpop('a') == b('3')
        assert nsr.rpop('a') == b('2')
        assert nsr.rpop('a') == b('1')
        assert nsr.rpop('a') is None

    def test_nsr_rpoplpush(self, nsr):
        nsr.rpush('a', 'a1', 'a2', 'a3')
        nsr.rpush('b', 'b1', 'b2', 'b3')
        assert nsr.rpoplpush('a', 'b') == b('a3')
        assert nsr.lrange('a', 0, -1) == [b('a1'), b('a2')]
        assert nsr.lrange('b', 0, -1) == [b('a3'), b('b1'), b('b2'), b('b3')]

    def test_nsr_rpush(self, nsr):
        assert nsr.rpush('a', '1') == 1
        assert nsr.rpush('a', '2') == 2
        assert nsr.rpush('a', '3', '4') == 4
        assert nsr.lrange('a', 0, -1) == [b('1'), b('2'), b('3'), b('4')]

    def test_nsr_rpushx(self, nsr):
        assert nsr.rpushx('a', 'b') == 0
        assert nsr.lrange('a', 0, -1) == []
        nsr.rpush('a', '1', '2', '3')
        assert nsr.rpushx('a', '4') == 4
        assert nsr.lrange('a', 0, -1) == [b('1'), b('2'), b('3'), b('4')]

    # SCAN COMMANDS
    @skip_if_server_version_lt('2.8.0')
    def test_nsr_scan(self, nsr):
        nsr.set('a', 1)
        nsr.set('b', 2)
        nsr.set('c', 3)
        cursor, keys = nsr.scan()
        assert cursor == 0
        assert set(keys) == set([b('a'), b('b'), b('c')])
        _, keys = nsr.scan(match='a')
        assert set(keys) == set([b('a')])

    @skip_if_server_version_lt('2.8.0')
    def test_nsr_scan_iter(self, nsr):
        nsr.set('a', 1)
        nsr.set('b', 2)
        nsr.set('c', 3)
        keys = list(nsr.scan_iter())
        assert set(keys) == set([b('a'), b('b'), b('c')])
        keys = list(nsr.scan_iter(match='a'))
        assert set(keys) == set([b('a')])

    @skip_if_server_version_lt('2.8.0')
    def test_nsr_sscan(self, nsr):
        nsr.sadd('a', 1, 2, 3)
        cursor, members = nsr.sscan('a')
        assert cursor == 0
        assert set(members) == set([b('1'), b('2'), b('3')])
        _, members = nsr.sscan('a', match=b('1'))
        assert set(members) == set([b('1')])

    @skip_if_server_version_lt('2.8.0')
    def test_nsr_sscan_iter(self, nsr):
        nsr.sadd('a', 1, 2, 3)
        members = list(nsr.sscan_iter('a'))
        assert set(members) == set([b('1'), b('2'), b('3')])
        members = list(nsr.sscan_iter('a', match=b('1')))
        assert set(members) == set([b('1')])

    @skip_if_server_version_lt('2.8.0')
    def test_nsr_hscan(self, nsr):
        nsr.hmset('a', {'a': 1, 'b': 2, 'c': 3})
        cursor, dic = nsr.hscan('a')
        assert cursor == 0
        assert dic == {b('a'): b('1'), b('b'): b('2'), b('c'): b('3')}
        _, dic = nsr.hscan('a', match='a')
        assert dic == {b('a'): b('1')}

    @skip_if_server_version_lt('2.8.0')
    def test_nsr_hscan_iter(self, nsr):
        nsr.hmset('a', {'a': 1, 'b': 2, 'c': 3})
        dic = dict(nsr.hscan_iter('a'))
        assert dic == {b('a'): b('1'), b('b'): b('2'), b('c'): b('3')}
        dic = dict(nsr.hscan_iter('a', match='a'))
        assert dic == {b('a'): b('1')}

    @skip_if_server_version_lt('2.8.0')
    def test_nsr_zscan(self, nsr):
        nsr.zadd('a', 'a', 1, 'b', 2, 'c', 3)
        cursor, pairs = nsr.zscan('a')
        assert cursor == 0
        assert set(pairs) == set([(b('a'), 1), (b('b'), 2), (b('c'), 3)])
        _, pairs = nsr.zscan('a', match='a')
        assert set(pairs) == set([(b('a'), 1)])

    @skip_if_server_version_lt('2.8.0')
    def test_nsr_zscan_iter(self, nsr):
        nsr.zadd('a', 'a', 1, 'b', 2, 'c', 3)
        pairs = list(nsr.zscan_iter('a'))
        assert set(pairs) == set([(b('a'), 1), (b('b'), 2), (b('c'), 3)])
        pairs = list(nsr.zscan_iter('a', match='a'))
        assert set(pairs) == set([(b('a'), 1)])

    # SET COMMANDS
    def test_nsr_sadd(self, nsr):
        members = set([b('1'), b('2'), b('3')])
        nsr.sadd('a', *members)
        assert nsr.smembers('a') == members

    def test_nsr_scard(self, nsr):
        nsr.sadd('a', '1', '2', '3')
        assert nsr.scard('a') == 3

    def test_nsr_sdiff(self, nsr):
        nsr.sadd('a', '1', '2', '3')
        assert nsr.sdiff('a', 'b') == set([b('1'), b('2'), b('3')])
        nsr.sadd('b', '2', '3')
        assert nsr.sdiff('a', 'b') == set([b('1')])

    def test_nsr_sdiffstore(self, nsr):
        nsr.sadd('a', '1', '2', '3')
        assert nsr.sdiffstore('c', 'a', 'b') == 3
        assert nsr.smembers('c') == set([b('1'), b('2'), b('3')])
        nsr.sadd('b', '2', '3')
        assert nsr.sdiffstore('c', 'a', 'b') == 1
        assert nsr.smembers('c') == set([b('1')])

    def test_nsr_sinter(self, nsr):
        nsr.sadd('a', '1', '2', '3')
        assert nsr.sinter('a', 'b') == set()
        nsr.sadd('b', '2', '3')
        assert nsr.sinter('a', 'b') == set([b('2'), b('3')])

    def test_nsr_sinterstore(self, nsr):
        nsr.sadd('a', '1', '2', '3')
        assert nsr.sinterstore('c', 'a', 'b') == 0
        assert nsr.smembers('c') == set()
        nsr.sadd('b', '2', '3')
        assert nsr.sinterstore('c', 'a', 'b') == 2
        assert nsr.smembers('c') == set([b('2'), b('3')])

    def test_nsr_sismember(self, nsr):
        nsr.sadd('a', '1', '2', '3')
        assert nsr.sismember('a', '1')
        assert nsr.sismember('a', '2')
        assert nsr.sismember('a', '3')
        assert not nsr.sismember('a', '4')

    def test_nsr_smembers(self, nsr):
        nsr.sadd('a', '1', '2', '3')
        assert nsr.smembers('a') == set([b('1'), b('2'), b('3')])

    def test_nsr_smove(self, nsr):
        nsr.sadd('a', 'a1', 'a2')
        nsr.sadd('b', 'b1', 'b2')
        assert nsr.smove('a', 'b', 'a1')
        assert nsr.smembers('a') == set([b('a2')])
        assert nsr.smembers('b') == set([b('b1'), b('b2'), b('a1')])

    def test_nsr_spop(self, nsr):
        s = [b('1'), b('2'), b('3')]
        nsr.sadd('a', *s)
        value = nsr.spop('a')
        assert value in s
        assert nsr.smembers('a') == set(s) - set([value])

    def test_nsr_srandmember(self, nsr):
        s = [b('1'), b('2'), b('3')]
        nsr.sadd('a', *s)
        assert nsr.srandmember('a') in s

    @skip_if_server_version_lt('2.6.0')
    def test_nsr_srandmember_multi_value(self, nsr):
        s = [b('1'), b('2'), b('3')]
        nsr.sadd('a', *s)
        randoms = nsr.srandmember('a', number=2)
        assert len(randoms) == 2
        assert set(randoms).intersection(s) == set(randoms)

    def test_nsr_srem(self, nsr):
        nsr.sadd('a', '1', '2', '3', '4')
        assert nsr.srem('a', '5') == 0
        assert nsr.srem('a', '2', '4') == 2
        assert nsr.smembers('a') == set([b('1'), b('3')])

    def test_nsr_sunion(self, nsr):
        nsr.sadd('a', '1', '2')
        nsr.sadd('b', '2', '3')
        assert nsr.sunion('a', 'b') == set([b('1'), b('2'), b('3')])

    def test_nsr_sunionstore(self, nsr):
        nsr.sadd('a', '1', '2')
        nsr.sadd('b', '2', '3')
        assert nsr.sunionstore('c', 'a', 'b') == 3
        assert nsr.smembers('c') == set([b('1'), b('2'), b('3')])

    # SORTED SET COMMANDS
    def test_nsr_zadd(self, nsr):
        nsr.zadd('a', a1=1, a2=2, a3=3)
        assert nsr.zrange('a', 0, -1) == [b('a1'), b('a2'), b('a3')]

    def test_nsr_zcard(self, nsr):
        nsr.zadd('a', a1=1, a2=2, a3=3)
        assert nsr.zcard('a') == 3

    def test_nsr_zcount(self, nsr):
        nsr.zadd('a', a1=1, a2=2, a3=3)
        assert nsr.zcount('a', '-inf', '+inf') == 3
        assert nsr.zcount('a', 1, 2) == 2
        assert nsr.zcount('a', 10, 20) == 0

    def test_nsr_zincrby(self, nsr):
        nsr.zadd('a', a1=1, a2=2, a3=3)
        assert nsr.zincrby('a', 'a2') == 3.0
        assert nsr.zincrby('a', 'a3', amount=5) == 8.0
        assert nsr.zscore('a', 'a2') == 3.0
        assert nsr.zscore('a', 'a3') == 8.0

    @skip_if_server_version_lt('2.8.9')
    def test_nsr_zlexcount(self, nsr):
        nsr.zadd('a', a=0, b=0, c=0, d=0, e=0, f=0, g=0)
        assert nsr.zlexcount('a', '-', '+') == 7
        assert nsr.zlexcount('a', '[b', '[f') == 5

    def test_nsr_zinterstore_sum(self, nsr):
        nsr.zadd('a', a1=1, a2=1, a3=1)
        nsr.zadd('b', a1=2, a2=2, a3=2)
        nsr.zadd('c', a1=6, a3=5, a4=4)
        assert nsr.zinterstore('d', ['a', 'b', 'c']) == 2
        assert nsr.zrange('d', 0, -1, withscores=True) == \
            [(b('a3'), 8), (b('a1'), 9)]

    def test_nsr_zinterstore_max(self, nsr):
        nsr.zadd('a', a1=1, a2=1, a3=1)
        nsr.zadd('b', a1=2, a2=2, a3=2)
        nsr.zadd('c', a1=6, a3=5, a4=4)
        assert nsr.zinterstore('d', ['a', 'b', 'c'], aggregate='MAX') == 2
        assert nsr.zrange('d', 0, -1, withscores=True) == \
            [(b('a3'), 5), (b('a1'), 6)]

    def test_nsr_zinterstore_min(self, nsr):
        nsr.zadd('a', a1=1, a2=2, a3=3)
        nsr.zadd('b', a1=2, a2=3, a3=5)
        nsr.zadd('c', a1=6, a3=5, a4=4)
        assert nsr.zinterstore('d', ['a', 'b', 'c'], aggregate='MIN') == 2
        assert nsr.zrange('d', 0, -1, withscores=True) == \
            [(b('a1'), 1), (b('a3'), 3)]

    def test_nsr_zinterstore_with_weight(self, nsr):
        nsr.zadd('a', a1=1, a2=1, a3=1)
        nsr.zadd('b', a1=2, a2=2, a3=2)
        nsr.zadd('c', a1=6, a3=5, a4=4)
        assert nsr.zinterstore('d', {'a': 1, 'b': 2, 'c': 3}) == 2
        assert nsr.zrange('d', 0, -1, withscores=True) == \
            [(b('a3'), 20), (b('a1'), 23)]

    def test_nsr_zrange(self, nsr):
        nsr.zadd('a', a1=1, a2=2, a3=3)
        assert nsr.zrange('a', 0, 1) == [b('a1'), b('a2')]
        assert nsr.zrange('a', 1, 2) == [b('a2'), b('a3')]

        # withscores
        assert nsr.zrange('a', 0, 1, withscores=True) == \
            [(b('a1'), 1.0), (b('a2'), 2.0)]
        assert nsr.zrange('a', 1, 2, withscores=True) == \
            [(b('a2'), 2.0), (b('a3'), 3.0)]

        # custom score function
        assert nsr.zrange('a', 0, 1, withscores=True, score_cast_func=int) == \
            [(b('a1'), 1), (b('a2'), 2)]

    @skip_if_server_version_lt('2.8.9')
    def test_nsr_zrangebylex(self, nsr):
        nsr.zadd('a', a=0, b=0, c=0, d=0, e=0, f=0, g=0)
        assert nsr.zrangebylex('a', '-', '[c') == [b('a'), b('b'), b('c')]
        assert nsr.zrangebylex('a', '-', '(c') == [b('a'), b('b')]
        assert nsr.zrangebylex('a', '[aaa', '(g') == \
            [b('b'), b('c'), b('d'), b('e'), b('f')]
        assert nsr.zrangebylex('a', '[f', '+') == [b('f'), b('g')]
        val = nsr.zrangebylex('a', '-', '+', start=3, num=2)
        assert val == [b('d'), b('e')]

    @skip_if_server_version_lt('2.9.9')
    def test_nsr_zrevrangebylex(self, nsr):
        nsr.zadd('a', a=0, b=0, c=0, d=0, e=0, f=0, g=0)
        assert nsr.zrevrangebylex('a', '[c', '-') == [b('c'), b('b'), b('a')]
        assert nsr.zrevrangebylex('a', '(c', '-') == [b('b'), b('a')]
        assert nsr.zrevrangebylex('a', '(g', '[aaa') == \
            [b('f'), b('e'), b('d'), b('c'), b('b')]
        assert nsr.zrevrangebylex('a', '+', '[f') == [b('g'), b('f')]
        assert nsr.zrevrangebylex('a', '+', '-', start=3, num=2) == \
            [b('d'), b('c')]

    def test_nsr_zrangebyscore(self, nsr):
        nsr.zadd('a', a1=1, a2=2, a3=3, a4=4, a5=5)
        assert nsr.zrangebyscore('a', 2, 4) == [b('a2'), b('a3'), b('a4')]

        # slicing with start/num
        assert nsr.zrangebyscore('a', 2, 4, start=1, num=2) == \
            [b('a3'), b('a4')]

        # withscores
        assert nsr.zrangebyscore('a', 2, 4, withscores=True) == \
            [(b('a2'), 2.0), (b('a3'), 3.0), (b('a4'), 4.0)]

        # custom score function
        assert nsr.zrangebyscore('a', 2, 4, withscores=True,
                                 score_cast_func=int) == \
            [(b('a2'), 2), (b('a3'), 3), (b('a4'), 4)]

    def test_nsr_zrank(self, nsr):
        nsr.zadd('a', a1=1, a2=2, a3=3, a4=4, a5=5)
        assert nsr.zrank('a', 'a1') == 0
        assert nsr.zrank('a', 'a2') == 1
        assert nsr.zrank('a', 'a6') is None

    def test_nsr_zrem(self, nsr):
        nsr.zadd('a', a1=1, a2=2, a3=3)
        assert nsr.zrem('a', 'a2') == 1
        assert nsr.zrange('a', 0, -1) == [b('a1'), b('a3')]
        assert nsr.zrem('a', 'b') == 0
        assert nsr.zrange('a', 0, -1) == [b('a1'), b('a3')]

    def test_nsr_zrem_multiple_keys(self, nsr):
        nsr.zadd('a', a1=1, a2=2, a3=3)
        assert nsr.zrem('a', 'a1', 'a2') == 2
        assert nsr.zrange('a', 0, 5) == [b('a3')]

    @skip_if_server_version_lt('2.8.9')
    def test_nsr_zremrangebylex(self, nsr):
        nsr.zadd('a', a=0, b=0, c=0, d=0, e=0, f=0, g=0)
        assert nsr.zremrangebylex('a', '-', '[c') == 3
        assert nsr.zrange('a', 0, -1) == [b('d'), b('e'), b('f'), b('g')]
        assert nsr.zremrangebylex('a', '[f', '+') == 2
        assert nsr.zrange('a', 0, -1) == [b('d'), b('e')]
        assert nsr.zremrangebylex('a', '[h', '+') == 0
        assert nsr.zrange('a', 0, -1) == [b('d'), b('e')]

    def test_nsr_zremrangebyrank(self, nsr):
        nsr.zadd('a', a1=1, a2=2, a3=3, a4=4, a5=5)
        assert nsr.zremrangebyrank('a', 1, 3) == 3
        assert nsr.zrange('a', 0, 5) == [b('a1'), b('a5')]

    def test_nsr_zremrangebyscore(self, nsr):
        nsr.zadd('a', a1=1, a2=2, a3=3, a4=4, a5=5)
        assert nsr.zremrangebyscore('a', 2, 4) == 3
        assert nsr.zrange('a', 0, -1) == [b('a1'), b('a5')]
        assert nsr.zremrangebyscore('a', 2, 4) == 0
        assert nsr.zrange('a', 0, -1) == [b('a1'), b('a5')]

    def test_nsr_zrevrange(self, nsr):
        nsr.zadd('a', a1=1, a2=2, a3=3)
        assert nsr.zrevrange('a', 0, 1) == [b('a3'), b('a2')]
        assert nsr.zrevrange('a', 1, 2) == [b('a2'), b('a1')]

        # withscores
        assert nsr.zrevrange('a', 0, 1, withscores=True) == \
            [(b('a3'), 3.0), (b('a2'), 2.0)]
        assert nsr.zrevrange('a', 1, 2, withscores=True) == \
            [(b('a2'), 2.0), (b('a1'), 1.0)]

        # custom score function
        assert nsr.zrevrange('a', 0, 1, withscores=True,
                             score_cast_func=int) == \
            [(b('a3'), 3.0), (b('a2'), 2.0)]

    def test_nsr_zrevrangebyscore(self, nsr):
        nsr.zadd('a', a1=1, a2=2, a3=3, a4=4, a5=5)
        assert nsr.zrevrangebyscore('a', 4, 2) == [b('a4'), b('a3'), b('a2')]

        # slicing with start/num
        assert nsr.zrevrangebyscore('a', 4, 2, start=1, num=2) == \
            [b('a3'), b('a2')]

        # withscores
        assert nsr.zrevrangebyscore('a', 4, 2, withscores=True) == \
            [(b('a4'), 4.0), (b('a3'), 3.0), (b('a2'), 2.0)]

        # custom score function
        assert nsr.zrevrangebyscore('a', 4, 2, withscores=True,
                                    score_cast_func=int) == \
            [(b('a4'), 4), (b('a3'), 3), (b('a2'), 2)]

    def test_nsr_zrevrank(self, nsr):
        nsr.zadd('a', a1=1, a2=2, a3=3, a4=4, a5=5)
        assert nsr.zrevrank('a', 'a1') == 4
        assert nsr.zrevrank('a', 'a2') == 3
        assert nsr.zrevrank('a', 'a6') is None

    def test_nsr_zscore(self, nsr):
        nsr.zadd('a', a1=1, a2=2, a3=3)
        assert nsr.zscore('a', 'a1') == 1.0
        assert nsr.zscore('a', 'a2') == 2.0
        assert nsr.zscore('a', 'a4') is None

    def test_nsr_zunionstore_sum(self, nsr):
        nsr.zadd('a', a1=1, a2=1, a3=1)
        nsr.zadd('b', a1=2, a2=2, a3=2)
        nsr.zadd('c', a1=6, a3=5, a4=4)
        assert nsr.zunionstore('d', ['a', 'b', 'c']) == 4
        assert nsr.zrange('d', 0, -1, withscores=True) == \
            [(b('a2'), 3), (b('a4'), 4), (b('a3'), 8), (b('a1'), 9)]

    def test_nsr_zunionstore_max(self, nsr):
        nsr.zadd('a', a1=1, a2=1, a3=1)
        nsr.zadd('b', a1=2, a2=2, a3=2)
        nsr.zadd('c', a1=6, a3=5, a4=4)
        assert nsr.zunionstore('d', ['a', 'b', 'c'], aggregate='MAX') == 4
        assert nsr.zrange('d', 0, -1, withscores=True) == \
            [(b('a2'), 2), (b('a4'), 4), (b('a3'), 5), (b('a1'), 6)]

    def test_nsr_zunionstore_min(self, nsr):
        nsr.zadd('a', a1=1, a2=2, a3=3)
        nsr.zadd('b', a1=2, a2=2, a3=4)
        nsr.zadd('c', a1=6, a3=5, a4=4)
        assert nsr.zunionstore('d', ['a', 'b', 'c'], aggregate='MIN') == 4
        assert nsr.zrange('d', 0, -1, withscores=True) == \
            [(b('a1'), 1), (b('a2'), 2), (b('a3'), 3), (b('a4'), 4)]

    def test_nsr_zunionstore_with_weight(self, nsr):
        nsr.zadd('a', a1=1, a2=1, a3=1)
        nsr.zadd('b', a1=2, a2=2, a3=2)
        nsr.zadd('c', a1=6, a3=5, a4=4)
        assert nsr.zunionstore('d', {'a': 1, 'b': 2, 'c': 3}) == 4
        assert nsr.zrange('d', 0, -1, withscores=True) == \
            [(b('a2'), 5), (b('a4'), 12), (b('a3'), 20), (b('a1'), 23)]

    # HYPERLOGLOG TESTS
    @skip_if_server_version_lt('2.8.9')
    def test_nsr_pfadd(self, nsr):
        members = set([b('1'), b('2'), b('3')])
        assert nsr.pfadd('a', *members) == 1
        assert nsr.pfadd('a', *members) == 0
        assert nsr.pfcount('a') == len(members)

    @skip_if_server_version_lt('2.8.9')
    def test_nsr_pfcount(self, nsr):
        members = set([b('1'), b('2'), b('3')])
        nsr.pfadd('a', *members)
        assert nsr.pfcount('a') == len(members)
        members_b = set([b('2'), b('3'), b('4')])
        nsr.pfadd('b', *members_b)
        assert nsr.pfcount('b') == len(members_b)
        assert nsr.pfcount('a', 'b') == len(members_b.union(members))

    @skip_if_server_version_lt('2.8.9')
    def test_nsr_pfmerge(self, nsr):
        mema = set([b('1'), b('2'), b('3')])
        memb = set([b('2'), b('3'), b('4')])
        memc = set([b('5'), b('6'), b('7')])
        nsr.pfadd('a', *mema)
        nsr.pfadd('b', *memb)
        nsr.pfadd('c', *memc)
        nsr.pfmerge('d', 'c', 'a')
        assert nsr.pfcount('d') == 6
        nsr.pfmerge('d', 'b')
        assert nsr.pfcount('d') == 7

    # HASH COMMANDS
    def test_nsr_hget_and_hset(self, nsr):
        nsr.hmset('a', {'1': 1, '2': 2, '3': 3})
        assert nsr.hget('a', '1') == b('1')
        assert nsr.hget('a', '2') == b('2')
        assert nsr.hget('a', '3') == b('3')

        # field was updated, nsredis returns 0
        assert nsr.hset('a', '2', 5) == 0
        assert nsr.hget('a', '2') == b('5')

        # field is new, nsredis returns 1
        assert nsr.hset('a', '4', 4) == 1
        assert nsr.hget('a', '4') == b('4')

        # key inside of hash that doesn't exist returns null value
        assert nsr.hget('a', 'b') is None

    def test_nsr_hdel(self, nsr):
        nsr.hmset('a', {'1': 1, '2': 2, '3': 3})
        assert nsr.hdel('a', '2') == 1
        assert nsr.hget('a', '2') is None
        assert nsr.hdel('a', '1', '3') == 2
        assert nsr.hlen('a') == 0

    def test_nsr_hexists(self, nsr):
        nsr.hmset('a', {'1': 1, '2': 2, '3': 3})
        assert nsr.hexists('a', '1')
        assert not nsr.hexists('a', '4')

    def test_nsr_hgetall(self, nsr):
        h = {b('a1'): b('1'), b('a2'): b('2'), b('a3'): b('3')}
        nsr.hmset('a', h)
        assert nsr.hgetall('a') == h

    def test_nsr_hincrby(self, nsr):
        assert nsr.hincrby('a', '1') == 1
        assert nsr.hincrby('a', '1', amount=2) == 3
        assert nsr.hincrby('a', '1', amount=-2) == 1

    @skip_if_server_version_lt('2.6.0')
    def test_nsr_hincrbyfloat(self, nsr):
        assert nsr.hincrbyfloat('a', '1') == 1.0
        assert nsr.hincrbyfloat('a', '1') == 2.0
        assert nsr.hincrbyfloat('a', '1', 1.2) == 3.2

    def test_nsr_hkeys(self, nsr):
        h = {b('a1'): b('1'), b('a2'): b('2'), b('a3'): b('3')}
        nsr.hmset('a', h)
        local_keys = list(iterkeys(h))
        remote_keys = nsr.hkeys('a')
        assert (sorted(local_keys) == sorted(remote_keys))

    def test_nsr_hlen(self, nsr):
        nsr.hmset('a', {'1': 1, '2': 2, '3': 3})
        assert nsr.hlen('a') == 3

    def test_nsr_hmget(self, nsr):
        assert nsr.hmset('a', {'a': 1, 'b': 2, 'c': 3})
        assert nsr.hmget('a', 'a', 'b', 'c') == [b('1'), b('2'), b('3')]

    def test_nsr_hmset(self, nsr):
        h = {b('a'): b('1'), b('b'): b('2'), b('c'): b('3')}
        assert nsr.hmset('a', h)
        assert nsr.hgetall('a') == h

    def test_nsr_hsetnx(self, nsr):
        # Initially set the hash field
        assert nsr.hsetnx('a', '1', 1)
        assert nsr.hget('a', '1') == b('1')
        assert not nsr.hsetnx('a', '1', 2)
        assert nsr.hget('a', '1') == b('1')

    def test_nsr_hvals(self, nsr):
        h = {b('a1'): b('1'), b('a2'): b('2'), b('a3'): b('3')}
        nsr.hmset('a', h)
        local_vals = list(itervalues(h))
        remote_vals = nsr.hvals('a')
        assert sorted(local_vals) == sorted(remote_vals)

    # SORT
    def test_nsr_sort_basic(self, nsr):
        nsr.rpush('a', '3', '2', '1', '4')
        assert nsr.sort('a') == [b('1'), b('2'), b('3'), b('4')]

    def test_nsr_sort_limited(self, nsr):
        nsr.rpush('a', '3', '2', '1', '4')
        assert nsr.sort('a', start=1, num=2) == [b('2'), b('3')]

    def test_nsr_sort_by(self, nsr):
        nsr['score:1'] = 8
        nsr['score:2'] = 3
        nsr['score:3'] = 5
        nsr.rpush('a', '3', '2', '1')
        assert nsr.sort('a', by='score:*') == [b('2'), b('3'), b('1')]

    def test_nsr_sort_get(self, nsr):
        nsr['user:1'] = 'u1'
        nsr['user:2'] = 'u2'
        nsr['user:3'] = 'u3'
        nsr.rpush('a', '2', '3', '1')
        assert nsr.sort('a', get='user:*') == [b('u1'), b('u2'), b('u3')]

    def test_nsr_sort_get_multi(self, nsr):
        nsr['user:1'] = 'u1'
        nsr['user:2'] = 'u2'
        nsr['user:3'] = 'u3'
        nsr.rpush('a', '2', '3', '1')
        assert nsr.sort('a', get=('user:*', '#')) == \
            [b('u1'), b('1'), b('u2'), b('2'), b('u3'), b('3')]

    def test_nsr_sort_get_groups_two(self, nsr):
        nsr['user:1'] = 'u1'
        nsr['user:2'] = 'u2'
        nsr['user:3'] = 'u3'
        nsr.rpush('a', '2', '3', '1')
        assert nsr.sort('a', get=('user:*', '#'), groups=True) == \
            [(b('u1'), b('1')), (b('u2'), b('2')), (b('u3'), b('3'))]

    def test_nsr_sort_groups_string_get(self, nsr):
        nsr['user:1'] = 'u1'
        nsr['user:2'] = 'u2'
        nsr['user:3'] = 'u3'
        nsr.rpush('a', '2', '3', '1')
        with pytest.raises(exceptions.DataError):
            nsr.sort('a', get='user:*', groups=True)

    def test_nsr_sort_groups_just_one_get(self, nsr):
        nsr['user:1'] = 'u1'
        nsr['user:2'] = 'u2'
        nsr['user:3'] = 'u3'
        nsr.rpush('a', '2', '3', '1')
        with pytest.raises(exceptions.DataError):
            nsr.sort('a', get=['user:*'], groups=True)

    def test_nsr_sort_groups_no_get(self, nsr):
        nsr['user:1'] = 'u1'
        nsr['user:2'] = 'u2'
        nsr['user:3'] = 'u3'
        nsr.rpush('a', '2', '3', '1')
        with pytest.raises(exceptions.DataError):
            nsr.sort('a', groups=True)

    def test_nsr_sort_groups_three_gets(self, nsr):
        nsr['user:1'] = 'u1'
        nsr['user:2'] = 'u2'
        nsr['user:3'] = 'u3'
        nsr['door:1'] = 'd1'
        nsr['door:2'] = 'd2'
        nsr['door:3'] = 'd3'
        nsr.rpush('a', '2', '3', '1')
        assert nsr.sort('a', get=('user:*', 'door:*', '#'), groups=True) == \
            [
                (b('u1'), b('d1'), b('1')),
                (b('u2'), b('d2'), b('2')),
                (b('u3'), b('d3'), b('3'))
            ]

    def test_nsr_sort_desc(self, nsr):
        nsr.rpush('a', '2', '3', '1')
        assert nsr.sort('a', desc=True) == [b('3'), b('2'), b('1')]

    def test_nsr_sort_alpha(self, nsr):
        nsr.rpush('a', 'e', 'c', 'b', 'd', 'a')
        assert nsr.sort('a', alpha=True) == \
            [b('a'), b('b'), b('c'), b('d'), b('e')]

    def test_nsr_sort_store(self, nsr):
        nsr.rpush('a', '2', '3', '1')
        assert nsr.sort('a', store='sorted_values') == 3
        assert nsr.lrange('sorted_values', 0, -1) == [b('1'), b('2'), b('3')]

    def test_nsr_sort_all_options(self, nsr):
        nsr['user:1:username'] = 'zeus'
        nsr['user:2:username'] = 'titan'
        nsr['user:3:username'] = 'hermes'
        nsr['user:4:username'] = 'hercules'
        nsr['user:5:username'] = 'apollo'
        nsr['user:6:username'] = 'athena'
        nsr['user:7:username'] = 'hades'
        nsr['user:8:username'] = 'dionysus'

        nsr['user:1:favorite_drink'] = 'yuengling'
        nsr['user:2:favorite_drink'] = 'rum'
        nsr['user:3:favorite_drink'] = 'vodka'
        nsr['user:4:favorite_drink'] = 'milk'
        nsr['user:5:favorite_drink'] = 'pinot noir'
        nsr['user:6:favorite_drink'] = 'water'
        nsr['user:7:favorite_drink'] = 'gin'
        nsr['user:8:favorite_drink'] = 'apple juice'

        nsr.rpush('gods', '5', '8', '3', '1', '2', '7', '6', '4')
        num = nsr.sort('gods', start=2, num=4, by='user:*:username',
                       get='user:*:favorite_drink', desc=True, alpha=True,
                       store='sorted')
        assert num == 4
        assert nsr.lrange('sorted', 0, 10) == \
            [b('vodka'), b('milk'), b('gin'), b('apple juice')]


class TestBinarySave(object):
    def test_nsr_binary_get_set(self, nsr):
        assert nsr.set(' foo bar ', '123')
        assert nsr.get(' foo bar ') == b('123')

        assert nsr.set(' foo\r\nbar\r\n ', '456')
        assert nsr.get(' foo\r\nbar\r\n ') == b('456')

        assert nsr.set(' \r\n\t\x07\x13 ', '789')
        assert nsr.get(' \r\n\t\x07\x13 ') == b('789')

        assert sorted(nsr.keys('*')) == \
            [b(' \r\n\t\x07\x13 '), b(' foo\r\nbar\r\n '), b(' foo bar ')]

        assert nsr.delete(' foo bar ')
        assert nsr.delete(' foo\r\nbar\r\n ')
        assert nsr.delete(' \r\n\t\x07\x13 ')

    def test_nsr_binary_lists(self, nsr):
        mapping = {
            b('foo bar'): [b('1'), b('2'), b('3')],
            b('foo\r\nbar\r\n'): [b('4'), b('5'), b('6')],
            b('foo\tbar\x07'): [b('7'), b('8'), b('9')],
        }
        # fill in lists
        for key, value in iteritems(mapping):
            nsr.rpush(key, *value)

        # check that KEYS returns all the keys as they are
        assert sorted(nsr.keys('*')) == sorted(list(iterkeys(mapping)))

        # check that it is possible to get list content by key name
        for key, value in iteritems(mapping):
            assert nsr.lrange(key, 0, -1) == value

    def test_nsr_22_info(self, nsr):
        """
        Older Redis versions contained 'allocation_stats' in INFO that
        was the cause of a number of bugs when parsing.
        """
        info = "allocation_stats:6=1,7=1,8=7141,9=180,10=92,11=116,12=5330," \
               "13=123,14=3091,15=11048,16=225842,17=1784,18=814,19=12020," \
               "20=2530,21=645,22=15113,23=8695,24=142860,25=318,26=3303," \
               "27=20561,28=54042,29=37390,30=1884,31=18071,32=31367,33=160," \
               "34=169,35=201,36=10155,37=1045,38=15078,39=22985,40=12523," \
               "41=15588,42=265,43=1287,44=142,45=382,46=945,47=426,48=171," \
               "49=56,50=516,51=43,52=41,53=46,54=54,55=75,56=647,57=332," \
               "58=32,59=39,60=48,61=35,62=62,63=32,64=221,65=26,66=30," \
               "67=36,68=41,69=44,70=26,71=144,72=169,73=24,74=37,75=25," \
               "76=42,77=21,78=126,79=374,80=27,81=40,82=43,83=47,84=46," \
               "85=114,86=34,87=37,88=7240,89=34,90=38,91=18,92=99,93=20," \
               "94=18,95=17,96=15,97=22,98=18,99=69,100=17,101=22,102=15," \
               "103=29,104=39,105=30,106=70,107=22,108=21,109=26,110=52," \
               "111=45,112=33,113=67,114=41,115=44,116=48,117=53,118=54," \
               "119=51,120=75,121=44,122=57,123=44,124=66,125=56,126=52," \
               "127=81,128=108,129=70,130=50,131=51,132=53,133=45,134=62," \
               "135=12,136=13,137=7,138=15,139=21,140=11,141=20,142=6,143=7," \
               "144=11,145=6,146=16,147=19,148=1112,149=1,151=83,154=1," \
               "155=1,156=1,157=1,160=1,161=1,162=2,166=1,169=1,170=1,171=2," \
               "172=1,174=1,176=2,177=9,178=34,179=73,180=30,181=1,185=3," \
               "187=1,188=1,189=1,192=1,196=1,198=1,200=1,201=1,204=1,205=1," \
               "207=1,208=1,209=1,214=2,215=31,216=78,217=28,218=5,219=2," \
               "220=1,222=1,225=1,227=1,234=1,242=1,250=1,252=1,253=1," \
               ">=256=203"
        parsed = parse_info(info)
        assert 'allocation_stats' in parsed
        assert '6' in parsed['allocation_stats']
        assert '>=256' in parsed['allocation_stats']

    def test_nsr_large_responses(self, nsr):
        "The PythonParser has some special cases for return values > 1MB"
        # load up 5MB of data into a key
        data = ''.join([ascii_letters] * (5000000 // len(ascii_letters)))
        nsr['a'] = data
        assert nsr['a'] == b(data)

    def test_nsr_floating_point_encoding(self, nsr):
        """
        High precision floating point values sent to the server should keep
        precision.
        """
        timestamp = 1349673917.939762
        nsr.zadd('a', 'a1', timestamp)
        assert nsr.zscore('a', 'a1') == timestamp
