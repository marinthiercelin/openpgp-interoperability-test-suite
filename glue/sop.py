#!/usr/bin/python3
# PYTHON_ARGCOMPLETE_OK
'''Stateless OpenPGP Scaffolding

Author: Daniel Kahn Gillmor
Date: October 2019
License: MIT (see below)

This module implements a pythonic framework for `sop`, the Stateless
OpenPGP command-line interface.  It makes it easier to build out a
python-based backend.

In particular, sop.StatelessOpenPGP presents a generic baseclass for
building an implementation of `sop`.

To use it sensibly, subclass sop.StatelessOpenPGP and override the
following functions:

 - generate()
 - convert()
 - sign()
 - verify()
 - encrypt()
 - decrypt()
 - armor()
 - dearmor()

See the docstrings for each of these functions for more detail on
their expected behavior.

To augment the interface by adding new subcommands, or to add
arguments to existing subcommands, override extend_parsers().

To add an additional indirect forms of input like @FOO:bar, create a
method indirect_input_FOO(self, name:str)->bytes.  For example, if a default
keyring is available, indexable by primary key fingerprint:

    def indirect_input_KEYRING(self, name:str) -> bytes:
         return self._keyring.get_certificate_by_fingerprint(name)

The program invocable from the command line should instantiate the
subclass, and then call dispatch() on it.

A minimal example follows:

----------
#!/usr/bin/python3
# PYTHON_ARGCOMPLETE_OK
import sop

class FooSop(sop.StatelessOpenPGP):
    def __init__(self):
        super().__init__(prog='FooPGP', version='0.17')
    # overrides go here...

if __name__ = "__main__":
    foo = FooSop()
    foo.dispatch()
----------

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation files
(the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software,
and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

'''

import os
import io
import sys
import string
import logging

from enum import Enum,auto
from binascii import unhexlify, hexlify
from datetime import datetime, timezone
from argparse import ArgumentParser, _SubParsersAction, Namespace
from typing import List, Optional, Dict, Sequence, MutableMapping, Tuple

__version__:str = '0.1'

try:
    import argcomplete #type: ignore
except ImportError:
    argcomplete = None


class SOPSigType(Enum):
    binary = auto()
    text = auto()

class SOPLiteralDataType(Enum):
    binary = auto()
    text = auto()
    mime = auto()

class SOPArmorLabel(Enum):
    sig = auto()
    cert = auto()
    key = auto()
    message = auto()

class SOPEncryptMode(Enum):
    any = auto()
    communications = auto()
    storage = auto()

class SOPException(Exception):
    exit_code = 2
class SOPNoSignature(SOPException):
    exit_code = 3
class SOPMissingRequiredArgument(SOPException):
    exit_code = 19
class SOPIncompleteVerificationInstructions(SOPException):
    exit_code = 23
class SOPCouldNotDecrypt(SOPException):
    exit_code = 29
class SOPNonUTF8Password(SOPException):
    exit_code = 31
class SOPUnsupportedOption(SOPException):
    exit_code = 37
class SOPInvalidDataType(SOPException):
    exit_code = 41
class SOPNotUTF8Text(SOPException):
    exit_code = 53
class SOPUnsupportedSubcommand(SOPException):
    exit_code = 69

class _SOPInputHandler(object):
    '''Base class for handling indirect input

    This will never be instantiated directly, it is only split out
    from StatelessOpenPGP as a form of forward declaration to provide
    typechecking coverage for SOPSessionKey.
    '''
    def _get_indirect_input(self, name:str) -> bytes:
        if name.startswith('@'):
            method, target = name[1:].split(':', maxsplit=1)
            finder = getattr(self, f'indirect_input_{method}')
            return bytes(finder(target))
        else:
            with open(name, 'rb') as f:
                return f.read()


class SOPSessionKey(object):
    '''Stateless OpenPGP session key

    Simple class to represent an OpenPGP session key.

    Destroy this object as soon as possible, as leaking it will allow
    decryption of whatever is encrypted with it.

    `algo`: integer value referring to the number of the symmetric key algorithm

    `key`: bytes of the actual session key

    '''
    def __init__(self, sop:_SOPInputHandler, handle:str):
        try:
            data:bytes = sop._get_indirect_input(handle).strip()
            algob:bytes
            keyb:bytes
            algob, keyb = data.split(b':', maxsplit=2)
            self.algo:int = int(algob)
            self.key:Optional[bytes] = None
            if keyb != b'':
                key = unhexlify(keyb)
        except Exception as e:
            raise SOPInvalidDataType(f'Malformed session key {handle} ({e})')

    def __str__(self) -> str:
        key:bytes = b''
        if self.key is not None:
            key = hexlify(self.key)
        return f'{self.algo}:{key}'

    
class SOPSigResult(object):
    '''Stateless OpenPGP Signature Result

    This class describes a valid OpenPGP signature.
    '''
    def __init__(self, when:datetime, fingerprint:str, moreinfo:str):
        self._when:datetime = when
        self._fingerprint:str = fingerprint
        self._moreinfo:str = fingerprint

    def __str__(self) -> str:
        # ensure tz=UTC:
        whendt:datetime = datetime.fromtimestamp(self._when.timestamp(), tz=timezone.utc)
        when:str = whendt.strftime('%Y-%m-%dT%H:%M%S%Z')
        # strip all whitespace from fpr
        fpr:str = self._fingerprint.translate(str.maketrans('', '', string.whitespace))
        # strip all newlines from moreinfo
        moreinfo:str = self._moreinfo.translate(str.maketrans('\n\r', '  '))
        return f'{when} {fpr} {moreinfo}'
    
class StatelessOpenPGP(_SOPInputHandler):
    '''Stateless OpenPGP baseclass

    Subclass this object, overriding the methods with code that
    implements their declared behavior.  The methods to override are:
    generate, convert, sign, verify, encrypt, decrypt, armor, and
    dearmor.

    Then, instantiate your subclass and call dispatch() on it.

    '''
    def __init__(self, version:str, name:Optional[str]=None,
                 description:Optional[str]='A Stateless OpenPGP implementation'):
        '''Set up Stateless OpenPGP command line interface parser

        `version` should be a version string like 0.17.3

        `name` should be a human-readable name for the project with no
        whitespace in it.

        `description` should be human-readable text that describes the
        implementation.

        '''
        self._version = version

        self._parser = ArgumentParser(prog=name, description=description)
        self._parser.add_argument('--debug', action='store_true',
                                  help='show debugging data')
        _cmds:_SubParsersAction = self._parser.add_subparsers(required=True,
                                            metavar='SUBCOMMAND',
                                            dest='subcmd')
        _subs = {}
        _version = _cmds.add_parser('version', help='emit version')
        _subs['version'] = _version

        def _add_armor_flag(parser:ArgumentParser) -> None:
            g = parser.add_mutually_exclusive_group(required=False)
            g.add_argument('--armor', dest='armor', action='store_true',
                           help='generate ASCII-armored output')
            g.add_argument('--no-armor', dest='armor', action='store_false',
                           help='generate binary output')
            parser.set_defaults(armor=True)
        
        _generate = _cmds.add_parser('generate',
                                           help='generate a secret key to stdout')
        _add_armor_flag(_generate)
        _generate.add_argument('uids', metavar='USERID', nargs='*',
                               help='a User ID (a UTF-8 string)')
        _subs['generate'] = _generate

        _convert_h = 'convert a secret key from stdin to a certificate on stdout'
        _convert = _cmds.add_parser('convert',
                                          help=_convert_h)
        _add_armor_flag(_convert)
        _subs['convert'] = _convert
        
        _sign = _cmds.add_parser('sign',
                                       help='create a detached signature')
        _add_armor_flag(_sign)
        _sign.add_argument('--as', dest='sigtype',
                           choices=SOPSigType.__members__,
                           default='binary',
                           help='sign as binary document or canonical text document')
        _sign.add_argument('signers', metavar='KEY', nargs='+',
                           help='filename containing a secret key')
        _subs['sign'] = _sign

        _verify = _cmds.add_parser('verify', help='verify detached signatures')
        _verify.add_argument('--not-before', dest='start', metavar='DATE',
                             help='ignore signatures before (ISO-8601 timestamp)')
        _verify.add_argument('--not-after', dest='end', metavar='DATE',
                             help='ignore signatures after (ISO-8601 timestamp)')
        _verify.add_argument('sig', metavar='SIGNATURE',
                             help='filename containing signature(s)')
        _verify.add_argument('signers', metavar='CERT', nargs='+',
                             help='filename containing certificate of acceptable signer')
        _subs['verify'] = _verify
        
        _encrypt = _cmds.add_parser('encrypt', help='encrypt message')
        _add_armor_flag(_encrypt)
        _encrypt.add_argument('--as', dest='literaltype',
                              choices=SOPLiteralDataType.__members__,
                              default='binary',
                              help='encrypt cleartext as binary, UTF-8, or MIME')
        _encrypt.add_argument('--mode',
                              choices=SOPEncryptMode.__members__,
                              default='any',
                              help='what type of encryption-capable subkey to use')
        _encrypt.add_argument('--with-password', dest='passwords', metavar='PASSWORD',
                              action='append',
                              help='filename containing a password for symmetric encryption')
        _encrypt.add_argument('--session-key', dest='sessionkey', metavar='SESSIONKEY',
                              help='filename containing a session key to use')
        _encrypt.add_argument('--sign-with', dest='signers', metavar='KEY', action='append',
                              help='filename containing a secret key to sign with')
        _encrypt.add_argument('recipients', metavar='CERT', nargs='*',
                              help='filename containing certificate')
        _subs['encrypt'] = _encrypt


        _decrypt = _cmds.add_parser('decrypt', help='decrypt message')
        _decrypt.add_argument('--session-key-out', dest='sessionkey', metavar='SESSIONKEY',
                              help='filename to output session key to on successful decryption')
        _decrypt.add_argument('--with-password', dest='passwords',
                              metavar='password', action='append',
                              help='filename containing a password for symmetric encryption')
        _decrypt.add_argument('--verify-out', dest='verifications', metavar='VERIFICATIONS',
                             help='filename to output verification status')
        _decrypt.add_argument('--verify-with', dest='signers', metavar='CERT', nargs='*',
                             help='filename containing certificate of acceptable signer')
        _decrypt.add_argument('--verify-not-before', dest='start', metavar='DATE',
                             help='ignore signatures before (ISO-8601 timestamp)')
        _decrypt.add_argument('--verify-not-after', dest='end', metavar='DATE',
                             help='ignore signatures after (ISO-8601 timestamp)')
        _decrypt.add_argument('secretkeys', metavar='KEY', nargs='*',
                              help='filename containing secret key')
        _subs['decrypt'] = _decrypt

        _armor = _cmds.add_parser('armor', help='add ASCII armor')
        _armor.add_argument('--label', choices=SOPArmorLabel.__members__,
                            help='specify the type of ASCII armoring')
        _subs['armor'] = _armor

        _dearmor = _cmds.add_parser('dearmor', help='remove ASCII armor')
        _subs['dearmor'] = _dearmor

        self.extend_parsers(_cmds, _subs)
        if argcomplete:
            argcomplete.autocomplete(self._parser)
        elif '_ARGCOMPLETE' in os.environ:
            logging.error('Argument completion requested but the "argcomplete" module is not installed.'
                          'It can be obtained at https://pypi.python.org/pypi/argcomplete')
            sys.exit(1)

    def indirect_input_FD(self, name:str) -> bytes:
        '''Retrieve indirect data from an open file descriptor

        When providing indirect data to `sop`, rather than providing a
        filename, the user can indicate an already open file
        descriptor nnn (where nnn is a decimal integer) as `@FD:nnn`.

        '''
        with open(int(name), 'rb') as filed:
            return filed.read()
        
    def indirect_input_ENV(self, name:str) -> bytes:
        '''Retrieve indirect data from the environment

        When providing indirect data to `sop`, rather than providing a
        filename, the user can indicate an environment variable foo as
        `@ENV:foo`.
        '''
        return os.environ[name].encode()

    def extend_parsers(self, subcommands:_SubParsersAction,
                       subparsers:Dict[str,ArgumentParser]) -> None:
        '''override this function to add options or subcommands

        To add a new option to an existing subcommand, look up the
        subcommand in `subparsers` and call `add_argument` on it.
        You'll also need to override `_handle_xxx` (where `xxx` is the
        name of the modified subcommand) to accomodate the additional
        option.

        To add a new subcommand entirely, invoke `add_parser` on
        `subcommands`, and populate it appropriately.  Then implement
        method `_handle_xxx` (where `xxx` is the name of the new
        subcommand).

        '''
        pass


    def parse_timestamp(self, when:Optional[str]) -> Optional[datetime]:
        '''Parse a user-supplied string that represents a timestamp

        Handle strict ISO-8601 date formats.  Override this function
        if you want to accept fancier formats.
        '''
        if when is None:
            return None
        return datetime.strptime(when, '%Y-%m-%dT%H:%M:%S%z')


    def dispatch(self, argstrs:Optional[Sequence[str]]=None) -> None:

        '''handle the arguments passed by the user, and invoke the correct subcommand'''
        args:Namespace = self._parser.parse_args(argstrs)
        subcmd = args.subcmd
        method = getattr(self, f'_handle_{args.subcmd}')
        debug = args.debug
        if debug:
            logging.basicConfig(level=logging.DEBUG)
        subargs = vars(args)
        del subargs['subcmd']
        del subargs['debug']
        try:
            out = method(sys.stdin.buffer, **subargs)
            sys.stdout.buffer.write(out)
        except SOPException as e:
            logging.error(f'{type(e).__name__} {e}')
            exit(e.exit_code)


    def _handle_version(self, inp:io.BufferedReader) -> bytes:
        return f'{self._parser.prog} {self._version}\n'.encode('ascii')

    def _handle_generate(self,
                         inp:io.BufferedReader,
                         armor:bool,
                         uids:List[str]) -> bytes:
        return self.generate(armor, uids)
    def generate(self, armor:bool, uids:List[str]) -> bytes:
        '''Produce an OpenPGP transferable secret key

`armor`: whether to produce an ASCII-armored form or a binary-encoded form.
        '''
        raise SOPUnsupportedSubcommand('generate')

    def _handle_convert(self,
                        inp:io.BufferedReader,
                        armor:bool) -> bytes:
        return self.convert(inp.read(), armor)
    def convert(self, key:bytes, armor:bool) -> bytes:
        '''Convert an OpenPGP transferable secret key to an OpenPGP certificate

        `key`: the OpenPGP secret key (may be in armored or unarmored
        form).

        `armor`: whether to produce an ASCII-armored form or a
        binary-encoded form.

        '''
        raise SOPUnsupportedSubcommand('convert')

    def _handle_sign(self,
                     inp:io.BufferedReader,
                     armor:bool,
                     sigtype:str,
                     signers:List[str]) -> bytes:
        return self.sign(inp.read(), armor, SOPSigType.__members__[sigtype],
                         dict((signer, self._get_indirect_input(signer)) for signer in signers))
    def sign(self, data:bytes, armor:bool, sigtype:SOPSigType,
             signers:MutableMapping[str,bytes]) -> bytes:
        '''Create a detached OpenPGP signature

        `data`: the data to sign.

        `armor`: whether to produce an ASCII-armored form or a
        binary-encoded form.

        `sigtype`: whether to make the signature as a binary signature
        or as a signature in canonical text form.

        `signers`: a map of OpenPGP transferable secret keys with
        signing capability.  The keys of this map are handles that can
        be used to identify a particular secret key in error messages.

        '''
        raise SOPUnsupportedSubcommand('sign')

    def _handle_verify(self,
                       inp:io.BufferedReader,
                       start:Optional[str],
                       end:Optional[str],
                       sig:str,
                       signers:List[str]) -> bytes:
        ret:List[SOPSigResult] = []
        ret =  self.verify(inp.read(),
                           self.parse_timestamp(start),
                           self.parse_timestamp(end),
                           self._get_indirect_input(sig),
                           dict((signer, self._get_indirect_input(signer)) for signer in signers))
        return ''.join([f'{status}\n' for status in ret]).encode()
    def verify(self, data:bytes,
               start:Optional[datetime], end:Optional[datetime],
               sig:bytes, signers:MutableMapping[str,bytes]) -> List[SOPSigResult]:
        '''Verify a detached OpenPGP signature

        If an acceptable signature was found, return a list of
        SOPSigResult objects.

        If no acceptable signature is found, raise SOPNoSignature.

        `data`: what was ostensibly signed.

        `start`: the earliest acceptable time for a signature (`None`
        means no required time).
        
        `end`: the latest acceptable time for a signature (`None`
        means "right now" -- signatures in the future should not be
        accepted).

        `signers`: the OpenPGP certificates of any acceptable signers.
        The keys to this map are handles that can be used to identify
        a particular certificate in error messages.

        '''
        raise SOPUnsupportedSubcommand('verify')

    def _handle_encrypt(self,
                        inp:io.BufferedReader,
                        literaltype:str,
                        armor:bool,
                        mode:str,
                        passwords:List[str],
                        sessionkey:Optional[str],
                        signers:List[str],
                        recipients:List[str]) -> bytes:
        sess:Optional[SOPSessionKey] = None
        if sessionkey:
            sess = SOPSessionKey(self, sessionkey)
        return self.encrypt(inp.read(), SOPLiteralDataType.__members__[literaltype],
                            armor, SOPEncryptMode.__members__[mode],
                            dict((password, self._get_indirect_input(password))
                                 for password in passwords) if passwords else dict(),
                            sess,
                            dict((signer, self._get_indirect_input(signer))
                                 for signer in signers) if signers else dict(),
                            dict((recipient, self._get_indirect_input(recipient))
                                 for recipient in recipients) if recipients else dict())
    def encrypt(self, data:bytes,
                literaltype:SOPLiteralDataType,
                armor:bool, mode:SOPEncryptMode,
                passwords:MutableMapping[str,bytes],
                sessionkey:Optional[SOPSessionKey],
                signers:MutableMapping[str,bytes],
                recipients:MutableMapping[str,bytes]) -> bytes:
        '''Encrypt a message

        Encrypt a message so that only the intended recipients (or
        someone with access to a provided password) can read it.

        `data`: the message to be encrypted

        `armor`: whether to produce an ASCII-armored message or a
        binary-encoded message.

        `passwords`: a map of passwords for symmetric encryption.  The
        keys to the map are identifiers.

        `sessionkey`: a session key to use for this encryption.

        `signers`: a map of OpenPGP secret keys to sign with.  The
        keys to this map are handles that can be used to refer to
        specific secret keys in error messages.

        `recipients`: a map of OpenPGP certificates that should be
        able to decrypt the resulting message.  The keys to this map
        are handles that can be used to refer to specific certificates
        in error messages.

        '''
        raise SOPUnsupportedSubcommand('encrypt')


    def _handle_decrypt(self,
                        inp:io.BufferedReader,
                        sessionkey:Optional[str],
                        passwords:List[str],
                        verifications:Optional[str],
                        signers:List[str],
                        start:Optional[str],
                        end:Optional[str],
                        secretkeys:List[str]) -> bytes:
        if verifications and not signers:
            raise SOPIncompleteVerificationInstructions('When --verify-out is present, at least one '
                                                        '--verify-with argument must also be present')
        if signers and not verifications:
            raise SOPIncompleteVerificationInstructions('When --verify-with is present, '
                                                        '--verify-out must also be present')
        sess:Optional[SOPSessionKey] = None
        if sessionkey:
            sess = SOPSessionKey(self, sessionkey)
        msg:bytes
        verifs:List[SOPSigResult]
        msg,verifs = self.decrypt(inp.read(),
                                  sess,
                                  dict((password, self._get_indirect_input(password))
                                       for password in passwords) if passwords else dict(),
                                  dict((signer, self._get_indirect_input(signer))
                                       for signer in signers) if signers else dict(),
                                  self.parse_timestamp(start),
                                  self.parse_timestamp(end),
                                  dict((secretkey, self._get_indirect_input(secretkey))
                                       for secretkey in secretkeys) if secretkeys else dict())
        # FIXME: do something with verifs and verifications!
        return msg
                                
    def decrypt(self,
                data:bytes,
                sessionkey:Optional[SOPSessionKey],
                passwords:MutableMapping[str,bytes],
                signers:MutableMapping[str,bytes],
                start:Optional[datetime],
                end:Optional[datetime],
                secretkeys:MutableMapping[str,bytes]) -> Tuple[bytes, List[SOPSigResult]]:
        raise SOPUnsupportedSubcommand('decrypt')

    def _handle_armor(self,
                      inp:io.BufferedReader,
                      label:Optional[str]) -> bytes:
        return self.armor(inp.read(), SOPArmorLabel.__members__[label] if label else None)
    def armor(self, data:bytes, label:Optional[SOPArmorLabel]) -> bytes:

        '''Add OpenPGP ASCII Armor

        Return the ASCII-armored form of `data`.

        `label`: which type of ASCII armor to provide (default: best guess)
        '''
        raise SOPUnsupportedSubcommand('armor')

    def _handle_dearmor(self,
                        inp:io.BufferedReader) -> bytes:
        return self.dearmor(inp.read())
    def dearmor(self, data:bytes) -> bytes:
        '''Remove OpenPGP ASCII Armor

        Return the binary-encoded form of `data`, removing any OpenPGP ASCII armor.
        '''
        raise SOPUnsupportedSubcommand('dearmor')

def main() -> None:
    sop = StatelessOpenPGP(version=__version__)
    sop.dispatch()

if __name__ == '__main__':
    main()
