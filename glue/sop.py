#!/usr/bin/python3
'''Stateless OpenPGP Scaffolding

This implements a pythonic framework for `sop`

This should make it easier to build out different python-based
backends that can support the same CLI interface.

Author: Daniel Kahn Gillmor
Date: 2019-10-24
License: MIT (see below)

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

import io
import sys
import logging

from argparse import ArgumentParser
from typing import List, Optional

class SOPNotImplementedError(NotImplementedError):
    pass
    
class StatelessOpenPGP(object):
    def __init__(self, prog='sop',
                 description='A Stateless OpenPGP implementation',
                 version='0.0.0'):
        '''Set up Stateless OpenPGP command line interface parser'''
        self._version = version

        # FIXME: make parser and subparsers manipulable by subclasses so that
        # implementers can extend the interface
        self._parser = ArgumentParser(prog=prog, description=description)
        self._parser.add_argument('--debug', action='store_true',
                                  help='show debugging data')
        _subparsers = self._parser.add_subparsers(required=True,
                                                  metavar='SUBCOMMAND',
                                                  dest='subcmd')
        _version = _subparsers.add_parser('version', help='emit version')

        def _add_armor_flag(parser):
            g = parser.add_mutually_exclusive_group(required=False)
            g.add_argument('--armor', dest='armor', action='store_true',
                           help='generate ASCII-armored output')
            g.add_argument('--no-armor', dest='armor', action='store_false',
                           help='generate binary output')
            parser.set_defaults(armor=True)
        
        _generate = _subparsers.add_parser('generate',
                                           help='generate a secret key to stdout')
        _add_armor_flag(_generate)
        _generate.add_argument('uids', metavar='USERID', nargs='*',
                               help='a User ID (a UTF-8 string)')

        _convert_h = 'convert a secret key from stdin to a certificate on stdout'
        _convert = _subparsers.add_parser('convert',
                                          help=_convert_h)
        _add_armor_flag(_convert)
        
        _sign = _subparsers.add_parser('sign',
                                       help='create a detached signature')
        _add_armor_flag(_sign)
        _sign.add_argument('--as', dest='sigtype',
                           choices=['binary', 'text'],
                           default='binary',
                           help='sign as binary document or canonical text document')
        _sign.add_argument('signers', metavar='KEY', nargs='+',
                           help='filename containing a secret key')
        

        _verify = _subparsers.add_parser('verify', help='verify detached signatures')
        _verify.add_argument('--not-before', dest='start', metavar='DATE',
                             help='ignore signatures before (ISO-8601 timestamp)')
        _verify.add_argument('--not-after', dest='end', metavar='DATE',
                             help='ignore signatures after (ISO-8601 timestamp)')
        _verify.add_argument('sig', metavar='SIGNATURE',
                             help='filename containing signature(s)')
        _verify.add_argument('signers', metavar='CERT', nargs='+',
                             help='filename containing certificate of acceptable signer')
        
        
        _encrypt = _subparsers.add_parser('encrypt', help='encrypt message')
        _add_armor_flag(_encrypt)
        _encrypt.add_argument('--as', dest='literaltype',
                              choices=['binary', 'text', 'mime'],
                              default='binary',
                              help='encrypt cleartext as binary, UTF-8, or MIME')
        _encrypt.add_argument('--mode',
                              choices=['any', 'communications', 'storage'],
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


        _decrypt = _subparsers.add_parser('decrypt', help='decrypt message')
        _decrypt.add_argument('--session-key-out', dest='sessionkey', metavar='SESSIONKEY',
                              help='filename to output session key to on successful decryption')
        _decrypt.add_argument('--with-password', dest='passwords',
                              metavar='password', action='append',
                              help='filename containing a password for symmetric encryption')
        _decrypt.add_argument('--verify-out', dest='verifications', metavar='VERIFICATIONS',
                             help='filename to output verification status')
        _decrypt.add_argument('--verify-with', dest='signers', metavar='CERT',
                             help='filename containing certificate of acceptable signer')
        _decrypt.add_argument('--verify-not-before', dest='start', metavar='DATE',
                             help='ignore signatures before (ISO-8601 timestamp)')
        _decrypt.add_argument('--verify-not-after', dest='end', metavar='DATE',
                             help='ignore signatures after (ISO-8601 timestamp)')
        _decrypt.add_argument('secretkeys', metavar='KEY', nargs='*',
                              help='filename containing secret key')


    def dispatch(self, args=None):
        '''handle the arguments passed by the user, and invoke the correct subcommand'''
        args=self._parser.parse_args(args)
        subcmd = args.subcmd
        method = getattr(self, args.subcmd)
        debug = args.debug
        if debug:
            logging.basicConfig(level=logging.DEBUG)
        subargs = vars(args)
        del subargs['subcmd']
        del subargs['debug']
        try:
            out = method(sys.stdin.buffer, **subargs)
            sys.stdout.buffer.write(out)
        except SOPNotImplementedError:
            logging.error(f'subcommand {subcmd} not yet implemented')
            exit(69)
        

    def version(self, inp:io.BufferedReader) -> bytes:
        return f'{self._parser.prog} {self._version}\n'.encode('ascii')

    def generate(self,
                 inp:io.BufferedReader,
                 armor:bool,
                 uids:List[str]) -> bytes:
        raise SOPNotImplementedError()

    def convert(self,
                inp:io.BufferedReader,
                armor:bool) -> bytes:
        raise SOPNotImplementedError()

    def sign(self,
             inp:io.BufferedReader,
             armor:bool,
             sigtype:str,
             signers:List[str]) -> bytes:
        raise SOPNotImplementedError()

    def verify(self,
               inp:io.BufferedReader,
               start:Optional[str],
               end:Optional[str],
               sig:str,
               signers:List[str]) -> bytes:
        raise SOPNotImplementedError()
    
    def encrypt(self,
                inp:io.BufferedReader,
                literaltype:str,
                armor:bool,
                mode:str,
                passwords:List[str],
                sessionkey:Optional[str],
                signers:List[str],
                recipients:List[str]) -> bytes:
        raise SOPNotImplementedError()

    def decrypt(self,
                inp:io.BufferedReader,
                sessionkey:Optional[str],
                passwords:List[str],
                verifications:Optional[str],
                signers:List[str],
                start:Optional[str],
                end:Optional[str],
                secretkeys:List[str]) -> bytes:
        raise SOPNotImplementedError()

def main():
    sop = StatelessOpenPGP()
    sop.dispatch()

if __name__ == '__main__':
    main()
