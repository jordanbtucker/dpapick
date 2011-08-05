#   Copyright (c) 2006-2007 Open Source Applications Foundation
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

# Trimmed down for M2Crypto build purposes

import os, sys
import glob
import fnmatch
import shutil
import fileinput
import errno
import subprocess
import killableprocess
import tempfile


_logFilename   = 'tbox.log'
_logPrefix     = ''
_logFile       = None
_logEcho       = True
_logEchoErrors = False


def initLog(filename, prefix='', echo=True, echoErrors=False):
    """
    Initialize log file and store log parameters

    Note: initLog assumes it is called only once per program
    """
    global _logFilename, _logPrefix, _logFile, _logEcho, _logEchoErrors

    _logFilename   = filename or _logFilename
    _logEcho       = echo
    _logEchoErrors = echoErrors
    _logPrefix     = prefix

    try:
        _logFile = open(_logFilename, 'w+')
        result = True
    except:
        result = False

    return result


def closeLog():
    """Need to close log to flush all data."""
    _logFile.close()


def log(msg, error=False, newline='\n'):
    """
    Output log message to an open log file or to StdOut
    """
    echo = _logEcho

    if _logFile is None:
        if error or _logEcho:
            echo = True
    else:
        _logFile.write('%s%s%s' % (_logPrefix, msg, newline))

        if error and _logEchoErrors:
            sys.stderr.write('%s%s%s' % (_logPrefix, msg, newline))

    if echo:
        sys.stdout.write('%s%s%s' % (_logPrefix, msg, newline))
        sys.stdout.flush()


def setpgid_preexec_fn():
    os.setpgid(0, 0)


def runCommand(cmd, env=None, timeout=-1, logger=log, ignorepreexec=False):
    """
    Execute the given command and log all output

        Success and failure codes:

        >>> runCommand(['true'])
        0
        >>> runCommand(['false'])
        1

        Interleaved stdout and stderr messages:

        >>> runCommand(['python', '-c', r'print 1;import sys;sys.stdout.flush();print >>sys.stderr, 2;print 3'])
        1
        2
        3
        0

        Now with timeout:

        >>> runCommand(['python', '-c', r'print 1;import sys;sys.stdout.flush();print >>sys.stderr, 2;print 3'], timeout=5)
        1
        2
        3
        0

        Setting environment variable:

        >>> runCommand(['python', '-c', 'import os;print os.getenv("ENVTEST")'], env={'ENVTEST': '42'})
        42
        0

        Timeout:
        >>> runCommand(['sleep', '60'], timeout=5)
        -9
    """
    redirect = True

    if logger == log and _logFile is None:
        redirect = False
    else:
        if timeout == -1:
            output = subprocess.PIPE
        else:
            output = tempfile.TemporaryFile()

    if ignorepreexec:
        preexec_fn = None
    else:
        preexec_fn = setpgid_preexec_fn

    if redirect:
        p = killableprocess.Popen(cmd, env=env, stdin=subprocess.PIPE, stdout=output, stderr=subprocess.STDOUT, preexec_fn=preexec_fn)
    else:
        p = killableprocess.Popen(cmd, env=env, stdin=subprocess.PIPE, preexec_fn=preexec_fn)

    try:
        if timeout == -1 and redirect:
            for line in p.stdout:
                logger(line[:-1])

        p.wait(timeout=timeout, group=True)

    except KeyboardInterrupt:
        try:
            p.kill(group=True)

        except OSError:
            p.wait(30)

    if timeout != -1 and redirect:
        output.seek(0)
        for line in output:
            logger(line[:-1])

    return p.returncode
