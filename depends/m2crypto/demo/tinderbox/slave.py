#!/usr/bin/env python
#
"""
This is a sample Tinderbox2 buildslave script.

NOTE: WAIT at least 6 minutes after the last build before starting
      the next build!

Create config.ini file with the following contents:

[build]
name = identify your build slave, for example Ubuntu 8.04 32-bit
;;optional fields:
;;uname = uname -a
;;swig = swig -version
;;cc = gcc --version
;;openssl = openssl version
;;python = python --version
;;clean = rm -fr m2crypto
;;svn = svn co http://svn.osafoundation.org/m2crypto/trunk m2crypto
;;patch = 
;;build = python setup.py clean --all build
;; OR another way to do tests without setuptools:
;;build = PYTHONPATH=build/lib-something python tests/alltests.py
;;test = python setup.py test
;;wait = 3600
;;timeout = 180

[email]
from = your email
to = Email Heikki Toivonen to get the address
user = smtp username
password = smtp password
server = smtp server
port = smtp port
"""

import time, smtplib, os, ConfigParser, tempfile
import build_lib as bl

# Change to True when you are troubleshooting this build script
debug_script = False

# These commands assume we are running on a unix-like system where default
# build options work and all prerequisites are installed and in PATH etc.
DEFAULT_COMMANDS = {
  'uname': ['uname', '-a'],
  'swig': ['swig', '-version'],
  'cc': ['gcc', '--version'],
  'openssl': ['openssl', 'version'],
  'python': ['python', '--version'],
  'clean': ['rm', '-rf', 'm2crypto'],
  'svn': ['svn', 'co', 'http://svn.osafoundation.org/m2crypto/trunk', 'm2crypto'],
  'patch': [],
  'build': ['python', 'setup.py', 'clean', '--all', 'build'],
  'test': ['python', 'setup.py', 'test']
}

def load_config(cfg='config.ini'):
    config = {}
    cp = ConfigParser.ConfigParser()
    cp.read(cfg)
    for section in cp.sections():
        for option in cp.options(section):
            config[option] = cp.get(section, option).strip()
    return config

# XXX copied from test_ssl
def zap_servers():
    s = 's_server'
    fn = tempfile.mktemp() 
    cmd = 'ps | egrep %s > %s' % (s, fn)
    os.system(cmd)
    f = open(fn)
    while 1:
        ps = f.readline()
        if not ps:
            break
        chunk = string.split(ps)
        pid, cmd = chunk[0], chunk[4]
        if cmd == s:
            os.kill(int(pid), 1)
    f.close()
    os.unlink(fn)

def build(commands, config):
    status = 'success'
    
    cwd = os.getcwd()
    timeout = int(config.get('timeout') or 180)
    
    bl.initLog('tbox.log', echo=debug_script)
    
    starttime = int(time.time())
    
    for command in commands:
        cmd = config.get(command) 
        if not cmd:
            cmd = DEFAULT_COMMANDS[command]
            if not cmd:
                continue
        else:
            cmd = cmd.split()
        
        bl.log('*** %s, timeout=%ds' % (' '.join(cmd), timeout))
        
        exit_code = bl.runCommand(cmd, timeout=timeout) 
        if exit_code:
            bl.log('*** error exit code = %d' % exit_code)
            if command == 'test':
                status = 'test_failed'
                if os.name != 'nt':
                    try:
                        # If tests were killed due to timeout, we may have left
                        # openssl processes running, so try killing
                        zap_servers()
                    except Exception, e:
                        bl.log('*** error: tried to zap_servers: ' + str(e))
            else:
                status = 'build_failed'
            break
        if command == 'svn':
            os.chdir('m2crypto')
        
    timenow = int(time.time())
    
    bl.closeLog()
    
    os.chdir(cwd)

    return 'tbox.log', starttime, timenow, status


def email(logpath, starttime, timenow, status, config):
    msg = """From: %(from)s
To: %(to)s
Subject: tree: M2Crypto


tinderbox: tree: M2Crypto
tinderbox: starttime: %(starttime)d
tinderbox: timenow: %(timenow)d
tinderbox: status: %(status)s
tinderbox: buildname: %(buildname)s
tinderbox: errorparser: unix
tinderbox: END

""" % {'from': config['from'], 'to': config['to'], 
       'starttime': starttime, 'timenow': timenow,
       'status': status,
       'buildname': config['name']}
    
    msg += open(logpath).read()
    
    server = smtplib.SMTP(host=config['server'], port=int(config['port']))
    if debug_script:
        server.set_debuglevel(1)
    server.starttls() # if your server supports STARTTLS
    if config.get('user'):
        server.login(config['user'], config['password'])
    server.sendmail(config['from'], config['to'], msg)
    server.quit()


if __name__ == '__main__':
    config = load_config()    
    
    commands = ['uname', 'swig', 'cc', 'openssl', 'python', 'clean', 'svn',
                'patch', 'build', 'test']

    logpath, starttime, timenow, status = build(commands, config)
    email(logpath, starttime, timenow, status, config)
