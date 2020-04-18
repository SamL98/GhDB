import atexit
import lldb
import os
import re

from multiprocessing.connection import Client
from os.path import abspath, dirname, join

class GhDBClient(object):
    def __init__(self):
        self.conn = Client(('localhost', 13377))
        atexit.register(self.shutdown)

    def notify_bp_created(self, bp_idx, addr):
        self.conn.send_bytes(('bp %d 0x%x' % (bp_idx, addr)).encode('utf-8'))

    def notify_bp_triggered(self, addr):
        self.conn.send_bytes(('goto 0x%x' % addr).encode('utf-8'))

    def shutdown(self):
        self.conn.send_bytes('stop'.encode('utf-8'))
        self.conn.close()

# regex to get the breakpoint index from a created breakpoint.
BP_IDX_RE = re.compile('Breakpoint \d+:')

# Client to interact with the Ghidra-facing server.
client = GhDBClient()

# Set the absolute path to this file as an environment variable so that our breakpoint script can import
# `client` from us. Like almost everything else in this script, it is an ugly workaround.
os.environ['GHDB_CLIENT_PATH'] = abspath(__file__)

# I wish we could just pass a function but at least we get syntax highlighting this way.
bp_script_path = abspath(join(dirname(__file__), 'breakpoint_script.py'))
with open(bp_script_path) as f:
    bp_script = f.read()


# TODO: Add support for deleting and enabling/disabling breakpoints.
def _bp_set(debugger, result):
    if not result.Succeeded():
        return

    # Get the breakpoint index from the output string. Does anyone know how to get this programmatically?
    output = result.GetOutput()
    if not BP_IDX_RE.match(output):
        return

    bp_idx = output.split(': ')[0].split(' ')[1]
    if not bp_idx.isdigit():
        return

    bp_idx = int(bp_idx) - 1

    bp = debugger.GetSelectedTarget().GetBreakpointAtIndex(bp_idx)

    # Set our function to run when the breakpoint is triggered.
    bp.SetScriptCallbackBody(bp_script)

    num_locations = bp.GetNumLocations()

    for loc_idx in range(num_locations):
        loc = bp.GetLocationAtIndex(loc_idx)
        addr = loc.GetAddress().GetFileAddress() # TODO: Figure out how to deal with different modules

        # Let Ghidra know every address associated with our breakpoint.
        client.notify_bp_created(bp_idx + 1, addr)


def ghb(debugger, command, result, internal_dict):
    debugger.GetCommandInterpreter().HandleCommand('b %s' % command, result)
    _bp_set(debugger, result)


def ghbr(debugger, command, result, internal_dict):
    debugger.GetCommandInterpreter().HandleCommand('br %s' % command, result)
    _bp_set(debugger, result)


def ghbreakpoint(debugger, command, result, internal_dict):
    debugger.GetCommandInterpreter().HandleCommand('breakpoint %s' % command, result)
    _bp_set(debugger, result)


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f ghdb_client.ghb ghb')
    debugger.HandleCommand('command script add -f ghdb_client.ghbr ghbr')
    debugger.HandleCommand('command script add -f ghdb_client.ghbreakpoint ghbreakpoint')
    print('ghb locked and loaded')
