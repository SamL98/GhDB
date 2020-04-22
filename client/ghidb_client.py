import atexit
import lldb
import re
import threading

from os.path import abspath, dirname, join
from client_thread import GhiDBClientThread


# regex to get the breakpoint index from a created breakpoint.
BP_IDX_RE = re.compile('Breakpoint \d+:')

# Client to interact with the Ghidra-facing server.
client = None


# TODO: Add support for deleting and enabling/disabling breakpoints.
def _bp_set(debugger, result):
    global client

    if not result.Succeeded() or client is None:
        return

    # It would be possible to programmatically create the breakpoint but I didn't feel like manually
    # handling all of the possible arguments and options, so I'm just forwarding them to lldb and parse the output string.
    output = result.GetOutput()
    if not BP_IDX_RE.match(output):
        return

    bp_idx = output.split(': ')[0].split(' ')[1]
    if not bp_idx.isdigit():
        return

    bp_idx = int(bp_idx) - 1
    bp = debugger.GetSelectedTarget().GetBreakpointAtIndex(bp_idx)

    for loc_idx in range(bp.GetNumLocations()):
        loc = bp.GetLocationAtIndex(loc_idx)

        # TODO: Figure out how to deal with different modules
        addr = loc.GetAddress().GetFileAddress()  

        # Tell the thread to let Ghidra know every address associated with our breakpoint.
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


def ghstart(debugger, command, result, internal_dict):
    global client

    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    broadcaster = target.GetBroadcaster()

    # Add our thread as a listener to the broadcaster.
    listener = lldb.SBListener("breakpoint listener")
    rc = broadcaster.AddListener(listener, lldb.SBProcess.eBroadcastBitStateChanged)

    if not rc:
        result.SetStatus(lldb.eReturnStatusFailed)
        result.AppendMessage('Failed to add listener')
        return

    # Create the thread for maximum power!
    client = GhiDBClientThread(listener, process, process.GetSelectedThread().GetSelectedFrame())
    client.start()

    # Join the thread on exit.
    atexit.register(_cleanup)
    
    # Let the user know everythin's honkey-dorey.
    result.SetStatus(lldb.eReturnStatusSuccessContinuingResult)
    result.AppendMessage('Connected to Ghidra server')


def _cleanup():
    global client

    if client is not None:
        client.exit()
        client.join()


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f ghidb_client.ghstart ghstart')
    debugger.HandleCommand('command script add -f ghidb_client.ghb ghb')
    debugger.HandleCommand('command script add -f ghidb_client.ghbr ghbr')
    debugger.HandleCommand('command script add -f ghidb_client.ghbreakpoint ghbreakpoint')
    print('GhiDB locked and loaded')
