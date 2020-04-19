import atexit
import lldb
import re
import threading

from multiprocessing.connection import Client
from os.path import abspath, dirname, join


class GhiDBClient(object):
    def __init__(self):
        self.conn = Client(('localhost', 13377))
        atexit.register(self.shutdown)

    def notify_bp_created(self, bp_idx, addr):
        self.conn.send_bytes(('bp %d 0x%x' % (bp_idx, addr)).encode('utf-8'))

    def notify_pc_changed(self, addr):
        self.conn.send_bytes(('goto 0x%x' % addr).encode('utf-8'))

    def notify_bp_triggered(self, addr):
        self.notify_pc_changed(addr)

    def shutdown(self):
        self.conn.send_bytes('stop'.encode('utf-8'))
        self.conn.close()


# regex to get the breakpoint index from a created breakpoint.
BP_IDX_RE = re.compile('Breakpoint \d+:')

# Client to interact with the Ghidra-facing server.
client = None

class ListenerThread(threading.Thread):
    # The code for this thread is based off LLDB docs: https://lldb.llvm.org/python_reference/index.html
    # and similarly lldb-trace: https://github.com/gm281/lldb-trace.

    def __init__(self, listener, process, frame):
        super().__init__()
        self.listener = listener
        self.process = process
        self.last_pc = frame.GetPC()
        self.module_uuid = frame.GetModule().GetUUIDString()
        self.frame_id = frame.GetFrameID()
        self.should_exit = False

    def exit(self):
        self.should_exit = True

    def run(self):
        global client

        while self.should_exit:
            # Get an event every second.
            event = lldb.SBEvent()
            self.listener.WaitForEvent(1, event)

            # Keep spinning if the process isn't stopped.
            if self.process.GetState() != lldb.eStateStopped:
                continue

            thread = self.process.GetSelectedThread()
            curr_frame = thread.GetSelectedFrame()
            num_frames = thread.GetNumFrames()

            # If we are stopped at a location not in the module our listener thread was created with (i.e. in printf),
            # try each parent frame until we are in the selected module.
            while curr_frame.GetFrameID() < num_frames-1 and curr_frame.GetModule().GetUUIDString() != self.module_uuid:
                curr_frame = thread.GetFrameAtIndex(curr_frame.GetFrameID() + 1)

            # If we still aren't in the selected module, we are maybe in a different thread?
            # We could probably recover from this but just igore it for now.
            if curr_frame.GetModule().GetUUIDString() != self.module_uuid:
                continue

            # If the PC hasn't changed, the user just hasn't continued from this breakpoint.
            # Wait until they do so.
            curr_pc = curr_frame.GetPC()
            if curr_pc == self.last_pc:
                continue

            # Tell Ghidra we stopped at a new location.
            if client is not None:
                client.notify_pc_changed(curr_pc)

            self.last_pc = curr_pc


listener_thread = None
        

# I wish we could just pass a function but at least we get syntax highlighting this way.
bp_script_path = abspath(join(dirname(__file__), 'breakpoint_script.py'))
with open(bp_script_path) as f:
    bp_script = f.read()


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


def ghstart(debugger, command, result, internal_dict):
    global client
    client = GhiDBClient()

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

    global listener_thread
    listener_thread = ListenerThread(listener, process, process.GetSelectedThread().GetSelectedFrame())
    listener_thread.start()

    # Join the thread on exit.
    atexit.register(_cleanup)
    
    # Let the user know everythin's honkey-dorey.
    result.SetStatus(lldb.eReturnStatusSuccessContinuingResult)
    result.AppendMessage('Connected to Ghidra server')


def _cleanup():
    global listener_thread

    if listener_thread is not None:
        listener_thread.exit()
        listener_thread.join()


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f ghidb_client.ghstart ghstart')
    debugger.HandleCommand('command script add -f ghidb_client.ghb ghb')
    debugger.HandleCommand('command script add -f ghidb_client.ghbr ghbr')
    debugger.HandleCommand('command script add -f ghidb_client.ghbreakpoint ghbreakpoint')
    print('GhiDB locked and loaded')
