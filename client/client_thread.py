import lldb
import threading
import socket
import struct as st
import sys


class GhiDBClientThread(threading.Thread):
    # The code for this thread is based off LLDB docs: https://lldb.llvm.org/python_reference/index.html
    # and similarly lldb-trace: https://github.com/gm281/lldb-trace.

    def __init__(self, listener, process, frame):
        super().__init__()

        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.connect(('127.0.0.1', 13377))
        self.conn.settimeout(0.1)

        self.conn_lock = threading.Lock()

        self.listener = listener
        self.process = process

        self.last_pc = None
        self.module_uuid = frame.GetModule().GetUUIDString()
        self.frame_id = frame.GetFrameID()

        self.should_exit = False


    def send(self, msg):
        tot_bytes_sent = 0

        while tot_bytes_sent < len(msg):
            bytes_sent = self.conn.send(msg[tot_bytes_sent:])
            if bytes_sent == 0:
                return

            tot_bytes_sent += bytes_sent
            print('%d / %d' % (tot_bytes_sent, len(msg)))

        print('Sent %s' % str(msg))


    def send_with_len(self, msg):
        # This is the only method we need to protect with a lock since we call it if
        # the process is stopped but the main thread also calls it when a new breakpoint is set.
        self.conn_lock.acquire()

        # Apparently Java runs on big endian. This probably isn't universal. Work in a way
        # to not hardcode endianness.
        self.send(st.pack('>H', len(msg)))
        self.send(msg)

        self.conn_lock.release()


    def read_bs(self, nb):
        bs = []

        while len(bs) < nb:
            try:
                chunk = list(self.conn.recv(nb - len(bs)))
            except socket.timeout:
                return bytes(bs)

            if len(chunk) == 0:
                return bytes(bs)

            bs.extend(chunk)

        return bytes(bs)


    def read_java_str(self):
        str_len_bs = self.read_bs(2)
        if len(str_len_bs) < 2:
            return None

        str_len = st.unpack('>H', str_len_bs)[0]

        str_bs = self.read_bs(str_len)
        if len(str_bs) < str_len:
            return None

        return str_bs.decode('utf-8')


    def exit(self):
        self.should_exit = True


    def notify_bp_created(self, bp_idx, addr):
        self.send_with_len(('bp %d 0x%x' % (bp_idx, addr)).encode('utf-8'))


    def notify_pc_changed(self, addr):
        self.send_with_len(('goto 0x%x' % addr).encode('utf-8'))


    def handle_remote_cmd(self, cmd):
        print(cmd)


    def shutdown(self):
        self.conn.send_bytes('stop'.encode('utf-8'))
        self.conn.close()


    def check_for_process_stopped(self):
        # Wait one second for an LLDB event.
        event = lldb.SBEvent()
        self.listener.WaitForEvent(1, event)

        # Keep spinning if the process isn't stopped.
        if self.process.GetState() != lldb.eStateStopped:
            return

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
            return

        # If the PC hasn't changed, the user just hasn't continued from this breakpoint.
        # Wait until they do so.
        curr_pc = curr_frame.GetPC()
        if self.last_pc is not None and curr_pc == self.last_pc:
            return

        # Tell Ghidra we stopped at a new location.
        self.notify_pc_changed(curr_pc)
        self.last_pc = curr_pc


    def check_for_cmd_to_receive(self):
        cmd = self.read_java_str()
        if cmd is None:
            return

        self.handle_remote_cmd(cmd)


    def run(self):
        while not self.should_exit:
            self.check_for_process_stopped()
            self.check_for_cmd_to_receive()
    
        self.shutdown()

