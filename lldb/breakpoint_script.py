from ghdb_client import client

addr = bp_loc.GetAddress().GetFileAddress()
client.notify_bp_triggered(addr)
