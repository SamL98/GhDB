import os

# Try to get the client path from our environment.
client_path_envvar = 'GHDB_CLIENT_PATH'
if not client_path_envvar in os.environ:
    print('%d not set in environment' % client_path_envvar)
    return

# Import the client module.
client_path = os.environ[client_path_envvar]
client_module = __import__(client_path)

# Try to get the client variable from the module.
if not hasattr(client_module, 'client'):
    print('No client variable in client module')
    return

addr = bp_loc.GetAddress().GetFileAddress()
client_module.client.notify_bp_triggered(addr)
