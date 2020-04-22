package ghidbplugin;

import java.io.*;
import java.net.*;
import java.lang.Thread;

public class GhiDBServer extends Thread {
	
	private GhiDBPluginPlugin owner;
	private boolean shouldExit;
	private boolean started;
	
	public Object socketLock;
	private DataOutputStream dos;
	
	public GhiDBServer(GhiDBPluginPlugin owner) {		
		this.owner = owner;
		shouldExit = false;
		started = false;
		
		socketLock = new Object();
		dos = null;
	}
	
	public void exit() {
		shouldExit = true;
	}
	
	public boolean hasStarted() {
		return started;
	}
	
	public void setBpEnabled(Breakpoint bp) {
		if (dos == null)
			return;
		
		String cmd;
		
		if (bp.isEnabled())
			cmd = "br en ";
		else
			cmd = "br dis ";
		
		cmd += bp.getId();
		
		try {
			synchronized(socketLock) {
				dos.writeUTF(cmd);
				dos.flush();
			}
		}
		catch (IOException e) {
			owner.setStatusMsg("Error writing to socket: " + e);
		}
	}
	
	public void deleteBp(Breakpoint bp) {
		if (dos == null)
			return;
		
		String cmd = "br del " + bp.getId();
		
		try {
			synchronized(socketLock) {
				dos.writeUTF(cmd);
				dos.flush();
			}
		}
		catch (IOException e) {
			owner.setStatusMsg("Error writing to socket: " + e);
		}
	}
	
	public void run() {
		owner.setStatusMsg("Starting GhiDB server");
		started = true;
		
		ServerSocket ss;
		DataInputStream dis;
		String msg;
		
		try {
			ss = new ServerSocket(13377);
			Socket s = ss.accept();
			
			dis = new DataInputStream(s.getInputStream());
			dos = new DataOutputStream(s.getOutputStream());
		}
		catch (IOException e) {
			owner.setStatusMsg("Error creating socket/accepting connection: " + e);
			return;
		}

        owner.setStatusMsg("Accepted connection");

        while (!this.shouldExit) {
            try {
            	// I assume there's a better way than just spinning? Java people, help me out here.
                if (dis.available() == 0)
                	continue;
                
            	synchronized(socketLock) {
            		msg = dis.readUTF();
            	}
            }
            catch (IOException e) {
                owner.setStatusMsg("Error while reading from socket. Client must've disconnected");
                break;
            }

            if (msg.startsWith("goto")) {
                String[] comps = msg.split(" ");

                if (comps.length != 2) {
                    owner.setStatusMsg("Must pass an address with the goto command");
                    continue;
                }

                owner.setStatusMsg(String.format("Going to %s", comps[1]));
                owner.bpHit(comps[1]);
            }
            else if (msg.startsWith("bp")) {
                String[] comps = msg.split(" ");

                if (comps.length != 3) {
                    this.owner.setStatusMsg("Must pass a breakpoint index and an address with the bp command");
                    continue;
                }

                int bpID = Integer.parseInt(comps[1]);

                owner.setStatusMsg(String.format("Breakpoint %d created at %s", bpID, comps[2]));
                owner.bpCreated(bpID, comps[2]);
            }
            else if (msg.equals("stop")) {
                this.owner.setStatusMsg("Shutting down server");
                break;
            }
        }
        
        owner.clearBps();

        try {
        	if (dos != null)
        		dos.close();
        	
        	dis.close();
        	ss.close();
        }
        catch (IOException e) {
        	this.owner.setStatusMsg("Error closing socket: " + e);
        }
    }

}
