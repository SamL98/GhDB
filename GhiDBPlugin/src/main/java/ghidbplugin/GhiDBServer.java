package ghidbplugin;

import java.io.*;
import java.net.*;
import java.lang.Thread;

public class GhiDBServer extends Thread {
	
	private GhiDBPluginPlugin owner;
	boolean shouldExit;
	boolean started;
	
	public GhiDBServer(GhiDBPluginPlugin owner) {		
		this.owner = owner;
		this.shouldExit = false;
		this.started = false;
	}
	
	public void exit() {
		shouldExit = true;
	}
	
	public boolean hasStarted() {
		return started;
	}
	
	public void run() {
		owner.setStatusMsg("Starting GhiDB server");
		started = true;
		
		ServerSocket ss;
		DataInputStream dis;
		
		try {
			ss = new ServerSocket(13377);
			Socket s = ss.accept();
			dis = new DataInputStream(s.getInputStream());
		}
		catch (IOException e) {
			owner.setStatusMsg("Error creating socket/accepting connection: " + e);
			return;
		}

        owner.setStatusMsg("Accepted connection");

        while (!this.shouldExit) {
            String msg;

            try {
                msg = dis.readUTF();
            }
            catch (IOException e) {
                owner.setStatusMsg("Error while reading from socket " + e);
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
        	ss.close();
        }
        catch (IOException e) {
        	this.owner.setStatusMsg("Error closing socket: " + e);
        }
    }

}
