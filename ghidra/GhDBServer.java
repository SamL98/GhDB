import java.io.*;
import java.net.*;
import java.util.ArrayList;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;

public class GhDBServer extends GhidraScript {

    public void run() throws Exception {
        ServerSocket ss = new ServerSocket(13377);
        Socket s = ss.accept();

        println("Accepted connection");

        DataInputStream dis = new DataInputStream(s.getInputStream());
        ArrayList bookmarks = new ArrayList<Bookmark>();

        while (true) {
            String msg;

            try {
                msg = (String)dis.readUTF();
            }
            catch (IOException e) {
                printerr("Error while reading from socket " + e);
                break;
            }

            if (msg.startsWith("goto")) {
                String[] comps = msg.split(" ");
                
                if (comps.length != 2) {
                    printerr("Must pass an address with the goto command");
                    continue;
                }

                Address newLoc = toAddr(comps[1]);

                printf("Going to %x\n", newLoc.getOffset());

                setCurrentLocation(newLoc);
            }
            else if (msg.startsWith("bp")) {
                String[] comps = msg.split(" ");

                if (comps.length != 3) {
                    printerr("Must pass a breakpoint index and an address with the bp command");
                    continue;
                }

                int bpIdx = Integer.parseInt(comps[1]);
                Address bpAddr = toAddr(comps[2]);

                printf("Breakpoint %d created at %x\n", bpIdx, bpAddr.getOffset());

                Bookmark bookmark = createBookmark(bpAddr, "breakpoints", String.format("Breakpoint %d", bpIdx));
                bookmarks.add(bookmark);
            }
            else if (msg.equals("stop")) {
                println("Shutting down server");
                break;
            }
        }

        // Remove all of the bookmarks created and close the socket

        for (int i = 0; i < bookmarks.size(); i++) {
            removeBookmark((Bookmark)bookmarks.get(i));
        }

        ss.close();
    }
    
}
