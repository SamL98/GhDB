/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidbplugin;

import java.awt.BorderLayout;
import java.awt.Dimension;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.util.HelpLocation;
import java.util.HashMap;
import java.util.Map;
import docking.widgets.table.GTable;
import resources.Icons;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Ghidra interface for LLDB.",
	description = "Add breakpoints, step through code, all in Ghidra."
)
//@formatter:on
public class GhiDBPluginPlugin extends ProgramPlugin {

	MyProvider provider;
	GhiDBServer serverThread;
	
	private Map<Integer, Bookmark> breakpoints;
	private Program program;
	private FlatProgramAPI flatProgram;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public GhiDBPluginPlugin(PluginTool tool) {		
		super(tool, true, true);

		// TODO: Customize provider (or remove if a provider is not desired)
		String pluginName = getName();
		provider = new MyProvider(this, pluginName);

		// TODO: Customize help (or remove if help is not desired)
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));
		
		breakpoints = new HashMap<Integer, Bookmark>();
	}

	@Override
	public void init() {
		super.init();
	}
	
	@Override
	public void dispose() {
		super.dispose();
		
		if (serverThread == null || !serverThread.hasStarted())
			return;
		
		serverThread.exit();
		
		try {
			serverThread.join();
		} catch (InterruptedException e) {
			setStatusMsg("Error joining server thread: " + e);
		}
	}
	
	@Override
	public void programActivated(Program p) {
		program = p;
		
		if (program == null) {
			System.err.println("Active program is null. Cannot create server thread");
			return;
		}
		
		flatProgram = new FlatProgramAPI(program);
		
		serverThread = new GhiDBServer(this);
		serverThread.start();
	}

	public void setStatusMsg(String msg) {
		System.out.println(msg);
		tool.setStatusInfo(msg);
	}
	
	public void bpCreated(int bpID, String addrString) {
		if (program == null || flatProgram == null)
			return;
		
		Address addr = flatProgram.toAddr(addrString);
		
		int transactionID = program.startTransaction("Create bookmark");
		Bookmark bookmark = this.flatProgram.createBookmark(addr, "breakpoints", String.format("Breakpoint %d", bpID));
		program.endTransaction(transactionID, true);
		
        breakpoints.put(bpID, bookmark);
        
        // Create a breakpoint row in the GUI
        provider.createBreakpoint(bpID, "Breakpoint " + bpID, addr);
	}
	
	public void bpHit(String addrString) {
		if (flatProgram == null)
			return;
		
		Address addr = flatProgram.toAddr(addrString);
		
		ProgramLocation location = new ProgramLocation(currentProgram, addr);
		PluginEvent ev = new ProgramLocationPluginEvent(null, location, currentProgram);
		tool.firePluginEvent(ev);
		
		AddressSet addrSet = new AddressSet(addr);
		ProgramSelection sel = new ProgramSelection(addrSet);
		ev = new ProgramSelectionPluginEvent(getClass().getName(), sel, currentProgram);
		tool.firePluginEvent(ev);
	}
	
	public void bpDeleted(int bpID) {
		if (program == null || flatProgram == null || !breakpoints.containsKey(bpID))
			return;
		
		int transactionID = program.startTransaction("Create bookmark");
		flatProgram.removeBookmark(breakpoints.get(bpID));
		program.endTransaction(transactionID, true);
	}
	
	public void clearBps() {
		for (Integer bpID : breakpoints.keySet())
			bpDeleted(bpID);
		
		breakpoints = new HashMap<Integer, Bookmark>();
	}

	// TODO: If provider is desired, it is recommended to move it to its own file
	private static class MyProvider extends ComponentProvider {

		private JPanel panel;
		private DockingAction action;
		private GTable bpTable;

		public MyProvider(Plugin plugin, String owner) {
			super(plugin.getTool(), owner, owner);
			buildPanel();
			createActions();
		}

		// Customize GUI
		private void buildPanel() {
			panel = new JPanel(new BorderLayout());
			panel.setPreferredSize(new Dimension(400, 200));
			
			DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
			centerRenderer.setHorizontalAlignment(SwingConstants.CENTER);
			
			bpTable = new GTable(new BreakpointTableModel());
			
			bpTable.getColumn("Enabled").setWidth(5);
			
			bpTable.getColumn("ID").setWidth(5);
			bpTable.getColumn("ID").setCellRenderer(centerRenderer);
			
			JScrollPane scrollPane = new JScrollPane(bpTable);
			panel.add(scrollPane, BorderLayout.PAGE_START);
			
			setVisible(true);
		}

		// TODO: Customize actions
		private void createActions() {
			action = new DockingAction("Create Breakpoint", getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					//JPanel panel = new JPanel(new BorderLayout());
				}
			};
			action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
			action.setEnabled(true);
			action.markHelpUnnecessary();
			dockingTool.addLocalAction(this, action);
			
			dockingTool.setStatusInfo("GhiDB not yet started");
		}

		@Override
		public JComponent getComponent() {
			return panel;
		}
		
		private BreakpointTableModel getTableModel() {
			return (BreakpointTableModel)bpTable.getModel();
		}
		
		public void createBreakpoint(int bpID, String bpName, Address bpAddr) {
			getTableModel().addRow(bpID, bpName, bpAddr);
			refresh();
		}
		
		public void refresh() {
			panel.revalidate();
			panel.repaint();
		}
	}
}
