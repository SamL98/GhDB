package ghidbplugin;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import ghidra.program.model.address.Address;

public class BreakpointTableModel extends AbstractTableModel {
	
	private GhiDBPluginPlugin owner;
	private String[] columnNames;
	private ArrayList<Breakpoint> data;
	
	public BreakpointTableModel(GhiDBPluginPlugin owner) {
		this.owner = owner;
		columnNames = Breakpoint.getFieldNames();
		data = new ArrayList<Breakpoint>();
	}

	public int getRowCount() {
		return data.size();
	}

	public int getColumnCount() {
		return columnNames.length;
	}

	public String getColumnName(int columnIndex) {
		if (columnIndex < 0 || columnIndex >= columnNames.length)
			return null;
		
		return columnNames[columnIndex];
	}

	public Class<?> getColumnClass(int columnIndex) {
		return getValueAt(0, columnIndex).getClass();
	}

	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return (columnIndex == 0) || (columnIndex == 2);
	}

	public Object getValueAt(int rowIndex, int columnIndex) {
		if (rowIndex < 0 || rowIndex >= data.size() || columnIndex < 0 || columnIndex >= columnNames.length)
			return null;
		
		return data.get(rowIndex).getValueAt(columnIndex);
	}

	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		if (rowIndex < 0 || rowIndex >= data.size() || columnIndex < 0 || columnIndex >= columnNames.length)
			return;
		
		Breakpoint bp = data.get(rowIndex);		
		bp.setValueAt(columnIndex, aValue);
		
		switch (columnIndex) {
		case 0: owner.setBpEnabled(bp); break;
		default: break;
		}
		
		fireTableCellUpdated(rowIndex, columnIndex);
	}
	
	public void addRow(int bpID, String bpName, Address bpAddr, boolean fromLLDB) {
		Breakpoint bp = new Breakpoint(true, bpID, bpName, bpAddr, fromLLDB);
		data.add(bp);
		
		if (!fromLLDB)
			owner.createBp(bp);
		
		fireTableRowsInserted(data.size()-1, data.size()-1);
	}
	
	public void deleteRow(int rowIndex) {
		if (rowIndex < 0 || rowIndex >= data.size())
			return;
		
		Breakpoint bp = data.get(rowIndex);
		owner.deleteBp(bp);
		data.remove(bp);
		
		fireTableRowsDeleted(rowIndex, rowIndex);
	}

}
