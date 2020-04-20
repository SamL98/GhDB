package ghidbplugin;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import ghidra.program.model.address.Address;

public class BreakpointTableModel extends AbstractTableModel {
	
	private final String[] columnNames = {"Enabled", "ID", "Name", "Address"};
	private ArrayList<Object[]> data;
	
	public BreakpointTableModel() {
		data = new ArrayList<Object[]>();
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
		
		return data.get(rowIndex)[columnIndex];
	}

	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		if (rowIndex < 0 || rowIndex >= data.size() || columnIndex < 0 || columnIndex >= columnNames.length)
			return;
		
		data.get(rowIndex)[columnIndex] = aValue;
		
		fireTableCellUpdated(rowIndex, columnIndex);
	}
	
	public void addRow(int bpID, String bpName, Address bpAddr) {
		Object[] row = {true, bpID, bpName, bpAddr};
		data.add(row);
		
		fireTableRowsInserted(data.size()-1, data.size()-1);
	}
	
	public void deleteRow(int rowIndex) {
		if (rowIndex < 0 || rowIndex >= data.size())
			return;
		
		fireTableRowsDeleted(rowIndex, rowIndex);
	}

}
