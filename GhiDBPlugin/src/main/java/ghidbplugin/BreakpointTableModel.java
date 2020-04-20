package ghidbplugin;

import javax.swing.event.TableModelListener;
import javax.swing.table.TableModel;
import javax.swing.event.TableModelEvent;
import java.util.ArrayList;
import java.util.Set;
import java.util.HashSet;
import ghidra.program.model.address.Address;

public class BreakpointTableModel implements TableModel {
	
	private final String[] columnNames = {"ID", "Name", "Address"};
	private ArrayList<Object[]> data;
	private Set<TableModelListener> listeners;
	
	public BreakpointTableModel() {
		data = new ArrayList<Object[]>();
		listeners = new HashSet<TableModelListener>();
	}
	
	private void notifyListeners(TableModelEvent e) {
		for (TableModelListener l : listeners)
			l.tableChanged(e);
	}

	@Override
	public int getRowCount() {
		return data.size();
	}

	@Override
	public int getColumnCount() {
		return columnNames.length;
	}

	@Override
	public String getColumnName(int columnIndex) {
		if (columnIndex < 0 || columnIndex >= columnNames.length)
			return null;
		
		return columnNames[columnIndex];
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		return getValueAt(0, columnIndex).getClass();
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return columnIndex == 1;
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		if (rowIndex < 0 || rowIndex >= data.size() || columnIndex < 0 || columnIndex >= columnNames.length)
			return null;
		
		return data.get(rowIndex)[columnIndex];
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		if (rowIndex < 0 || rowIndex >= data.size() || columnIndex < 0 || columnIndex >= columnNames.length)
			return;
		
		data.get(rowIndex)[columnIndex] = aValue;
		
		notifyListeners(new TableModelEvent(this, rowIndex, rowIndex, columnIndex, TableModelEvent.UPDATE));
	}
	
	public void addRow(int bpID, String bpName, Address bpAddr) {
		Object[] row = {bpID, bpName, bpAddr};
		data.add(row);
		
		notifyListeners(new TableModelEvent(this, data.size()-1, data.size()-1, TableModelEvent.ALL_COLUMNS, TableModelEvent.INSERT));
	}
	
	public void deleteRow(int rowIndex) {
		if (rowIndex < 0 || rowIndex >= data.size())
			return;
		
		notifyListeners(new TableModelEvent(this, rowIndex, rowIndex, TableModelEvent.ALL_COLUMNS, TableModelEvent.DELETE));
	}

	@Override
	public void addTableModelListener(TableModelListener l) {	
		listeners.add(l);
	}

	@Override
	public void removeTableModelListener(TableModelListener l) {	
		listeners.remove(l);
	}

}
