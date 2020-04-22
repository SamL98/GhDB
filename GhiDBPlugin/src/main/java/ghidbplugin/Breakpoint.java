package ghidbplugin;

import ghidra.program.model.address.Address;

public class Breakpoint {
	
	private boolean enabled;
	private int id;
	private String name;
	private Address address;
	private boolean cameFromLLDB;
	
	public Breakpoint(boolean enabled, int id, String name, Address address, boolean cameFromLLDB) {
		super();
		this.enabled = enabled;
		this.id = id;
		this.name = name;
		this.address = address;
		this.cameFromLLDB = cameFromLLDB;
	}
	
	public static String[] getFieldNames() {
		String[] names = {"Enabled", "ID", "Name", "Address"};
		return names;
	}
	
	public Object getValueAt(int i) {
		switch (i) {
		case 0: return enabled;
		case 1: return id;
		case 2: return name;
		case 3: return address;
		default: return null;
		}
	}
	
	public void setValueAt(int i, Object o) {
		switch (i) {
		case 0: if (o instanceof Boolean) enabled = (boolean)o; break;
		case 1: if (o instanceof Integer) id = (int)o; break;
		case 2: if (o instanceof String) name = (String)o; break;
		case 3: if (o instanceof Address) address = (Address)o; break;
		default: return;
		}
	}

	public boolean isEnabled() {
		return enabled;
	}
	
	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}
	
	public int getId() {
		return id;
	}
	
	public void setId(int id) {
		this.id = id;
	}
	
	public String getName() {
		return name;
	}
	
	public void setName(String name) {
		this.name = name;
	}
	
	public Address getAddress() {
		return address;
	}
	
	public void setAddress(Address address) {
		this.address = address;
	}
	
	public boolean didComeFromLLDB() {
		return cameFromLLDB;
	}

}
