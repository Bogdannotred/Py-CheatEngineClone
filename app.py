import tkinter as tk
from tkinter import ttk
import psutil
# import process_connector # This module is missing
import ctypes
import struct
from ctypes import wintypes


PROCESS_ALL_ACCESS = 0x1F0FFF

# Import Windows API functions
OpenProcess = ctypes.windll.kernel32.OpenProcess
ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
WriteProcessMemory = ctypes.windll.kernel32.WriteProcessMemory
VirtualQueryEx = ctypes.windll.kernel32.VirtualQueryEx
CloseHandle = ctypes.windll.kernel32.CloseHandle

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wintypes.LPVOID),
        ("AllocationBase", wintypes.LPVOID),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

root = tk.Tk()
root.geometry("900x600")
root.title("Memory Scanner")
root.configure(bg="#2C2F33")


root.columnconfigure(0, weight=1)  
root.columnconfigure(1, weight=3, minsize=300)  
root.rowconfigure(1, weight=1)  


top_frame = ttk.Frame(root)
top_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=5)
top_frame.columnconfigure(0, weight=0)  
top_frame.columnconfigure(1, weight=1)  

# Search label
text = ttk.Label(top_frame, text="Search for a process:")
text.grid(row=0, column=0, sticky="w", padx=0, pady=5)

# Entry - will occupy all available space after the text
search_input = ttk.Entry(top_frame)
search_input.grid(row=0, column=1, sticky="ew", padx=0, pady=5)

# Right-side label with fixed width to prevent resizing
text_right = ttk.Label(root, text="Selected process: None", width=10, anchor="w")
text_right.grid(row=0, column=1, sticky="ew", padx=10, pady=5)

found_count_label = ttk.Label(root, text="Found: ", width=10, anchor="w")
found_count_label.grid(row=2, column=2, sticky="nsew")

# Frame for the process list, to contain the scrollbar
process_list_frame = ttk.Frame(root)
process_list_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)

# Vertical scrollbar for the process list
process_list_scrollbar = ttk.Scrollbar(process_list_frame, orient="vertical")
process_list_scrollbar.pack(side="right", fill="y")

# Process table
columns = ("PID", "Process Name")
process_tree = ttk.Treeview(process_list_frame, columns=columns, show="headings", yscrollcommand=process_list_scrollbar.set)
process_tree.heading("PID", text="PID")
process_tree.heading("Process Name", text="Process Name")

# Bind scrollbar to the process list
process_list_scrollbar.config(command=process_tree.yview)

# Place widgets in the process list frame
process_tree.pack(side="left", fill="both", expand=True)

# Scrollbar for address_tree
address_columns = ("Address", "Value")
address_frame = ttk.Frame(root)
address_frame.grid(row=1, column=1, sticky="nsew")

address_scrollbar = ttk.Scrollbar(address_frame, orient="vertical")
address_scrollbar.pack(side="right", fill="y")

address_tree = ttk.Treeview(address_frame, columns=address_columns, show="headings", yscrollcommand=address_scrollbar.set)
address_tree.pack(side="left", fill="both", expand=True)
address_tree.heading("Address", text="Address")
address_tree.heading("Value", text="Value")

address_scrollbar.config(command=address_tree.yview)

# Populate the table with processes
for proc in psutil.process_iter(['pid', 'name']):
    process_tree.insert("", "end", values=(proc.info['pid'], proc.info['name']))

# Refresh function                                  
def refresh_processes():
    for row in process_tree.get_children():
        process_tree.delete(row)
    for proc in psutil.process_iter(['pid', 'name']):
        process_tree.insert("", "end", values=(proc.info['pid'], proc.info['name']))

# Process selection function
def on_process_select(event):
    global pid 
    selection = process_tree.selection()
    if selection:
        values = process_tree.item(selection, "values")
        text_right.config(text=f"Connected to process: {values[1]} (PID: {values[0]})")
        print(values[1], values[0])
        pid = int(values[0])
        # TODO: Implement process attachment
        # import process_connector
        # process_connector.attach_to_process(values[1])

def read_memory(handle , address , size):
    buffer = ctypes.create_string_buffer(size)
    bytesRead = ctypes.c_size_t()
    if ReadProcessMemory(handle , ctypes.c_void_p(address) , buffer , size , ctypes.byref(bytesRead)):
        return buffer.raw
    return None


def scan_memory(pid, value_to_find):

    handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    search_value = struct.pack("i", int(value_to_find))  # Make sure value_to_find is an integer
    address = 0x00000000
    mbi = MEMORY_BASIC_INFORMATION()
    global results
    results = []

    def scan_region(base , size):
        buffer = read_memory(handle , base, min(size , 1024 * 2024))
        if buffer:
            for i in range (0 , len(buffer) - 4 , 4):
                if buffer[i:i+4] == search_value:
                    found_address = base + i
                    found_value = struct.unpack("i" , buffer[i:i+4])[0]
                    results.append((hex(found_address), found_value))

    while True:
        result = VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if result == 0:
            break  # If there are no more valid regions to read, exit the loop

        if mbi.State == 0x1000 and mbi.Protect in (0x04, 0x02, 0x20, 0x40):  # Accessible memory regions
            scan_region(mbi.BaseAddress, mbi.RegionSize)

        address += mbi.RegionSize # Move to the next memory region

    CloseHandle(handle)  # Close the process
    root.after(0, lambda: update_results(results))
    return results

def update_results(results):
    address_tree.delete(*address_tree.get_children())
    for addr, value in results:
        address_tree.insert("", "end", values=(addr, value))

def search_processes(event):
    search_term = search_input.get().lower()
    for row in process_tree.get_children():
        process_tree.delete(row)
    for proc in psutil.process_iter(['pid', 'name']):
        if search_term in proc.info['name'].lower():
            process_tree.insert("", "end", values=(proc.info['pid'], proc.info['name']))

def start_scan():
    try:
        value_to_find = int(value_input.get())
        results = scan_memory(pid, value_to_find)
        found_count_label.config(text=f"Found: {len(results)}")
        if not results:
            print("No results found.")
    except ValueError:
        print("Invalid value!")

def next_scan():
    global results
    if not results:
        print("No previous results to filter!")
        return
    search_value = int(value_input.get())  # New value to search
    new_scan_results = scan_memory(pid, search_value)  # Rescan memory
    # Compare old results with new ones and keep only common addresses
    filtered_results = [(addr, val) for addr, val in new_scan_results if addr in dict(results)]
    results = filtered_results  # Update with filtered results
    update_results(results)
    found_count_label.config(text=f"Found: {len(results)}")  # Update UI

def write_memory():
    handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    new_value = value_input.get().lower()
    if not handle:
        print("Error: Could not open process.")
        return False
    
    selection = address_tree.selection()
    if selection:
        values = address_tree.item(selection, "values")
    address = int(values[0], 16)  # Convert "0x7FFDF000" to int
    value_bytes = struct.pack("i", int(new_value))  # Convert the new value to 4-byte format (int)
    bytes_written = ctypes.c_size_t()
    success = WriteProcessMemory(handle, ctypes.c_void_p(int(address)), value_bytes, len(value_bytes), ctypes.byref(bytes_written))
    new_scan_results = scan_memory(pid, new_value)  # Rescan memory
    update_results(new_scan_results)
    CloseHandle(handle)  # Close the process handle
    return success

    

# Create a frame for the search input and buttons
controls_frame = ttk.Frame(root)
controls_frame.grid(row=0, column=2, rowspan=2, sticky="nsew", padx=10, pady=5)

# Input box for value to find
value_input = ttk.Entry(controls_frame)
value_input.grid(row=0, column=0, padx=5, pady=5)

# Bind double-click event
process_tree.bind("<Double-1>", on_process_select)
search_input.bind("<KeyRelease>", search_processes)

# Button under the table
refresh_button = ttk.Button(root, text="Refresh", command=refresh_processes)
refresh_button.grid(row=2, column=0, sticky="nsew", padx=10, pady=5)

# Scan button
scan_button = ttk.Button(controls_frame, text="Scan" , command=start_scan)
scan_button.grid(row=1, column=0, padx=5, pady=5)

# Next Scan button
next_scan_button = ttk.Button(controls_frame, text="Next Scan" , command=next_scan)
next_scan_button.grid(row=2, column=0, padx=5, pady=5)

write_button = ttk.Button(controls_frame, text="Write" , command=write_memory)
write_button.grid(row=3, column=0, padx=5, pady=5)

# --- Main Loop ---

root.mainloop()
