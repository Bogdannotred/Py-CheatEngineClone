import tkinter as tk
from tkinter import ttk
import psutil
import conectare
import ctypes
import struct
from ctypes import wintypes


PROCESS_ALL_ACCESS = 0x1F0FFF

# Import funcții API Windows
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
root.title("Project Bogdan Rosu")
root.configure(bg="#2C2F33")


root.columnconfigure(0, weight=1)  
root.columnconfigure(1, weight=3, minsize=300)  
root.rowconfigure(1, weight=1)  


top_frame = ttk.Frame(root)
top_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=5)
top_frame.columnconfigure(0, weight=0)  
top_frame.columnconfigure(1, weight=1)  

# Eticheta de căutare
text = ttk.Label(top_frame, text="Search a process : ")
text.grid(row=0, column=0, sticky="w", padx=0, pady=5)

# Entry - va ocupa tot spațiul disponibil după text
search_input = ttk.Entry(top_frame)
search_input.grid(row=0, column=1, sticky="ew", padx=0, pady=5)

# Eticheta din dreapta cu lățime fixă pentru a preveni redimensionarea
text_right = ttk.Label(root, text="Selected process : None", width=10, anchor="w")
text_right.grid(row=0, column=1, sticky="ew", padx=10, pady=5)

addrese_int_right = ttk.Label(root, text="Au fost gasite : ", width=10, anchor="w")
addrese_int_right.grid(row=2, column=2, sticky="nsew")

# Frame pentru tabel, ca să conțină scrollbar-ul
frame_table = ttk.Frame(root)
frame_table.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)

# Scrollbar vertical pentru tabel
scrollbar = ttk.Scrollbar(frame_table, orient="vertical")
scrollbar.pack(side="right", fill="y")

# Tabelul proceselor
columns = ("PID", "Nume Proces")
tree = ttk.Treeview(frame_table, columns=columns, show="headings", yscrollcommand=scrollbar.set)
tree.heading("PID", text="PID")
tree.heading("Nume Proces", text="Nume Proces")

# Legare scrollbar la tabel
scrollbar.config(command=tree.yview)

# Plasare widget-uri în frame-ul tabelului
tree.pack(side="left", fill="both", expand=True)

# Scrollbar pentru tree_adress
columns_adress = ("Adress", "Value")
frame_adress = ttk.Frame(root)
frame_adress.grid(row=1, column=1, sticky="nsew")

tree_adress = ttk.Treeview(frame_adress, columns=columns_adress, show="headings", yscrollcommand=scrollbar.set)
tree_adress.pack(side="left", fill="both", expand=True)
tree_adress.heading("Adress", text="Adress")
tree_adress.heading("Value", text="Value")

scrollbar_adress = ttk.Scrollbar(frame_adress, orient="vertical", command=tree_adress.yview)
scrollbar_adress.pack(side="right", fill="y")
tree_adress.configure(yscrollcommand=scrollbar_adress.set)

# Umplem tabelul cu procese
for proc in psutil.process_iter(['pid', 'name']):
    tree.insert("", "end", values=(proc.info['pid'], proc.info['name']))

# Funcția de reîmprospătare                                  
def refresh_process():
    for row in tree.get_children():
        tree.delete(row)
    for proc in psutil.process_iter(['pid', 'name']):
        tree.insert("", "end", values=(proc.info['pid'], proc.info['name']))

# Funcția de selectare proces
def doubleClick(event):
    global pid 
    selection = tree.selection()
    if selection:
        values = tree.item(selection, "values")
        text_right.config(text=f"Conectat la procesul : {values[1]} (PID: {values[0]})")
        print(values[1], values[0])
        pid = int(values[0])
        conectare.attach_to_process(values[1])

def read_memory(handle , address , size):
    buffer = ctypes.create_string_buffer(size)
    bytesRead = ctypes.c_size_t()
    if ReadProcessMemory(handle , ctypes.c_void_p(address) , buffer , size , ctypes.byref(bytesRead)):
        return buffer.raw
    return None


def scan_memory(pid, value_to_find):

    handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    search_value = struct.pack("i", int(value_to_find))  # Asigură-te că value_to_find este un integer
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
            break  # Dacă nu mai sunt regiuni valide de citit, ieșim din buclă

        if mbi.State == 0x1000 and mbi.Protect in (0x04, 0x02, 0x20, 0x40):  # Regiuni de memorie accesibile
            scan_region(mbi.BaseAddress, mbi.RegionSize)

        address += mbi.RegionSize # Trecem la următoarea regiune de memorie

    CloseHandle(handle)  # Închidem procesul
    root.after(0, lambda: update_results(results))
    return results

def update_results(results):
    tree_adress.delete(*tree_adress.get_children())
    for addr, value in results:
        tree_adress.insert("", "end", values=(addr, value))

def search(event):
    search_term = search_input.get().lower()
    for row in tree.get_children():
        tree.delete(row)
    for proc in psutil.process_iter(['pid', 'name']):
        if search_term in proc.info['name'].lower():
            tree.insert("", "end", values=(proc.info['pid'], proc.info['name']))

def scan_button():
    try:
        value_to_find = int(input_box.get())
        results = scan_memory(pid, value_to_find)
        addrese_int_right.config(text=f"Au fost gasite : {len(results)}")
        if not results:
            print("Nu s-au găsit rezultate.")
    except ValueError:
        print("Valoare invalidă!")

def next_scan():
    global results
    if not results:
        print("Nu există rezultate anterioare pentru filtrare!")
        return
    search_value = int(input_box.get())  # Noua valoare căutată
    new_scan_results = scan_memory(pid, search_value)  # Rescanăm memoria
    # Comparăm rezultatele vechi cu cele noi și păstrăm doar adresele comune
    filtered_results = [(addr, val) for addr, val in new_scan_results if addr in dict(results)]
    results = filtered_results  # Actualizăm cu rezultatele filtrate
    update_results(results)
    addrese_int_right.config(text=f"Au fost găsite: {len(results)}")  # Actualizare UI

def scrie_mem():
    handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    new_value = input_box.get().lower()
    if not handle:
        print("Eroare: Nu s-a putut deschide procesul.")
        return False
    
    selection = tree_adress.selection()
    if selection:
        values = tree_adress.item(selection, "values")
    address = int(values[0], 16)  # Convertim "0x7FFDF000" în int
    value_bytes = struct.pack("i", int(new_value))  # Convertim noua valoare în format de 4 bytes (int)
    bytes_written = ctypes.c_size_t()
    success = WriteProcessMemory(handle, ctypes.c_void_p(int(address)), value_bytes, len(value_bytes), ctypes.byref(bytes_written))
    new_scan_results = scan_memory(pid, new_value)  # Rescanăm memoria
    update_results(new_scan_results)
    CloseHandle(handle)  # Închidem procesul
    return success

    

# Crearea unui frame pentru inputul de căutare și butoane
right_frame = ttk.Frame(root)
right_frame.grid(row=0, column=2, rowspan=2, sticky="nsew", padx=10, pady=5)

# Input box pentru value to find
input_box = ttk.Entry(right_frame)
input_box.grid(row=0, column=0, padx=5, pady=5)

# Legare eveniment dublu-click
tree.bind("<Double-1>", doubleClick)
search_input.bind("<KeyRelease>", search)

# Butonul sub tabel
btn_refresh = ttk.Button(root, text="Refresh", command=refresh_process)
btn_refresh.grid(row=2, column=0, sticky="nsew", padx=10, pady=5)

# Buton pentru Scan
scan_button = ttk.Button(right_frame, text="Scan" , command=scan_button)
scan_button.grid(row=1, column=0, padx=5, pady=5)

# Buton pentru Next Scan
next_scan_button = ttk.Button(right_frame, text="Next Scan" , command=next_scan)
next_scan_button.grid(row=2, column=0, padx=5, pady=5)

next_scan_button = ttk.Button(right_frame, text="Write" , command=scrie_mem)
next_scan_button.grid(row=3, column=0, padx=5, pady=5)

root.mainloop()
