# Py-CheatEngineClone

A simple memory scanner for Windows processes, built with Python and Tkinter. This project is a lightweight clone of some of the basic functionalities of Cheat Engine.

## Features

*   List all running processes with their PIDs.
*   Search for processes by name.
*   Scan the memory of a selected process for a specific integer value.
*   Perform subsequent scans to filter memory addresses.
*   Write a new value to a specific memory address.

## How to Run

1.  **Prerequisites:**
    *   Python 3
    *   `psutil` library (`pip install psutil`)
    *   Windows operating system

2.  **Run the script:**
    ```bash
    python app.py
    ```

## How to Use

1.  **Select a Process:**
    *   The main window displays a list of all running processes.
    *   You can refresh the list by clicking the "Refresh" button.
    *   You can search for a specific process by typing its name in the search bar at the top.
    *   Double-click on a process in the list to select it. The selected process will be displayed at the top right.

2.  **Scan for a Value:**
    *   Enter the integer value you want to search for in the input box on the right.
    *   Click the "Scan" button to start the memory scan.
    *   The found memory addresses and their current values will be displayed in the list on the right.

3.  **Filter Results (Next Scan):**
    *   After an initial scan, you can filter the results by entering a new value in the input box and clicking the "Next Scan" button.
    *   This will scan only the addresses found in the previous scan, and display the ones that now hold the new value.

4.  **Write to Memory:**
    *   Select a memory address from the address list.
    *   Enter the new integer value you want to write in the input box.
    *   Click the "Write" button to write the new value to the selected address.
    *   The address list will be updated to show the new value.

## Missing Module

The `conectare.py` module is missing from the project. This module is intended to handle the process attachment logic. Currently, the call to this module is commented out in the `on_process_select` function. To make the tool fully functional, you will need to implement the `attach_to_process` function in a `conectare.py` file.
