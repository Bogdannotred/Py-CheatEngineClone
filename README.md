# Py-CheatEngineClone

A simple memory scanner and editor, inspired by Cheat Engine, built with Python and Tkinter.

## Features

*   **Process Listing:** Lists all running processes with their PIDs.
*   **Process Filtering:** Search for specific processes by name.
*   **Memory Scanning:** Scan the memory of a selected process for a specific integer value.
*   **Next Scan:** Filter the results of the previous scan by searching for a new value within the found addresses.
*   **Memory Writing:** Modify the value at a specific memory address.

## Requirements

This project requires Python 3 and the `psutil` library.

To install the necessary dependencies, run:

```bash
pip install -r requirements.txt
```

## How to Use

1.  **Run the application:**

    ```bash
    python app.py
    ```

2.  **Select a process:** Double-click on a process from the list to attach to it.
3.  **Scan for a value:** Enter an integer value in the input box and click "Scan".
4.  **Filter results (Next Scan):** To narrow down the search, enter a new value and click "Next Scan". This will search for the new value only within the addresses found in the previous scan.
5.  **Write to memory:** Select an address from the results list, enter a new value in the input box, and click "Write".

## Disclaimer

This tool is for educational purposes only. Modifying the memory of other processes can cause them to crash or behave unexpectedly. Use at your own risk.
