import pymem

pm = None  # Variabilă globală pentru procesul atașat

def attach_to_process(process_name):
    global pm  # Folosim variabila globală
    try:
        pm = pymem.Pymem(process_name)
        print(f"Conectat la {process_name} (PID: {pm.process_id})")
        return pm
    except Exception as e:
        print(f"Eroare: {e}")
        pm = None  # Resetăm dacă apare o eroare
        return None
