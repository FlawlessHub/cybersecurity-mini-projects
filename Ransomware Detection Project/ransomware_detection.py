# IMPORTS
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import tkinter as tk
from tkinter import messagebox
import os


#CONFIGURATION
TIME_WINDOW = 10
ALERT_THRESHOLD = 5

#GLOBAL VARIABLES
recent_events = []
alert_active = False


# INITIALIZE REPORT FILE
with open("incident_report.txt", "w") as file:
    file.write("Ransomware Detection Reports\n")


# ALERT SYSTEM
def show_alert():

    root = tk.Tk()

    root.withdraw()

    messagebox.showwarning(
        "Ransomware Detection Alert",
        f"Suspicious file activity detected!\n\n"
        f"More than {ALERT_THRESHOLD} file modifications "
        f"were detected within {TIME_WINDOW} seconds.\n\n"
        f"Possible ransomware behavior observed."
    )

    root.destroy()


# INCIDENT REPORT GENERATOR
def generate_report(affected_files, modification_count):

    with open("incident_report.txt", "a") as file:

        file.write("\n======== INCIDENT REPORT ========\n")

        file.write(f"Time: {time.ctime()}\n")

        file.write(
            f"Recent Modifications: {modification_count}\n"
        )
        
        file.write(
            f"Detection Window: {TIME_WINDOW} seconds\n"
        )
        
        file.write(
            f"Alert Threshold: {ALERT_THRESHOLD}\n"
        )
        
        file.write(
            f"Number of Affected Files: {len(affected_files)}\n\n"
        )

        file.write("Affected Files:\n")
        file.write("----------------------\n")

        for affected_file in affected_files:
            file.write(f"- {affected_file}\n")

        file.write("===================================\n")





# FILE MONITORING HANDLER
class RansomwareDetectionHandler(FileSystemEventHandler):

    def on_modified(self, event):
        global alert_active
        if not event.is_directory:
        
            current_time = time.time()
        
            recent_events.append(
                (current_time, event.src_path)
            )
        
            recent_events[:] = [
                entry
                for entry in recent_events
                if current_time - entry[0] <= TIME_WINDOW
            ]
        
            print(f"\n[EVENT] File Modified: {os.path.basename(event.src_path)}")
            print(f"[INFO] Recent Modifications: {len(recent_events)}")
        
            if len(recent_events) >= ALERT_THRESHOLD and not alert_active:
        
                alert_active = True
        
                affected_files = {
                    os.path.basename(entry[1])
                    for entry in recent_events
                }
        
                show_alert()
        
                print("\nALERT! Suspicious file activity detected!")
        
                print("Affected files:")
        
                for file in affected_files:
                    print("-", file)
        
                generate_report(
                    affected_files,
                    len(recent_events)
                )
        
            if len(recent_events) < ALERT_THRESHOLD and alert_active:
                print("\n[INFO] Alert status reset.")
                alert_active = False
                


# MAIN PROGRAM
folder_to_watch = r"C:\ABHIJNA\studies\cybersecurity\nextchapter_cyber class\mini-project\ransomware-test"

event_handler = RansomwareDetectionHandler()
observer = Observer()

observer.schedule(event_handler, folder_to_watch, recursive=True)
observer.start()

print("=" * 50)
print("RANSOMWARE DETECTION SYSTEM")
print("=" * 50)
print(f"Monitoring Folder: {folder_to_watch}")
print(f"Detection Window: {TIME_WINDOW} seconds")
print(f"Alert Threshold: {ALERT_THRESHOLD}")
print("Status: ACTIVE")
print("=" * 50)

try:
    while True:
        time.sleep(1)

except KeyboardInterrupt:
    observer.stop()

observer.join()