# Ransomware Detection System

A simple Python project that monitors file activity and detects suspicious behavior that may indicate ransomware-like activity.
The program watches a folder in real time and raises an alert when multiple file modifications occur within a short time period.

## Features

- Real-time file monitoring using Watchdog
- Detection of rapid file modifications
- Warning popup using Tkinter
- Incident report generation
- Display of affected files

## Technologies Used

- Python
- Watchdog Library
- Tkinter

## How It Works

The system records file modification events along with their timestamps.

If the number of modifications within a 10-second window reaches the configured threshold (5 modifications), the program:
- Displays a warning popup
- Identifies affected files
- Generates an incident report

## Project Files

- `ransomware_detection.py` - Main source code
- `sample_incident_report.txt` - Example generated report
- `alert_demo.png` - Screenshot of the system in action

## Sample Incident Report

```text
Ransomware Detection Reports

======== INCIDENT REPORT ========
Time: Thu Jun 18 19:46:04 2026
Recent Modifications: 5
Detection Window: 10 seconds
Alert Threshold: 5
Number of Affected Files: 3

Affected Files:
----------------------
- hello.txt
- notes.txt
- data.txt
===================================
```

## Screenshot

See `alert_demo.png` for an example of the detection alert and console output.

