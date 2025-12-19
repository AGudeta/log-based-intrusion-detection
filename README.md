# Log-Based Intrusion Detection Tool

A Java-based blue team log monitoring tool that analyzes authentication logs to detect brute-force attacks, targeted accounts, and potential post-attack compromises.

## Features
- Parses authentication log files into structured events
- Detects brute-force attacks using rolling time-window analysis
- Identifies targeted user accounts based on repeated failures
- Flags successful logins following brute-force behavior
- Generates an incident-style security report

## Technologies
- Java
- Java Collections Framework (HashMap, HashSet, List)
- Time-based analysis with LocalDateTime and Duration

## How to Run
```bash
javac -d bin src/LogDetector.java
java -cp bin LogDetector lib/auth.log output/report.txt
