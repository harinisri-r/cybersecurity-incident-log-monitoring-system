# Cybersecurity Incident and Log Monitoring System

Java (OOP) mini project - 22IT321 Object Oriented Programming, B.Tech Information Technology,
Thiagarajar College of Engineering, Madurai. Author: Harinisri R.

A security monitoring application that processes system activity logs, identifies suspicious
login attempts, generates security alerts, and keeps incident records with categories and
severity levels. Four monitoring threads read log files in parallel and one responder thread
updates the incident records.

## Features
- 6 detection rules: brute force, login after failures, off-hours login, privilege escalation,
  sensitive file access, port scan
- 5 incident categories, 4 severity levels (Low, Medium, High, Critical), status workflow
  (Open, Investigating, Resolved)
- Multithreading with BlockingQueue, synchronized, AtomicInteger, volatile
- Swing dashboard (Dashboard, Incidents, Statistics, Alerts) and a console demo

## Requirements
JDK / JRE 17 or later. No external libraries.

## Build and run
```
javac -d out $(find src -name "*.java")
jar --create --file LogMonitor.jar --main-class com.logmonitor.Main -C out .
java -jar LogMonitor.jar            # GUI: press "Load Sample Logs"
java -jar LogMonitor.jar --demo     # console demo
```
(On Windows PowerShell use: `javac -d out (Get-ChildItem -Recurse src -Filter *.java).FullName`)

## Log format
`yyyy-MM-dd HH:mm:ss | host | EVENT | user | ip | detail`
Events: LOGIN_SUCCESS, LOGIN_FAILED, SYSTEM_COMMAND, PORT_CONNECT.

## Report
See `docs/Project_Report.pdf`.
