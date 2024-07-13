import subprocess
import re
import platform
import os

def run_command(command):
    """ Run a shell command and return the output """
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running command '{command}': {e}")
        return ""

def check_running_processes():
    """ Check for processes associated with known EDR solutions """
    print("[*] Checking running processes...")
    processes = run_command("tasklist /v")
    if processes:
        edr_processes = re.findall(r'(?i)(CarbonBlack|CbDefense|CrowdStrike|csagent|SentinelOne|SentinelAgent|Symantec|McAfee|ESET|TrendMicro|Sophos)', processes)
        if edr_processes:
            print(f"Found potential EDR processes: {', '.join(edr_processes)}")
        else:
            print("No known EDR processes found.")

def check_running_services():
    """ Check for services associated with known EDR solutions """
    print("\n[*] Checking running services...")
    services = run_command("sc query")
    if services:
        edr_services = re.findall(r'(?i)(CarbonBlack|CbDefense|CrowdStrike|SentinelOne|Symantec|McAfee|ESET|TrendMicro|Sophos)', services)
        if edr_services:
            print(f"Found potential EDR services: {', '.join(edr_services)}")
        else:
            print("No known EDR services found.")

def check_registry_keys():
    """ Check registry keys for entries associated with known EDR solutions """
    print("\n[*] Checking registry keys...")
    if platform.system() == "Windows":
        registry_keys = [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        ]
        for key in registry_keys:
            command = f"reg query \"{key}\" /s"
            output = run_command(command)
            if output:
                edr_entries = re.findall(r'(?i)(CarbonBlack|CbDefense|CrowdStrike|SentinelOne|Symantec|McAfee|ESET|TrendMicro|Sophos)', output)
                if edr_entries:
                    print(f"Found potential EDR entries in {key}: {', '.join(edr_entries)}")
    else:
        print("Registry check is not supported on this platform.")

def check_file_system():
    """ Check the file system for directories and files associated with known EDR solutions """
    print("\n[*] Checking file system...")
    if platform.system() == "Windows":
        search_paths = [
            r"C:\Program Files",
            r"C:\Program Files (x86)"
        ]
    else:
        search_paths = [
            "/opt",
            "/usr/local/bin"
        ]
    
    for path in search_paths:
        command = f"dir /s /b \"{path}\""
        output = run_command(command)
        if output:
            edr_files = re.findall(r'(?i)(CarbonBlack|CbDefense|CrowdStrike|SentinelOne|Symantec|McAfee|ESET|TrendMicro|Sophos)', output)
            if edr_files:
                print(f"Found potential EDR files in {path}: {', '.join(edr_files)}")

def check_network_traffic():
    """ Monitor network traffic for connections to known EDR vendor domains """
    print("\n[*] Monitoring network traffic...")
    known_edr_domains = ["crowdstrike.com", "carbonblack.com", "sentinelone.com"]
    connections = run_command("netstat -ano")
    for domain in known_edr_domains:
        if domain in connections:
            print(f"Detected connection to {domain}")

def perform_behavioral_tests():
    """ Perform actions to observe potential EDR responses """
    print("\n[*] Performing behavioral tests...")
    # Placeholder for advanced techniques
    # Example: Memory analysis, event log analysis, hidden process detection
    check_memory_analysis()
    check_event_logs()
    check_hidden_processes()

def check_memory_analysis():
    """ Example: Memory analysis to detect EDR artifacts """
    if platform.system() == "Windows":
        print("[*] Performing memory analysis (Volatility)...")
        # Example command using Volatility to find EDR artifacts in memory
        volatility_cmd = "volatility -f memory_dump.raw --profile=Win10x64 malfind"
        output = run_command(volatility_cmd)
        if output:
            print(output)

def check_event_logs():
    """ Example: Event log analysis for EDR events """
    if platform.system() == "Windows":
        print("[*] Checking Windows event logs for EDR events...")
        # Example command to query security event logs for EDR-related events
        eventlog_cmd = "wevtutil qe Security /q:\"*[System[Provider[@Name='Microsoft-Windows-Security-Auditing']]]\" /f:text"
        output = run_command(eventlog_cmd)
        if output:
            print(output)

def check_hidden_processes():
    """ Example: Detection of hidden processes """
    print("[*] Checking for hidden processes...")
    # Example technique to detect hidden processes using native tools or techniques
    if platform.system() == "Windows":
        # Example using WMIC to query hidden processes
        hidden_processes = run_command("wmic process where \"caption='cmd.exe'\" get caption,executablepath")
        if hidden_processes:
            print(hidden_processes)

if __name__ == "__main__":
    print("=== EDR IS HERE ===")
    
    check_running_processes()
    check_running_services()
    check_registry_keys()
    check_file_system()
    check_network_traffic()
    perform_behavioral_tests()

    print("\n[*] All Done!!.")
