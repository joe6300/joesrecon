import os

# prompt the user to enter the IP address of the target Android device
ip_address = input("Enter the IP address of the target Android device: ")

# prompt the user to select the type of Metasploit module to use
module_type = input("Enter the type of Metasploit module to use (e.g. exploit/android): ")

# start Metasploit console and connect to the device
os.system("msfconsole")
os.system(f"use {module_type}")
os.system(f"set RHOSTS {ip_address}")
os.system("run")
