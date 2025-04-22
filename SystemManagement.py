import tkinter as tk
from socket import socket
from tkinter import ttk, messagebox, scrolledtext
import requests
import time
import threading
import queue
import paramiko
import re
from collections import deque
from datetime import datetime, timedelta


class SystemManagementWindow:
    def __init__(self, ip, user, password, parent_frame):
        self.ip = ip
        self.user = user
        self.password = password
        self.parent_frame = parent_frame
        self.is_monitoring = False
        self.monitor_thread = None

        # SSH connection variables
        self.ssh_client = None
        self.ssh_shell = None
        self.ssh_output_queue = queue.Queue()
        self.keep_receiving = False

        # Create main frame
        self.main_frame = ttk.Frame(parent_frame)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Title label
        ttk.Label(self.main_frame, text="System Management", font=("Arial", 14, "bold")).pack(pady=10)

        # Create a notebook with tabs
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=5)

        # Create System Info tab
        self.system_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.system_tab, text="System Info")

        # Create Terminal tab
        self.terminal_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.terminal_tab, text="Terminal")

        # Create Controls tab
        self.control_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.control_tab, text="System Control")

        # Setup tabs
        self.setup_system_info_tab()
        self.setup_terminal_tab()
        self.setup_control_tab()

        # Start monitoring
        self.start_monitoring()

    def setup_system_info_tab(self):
        info_frame = ttk.LabelFrame(self.system_tab, text="System Information")
        info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        resource_frame = ttk.Frame(info_frame)
        resource_frame.pack(fill=tk.X, pady=5)

        # Uptime
        ttk.Label(resource_frame, text="Uptime:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        self.uptime_var = tk.StringVar(value="Loading...")
        ttk.Label(resource_frame, textvariable=self.uptime_var).grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)

        # CPU Load
        ttk.Label(resource_frame, text="CPU Load:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        self.cpu_var = tk.StringVar(value="Loading...")
        ttk.Label(resource_frame, textvariable=self.cpu_var).grid(row=1, column=1, sticky=tk.W, padx=10, pady=5)

        # Memory Usage
        ttk.Label(resource_frame, text="Memory Usage:").grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
        self.memory_var = tk.StringVar(value="Loading...")
        ttk.Label(resource_frame, textvariable=self.memory_var).grid(row=2, column=1, sticky=tk.W, padx=10, pady=5)

        # Disk Usage
        ttk.Label(resource_frame, text="Disk Usage:").grid(row=3, column=0, sticky=tk.W, padx=10, pady=5)
        self.disk_var = tk.StringVar(value="Loading...")
        ttk.Label(resource_frame, textvariable=self.disk_var).grid(row=3, column=1, sticky=tk.W, padx=10, pady=5)

        # Current Time
        ttk.Label(resource_frame, text="Router Time:").grid(row=4, column=0, sticky=tk.W, padx=10, pady=5)
        self.time_var = tk.StringVar(value="Loading...")
        ttk.Label(resource_frame, textvariable=self.time_var).grid(row=4, column=1, sticky=tk.W, padx=10, pady=5)

        # Version Info
        ttk.Label(resource_frame, text="RouterOS Version:").grid(row=5, column=0, sticky=tk.W, padx=10, pady=5)
        self.version_var = tk.StringVar(value="Loading...")
        ttk.Label(resource_frame, textvariable=self.version_var).grid(row=5, column=1, sticky=tk.W, padx=10, pady=5)

        ttk.Button(info_frame, text="Refresh Information", command=self.refresh_system_info).pack(pady=10)

    def print_debug_info(self):
        debug_info = [
            "===== SSH Debug Information =====",
            f"SSH Client Connected: {self.ssh_client is not None}",
            f"SSH Shell Active: {self.ssh_shell is not None}",
            f"Keep Receiving Flag: {self.keep_receiving}",
            f"Queue Size: {self.ssh_output_queue.qsize()}",
            "================================="
        ]

        for line in debug_info:
            self.append_to_terminal(line + "\n", "system")

        # Try to get connection info if available
        if self.ssh_client and self.ssh_client.get_transport():
            transport = self.ssh_client.get_transport()
            self.append_to_terminal(f"Transport active: {transport.is_active()}\n", "system")
            self.append_to_terminal(f"Transport authenticated: {transport.is_authenticated()}\n", "system")

    def setup_terminal_tab(self):
        terminal_frame = ttk.Frame(self.terminal_tab)
        terminal_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Add a command history dropdown
        history_frame = ttk.Frame(terminal_frame)
        history_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(history_frame, text="Command History:").pack(side=tk.LEFT)
        self.history_var = tk.StringVar()
        self.history_dropdown = ttk.Combobox(history_frame, textvariable=self.history_var, state="readonly", width=50)
        self.history_dropdown.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.history_dropdown.bind("<<ComboboxSelected>>", self.select_history_command)
        self.command_history = deque(maxlen=20)  # Store up to 20 commands

        ttk.Label(terminal_frame, text="Terminal Output:").pack(anchor=tk.W)
        self.terminal_output = scrolledtext.ScrolledText(terminal_frame, height=15, width=80, bg='black', fg='white')
        self.terminal_output.pack(fill=tk.BOTH, expand=True, pady=5)
        self.terminal_output.config(state=tk.DISABLED)

        # Configure tags for syntax highlighting
        self.terminal_output.tag_configure("prompt", foreground="#00ff00")  # Green prompt
        self.terminal_output.tag_configure("command", foreground="#ffffff")  # White command
        self.terminal_output.tag_configure("output", foreground="#aaaaaa")  # Light gray output
        self.terminal_output.tag_configure("error", foreground="#ff5555")  # Red for errors
        self.terminal_output.tag_configure("success", foreground="#55ff55")  # Green for success messages
        self.terminal_output.tag_configure("warning", foreground="#ffff55")  # Yellow for warnings
        self.terminal_output.tag_configure("system", foreground="#5555ff")  # Blue for system messages

        self.connection_status = ttk.Label(terminal_frame, text="Not connected")
        self.connection_status.pack(anchor=tk.W)

        input_frame = ttk.Frame(terminal_frame)
        input_frame.pack(fill=tk.X, pady=5)

        ttk.Label(input_frame, text="Command:").pack(side=tk.LEFT, padx=5)
        self.command_entry = ttk.Entry(input_frame, width=50)
        self.command_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.command_entry.bind("<Return>", lambda e: self.execute_ssh_command())
        self.command_entry.bind("<Up>", self.previous_command)
        self.command_entry.bind("<Down>", self.next_command)

        # Add common commands dropdown
        ttk.Label(input_frame, text="Common:").pack(side=tk.LEFT, padx=5)
        self.common_commands = ["system resource print", "ip address print", "interface print",
                                "system package update print", "system health print", "log print"]
        self.common_var = tk.StringVar()
        common_dropdown = ttk.Combobox(input_frame, textvariable=self.common_var, values=self.common_commands, width=15)
        common_dropdown.pack(side=tk.LEFT, padx=5)
        common_dropdown.bind("<<ComboboxSelected>>", self.insert_common_command)

        button_frame = ttk.Frame(terminal_frame)
        button_frame.pack(fill=tk.X, pady=5)

        ttk.Button(button_frame, text="Connect", command=self.connect_ssh).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Execute", command=self.execute_ssh_command).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear_terminal).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Disconnect", command=self.disconnect_ssh).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Debug Info", command=self.print_debug_info).pack(side=tk.LEFT,
                                                                                        padx=5)  # Add debug button

        self.update_terminal_output()


    def setup_control_tab(self):
        control_frame = ttk.LabelFrame(self.control_tab, text="System Controls")
        control_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        reboot_frame = ttk.Frame(control_frame)
        reboot_frame.pack(fill=tk.X, pady=10)

        ttk.Label(reboot_frame, text="System Reboot:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        ttk.Button(reboot_frame, text="Reboot Router", command=self.reboot_router).grid(row=0, column=1, padx=10,
                                                                                        pady=5)

        web_access_frame = ttk.Frame(control_frame)
        web_access_frame.pack(fill=tk.X, pady=10)

        ttk.Label(web_access_frame, text="Web Interface:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        self.web_access_var = tk.StringVar(value="Unknown")
        ttk.Label(web_access_frame, textvariable=self.web_access_var).grid(row=0, column=1, sticky=tk.W, padx=10,
                                                                           pady=5)

        web_buttons_frame = ttk.Frame(web_access_frame)
        web_buttons_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=5)

        ttk.Button(web_buttons_frame, text="Enable Web Access", command=lambda: self.toggle_web_access(True)).pack(
            side=tk.LEFT, padx=5)
        ttk.Button(web_buttons_frame, text="Disable Web Access", command=lambda: self.toggle_web_access(False)).pack(
            side=tk.LEFT, padx=5)

        shutdown_frame = ttk.Frame(control_frame)
        shutdown_frame.pack(fill=tk.X, pady=10)

        ttk.Label(shutdown_frame, text="System Shutdown:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        ttk.Button(shutdown_frame, text="Shutdown Router", command=self.shutdown_router).grid(row=0, column=1, padx=10,
                                                                                              pady=5)

        self.check_web_access()

    # SSH Terminal Functions
    def connect_ssh(self):
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            self.append_to_terminal("Connecting to " + self.ip + "...\n", "system")

            self.ssh_client.connect(
                hostname=self.ip,
                username=self.user,
                password=self.password,
                timeout=10,
                allow_agent=False,
                look_for_keys=False
            )

            self.ssh_shell = self.ssh_client.invoke_shell()
            self.ssh_shell.settimeout(1.0)  # Add a timeout to prevent blocking
            self.keep_receiving = True

            # Start the receiver thread
            receiver_thread = threading.Thread(target=self.receive_ssh_output, daemon=True)
            receiver_thread.start()

            self.connection_status.config(text="Connected", foreground="green")
            self.append_to_terminal("SSH connection established\n", "success")

        except Exception as e:
            self.append_to_terminal(f"Connection failed: {str(e)}\n", "error")
            self.connection_status.config(text="Connection failed", foreground="red")

    def disconnect_ssh(self):
        self.keep_receiving = False
        if self.ssh_shell:
            self.ssh_shell.close()
        if self.ssh_client:
            self.ssh_client.close()
        self.append_to_terminal("SSH connection closed\n", "system")
        self.connection_status.config(text="Disconnected", foreground="red")

    def receive_ssh_output(self):
        output_buffer = ""
        last_recv_time = time.time()

        while self.keep_receiving and self.ssh_shell:
            try:
                if self.ssh_shell.recv_ready():
                    output = self.ssh_shell.recv(4096).decode('utf-8', 'ignore')
                    if output:
                        print("RAW OUTPUT:", repr(output))  # DEBUG
                        output_buffer += output.replace('\r\n', '\n').replace('\r', '\n')
                        last_recv_time = time.time()

                # Force flush if waiting too long with output in buffer
                if output_buffer and (time.time() - last_recv_time > 0.4):
                    self.ssh_output_queue.put(output_buffer)
                    output_buffer = ""

                time.sleep(0.1)
            except Exception as e:
                self.ssh_output_queue.put(f"\n[SSH Error: {str(e)}]\n")
                break

        if output_buffer:
            self.ssh_output_queue.put(output_buffer)

    def update_terminal_output(self):
        while not self.ssh_output_queue.empty():
            output = self.ssh_output_queue.get_nowait()
            print(output)

            # Detect error messages
            if re.search(r'(error|fail|bad|invalid)', output.lower()):
                self.append_to_terminal(output, "error")
            # Detect success messages
            elif re.search(r'(success|ok|done|completed)', output.lower()):
                self.append_to_terminal(output, "success")
            # Detect warning messages
            elif re.search(r'(warning|caution|attention)', output.lower()):
                self.append_to_terminal(output, "warning")
            else:
                self.append_to_terminal(output, "output")

        self.parent_frame.after(100, self.update_terminal_output)

    def append_to_terminal(self, text, tag="output"):
        try:
            self.terminal_output.config(state=tk.NORMAL)
            self.terminal_output.insert(tk.END, text, tag)
            self.terminal_output.see(tk.END)
            self.terminal_output.config(state=tk.DISABLED)
            # Force update to ensure text is displayed immediately
            self.terminal_output.update_idletasks()
        except Exception as e:
            print(f"Error appending to terminal: {str(e)}")

    def execute_ssh_command(self):
        if not self.ssh_shell:
            self.append_to_terminal("Not connected to SSH server\n", "error")
            return

        command = self.command_entry.get().strip()
        if not command:
            return

        # Add to command history
        if command not in self.command_history:
            self.command_history.appendleft(command)
            self.update_history_dropdown()

        try:
            self.append_to_terminal(f"{command}\n", "command")  # Only the command itself
            self.ssh_shell.send((command + "\r\n").encode())


            # Small delay gives the receive thread time to pick up output
            time.sleep(0.2)

            self.command_entry.delete(0, tk.END)
        except Exception as e:
            self.append_to_terminal(f"Error executing command: {str(e)}\n", "error")
            
    def clear_terminal(self):
        self.terminal_output.config(state=tk.NORMAL)
        self.terminal_output.delete(1.0, tk.END)
        self.terminal_output.config(state=tk.DISABLED)

    def update_history_dropdown(self):
        self.history_dropdown['values'] = list(self.command_history)

    def select_history_command(self, event):
        selected = self.history_var.get()
        if selected:
            self.command_entry.delete(0, tk.END)
            self.command_entry.insert(0, selected)
            # Clear the selection to allow re-selection of the same item
            self.history_dropdown.selection_clear()

    def previous_command(self, event):
        current = self.command_entry.get()
        if current in self.command_history:
            idx = list(self.command_history).index(current)
            if idx < len(self.command_history) - 1:
                next_cmd = list(self.command_history)[idx + 1]
                self.command_entry.delete(0, tk.END)
                self.command_entry.insert(0, next_cmd)
        elif self.command_history:
            self.command_entry.delete(0, tk.END)
            self.command_entry.insert(0, list(self.command_history)[0])
        return "break"  # Prevent default behavior

    def next_command(self, event):
        current = self.command_entry.get()
        if current in self.command_history:
            idx = list(self.command_history).index(current)
            if idx > 0:
                prev_cmd = list(self.command_history)[idx - 1]
                self.command_entry.delete(0, tk.END)
                self.command_entry.insert(0, prev_cmd)
        return "break"  # Prevent default behavior

    def insert_common_command(self, event):
        selected = self.common_var.get()
        if selected:
            self.command_entry.delete(0, tk.END)
            self.command_entry.insert(0, selected)
            self.common_var.set('')  # Reset dropdown

    # System Monitoring Functions
    def start_monitoring(self):
        if not self.is_monitoring:
            self.is_monitoring = True
            self.monitor_thread = threading.Thread(target=self.monitor_system_info, daemon=True)
            self.monitor_thread.start()

    def stop_monitoring(self):
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1)

    def monitor_system_info(self):
        while self.is_monitoring:
            try:
                self.refresh_system_info()
            except Exception as e:
                print(f"Error in monitoring: {str(e)}")
            time.sleep(10)

    def refresh_system_info(self):
        try:
            resource_url = f"https://{self.ip}/rest/system/resource"
            response = requests.get(resource_url, auth=(self.user, self.password), verify=False)

            if response.status_code == 200:
                resource_data = response.json()

                uptime_str = resource_data.get("uptime", "0s")
                if isinstance(uptime_str, str) and any(x in uptime_str for x in ['d', 'h', 'm', 's']):
                    self.uptime_var.set(uptime_str)
                else:
                    try:
                        uptime_seconds = int(uptime_str)
                        uptime_delta = timedelta(seconds=uptime_seconds)
                        days, remainder = divmod(uptime_delta.total_seconds(), 86400)
                        hours, remainder = divmod(remainder, 3600)
                        minutes, seconds = divmod(remainder, 60)
                        uptime_str = f"{int(days)} days, {int(hours)} hours, {int(minutes)} minutes"
                        self.uptime_var.set(uptime_str)
                    except ValueError:
                        self.uptime_var.set(f"Uptime: {uptime_str}")

                cpu_load = resource_data.get("cpu-load", 0)
                self.cpu_var.set(f"{cpu_load}%")

                free_memory = int(resource_data.get("free-memory", 0))
                total_memory = int(resource_data.get("total-memory", 0))
                used_memory = total_memory - free_memory
                memory_percent = (used_memory / total_memory) * 100 if total_memory > 0 else 0
                self.memory_var.set(
                    f"{memory_percent:.1f}% ({self.format_bytes(used_memory)}/{self.format_bytes(total_memory)})")

                free_hdd = int(resource_data.get("free-hdd-space", 0))
                total_hdd = int(resource_data.get("total-hdd-space", 0))
                used_hdd = total_hdd - free_hdd
                disk_percent = (used_hdd / total_hdd) * 100 if total_hdd > 0 else 0
                self.disk_var.set(f"{disk_percent:.1f}% ({self.format_bytes(used_hdd)}/{self.format_bytes(total_hdd)})")

                version = resource_data.get("version", "Unknown")
                self.version_var.set(version)

            clock_url = f"https://{self.ip}/rest/system/clock"
            response = requests.get(clock_url, auth=(self.user, self.password), verify=False)

            if response.status_code == 200:
                clock_data = response.json()
                date_time = clock_data.get("date", "") + " " + clock_data.get("time", "")
                self.time_var.set(date_time)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh system info: {str(e)}")

    def format_bytes(self, size_bytes):
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 ** 2:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 ** 3:
            return f"{size_bytes / (1024 ** 2):.1f} MB"
        else:
            return f"{size_bytes / (1024 ** 3):.1f} GB"

    # System Control Functions
    def reboot_router(self):
        if messagebox.askyesno("Confirm Reboot",
                               "Are you sure you want to reboot the router? All connections will be lost temporarily."):
            try:
                url = f"https://{self.ip}/rest/system/reboot"
                response = requests.post(url, auth=(self.user, self.password), verify=False)

                if response.status_code == 200:
                    messagebox.showinfo("Reboot Initiated",
                                        "Router reboot has been initiated. Please wait a few minutes before reconnecting.")
                else:
                    messagebox.showerror("Error", f"Failed to reboot router. Status code: {response.status_code}")

            except Exception as e:
                messagebox.showerror("Error", f"Failed to reboot router: {str(e)}")

    def shutdown_router(self):
        if messagebox.askyesno("Confirm Shutdown",
                               "Are you sure you want to shutdown the router? You will need physical access to power it back on."):
            try:
                url = f"https://{self.ip}/rest/system/shutdown"
                response = requests.post(url, auth=(self.user, self.password), verify=False)

                if response.status_code == 200:
                    messagebox.showinfo("Shutdown Initiated", "Router shutdown has been initiated.")
                else:
                    messagebox.showerror("Error", f"Failed to shutdown router. Status code: {response.status_code}")

            except Exception as e:
                messagebox.showerror("Error", f"Failed to shutdown router: {str(e)}")

    def check_web_access(self):
        try:
            url = f"https://{self.ip}/rest/ip/service"
            response = requests.get(url, auth=(self.user, self.password), verify=False)

            if response.status_code == 200:
                services = response.json()
                for service in services:
                    if service.get("name") == "www":
                        status = "Enabled" if service.get("disabled") == "false" else "Disabled"
                        self.web_access_var.set(status)
                        return

                self.web_access_var.set("Service not found")
            else:
                self.web_access_var.set(f"Error: {response.status_code}")

        except Exception as e:
            self.web_access_var.set(f"Error: {str(e)}")

    def toggle_web_access(self, enable):
        try:
            url = f"https://{self.ip}/rest/ip/service"
            response = requests.get(url, auth=(self.user, self.password), verify=False)

            if response.status_code == 200:
                services = response.json()
                www_service = None

                for service in services:
                    if service.get("name") == "www":
                        www_service = service
                        break

                if www_service:
                    service_id = www_service.get(".id")

                    update_url = f"https://{self.ip}/rest/ip/service/{service_id}"
                    data = {"disabled": "false" if enable else "true"}

                    update_response = requests.patch(update_url, json=data, auth=(self.user, self.password),
                                                     verify=False)

                    if update_response.status_code == 200:
                        status = "enabled" if enable else "disabled"
                        messagebox.showinfo("Success", f"Web access has been {status}")
                        self.web_access_var.set("Enabled" if enable else "Disabled")
                    else:
                        messagebox.showerror("Error",
                                             f"Failed to update web access. Status code: {update_response.status_code}")
                else:
                    messagebox.showerror("Error", "Web service not found")
            else:
                messagebox.showerror("Error", f"Failed to get services. Status code: {response.status_code}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to toggle web access: {str(e)}")

    def __del__(self):
        self.stop_monitoring()
        self.disconnect_ssh()