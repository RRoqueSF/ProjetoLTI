import sys
from DNS import *
from DHCP import *
from IpAddress import *
import requests
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json
import base64
import urllib3
import logging

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class MikroTikLogin:
    def __init__(self, root):
        self.root = root
        self.root.title("MikroTik API Login")
        self.root.geometry("400x250")
        
        ttk.Label(root, text="MikroTik IP:").pack(pady=2)
        self.ip_input = ttk.Entry(root)
        self.ip_input.pack(pady=2)
        
        ttk.Label(root, text="Username:").pack(pady=2)
        self.user_input = ttk.Entry(root)
        self.user_input.pack(pady=2)
        
        ttk.Label(root, text="Password:").pack(pady=2)
        self.pass_input = ttk.Entry(root, show="*")
        self.pass_input.pack(pady=2)
        
        self.login_button = ttk.Button(root, text="Login", command=self.login)
        self.login_button.pack(pady=5)
    
    def login(self):

         #ip = self.ip_input.get().strip()
        #user = self.user_input.get().strip()
        #password = self.pass_input.get().strip()
        ip= "10.20.30.1"
        user="admin"
        password="ubuntu123"
        
        if not ip or not user or not password:
            messagebox.showwarning("Input Error", "Please fill in all fields.")
            return
        
        url = f"https://{ip}/rest/interface"
        try:
            response = requests.get(url, auth=(user, password), verify=False, timeout=5)
            if response.status_code == 200:
                self.root.destroy()
                NetworkAdmin(ip, user, password)
            else:
                messagebox.showerror("Login Failed", f"Error: {response.status_code}\n{response.text}")
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Connection Error", f"{str(e)}")

class NetworkAdmin:
    def __init__(self, ip, user, password):
        self.ip = ip
        self.user = user
        self.password = password
        
        self.admin_window = tk.Tk()
        self.admin_window.title("Network Administration")
        self.admin_window.geometry("800x400")
        
        # Left side menu (Frame)
        self.menu_frame = tk.Frame(self.admin_window, width=200, bg="lightgray")
        self.menu_frame.pack(side=tk.LEFT, fill=tk.Y)
        
        # Right side content frame (Frame)
        self.content_frame = tk.Frame(self.admin_window, bg="white")
        self.content_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Menu Buttons
        self.menu_button_interfaces = ttk.Button(self.menu_frame, text="Interface Management", command=self.show_interfaces_window)
        self.menu_button_interfaces.pack(pady=10, fill=tk.X)
        
        self.menu_button_dns = ttk.Button(self.menu_frame, text="DNS Management", command=self.show_dns_window)
        self.menu_button_dns.pack(pady=10, fill=tk.X)

        self.menu_button_dhcp = ttk.Button(self.menu_frame, text="DHCP Management", command=self.show_dhcp_window)
        self.menu_button_dhcp.pack(pady=10, fill=tk.X)

        self.menu_button_dhcp = ttk.Button(self.menu_frame, text="Ip Addresses", command=self.show_ipAddresses_window)
        self.menu_button_dhcp.pack(pady=10, fill=tk.X)


         # Add Security Profiles button to the side menu
        self.menu_button_security = ttk.Button(self.menu_frame, text="Security Profiles", command=self.show_security_profiles_window)
        self.menu_button_security.pack(pady=10, fill=tk.X)

        self.admin_window.mainloop()

    def show_security_profiles_window(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()  # Clear previous content
        SecurityProfilesWindow(self.ip, self.user, self.password, self.content_frame)

    def show_interfaces_window(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()  # Clear previous content
        InterfacesWindow(self.ip, self.user, self.password, self.content_frame)

    def show_dns_window(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()  # Clear previous content
        DNSWindow(self.ip, self.user, self.password, self.content_frame)


    def show_dhcp_window(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        DHCPWindow(self.ip, self.user, self.password, self.content_frame)

    def show_ipAddresses_window(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        IPAddressWindow(self.ip, self.user, self.password, self.content_frame)


class InterfacesWindow:
    def __init__(self, ip, user, password, parent_frame):
        self.ip = ip
        self.user = user
        self.password = password
        
        self.interface_window_frame = tk.Frame(parent_frame, bg="white")
        self.interface_window_frame.pack(fill=tk.BOTH, expand=True)
        
        # Notebook (tabbed window)
        self.notebook = ttk.Notebook(self.interface_window_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Frames for tabs
        self.all_interfaces_frame = ttk.Frame(self.notebook)
        self.wireless_interfaces_frame = ttk.Frame(self.notebook)
        self.bridge_interfaces_frame = ttk.Frame(self.notebook)
        
        # Add tabs
        self.notebook.add(self.all_interfaces_frame, text="All Interfaces")
        self.notebook.add(self.wireless_interfaces_frame, text="Wireless Interfaces")
        self.notebook.add(self.bridge_interfaces_frame, text="Bridge Interfaces")
        
        # --- All Interfaces Tab ---
        self.all_listbox = tk.Listbox(self.all_interfaces_frame, width=60, height=15)
        self.all_listbox.pack(pady=5)
        self.all_listbox.bind("<Double-Button-1>", self.on_double_click)
        
        self.all_buttons_frame = tk.Frame(self.all_interfaces_frame, bg="white")
        self.all_buttons_frame.pack(pady=5)
        self.all_activate_button = ttk.Button(self.all_buttons_frame, text="Activate",
                                              command=lambda: self.toggle_interface_for(False, self.all_listbox, self.all_interfaces_frame))
        self.all_activate_button.pack(side=tk.LEFT, padx=5)
        self.all_deactivate_button = ttk.Button(self.all_buttons_frame, text="Deactivate",
                                                command=lambda: self.toggle_interface_for(True, self.all_listbox, self.all_interfaces_frame))
        self.all_deactivate_button.pack(side=tk.LEFT, padx=5)
        
        # --- Wireless Interfaces Tab ---
        self.wireless_listbox = tk.Listbox(self.wireless_interfaces_frame, width=60, height=15)
        self.wireless_listbox.pack(pady=5)
        self.wireless_listbox.bind("<Double-Button-1>", self.on_double_click)
        
        self.wireless_buttons_frame = tk.Frame(self.wireless_interfaces_frame, bg="white")
        self.wireless_buttons_frame.pack(pady=5)
        self.wireless_activate_button = ttk.Button(self.wireless_buttons_frame, text="Activate",
                                                   command=lambda: self.toggle_interface_for(False, self.wireless_listbox, self.wireless_interfaces_frame))
        self.wireless_activate_button.pack(side=tk.LEFT, padx=5)
        self.wireless_deactivate_button = ttk.Button(self.wireless_buttons_frame, text="Deactivate",
                                                     command=lambda: self.toggle_interface_for(True, self.wireless_listbox, self.wireless_interfaces_frame))
        self.wireless_deactivate_button.pack(side=tk.LEFT, padx=5)
        
        # --- Bridge Interfaces Tab ---
        self.bridge_listbox = tk.Listbox(self.bridge_interfaces_frame, width=60, height=10)
        self.bridge_listbox.pack(pady=5)
        self.bridge_listbox.bind("<Double-Button-1>", self.on_double_click_bridge)
        
        self.bridge_button_frame = tk.Frame(self.bridge_interfaces_frame, bg="white")
        self.bridge_button_frame.pack(fill=tk.X, pady=5)
        self.create_bridge_button = ttk.Button(self.bridge_button_frame, text="Create Bridge", command=self.create_bridge_popup)
        self.create_bridge_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.edit_bridge_button = ttk.Button(self.bridge_button_frame, text="Edit Bridge", command=self.edit_bridge_popup)
        self.edit_bridge_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.delete_bridge_button = ttk.Button(self.bridge_button_frame, text="Delete Bridge", command=self.delete_bridge)
        self.delete_bridge_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.manage_ports_button = ttk.Button(self.bridge_button_frame, text="Manage Ports", command=self.manage_ports_popup)
        self.manage_ports_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Load data into tabs
        self.load_interfaces()
        self.load_interfaces_wireless()
        self.load_bridge_interfaces()

    def load_interfaces(self):
        try:
            url = f"https://{self.ip}/rest/interface"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            interfaces = response.json()
            self.all_listbox.delete(0, tk.END)
            for interface in interfaces:
                info = f"ID: {interface['.id']} | {interface['name']} | Disabled: {interface['disabled']}"
                self.all_listbox.insert(tk.END, info)
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"{e}", parent=self.interface_window_frame)

    def load_interfaces_wireless(self):
        try:
            url = f"https://{self.ip}/rest/interface"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            interfaces = response.json()
            self.wireless_listbox.delete(0, tk.END)
            for interface in interfaces:
                if 'wlan' in interface['type'].lower():
                    info = f"ID: {interface['.id']} | {interface['name']} | Disabled: {interface['disabled']}"
                    self.wireless_listbox.insert(tk.END, info)
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"{e}", parent=self.interface_window_frame)

    def load_bridge_interfaces(self):
        try:
            authorization = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            url = f"https://{self.ip}/rest/interface/bridge"
            headers = {'Authorization': f'Basic {authorization}'}
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            bridges = response.json()
            self.bridge_listbox.delete(0, tk.END)
            for bridge in bridges:
                info = f"ID: {bridge['.id']} | {bridge['name']} | Disabled: {bridge['disabled']} | MAC: {bridge['mac-address']}"
                self.bridge_listbox.insert(tk.END, info)
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"{e}", parent=self.bridge_interfaces_frame)

    def toggle_interface_for(self, disable, listbox, parent):
        selected_index = listbox.curselection()
        if not selected_index:
            messagebox.showerror("Error", "No interface selected!", parent=parent)
            return
        selected_text = listbox.get(selected_index)
        interface_id = selected_text.split("ID: ")[1].split(" | ")[0].strip()
        url = f"https://{self.ip}/rest/interface/set"
        auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
        headers = {'Authorization': f'Basic {auth}'}
        data = {".id": interface_id, "disabled": disable}
        try:
            response = requests.post(url, headers=headers, json=data, verify=False)
            response.raise_for_status()
            messagebox.showinfo("Success", "Interface updated successfully!", parent=parent)
            if listbox == self.all_listbox:
                self.load_interfaces()
            else:
                self.load_interfaces_wireless()
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"{e}", parent=parent)

    def create_bridge_popup(self):
        popup = tk.Toplevel(self.interface_window_frame)
        popup.title("Create Bridge")
        popup.geometry("400x200")
        
        tk.Label(popup, text="Name:*").grid(row=0, column=0, padx=5, pady=5)
        name_entry = tk.Entry(popup)
        name_entry.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(popup, text="Comment:").grid(row=1, column=0, padx=5, pady=5)
        comment_entry = tk.Entry(popup)
        comment_entry.grid(row=1, column=1, padx=5, pady=5)
        
        disabled_var = tk.BooleanVar()
        tk.Checkbutton(popup, text="Disabled", variable=disabled_var).grid(row=2, column=0, padx=5, pady=5)
        
        def submit_create():
            name = name_entry.get().strip()
            if not name:
                messagebox.showerror("Error", "Name is required!", parent=popup)
                return
            comment = comment_entry.get().strip()
            disabled = disabled_var.get()
            authorization = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            url = f"https://{self.ip}/rest/interface/bridge/add"
            headers = {'Authorization': f'Basic {authorization}'}
            payload = {"name": name, "disabled": disabled}
            if comment:
                payload["comment"] = comment
            try:
                response = requests.post(url, headers=headers, json=payload, verify=False)
                response.raise_for_status()
                messagebox.showinfo("Success", "Bridge created successfully!", parent=popup)
                popup.destroy()
                self.load_bridge_interfaces()
            except requests.exceptions.RequestException as e:
                messagebox.showerror("Error", f"{e}", parent=popup)
                
        ttk.Button(popup, text="Create", command=submit_create).grid(row=3, column=0, padx=5, pady=10)
        ttk.Button(popup, text="Cancel", command=popup.destroy).grid(row=3, column=1, padx=5, pady=10)

    def edit_bridge_popup(self):
        selected = self.bridge_listbox.curselection()
        if not selected:
            messagebox.showerror("Error", "Select a bridge to edit!", parent=self.bridge_interfaces_frame)
            return
        item = self.bridge_listbox.get(selected)
        bridge_id = item.split("ID: ")[1].split(" | ")[0].strip()
        authorization = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
        try:
            url = f"https://{self.ip}/rest/interface/bridge/{bridge_id}"
            headers = {'Authorization': f'Basic {authorization}'}
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            bridge_data = response.json()
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"{e}", parent=self.bridge_interfaces_frame)
            return
        
        popup = tk.Toplevel(self.interface_window_frame)
        popup.title("Edit Bridge")
        popup.geometry("400x200")
        
        tk.Label(popup, text="Name:*").grid(row=0, column=0, padx=5, pady=5)
        name_entry = tk.Entry(popup)
        name_entry.grid(row=0, column=1, padx=5, pady=5)
        name_entry.insert(0, bridge_data.get("name", ""))
        
        tk.Label(popup, text="Comment:").grid(row=1, column=0, padx=5, pady=5)
        comment_entry = tk.Entry(popup)
        comment_entry.grid(row=1, column=1, padx=5, pady=5)
        comment_entry.insert(0, bridge_data.get("comment", ""))
        
        disabled_var = tk.BooleanVar(value=bridge_data.get("disabled", False))
        tk.Checkbutton(popup, text="Disabled", variable=disabled_var).grid(row=2, column=0, padx=5, pady=5)
        
        def submit_edit():
            new_name = name_entry.get().strip()
            if not new_name:
                messagebox.showerror("Error", "Name is required!", parent=popup)
                return
            comment = comment_entry.get().strip()
            disabled = disabled_var.get()
            payload = {".id": bridge_id, "name": new_name, "disabled": disabled}
            if comment:
                payload["comment"] = comment
            url = f"https://{self.ip}/rest/interface/bridge/set"
            headers = {'Authorization': f'Basic {authorization}'}
            try:
                response = requests.post(url, headers=headers, json=payload, verify=False)
                response.raise_for_status()
                messagebox.showinfo("Success", "Bridge updated successfully!", parent=popup)
                popup.destroy()
                self.load_bridge_interfaces()
            except requests.exceptions.RequestException as e:
                messagebox.showerror("Error", f"{e}", parent=popup)
        
        ttk.Button(popup, text="Update", command=submit_edit).grid(row=3, column=0, padx=5, pady=10)
        ttk.Button(popup, text="Cancel", command=popup.destroy).grid(row=3, column=1, padx=5, pady=10)

    def delete_bridge(self):
        selected = self.bridge_listbox.curselection()
        if not selected:
            messagebox.showerror("Error", "Select a bridge to delete!", parent=self.bridge_interfaces_frame)
            return
        item = self.bridge_listbox.get(selected)
        confirm = messagebox.askyesno("Confirm", f"Are you sure you want to delete the following bridge?\n\n{item}", parent=self.bridge_interfaces_frame)
        if not confirm:
            return
        bridge_id = item.split("ID: ")[1].split(" | ")[0].strip()
        authorization = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
        url = f"https://{self.ip}/rest/interface/bridge/remove"
        headers = {'Authorization': f'Basic {authorization}'}
        payload = {".id": bridge_id}
        try:
            response = requests.post(url, headers=headers, json=payload, verify=False)
            response.raise_for_status()
            messagebox.showinfo("Success", "Bridge deleted successfully!", parent=self.bridge_interfaces_frame)
            self.load_bridge_interfaces()
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"{e}", parent=self.bridge_interfaces_frame)

    def manage_ports_popup(self):
        # Popup for managing ports for the selected bridge.
        selected = self.bridge_listbox.curselection()
        if not selected:
            messagebox.showerror("Error", "Select a bridge to manage its ports!", parent=self.bridge_interfaces_frame)
            return
        item = self.bridge_listbox.get(selected)
        # Extract bridge name (assuming format: "ID: ... | name | Disabled: ...")
        bridge_name = item.split(" | ")[1].strip()
        bridge_id = item.split("ID: ")[1].split(" | ")[1].strip()
        
        popup = tk.Toplevel(self.interface_window_frame)
        popup.title(f"Manage Ports for Bridge: {bridge_name}")
        popup.geometry("500x400")
        
        # Listbox for ports
        ports_listbox = tk.Listbox(popup, width=70, height=10)
        ports_listbox.pack(pady=10)
        
        def load_ports():
            try:
                authorization = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
                url = f"https://{self.ip}/rest/interface/bridge/port"
                headers = {'Authorization': f'Basic {authorization}'}
                response = requests.get(url, headers=headers, verify=False)
                response.raise_for_status()
                ports = response.json()
                ports_listbox.delete(0, tk.END)
                self.current_ports = []  # store port data
                for port in ports:
                    if port.get("bridge") == bridge_name:
                        info = f"ID: {port['.id']} | Interface: {port['interface']}"
                        ports_listbox.insert(tk.END, info)
                        self.current_ports.append(port)
            except requests.exceptions.RequestException as e:
                messagebox.showerror("Error", f"{e}", parent=popup)
        
        load_ports()
        
        buttons_frame = tk.Frame(popup, bg="white")
        buttons_frame.pack(pady=5)
        
        def add_port_popup():
            add_popup = tk.Toplevel(popup)
            add_popup.title(f"Add Port to Bridge: {bridge_name}")
            add_popup.geometry("400x150")
            
            tk.Label(add_popup, text="Select Interface:*").grid(row=0, column=0, padx=5, pady=5)
            # Retrieve active interfaces (exclude bridges and loopback, only those not disabled)
            authorization = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            url = f"https://{self.ip}/rest/interface"
            headers = {'Authorization': f'Basic {authorization}'}
            try:
                response = requests.get(url, headers=headers, verify=False)
                response.raise_for_status()
                interfaces = response.json()
                active_interfaces = [iface['name'] for iface in interfaces if (iface['disabled'] in [False, "false"]) and iface['type'].lower() not in ["bridge", "loopback"]]
            except requests.exceptions.RequestException as e:
                active_interfaces = []
                messagebox.showerror("Error", f"{e}", parent=add_popup)
            
            # Use a combobox for selection
            interface_combo = ttk.Combobox(add_popup, values=active_interfaces, state="readonly")
            interface_combo.grid(row=0, column=1, padx=5, pady=5)
            
            def submit_add():
                interface_name = interface_combo.get().strip()
                if not interface_name:
                    messagebox.showerror("Error", "Select an interface!", parent=add_popup)
                    return
                authorization = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
                url = f"https://{self.ip}/rest/interface/bridge/port/add"
                headers = {'Authorization': f'Basic {authorization}'}
                payload = {"bridge": bridge_name, "interface": interface_name}
                try:
                    response = requests.post(url, headers=headers, json=payload, verify=False)
                    response.raise_for_status()
                    messagebox.showinfo("Success", "Port added successfully!", parent=add_popup)
                    add_popup.destroy()
                    load_ports()
                except requests.exceptions.RequestException as e:
                    messagebox.showerror("Error", f"{e}", parent=add_popup)
                    
            ttk.Button(add_popup, text="Add", command=submit_add).grid(row=1, column=0, padx=5, pady=10)
            ttk.Button(add_popup, text="Cancel", command=add_popup.destroy).grid(row=1, column=1, padx=5, pady=10)
        
        def edit_port_popup():
            selected_port_index = ports_listbox.curselection()
            if not selected_port_index:
                messagebox.showerror("Error", "Select a port to edit!", parent=popup)
                return
            port_item = ports_listbox.get(selected_port_index)
            port_id = port_item.split("ID: ")[1].split(" | ")[0].strip()
            # Get current port data from stored list
            port_data = next((p for p in self.current_ports if p.get('.id') == port_id), None)
            if not port_data:
                messagebox.showerror("Error", "Port data not found!", parent=popup)
                return
            edit_popup = tk.Toplevel(popup)
            edit_popup.title("Edit Port")
            edit_popup.geometry("400x150")
            
            tk.Label(edit_popup, text="Select Interface:*").grid(row=0, column=0, padx=5, pady=5)
            # Retrieve active interfaces as before
            authorization = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            url = f"https://{self.ip}/rest/interface"
            headers = {'Authorization': f'Basic {authorization}'}
            try:
                response = requests.get(url, headers=headers, verify=False)
                response.raise_for_status()
                interfaces = response.json()
                active_interfaces = [iface['name'] for iface in interfaces if (iface['disabled'] in [False, "false"]) and iface['type'].lower() not in ["bridge", "loopback"]]
            except requests.exceptions.RequestException as e:
                active_interfaces = []
                messagebox.showerror("Error", f"{e}", parent=edit_popup)
            
            interface_combo = ttk.Combobox(edit_popup, values=active_interfaces, state="readonly")
            interface_combo.grid(row=0, column=1, padx=5, pady=5)
            # Pre-select current interface
            interface_combo.set(port_data.get("interface", ""))
            
            def submit_edit():
                new_interface = interface_combo.get().strip()
                if not new_interface:
                    messagebox.showerror("Error", "Select an interface!", parent=edit_popup)
                    return
                authorization = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
                url = f"https://{self.ip}/rest/interface/bridge/port/set"
                headers = {'Authorization': f'Basic {authorization}'}
                payload = {".id": port_id, "interface": new_interface}
                try:
                    response = requests.post(url, headers=headers, json=payload, verify=False)
                    response.raise_for_status()
                    messagebox.showinfo("Success", "Port updated successfully!", parent=edit_popup)
                    edit_popup.destroy()
                    load_ports()
                except requests.exceptions.RequestException as e:
                    messagebox.showerror("Error", f"{e}", parent=edit_popup)
                    
            ttk.Button(edit_popup, text="Update", command=submit_edit).grid(row=1, column=0, padx=5, pady=10)
            ttk.Button(edit_popup, text="Cancel", command=edit_popup.destroy).grid(row=1, column=1, padx=5, pady=10)
        
        def delete_port():
            selected_port_index = ports_listbox.curselection()
            if not selected_port_index:
                messagebox.showerror("Error", "Select a port to delete!", parent=popup)
                return
            port_item = ports_listbox.get(selected_port_index)
            port_id = port_item.split("ID: ")[1].split(" | ")[0].strip()
            confirm = messagebox.askyesno("Confirm", f"Are you sure you want to delete port:\n\n{port_item}", parent=popup)
            if not confirm:
                return
            authorization = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            url = f"https://{self.ip}/rest/interface/bridge/port/remove"
            headers = {'Authorization': f'Basic {authorization}'}
            payload = {".id": port_id}
            try:
                response = requests.post(url, headers=headers, json=payload, verify=False)
                response.raise_for_status()
                messagebox.showinfo("Success", "Port deleted successfully!", parent=popup)
                load_ports()
            except requests.exceptions.RequestException as e:
                messagebox.showerror("Error", f"{e}", parent=popup)
        
        # Buttons for port management
        ttk.Button(buttons_frame, text="Add Port", command=add_port_popup).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Edit Port", command=edit_port_popup).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Delete Port", command=delete_port).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Close", command=popup.destroy).pack(side=tk.LEFT, padx=5)
        
    def on_double_click(self, event):
        selected_index = self.all_listbox.curselection() or self.wireless_listbox.curselection()
        if selected_index:
            selected_text = (self.all_listbox.get(selected_index) if self.all_listbox.curselection() 
                             else self.wireless_listbox.get(selected_index))
            messagebox.showinfo("Interface Info", selected_text, parent=self.interface_window_frame)
    
    def on_double_click_bridge(self, event):
        selected = self.bridge_listbox.curselection()
        if selected:
            item = self.bridge_listbox.get(selected)
            messagebox.showinfo("Bridge Info", item, parent=self.bridge_interfaces_frame)

class SecurityProfilesWindow:
    def __init__(self, ip, user, password, parent_frame):
        self.ip = ip
        self.user = user
        self.password = password
        
        self.security_window_frame = tk.Frame(parent_frame, bg="white")
        self.security_window_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview to display security profiles in a more structured format
        self.security_profiles_tree = ttk.Treeview(self.security_window_frame, columns=("ID", "Name", "Encryption", "WPA2 Key", "PMKID", "MAC Auth", "GCiphers"), show="headings")
        self.security_profiles_tree.heading("ID", text="ID")
        self.security_profiles_tree.heading("Name", text="Name")
        self.security_profiles_tree.heading("Encryption", text="Encryption")
        self.security_profiles_tree.heading("WPA2 Key", text="WPA2 Key")
        self.security_profiles_tree.heading("PMKID", text="PMKID Disabled")
        self.security_profiles_tree.heading("MAC Auth", text="MAC Authentication")
        self.security_profiles_tree.heading("GCiphers", text="Group Ciphers")
        self.security_profiles_tree.pack(pady=10)
        self.security_profiles_tree.bind("<Double-1>", self.on_double_click_security_profile)
        
        # Buttons to manage security profiles
        self.buttons_frame = tk.Frame(self.security_window_frame, bg="white")
        self.buttons_frame.pack(pady=5)
        self.create_security_button = ttk.Button(self.buttons_frame, text="Create Security Profile", command=self.create_security_profile_popup)
        self.create_security_button.pack(side=tk.LEFT, padx=5)
        self.edit_security_button = ttk.Button(self.buttons_frame, text="Edit Security Profile", command=self.edit_security_profile_popup)
        self.edit_security_button.pack(side=tk.LEFT, padx=5)
        self.delete_security_button = ttk.Button(self.buttons_frame, text="Delete Security Profile", command=self.delete_security_profile)
        self.delete_security_button.pack(side=tk.LEFT, padx=5)
        
        # Load security profiles into treeview
        self.load_security_profiles()

    def load_security_profiles(self):
        try:
            url = f"https://{self.ip}/rest/interface/wireless/security-profiles"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            security_profiles = response.json()
            for item in self.security_profiles_tree.get_children():
                self.security_profiles_tree.delete(item)
            for profile in security_profiles:
                # Insert profile data into treeview
                self.security_profiles_tree.insert("", "end", values=(
                    profile['.id'],
                    profile['name'],
                    profile.get('mode', 'None'),
                    profile.get('wpa2-pre-shared-key', 'None'),
                    profile.get('disable-pmkid', 'Not Set'),
                    profile.get('radius-mac-authentication', 'No'),
                    profile.get('group-ciphers', 'Not set')
                ))
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"{e}", parent=self.security_window_frame)

    def create_security_profile_popup(self):
        popup = tk.Toplevel(self.security_window_frame)
        popup.title("Criar Perfil de Segurança")
        popup.geometry("400x280")
        popup.configure(bg="white")

        content = ttk.Frame(popup, padding=10)
        content.pack(fill="both", expand=True)
        content.columnconfigure(1, weight=1)

    # Nome do perfil
        ttk.Label(content, text="Nome do Perfil:").grid(row=0, column=0, sticky="w", pady=5)
        name_entry = ttk.Entry(content)
        name_entry.grid(row=0, column=1, sticky="ew", pady=5)

    # WPA2 Pre-Shared Key
        ttk.Label(content, text="WPA2 Pre-Shared Key:").grid(row=1, column=0, sticky="w", pady=5)
        key_entry = ttk.Entry(content, show="*")
        key_entry.grid(row=1, column=1, sticky="ew", pady=5)

    # Disable PMKID checkbox
        pmkid_var = tk.BooleanVar()
        pmkid_checkbox = ttk.Checkbutton(content, text="Disable PMKID", variable=pmkid_var)
        pmkid_checkbox.grid(row=2, column=0, columnspan=2, sticky="w", pady=5)

    # MAC Authentication checkbox
        mac_auth_var = tk.BooleanVar()
        mac_checkbox = ttk.Checkbutton(content, text="Disable MAC Authentication", variable=mac_auth_var)
        mac_checkbox.grid(row=3, column=0, columnspan=2, sticky="w", pady=5)

        def submit():
            name_valor = name_entry.get()
            password_valor = key_entry.get()
            pmkid_off = "yes" if pmkid_var.get() else "no"
            mac_off = "yes" if mac_auth_var.get() else "no"

            if not name_valor or not password_valor:
                messagebox.showwarning("Campos obrigatórios", "Preencha todos os campos.")
                return

            if not 8 <= len(password_valor) <= 64:
                messagebox.showwarning("Senha inválida", "A chave WPA2 deve ter entre 8 e 64 caracteres.")
                return


            data = {
                "name": name_valor,
                "wpa2-pre-shared-key": password_valor,
                "mode": "dynamic-keys",
                "authentication-types": "wpa2-psk",
                "disable-pmkid": pmkid_off,
                "radius-mac-authentication": mac_off,
                "eap-methods": "passthrough",
                "group-ciphers": "aes-ccm",
                "management-protection": "disabled",
                "radius-mac-caching": "disabled",
                "radius-mac-format": "XX:XX:XX:XX:XX:XX",
                "radius-mac-mode": "as-username",
                "tls-mode": "no-certificates",
                "unicast-ciphers": "aes-ccm"
            }
            print(data)

            try:
                url = f"https://{self.ip}/rest/interface/wireless/security-profiles/add"
                auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
                headers = {'Authorization': f'Basic {auth}', 'Content-Type': 'application/json'}
                response = requests.post(url, headers=headers, json=(data), verify=False)
                response.raise_for_status()
                self.load_security_profiles()
                messagebox.showinfo("Sucesso", "Perfil de segurança criado com sucesso.")
                popup.destroy()
            except requests.exceptions.RequestException as e:
                messagebox.showerror("Erro", f"{e}", parent=popup)

        ttk.Button(content, text="Criar Perfil", command=submit).grid(row=4, column=0, columnspan=2, pady=15)

        popup.transient(self.security_window_frame)
        popup.grab_set()
        popup.wait_window()

    def edit_security_profile_popup(self):
        selected_item = self.security_profiles_tree.selection()
        if not selected_item:
            messagebox.showwarning("Select Profile", "Please select a security profile to edit.")
            return

        selected_profile = self.security_profiles_tree.item(selected_item)["values"]
        profile_id = selected_profile[0]
        current_name = selected_profile[1]
        current_key = selected_profile[3]
        current_pmkid = selected_profile[4].strip().lower() in ("no", "not set")
        current_mac_auth = selected_profile[5].strip().lower() in ("no", "not set")
        pmkid_var = tk.BooleanVar(value=current_pmkid)
        mac_auth_var = tk.BooleanVar(value=current_mac_auth)


        popup = tk.Toplevel(self.security_window_frame)
        popup.title("Editar Perfil de Segurança")
        popup.geometry("400x280")
        popup.configure(bg="white")

        content = ttk.Frame(popup, padding=10)
        content.pack(fill="both", expand=True)
        content.columnconfigure(1, weight=1)

    # Nome do perfil
        ttk.Label(content, text="Nome do Perfil:").grid(row=0, column=0, sticky="w", pady=5)
        name_entry = ttk.Entry(content)
        name_entry.insert(0, current_name)
        name_entry.grid(row=0, column=1, sticky="ew", pady=5)

    # WPA2 Pre-Shared Key
        ttk.Label(content, text="WPA2 Pre-Shared Key:").grid(row=1, column=0, sticky="w", pady=5)
        key_entry = ttk.Entry(content, show="*")
        key_entry.insert(0, current_key)
        key_entry.grid(row=1, column=1, sticky="ew", pady=5)

    # Disable PMKID checkbox
        pmkid_var = tk.BooleanVar(value=current_pmkid)
        pmkid_checkbox = ttk.Checkbutton(content, text="Disable PMKID", variable=pmkid_var)
        pmkid_checkbox.grid(row=2, column=0, columnspan=2, sticky="w", pady=5)

    # MAC Authentication checkbox
        mac_auth_var = tk.BooleanVar(value=current_mac_auth)
        mac_checkbox = ttk.Checkbutton(content, text=" MAC Authentication", variable=mac_auth_var)
        mac_checkbox.grid(row=3, column=0, columnspan=2, sticky="w", pady=5)

        def submit_edit():
            name_valor = name_entry.get()
            password_valor = key_entry.get()
            pmkid_off = "yes" if pmkid_var.get() else "no"
            mac_off = "yes" if mac_auth_var.get() else "no"

            if not name_valor or not password_valor:
                messagebox.showwarning("Campos obrigatórios", "Preencha todos os campos.")
                return

            if not 8 <= len(password_valor) <= 64:
                messagebox.showwarning("Senha inválida", "A chave WPA2 deve ter entre 8 e 64 caracteres.")
                return


            data = {
                "name": name_valor,
                "wpa2-pre-shared-key": password_valor,
                "mode": "dynamic-keys",
                "authentication-types": "wpa2-psk",
                "disable-pmkid": pmkid_off,
                "radius-mac-authentication": mac_off,
                "eap-methods": "passthrough",
                "group-ciphers": "aes-ccm",
                "management-protection": "disabled",
                "radius-mac-caching": "disabled",
                "radius-mac-format": "XX:XX:XX:XX:XX:XX",
                "radius-mac-mode": "as-username",
                "tls-mode": "no-certificates",
                "unicast-ciphers": "aes-ccm"
            }

            try:
                url = f"https://{self.ip}/rest/interface/wireless/security-profiles/{profile_id}"
                auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
                headers = {'Authorization': f'Basic {auth}', 'Content-Type': 'application/json'}
                response = requests.put(url, headers=headers, json=data, verify=False)
                response.raise_for_status()
                self.load_security_profiles()
                messagebox.showinfo("Sucesso", "Perfil atualizado com sucesso.")
                popup.destroy()
            except requests.exceptions.RequestException as e:
                messagebox.showerror("Erro", f"{e}", parent=popup)

        ttk.Button(content, text="Salvar Alterações", command=submit_edit).grid(row=4, column=0, columnspan=2, pady=15)

        popup.transient(self.security_window_frame)
        popup.grab_set()
        popup.wait_window()


    def delete_security_profile(self):
        selected_item = self.security_profiles_tree.selection()
        if not selected_item:
            messagebox.showwarning("Select Profile", "Please select a security profile to delete.")
            return
        selected_profile = self.security_profiles_tree.item(selected_item)["values"]
        try:
            url = f"https://{self.ip}/rest/interface/wireless/security-profiles/{selected_profile[0]}"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}
            response = requests.delete(url, headers=headers, verify=False)
            response.raise_for_status()
            self.load_security_profiles()
            messagebox.showinfo("Sucesso", "Perfil excluído com sucesso.")
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Erro", f"{e}", parent=self.security_window_frame)

    def on_double_click_security_profile(self, event):
        selected_item = self.security_profiles_tree.selection()
        if selected_item:
            selected_profile = self.security_profiles_tree.item(selected_item)["values"]
            profile_info = "\n".join(f"{col}: {val}" for col, val in zip(
                ["ID", "Name", "Encryption", "WPA2 Key", "PMKID", "MAC Auth", "WPA3"], selected_profile))
            messagebox.showinfo("Security Profile Info", profile_info, parent=self.security_window_frame)



if __name__ == "__main__":
    root = tk.Tk()
    app = MikroTikLogin(root)
    root.mainloop()
