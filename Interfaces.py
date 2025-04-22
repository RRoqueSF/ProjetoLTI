import base64

import requests
import tkinter as tk
from tkinter import ttk, messagebox

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
                                              command=lambda: self.toggle_interface_for(False, self.all_listbox,
                                                                                        self.all_interfaces_frame))
        self.all_activate_button.pack(side=tk.LEFT, padx=5)
        self.all_deactivate_button = ttk.Button(self.all_buttons_frame, text="Deactivate",
                                                command=lambda: self.toggle_interface_for(True, self.all_listbox,
                                                                                          self.all_interfaces_frame))
        self.all_deactivate_button.pack(side=tk.LEFT, padx=5)

        # --- Wireless Interfaces Tab ---
        self.wireless_listbox = tk.Listbox(self.wireless_interfaces_frame, width=60, height=15)
        self.wireless_listbox.pack(pady=5)
        self.wireless_listbox.bind("<Double-Button-1>", self.on_double_click)

        self.wireless_buttons_frame = tk.Frame(self.wireless_interfaces_frame, bg="white")
        self.wireless_buttons_frame.pack(pady=5)
        self.wireless_activate_button = ttk.Button(self.wireless_buttons_frame, text="Activate",
                                                   command=lambda: self.toggle_interface_for(False,
                                                                                             self.wireless_listbox,
                                                                                             self.wireless_interfaces_frame))
        self.wireless_activate_button.pack(side=tk.LEFT, padx=5)
        self.wireless_deactivate_button = ttk.Button(self.wireless_buttons_frame, text="Deactivate",
                                                     command=lambda: self.toggle_interface_for(True,
                                                                                               self.wireless_listbox,
                                                                                               self.wireless_interfaces_frame))
        self.wireless_deactivate_button.pack(side=tk.LEFT, padx=5)

        # Add this after the wireless_deactivate_button
        self.wireless_configure_button = ttk.Button(self.wireless_buttons_frame, text="Configure",
                                                    command=self.configure_wireless)
        self.wireless_configure_button.pack(side=tk.LEFT, padx=5)

        # --- Bridge Interfaces Tab ---
        self.bridge_listbox = tk.Listbox(self.bridge_interfaces_frame, width=60, height=10)
        self.bridge_listbox.pack(pady=5)
        self.bridge_listbox.bind("<Double-Button-1>", self.on_double_click_bridge)

        self.bridge_button_frame = tk.Frame(self.bridge_interfaces_frame, bg="white")
        self.bridge_button_frame.pack(fill=tk.X, pady=5)
        self.create_bridge_button = ttk.Button(self.bridge_button_frame, text="Create Bridge",
                                               command=self.create_bridge_popup)
        self.create_bridge_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.edit_bridge_button = ttk.Button(self.bridge_button_frame, text="Edit Bridge",
                                             command=self.edit_bridge_popup)
        self.edit_bridge_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.delete_bridge_button = ttk.Button(self.bridge_button_frame, text="Delete Bridge",
                                               command=self.delete_bridge)
        self.delete_bridge_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.manage_ports_button = ttk.Button(self.bridge_button_frame, text="Manage Ports",
                                              command=self.manage_ports_popup)
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
        confirm = messagebox.askyesno("Confirm", f"Are you sure you want to delete the following bridge?\n\n{item}",
                                      parent=self.bridge_interfaces_frame)
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
                active_interfaces = [iface['name'] for iface in interfaces if
                                     (iface['disabled'] in [False, "false"]) and iface['type'].lower() not in ["bridge",
                                                                                                               "loopback"]]
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
                active_interfaces = [iface['name'] for iface in interfaces if
                                     (iface['disabled'] in [False, "false"]) and iface['type'].lower() not in ["bridge",
                                                                                                               "loopback"]]
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
            confirm = messagebox.askyesno("Confirm", f"Are you sure you want to delete port:\n\n{port_item}",
                                          parent=popup)
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

    def configure_wireless(self):
        selected = self.wireless_listbox.curselection()
        if not selected:
            messagebox.showerror("Error", "Select a wireless interface to configure!",
                                 parent=self.wireless_interfaces_frame)
            return

        item = self.wireless_listbox.get(selected)
        interface_id = item.split("ID: ")[1].split(" | ")[0].strip()
        interface_name = item.split(" | ")[1].strip()

        # Get current wireless settings
        try:
            authorization = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            url = f"https://{self.ip}/rest/interface/wireless"
            headers = {'Authorization': f'Basic {authorization}'}
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            wireless_interfaces = response.json()

            # Find this specific interface
            wireless_data = None
            for wiface in wireless_interfaces:
                if wiface.get('.id') == interface_id or wiface.get('name') == interface_name:
                    wireless_data = wiface
                    break

            if not wireless_data:
                messagebox.showerror("Error", f"Could not find wireless configuration for {interface_name}!",
                                     parent=self.wireless_interfaces_frame)
                return

            # Get security profiles if available
            security_profiles = []
            try:
                url = f"https://{self.ip}/rest/interface/wireless/security-profiles"
                response = requests.get(url, headers=headers, verify=False)
                response.raise_for_status()
                security_profiles = response.json()
            except:
                pass

        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"{e}", parent=self.wireless_interfaces_frame)
            return

        # Create configuration popup
        popup = tk.Toplevel(self.interface_window_frame)
        popup.title(f"Configure Wireless Interface: {interface_name}")
        popup.geometry("650x550")

        # Create a frame with scrollbar
        main_frame = tk.Frame(popup)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        canvas = tk.Canvas(main_frame)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Basic settings
        tk.Label(scrollable_frame, text="Basic Settings", font=("Arial", 12, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(10, 5))

        # Row 1 - SSID
        tk.Label(scrollable_frame, text="SSID:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        ssid_entry = tk.Entry(scrollable_frame, width=30)
        ssid_entry.grid(row=1, column=1, sticky="w", padx=5, pady=5)
        ssid_entry.insert(0, wireless_data.get("ssid", ""))

        # Row 2 - Mode
        tk.Label(scrollable_frame, text="Mode:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        mode_values = ["ap", "station", "station-wds", "station-pseudobridge", "wds-slave", "bridge"]
        mode_combo = ttk.Combobox(scrollable_frame, values=mode_values, state="readonly", width=27)
        mode_combo.grid(row=2, column=1, sticky="w", padx=5, pady=5)
        mode_combo.set(wireless_data.get("mode", "ap"))

        # Row 3 - Band
        tk.Label(scrollable_frame, text="Band:").grid(row=3, column=0, sticky="w", padx=5, pady=5)
        band_values = ["2ghz-b/g/n", "5ghz-a/n/ac", "2ghz-onlyn", "5ghz-onlyn", "5ghz-onlyac"]
        band_combo = ttk.Combobox(scrollable_frame, values=band_values, state="readonly", width=27)
        band_combo.grid(row=3, column=1, sticky="w", padx=5, pady=5)
        band_combo.set(wireless_data.get("band", "2ghz-b/g/n"))

        # Row 4 - Channel Width
        tk.Label(scrollable_frame, text="Channel Width:").grid(row=4, column=0, sticky="w", padx=5, pady=5)
        width_values = ["20MHz", "20/40MHz", "20/40/80MHz"]
        width_combo = ttk.Combobox(scrollable_frame, values=width_values, state="readonly", width=27)
        width_combo.grid(row=4, column=1, sticky="w", padx=5, pady=5)
        width_combo.set(wireless_data.get("channel-width", "20MHz"))

        # Row 5 - Frequency
        tk.Label(scrollable_frame, text="Frequency:").grid(row=5, column=0, sticky="w", padx=5, pady=5)
        frequency_entry = tk.Entry(scrollable_frame, width=30)
        frequency_entry.grid(row=5, column=1, sticky="w", padx=5, pady=5)
        frequency_entry.insert(0, wireless_data.get("frequency", "auto"))

        # Security settings
        tk.Label(scrollable_frame, text="Security Settings", font=("Arial", 12, "bold")).grid(
            row=6, column=0, columnspan=3, sticky="w", pady=(20, 5))

        # Row 7 - Security Profile
        tk.Label(scrollable_frame, text="Security Profile:").grid(row=7, column=0, sticky="w", padx=5, pady=5)
        security_profile_names = [profile.get('name', 'default') for profile in security_profiles]
        security_combo = ttk.Combobox(scrollable_frame, values=security_profile_names, state="readonly", width=27)
        security_combo.grid(row=7, column=1, sticky="w", padx=5, pady=5)
        security_combo.set(wireless_data.get("security-profile", "default"))

        # Row 8 - Create New Profile button
        def create_security_profile():
            profile_popup = tk.Toplevel(popup)
            profile_popup.title("Create Security Profile")
            profile_popup.geometry("400x300")

            # Add form elements for creating a new security profile
            # (implementation depends on your specific requirements)

        ttk.Button(scrollable_frame, text="New Profile", command=create_security_profile).grid(
            row=7, column=2, sticky="w", padx=5, pady=5)

        # Advanced settings
        tk.Label(scrollable_frame, text="Advanced Settings", font=("Arial", 12, "bold")).grid(
            row=8, column=0, columnspan=3, sticky="w", pady=(20, 5))

        # Row 9 - TX Power
        tk.Label(scrollable_frame, text="TX Power (dBm):").grid(row=9, column=0, sticky="w", padx=5, pady=5)
        tx_power_entry = tk.Entry(scrollable_frame, width=30)
        tx_power_entry.grid(row=9, column=1, sticky="w", padx=5, pady=5)
        tx_power_entry.insert(0, wireless_data.get("tx-power", ""))

        # Row 10 - Disabled checkbox
        disabled_var = tk.BooleanVar(value=wireless_data.get("disabled", False))
        tk.Checkbutton(scrollable_frame, text="Disabled", variable=disabled_var).grid(
            row=10, column=0, sticky="w", padx=5, pady=5)

        # Buttons frame at bottom
        buttons_frame = tk.Frame(popup)
        buttons_frame.pack(fill=tk.X, pady=10)

        def save_configuration():
            # Prepare the configuration data
            config = {
                ".id": interface_id,
                "ssid": ssid_entry.get().strip(),
                "mode": mode_combo.get(),
                "band": band_combo.get(),
                "channel-width": width_combo.get(),
                "frequency": frequency_entry.get().strip(),
                "disabled": "true" if disabled_var.get() else "false"
            }

            # Only include these fields if they have values
            if tx_power_entry.get().strip():
                config["tx-power"] = tx_power_entry.get().strip()

            if security_combo.get() and security_combo.get() != "default":
                config["security-profile"] = security_combo.get()

            try:
                # Encode credentials
                auth_str = f"{self.user}:{self.password}"
                auth_bytes = auth_str.encode('ascii')
                auth_b64 = base64.b64encode(auth_bytes).decode('ascii')

                headers = {
                    'Authorization': f'Basic {auth_b64}',
                    'Content-Type': 'application/json'
                }

                url = f"https://{self.ip}/rest/interface/wireless/set"

                # Print the payload for debugging (remove in production)
                print("Sending payload:", config)

                # Send the request with verify=False to skip SSL verification
                response = requests.post(
                    url,
                    headers=headers,
                    json=config,
                    verify=False,
                    timeout=10
                )

                # Check for HTTP errors
                response.raise_for_status()

                # If we get here, the request was successful
                messagebox.showinfo(
                    "Success",
                    "Wireless interface updated successfully!",
                    parent=popup
                )

                # Refresh the interface list
                self.load_interfaces_wireless()
                popup.destroy()

            except requests.exceptions.RequestException as e:
                # Show detailed error message
                error_msg = f"Failed to update interface:\n\n"

                if hasattr(e, 'response') and e.response is not None:
                    try:
                        error_details = e.response.json()
                        error_msg += f"API Response: {error_details}\n\n"
                    except:
                        error_msg += f"Response Text: {e.response.text}\n\n"

                error_msg += f"Error: {str(e)}"

                messagebox.showerror(
                    "Error",
                    error_msg,
                    parent=popup
                )

        ttk.Button(buttons_frame, text="Save", command=save_configuration).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Cancel", command=popup.destroy).pack(side=tk.LEFT, padx=5)