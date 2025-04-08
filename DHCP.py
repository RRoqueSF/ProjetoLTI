import json
import tkinter as tk
from tkinter import ttk, messagebox
import requests
import base64


class DHCPWindow:
    def __init__(self, ip, user, password, parent_frame):
        self.ip = ip
        self.user = user
        self.password = password

        self.dhcp_window_frame = tk.Frame(parent_frame, bg="white")
        self.dhcp_window_frame.pack(fill=tk.BOTH, expand=True)

        # Notebook for tabs
        self.notebook = ttk.Notebook(self.dhcp_window_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Create frames for tabs
        self.dhcp_server_frame = ttk.Frame(self.notebook)
        self.dhcp_networks_frame = ttk.Frame(self.notebook)
        self.dhcp_leases_frame = ttk.Frame(self.notebook)

        # Add tabs to notebook
        self.notebook.add(self.dhcp_server_frame, text="DHCP Servers")
        self.notebook.add(self.dhcp_networks_frame, text="Networks")
        self.notebook.add(self.dhcp_leases_frame, text="Leases")

        # --- DHCP Servers Tab ---
        self.servers_tree = ttk.Treeview(self.dhcp_server_frame,
                                         columns=("ID", "Name", "Interface", "Address Pool", "Status"), show="headings")
        self.servers_tree.heading("ID", text="ID")
        self.servers_tree.heading("Name", text="Name")
        self.servers_tree.heading("Interface", text="Interface")
        self.servers_tree.heading("Address Pool", text="Address Pool")
        self.servers_tree.heading("Status", text="Status")

        self.servers_tree.column("ID", width=50)
        self.servers_tree.column("Name", width=100)
        self.servers_tree.column("Interface", width=100)
        self.servers_tree.column("Address Pool", width=150)
        self.servers_tree.column("Status", width=80)

        self.servers_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.server_buttons_frame = tk.Frame(self.dhcp_server_frame, bg="white")
        self.server_buttons_frame.pack(fill=tk.X, pady=5)

        self.add_server_button = ttk.Button(self.server_buttons_frame, text="Add Server", command=self.add_dhcp_server)
        self.add_server_button.pack(side=tk.LEFT, padx=5)

        self.edit_server_button = ttk.Button(self.server_buttons_frame, text="Edit Server",
                                             command=self.edit_dhcp_server)
        self.edit_server_button.pack(side=tk.LEFT, padx=5)

        self.delete_server_button = ttk.Button(self.server_buttons_frame, text="Delete Server",
                                               command=self.delete_dhcp_server)
        self.delete_server_button.pack(side=tk.LEFT, padx=5)

        # --- DHCP Networks Tab ---
        self.networks_tree = ttk.Treeview(self.dhcp_networks_frame,
                                          columns=("ID", "Address", "Gateway", "DNS", "Domain", "DHCP Server"),
                                          show="headings")
        self.networks_tree.heading("ID", text="ID")
        self.networks_tree.heading("Address", text="Network")
        self.networks_tree.heading("Gateway", text="Gateway")
        self.networks_tree.heading("DNS", text="DNS Server")
        self.networks_tree.heading("Domain", text="Domain")
        self.networks_tree.heading("DHCP Server", text="DHCP Server")

        self.networks_tree.column("ID", width=50)
        self.networks_tree.column("Address", width=150)
        self.networks_tree.column("Gateway", width=100)
        self.networks_tree.column("DNS", width=100)
        self.networks_tree.column("Domain", width=100)
        self.networks_tree.column("DHCP Server", width=100)

        self.networks_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.network_buttons_frame = tk.Frame(self.dhcp_networks_frame, bg="white")
        self.network_buttons_frame.pack(fill=tk.X, pady=5)

        self.add_network_button = ttk.Button(self.network_buttons_frame, text="Add Network",
                                             command=self.add_dhcp_network)
        self.add_network_button.pack(side=tk.LEFT, padx=5)

        self.edit_network_button = ttk.Button(self.network_buttons_frame, text="Edit Network",
                                              command=self.edit_dhcp_network)
        self.edit_network_button.pack(side=tk.LEFT, padx=5)

        self.delete_network_button = ttk.Button(self.network_buttons_frame, text="Delete Network",
                                                command=self.delete_dhcp_network)
        self.delete_network_button.pack(side=tk.LEFT, padx=5)

        # --- DHCP Leases Tab ---
        self.leases_tree = ttk.Treeview(self.dhcp_leases_frame,
                                        columns=("ID", "Address", "MAC", "Client ID", "Host", "Status"),
                                        show="headings")
        self.leases_tree.heading("ID", text="ID")
        self.leases_tree.heading("Address", text="IP Address")
        self.leases_tree.heading("MAC", text="MAC Address")
        self.leases_tree.heading("Client ID", text="Client ID")
        self.leases_tree.heading("Host", text="Hostname")
        self.leases_tree.heading("Status", text="Status")

        self.leases_tree.column("ID", width=50)
        self.leases_tree.column("Address", width=120)
        self.leases_tree.column("MAC", width=150)
        self.leases_tree.column("Client ID", width=150)
        self.leases_tree.column("Host", width=150)
        self.leases_tree.column("Status", width=80)

        self.leases_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.lease_buttons_frame = tk.Frame(self.dhcp_leases_frame, bg="white")
        self.lease_buttons_frame.pack(fill=tk.X, pady=5)

        self.refresh_leases_button = ttk.Button(self.lease_buttons_frame, text="Refresh Leases",
                                                command=self.load_dhcp_leases)
        self.refresh_leases_button.pack(side=tk.LEFT, padx=5)


        self.release_lease_button = ttk.Button(self.lease_buttons_frame, text="Release Lease",
                                               command=self.release_dhcp_lease)
        self.release_lease_button.pack(side=tk.LEFT, padx=5)

        # Load all data
        self.load_dhcp_servers()
        self.load_dhcp_networks()
        self.load_dhcp_leases()

    def load_dhcp_servers(self):
        """Load all DHCP server configurations from MikroTik"""
        try:
            url = f"https://{self.ip}/rest/ip/dhcp-server"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            servers = response.json()

            # Clear existing data
            for item in self.servers_tree.get_children():
                self.servers_tree.delete(item)

            # Insert new data
            for server in servers:
                self.servers_tree.insert("", tk.END, values=(
                    server.get('.id', ''),
                    server.get('name', ''),
                    server.get('interface', ''),
                    server.get('address-pool', ''),
                    'Enabled' if not server.get('disabled', False) else 'Disabled'
                ))
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Failed to load DHCP servers: {e}", parent=self.dhcp_window_frame)

    def load_dhcp_networks(self):
        """Load all DHCP networks configurations from MikroTik"""
        try:
            url = f"https://{self.ip}/rest/ip/dhcp-server/network"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            networks = response.json()

            # Clear existing data
            for item in self.networks_tree.get_children():
                self.networks_tree.delete(item)

            # Insert new data
            for network in networks:
                self.networks_tree.insert("", tk.END, values=(
                    network.get('.id', ''),
                    network.get('address', ''),
                    network.get('gateway', ''),
                    network.get('dns-server', ''),
                    network.get('domain', ''),
                    network.get('dhcp-server', '')
                ))
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Failed to load DHCP networks: {e}", parent=self.dhcp_window_frame)

    def load_dhcp_leases(self):
        """Load all DHCP leases from MikroTik"""
        try:
            url = f"https://{self.ip}/rest/ip/dhcp-server/lease"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            leases = response.json()

            # Clear existing data
            for item in self.leases_tree.get_children():
                self.leases_tree.delete(item)

            # Insert new data
            for lease in leases:
                # Determine status
                status = "Static" if lease.get('dynamic', '') == 'false' else "Dynamic"
                if lease.get('status', '') == 'bound':
                    status += " (Active)"

                self.leases_tree.insert("", tk.END, values=(
                    lease.get('.id', ''),
                    lease.get('address', ''),
                    lease.get('mac-address', ''),
                    lease.get('client-id', ''),
                    lease.get('host-name', ''),
                    status
                ))
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Failed to load DHCP leases: {e}", parent=self.dhcp_window_frame)

    def get_interfaces(self):
        """Fetch all interfaces from the Mikrotik RouterOS API"""
        try:
            url = f"https://{self.ip}/rest/interface"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()

            interfaces = response.json()
            interface_names = [interface.get('name', '') for interface in interfaces]
            return interface_names
        except requests.exceptions.RequestException as e:
            print(f"Error fetching interfaces: {e}")
            return []

    def get_dhcp_server_names(self):
        """Fetch all DHCP server names from the Mikrotik RouterOS API"""
        try:
            url = f"https://{self.ip}/rest/ip/dhcp-server"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()

            servers = response.json()
            server_names = [server.get('name', '') for server in servers]
            return server_names
        except requests.exceptions.RequestException as e:
            print(f"Error fetching DHCP servers: {e}")
            return []

    def get_address_pools(self):
        """Fetch address pools from the Mikrotik RouterOS API"""
        try:
            url = f"https://{self.ip}/rest/ip/pool"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()

            pools = response.json()
            pool_names = [pool.get('name', '') for pool in pools]
            return pool_names

        except requests.exceptions.RequestException as e:
            print(f"Error fetching address pools: {e}")
            return []

    def add_dhcp_server(self):
        """Open window to add a new DHCP server"""
        add_window = tk.Toplevel(self.dhcp_window_frame)
        add_window.title("Add DHCP Server")
        add_window.geometry("450x400")
        add_window.configure(bg="white")

        # Frame for form
        form_frame = ttk.Frame(add_window, padding=10)
        form_frame.pack(fill="both", expand=True)

        # Get available interfaces for dropdown
        interfaces = self.get_interfaces()
        address_pools = self.get_address_pools()

        # Form fields
        ttk.Label(form_frame, text="Server Name:").grid(row=0, column=0, sticky="w", pady=5)
        name_entry = ttk.Entry(form_frame, width=30)
        name_entry.grid(row=0, column=1, sticky="w", pady=5)

        ttk.Label(form_frame, text="Interface:").grid(row=1, column=0, sticky="w", pady=5)
        interface_combo = ttk.Combobox(form_frame, values=interfaces, width=28, state="readonly")
        interface_combo.grid(row=1, column=1, sticky="w", pady=5)

        ttk.Label(form_frame, text="Address Pool:").grid(row=2, column=0, sticky="w", pady=5)
        pool_combo = ttk.Combobox(form_frame, values=address_pools, width=28)
        pool_combo.grid(row=2, column=1, sticky="w", pady=5)

        ttk.Label(form_frame, text="Lease Time:").grid(row=3, column=0, sticky="w", pady=5)
        lease_frame = ttk.Frame(form_frame)
        lease_frame.grid(row=3, column=1, sticky="w", pady=5)
        lease_entry = ttk.Entry(lease_frame, width=8)
        lease_entry.pack(side=tk.LEFT)
        lease_entry.insert(0, "1")
        lease_unit = ttk.Combobox(lease_frame, values=["minutes", "hours", "days", "weeks"], width=10, state="readonly")
        lease_unit.pack(side=tk.LEFT, padx=5)
        lease_unit.current(2)  # Default to days

        ttk.Label(form_frame, text="Boot File:").grid(row=4, column=0, sticky="w", pady=5)
        boot_entry = ttk.Entry(form_frame, width=30)
        boot_entry.grid(row=4, column=1, sticky="w", pady=5)

        ttk.Label(form_frame, text="DHCP Options:").grid(row=5, column=0, sticky="w", pady=5)
        options_entry = ttk.Entry(form_frame, width=30)
        options_entry.grid(row=5, column=1, sticky="w", pady=5)

        disabled_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(form_frame, text="Disabled", variable=disabled_var).grid(row=6, column=0, columnspan=2,
                                                                                 sticky="w", pady=5)

        # Advanced settings section
        ttk.Separator(form_frame).grid(row=7, column=0, columnspan=2, sticky="ew", pady=10)
        ttk.Label(form_frame, text="Advanced Settings", font=("", 10, "bold")).grid(row=8, column=0, columnspan=2,
                                                                                    sticky="w")

        authoritative_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(form_frame, text="Authoritative", variable=authoritative_var).grid(row=9, column=0,
                                                                                           columnspan=2, sticky="w",
                                                                                           pady=2)

        ttk.Label(form_frame, text="Add ARP:").grid(row=10, column=0, sticky="w", pady=2)
        add_arp_var = tk.StringVar(value="yes")
        ttk.Radiobutton(form_frame, text="Yes", variable=add_arp_var, value="yes").grid(row=10, column=1, sticky="w",
                                                                                        pady=2)
        ttk.Radiobutton(form_frame, text="No", variable=add_arp_var, value="no").grid(row=11, column=1, sticky="w",
                                                                                      pady=2)

        # Buttons
        button_frame = ttk.Frame(form_frame)
        button_frame.grid(row=12, column=0, columnspan=2, pady=10)

        def submit_add():
            # Get values from form
            name = name_entry.get().strip()
            interface = interface_combo.get().strip()
            pool = pool_combo.get().strip()
            lease_time = f"{lease_entry.get().strip()}{lease_unit.get().strip()[0]}"  # e.g. "1d" for days
            boot_file = boot_entry.get().strip()
            options = options_entry.get().strip()
            disabled = "yes" if disabled_var.get() else "no"
            authoritative = "yes" if authoritative_var.get() else "no"
            add_arp = add_arp_var.get()

            # Validate required fields
            if not name or not interface or not pool:
                messagebox.showwarning("Missing Information", "Name, Interface and Address Pool are required.",
                                       parent=add_window)
                return

            # Prepare data for API
            payload = {
                "name": name,
                "interface": interface,
                "address-pool": pool,
                "lease-time": lease_time,
                "disabled": disabled,
                "authoritative": authoritative,
                "add-arp": add_arp
            }

            if boot_file:
                payload["boot-file-name"] = boot_file
            if options:
                payload["dhcp-option"] = options

            # Send request to MikroTik
            try:
                url = f"https://{self.ip}/rest/ip/dhcp-server/add"
                auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
                headers = {'Authorization': f'Basic {auth}'}
                response = requests.post(url, headers=headers, json=payload, verify=False)
                response.raise_for_status()
                messagebox.showinfo("Success", "DHCP server added successfully!", parent=add_window)
                add_window.destroy()
                self.load_dhcp_servers()
            except requests.exceptions.RequestException as e:
                messagebox.showerror("Error", f"Failed to add DHCP server: {e}", parent=add_window)

        ttk.Button(button_frame, text="Add", command=submit_add).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=add_window.destroy).pack(side=tk.LEFT, padx=5)

    def edit_dhcp_server(self):
        """Open window to edit selected DHCP server"""
        selected = self.servers_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a DHCP server to edit.",
                                   parent=self.dhcp_window_frame)
            return

        server_id = self.servers_tree.item(selected[0])["values"][0]

        # Get current server data
        try:
            url = f"https://{self.ip}/rest/ip/dhcp-server/{server_id}"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            server_data = response.json()
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Failed to retrieve server data: {e}", parent=self.dhcp_window_frame)
            return

        edit_window = tk.Toplevel(self.dhcp_window_frame)
        edit_window.title(f"Edit DHCP Server: {server_data.get('name', '')}")
        edit_window.geometry("450x400")
        edit_window.configure(bg="white")

        # Frame for form
        form_frame = ttk.Frame(edit_window, padding=10)
        form_frame.pack(fill="both", expand=True)

        # Get available interfaces and pools for dropdown
        interfaces = self.get_interfaces()
        address_pools = self.get_address_pools()

        # Parse lease time from string like "1d" to (1, "days")
        lease_value = ""
        lease_unit = "days"
        lease_time = server_data.get('lease-time', '1d')

        if lease_time:
            # Extract number and unit
            import re
            match = re.match(r'(\d+)([a-zA-Z]+)', lease_time)
            if match:
                lease_value = match.group(1)
                unit_map = {'s': 'seconds', 'm': 'minutes', 'h': 'hours', 'd': 'days', 'w': 'weeks'}
                unit_char = match.group(2)[0].lower()
                lease_unit = unit_map.get(unit_char, 'days')

        # Form fields
        ttk.Label(form_frame, text="Server Name:").grid(row=0, column=0, sticky="w", pady=5)
        name_entry = ttk.Entry(form_frame, width=30)
        name_entry.insert(0, server_data.get('name', ''))
        name_entry.grid(row=0, column=1, sticky="w", pady=5)

        ttk.Label(form_frame, text="Interface:").grid(row=1, column=0, sticky="w", pady=5)
        interface_combo = ttk.Combobox(form_frame, values=interfaces, width=28)
        interface_combo.set(server_data.get('interface', ''))
        interface_combo.grid(row=1, column=1, sticky="w", pady=5)

        ttk.Label(form_frame, text="Address Pool:").grid(row=2, column=0, sticky="w", pady=5)
        pool_combo = ttk.Combobox(form_frame, values=address_pools, width=28)
        pool_combo.set(server_data.get('address-pool', ''))
        pool_combo.grid(row=2, column=1, sticky="w", pady=5)

        ttk.Label(form_frame, text="Lease Time:").grid(row=3, column=0, sticky="w", pady=5)
        lease_frame = ttk.Frame(form_frame)
        lease_frame.grid(row=3, column=1, sticky="w", pady=5)
        lease_entry = ttk.Entry(lease_frame, width=8)
        lease_entry.pack(side=tk.LEFT)
        lease_entry.insert(0, lease_value)
        lease_unit_combo = ttk.Combobox(lease_frame, values=["seconds", "minutes", "hours", "days", "weeks"], width=10)
        lease_unit_combo.pack(side=tk.LEFT, padx=5)
        lease_unit_combo.set(lease_unit)

        ttk.Label(form_frame, text="Boot File:").grid(row=4, column=0, sticky="w", pady=5)
        boot_entry = ttk.Entry(form_frame, width=30)
        boot_entry.insert(0, server_data.get('boot-file-name', ''))
        boot_entry.grid(row=4, column=1, sticky="w", pady=5)

        ttk.Label(form_frame, text="DHCP Options:").grid(row=5, column=0, sticky="w", pady=5)
        options_entry = ttk.Entry(form_frame, width=30)
        options_entry.insert(0, server_data.get('dhcp-option', ''))
        options_entry.grid(row=5, column=1, sticky="w", pady=5)

        disabled_var = tk.BooleanVar(value=server_data.get('disabled', 'false') == 'true')
        ttk.Checkbutton(form_frame, text="Disabled", variable=disabled_var).grid(row=6, column=0, columnspan=2,
                                                                                 sticky="w", pady=5)

        # Advanced settings section
        ttk.Separator(form_frame).grid(row=7, column=0, columnspan=2, sticky="ew", pady=10)
        ttk.Label(form_frame, text="Advanced Settings", font=("", 10, "bold")).grid(row=8, column=0, columnspan=2,
                                                                                    sticky="w")

        authoritative_var = tk.BooleanVar(value=server_data.get('authoritative', 'yes') == 'yes')
        ttk.Checkbutton(form_frame, text="Authoritative", variable=authoritative_var).grid(row=9, column=0,
                                                                                           columnspan=2, sticky="w",
                                                                                           pady=2)

        ttk.Label(form_frame, text="Add ARP:").grid(row=10, column=0, sticky="w", pady=2)
        add_arp_var = tk.StringVar(value=server_data.get('add-arp', 'yes'))
        ttk.Radiobutton(form_frame, text="Yes", variable=add_arp_var, value="yes").grid(row=10, column=1, sticky="w",
                                                                                        pady=2)
        ttk.Radiobutton(form_frame, text="No", variable=add_arp_var, value="no").grid(row=11, column=1, sticky="w",
                                                                                      pady=2)

        # Buttons
        button_frame = ttk.Frame(form_frame)
        button_frame.grid(row=12, column=0, columnspan=2, pady=10)

        def submit_edit():
            # Get values from form
            name = name_entry.get().strip()
            interface = interface_combo.get().strip()
            pool = pool_combo.get().strip()
            lease_time = f"{lease_entry.get().strip()}{lease_unit_combo.get().strip()[0]}"  # e.g. "1d" for days
            boot_file = boot_entry.get().strip()
            options = options_entry.get().strip()
            disabled = "yes" if disabled_var.get() else "no"
            authoritative = "yes" if authoritative_var.get() else "no"
            add_arp = add_arp_var.get()

            # Validate required fields
            if not name or not interface or not pool:
                messagebox.showwarning("Missing Information", "Name, Interface and Address Pool are required.",
                                       parent=edit_window)
                return

            # Prepare data for API
            payload = {
                ".id": server_id,
                "name": name,
                "interface": interface,
                "address-pool": pool,
                "lease-time": lease_time,
                "disabled": disabled,
                "authoritative": authoritative,
                "add-arp": add_arp
            }

            if boot_file:
                payload["boot-file-name"] = boot_file
            if options:
                payload["dhcp-option"] = options

            # Send request to MikroTik
            try:
                url = f"https://{self.ip}/rest/ip/dhcp-server/set"
                auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
                headers = {'Authorization': f'Basic {auth}'}
                response = requests.post(url, headers=headers, json=payload, verify=False)
                response.raise_for_status()
                messagebox.showinfo("Success", "DHCP server updated successfully!", parent=edit_window)
                edit_window.destroy()
                self.load_dhcp_servers()
            except requests.exceptions.RequestException as e:
                messagebox.showerror("Error", f"Failed to update DHCP server: {e}", parent=edit_window)

        ttk.Button(button_frame, text="Update", command=submit_edit).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=edit_window.destroy).pack(side=tk.LEFT, padx=5)

    def delete_dhcp_server(self):
        """Delete selected DHCP server"""
        selected = self.servers_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a DHCP server to delete.",
                                   parent=self.dhcp_window_frame)
            return

        server_id = self.servers_tree.item(selected[0])["values"][0]
        server_name = self.servers_tree.item(selected[0])["values"][1]

        # Confirm deletion
        confirm = messagebox.askyesno(
            "Confirm Delete",
            f"Are you sure you want to delete DHCP server '{server_name}'?",
            parent=self.dhcp_window_frame
        )

        if not confirm:
            return

        # Delete the server
        try:
            url = f"https://{self.ip}/rest/ip/dhcp-server/remove"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}
            payload = {".id": server_id}

            response = requests.post(url, headers=headers, json=payload, verify=False)
            response.raise_for_status()

            messagebox.showinfo(
                "Success",
                f"DHCP server '{server_name}' deleted successfully!",
                parent=self.dhcp_window_frame
            )

            self.load_dhcp_servers()

        except requests.exceptions.RequestException as e:
            messagebox.showerror(
                "Error",
                f"Failed to delete DHCP server: {e}",
                parent=self.dhcp_window_frame
            )

    def add_dhcp_network(self):
        """Open window to add a new DHCP network with all available parameters"""
        add_window = tk.Toplevel(self.dhcp_window_frame)
        add_window.title("Add DHCP Network")
        add_window.geometry("500x600")

        # Main container with scrollbar
        container = ttk.Frame(add_window)
        canvas = tk.Canvas(container)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        container.pack(fill="both", expand=True)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Required fields
        ttk.Label(scrollable_frame, text="Network Address (e.g. 10.20.30.0/24):").grid(row=0, column=0, sticky="w",
                                                                                       pady=5)
        address_entry = ttk.Entry(scrollable_frame, width=30)
        address_entry.grid(row=0, column=1, sticky="w", pady=5)

        # Optional fields from the image
        fields = [
            ("Gateway:", "gateway"),
            ("Netmask:", "netmask"),
            ("DNS Servers:", "dns_servers"),
            ("Domain:", "domain"),
            ("WINS Servers:", "wins_servers"),
            ("NTP Servers:", "ntp_servers"),
            ("CAPS Managers:", "caps_managers"),
            ("Next Server:", "next_server"),
            ("Boot File Name:", "boot_file_name"),
            ("DHCP Options:", "dhcp_options"),
            ("DHCP Option Set:", "dhcp_option_set")
        ]

        entries = {}
        for row, (label_text, field_name) in enumerate(fields, start=1):
            ttk.Label(scrollable_frame, text=label_text).grid(row=row, column=0, sticky="w", pady=5)
            entry = ttk.Entry(scrollable_frame, width=30)
            entry.grid(row=row, column=1, sticky="w", pady=5)
            entries[field_name] = entry

        # Checkboxes for boolean options
        ttk.Label(scrollable_frame, text="Options:").grid(row=len(fields) + 1, column=0, sticky="w", pady=5)
        no_dns_var = tk.BooleanVar()
        ttk.Checkbutton(scrollable_frame, text="No DNS", variable=no_dns_var).grid(
            row=len(fields) + 1, column=1, sticky="w", pady=5)

        def submit_add():
            address = address_entry.get().strip()

            if not address:
                messagebox.showerror("Error", "Network Address is required", parent=add_window)
                return

            payload = {"address": address}

            # Add optional fields if they have values
            for field_name, entry in entries.items():
                value = entry.get().strip()
                if value:
                    # Convert field names to MikroTik's expected parameter names
                    param_name = {
                        "dns_servers": "dns-server",
                        "wins_servers": "wins-server",
                        "ntp_servers": "ntp-server",
                        "caps_managers": "caps-manager",
                        "next_server": "next-server",
                        "boot_file_name": "boot-file-name",
                        "dhcp_options": "dhcp-option",
                        "dhcp_option_set": "dhcp-option-set"
                    }.get(field_name, field_name)
                    payload[param_name] = value

            # Add boolean options
            if no_dns_var.get():
                payload["no-dns"] = "yes"

            try:
                url = f"https://{self.ip}/rest/ip/dhcp-server/network/add"
                auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
                headers = {'Authorization': f'Basic {auth}'}

                response = requests.post(
                    url,
                    headers=headers,
                    json=payload,
                    verify=False,
                    timeout=10
                )

                if response.status_code == 400:
                    error_data = response.json()
                    messagebox.showerror("API Error",
                                         f"{error_data.get('message', 'Bad Request')}\n"
                                         f"Detail: {error_data.get('detail', 'Unknown error')}",
                                         parent=add_window)
                    return

                response.raise_for_status()

                messagebox.showinfo("Success", "DHCP network added successfully!", parent=add_window)
                add_window.destroy()
                self.load_dhcp_networks()

            except requests.exceptions.RequestException as e:
                error_msg = str(e)
                if hasattr(e, 'response') and e.response:
                    try:
                        error_data = e.response.json()
                        error_msg = f"{error_data.get('message', error_msg)}\n{error_data.get('detail', '')}"
                    except:
                        pass
                messagebox.showerror("API Error", f"Failed to add network:\n{error_msg}", parent=add_window)

        # Buttons
        button_frame = ttk.Frame(scrollable_frame)
        button_frame.grid(row=len(fields) + 2, column=0, columnspan=2, pady=10)

        ttk.Button(button_frame, text="Add", command=submit_add).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=add_window.destroy).pack(side=tk.LEFT, padx=5)

        address_entry.focus_set()

    def edit_dhcp_network(self):
        """Open window to edit selected DHCP network"""
        selected = self.networks_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a DHCP network to edit.",
                                   parent=self.dhcp_window_frame)
            return

        network_id = self.networks_tree.item(selected[0])["values"][0]

        # Get current network data
        try:
            url = f"https://{self.ip}/rest/ip/dhcp-server/network/{network_id}"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            network_data = response.json()
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Failed to retrieve network data: {e}", parent=self.dhcp_window_frame)
            return

        edit_window = tk.Toplevel(self.dhcp_window_frame)
        edit_window.title(f"Edit DHCP Network: {network_data.get('address', '')}")
        edit_window.geometry("450x300")
        edit_window.configure(bg="white")

        # Frame for form
        form_frame = ttk.Frame(edit_window, padding=10)
        form_frame.pack(fill="both", expand=True)

        # Get available DHCP servers for dropdown
        dhcp_servers = self.get_dhcp_server_names()

        # Form fields
        ttk.Label(form_frame, text="Network Address:").grid(row=0, column=0, sticky="w", pady=5)
        address_entry = ttk.Entry(form_frame, width=30)
        address_entry.insert(0, network_data.get('address', ''))
        address_entry.grid(row=0, column=1, sticky="w", pady=5)

        ttk.Label(form_frame, text="Gateway:").grid(row=1, column=0, sticky="w", pady=5)
        gateway_entry = ttk.Entry(form_frame, width=30)
        gateway_entry.insert(0, network_data.get('gateway', ''))
        gateway_entry.grid(row=1, column=1, sticky="w", pady=5)

        ttk.Label(form_frame, text="DNS Servers:").grid(row=2, column=0, sticky="w", pady=5)
        dns_entry = ttk.Entry(form_frame, width=30)
        dns_entry.insert(0, network_data.get('dns-server', ''))
        dns_entry.grid(row=2, column=1, sticky="w", pady=5)

        ttk.Label(form_frame, text="Domain:").grid(row=3, column=0, sticky="w", pady=5)
        domain_entry = ttk.Entry(form_frame, width=30)
        domain_entry.insert(0, network_data.get('domain', ''))
        domain_entry.grid(row=3, column=1, sticky="w", pady=5)

        ttk.Label(form_frame, text="DHCP Server:").grid(row=4, column=0, sticky="w", pady=5)
        server_combo = ttk.Combobox(form_frame, values=dhcp_servers, width=28)
        server_combo.set(network_data.get('dhcp-server', ''))
        server_combo.grid(row=4, column=1, sticky="w", pady=5)

        disabled_var = tk.BooleanVar(value=network_data.get('disabled', 'false') == 'true')
        ttk.Checkbutton(form_frame, text="Disabled", variable=disabled_var).grid(row=5, column=0, columnspan=2,
                                                                                 sticky="w", pady=5)

        # Buttons
        button_frame = ttk.Frame(form_frame)
        button_frame.grid(row=6, column=0, columnspan=2, pady=10)

        def submit_edit():
            # Get values from form
            address = address_entry.get().strip()
            gateway = gateway_entry.get().strip()
            dns = dns_entry.get().strip()
            domain = domain_entry.get().strip()
            server = server_combo.get().strip()
            disabled = "yes" if disabled_var.get() else "no"

            # Validate required fields
            if not address or not server:
                messagebox.showwarning("Missing Information", "Network Address and DHCP Server are required.",
                                       parent=edit_window)
                return

            # Prepare data for API
            payload = {
                ".id": network_id,
                "address": address,
                "dhcp-server": server,
                "disabled": disabled
            }

            if gateway:
                payload["gateway"] = gateway
            if dns:
                payload["dns-server"] = dns
            if domain:
                payload["domain"] = domain

            # Send request to MikroTik
            try:
                url = f"https://{self.ip}/rest/ip/dhcp-server/network/set"
                auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
                headers = {'Authorization': f'Basic {auth}'}
                response = requests.post(url, headers=headers, json=payload, verify=False)
                response.raise_for_status()
                messagebox.showinfo("Success", "DHCP network updated successfully!", parent=edit_window)
                edit_window.destroy()
                self.load_dhcp_networks()
            except requests.exceptions.RequestException as e:
                messagebox.showerror("Error", f"Failed to update DHCP network: {e}", parent=edit_window)

        ttk.Button(button_frame, text="Update", command=submit_edit).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=edit_window.destroy).pack(side=tk.LEFT, padx=5)

    def delete_dhcp_network(self):
        """Delete selected DHCP network"""
        selected = self.networks_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a DHCP network to delete.",
                                   parent=self.dhcp_window_frame)
            return

        network_id = self.networks_tree.item(selected[0])["values"][0]
        network_address = self.networks_tree.item(selected[0])["values"][1]

        # Confirm deletion
        confirm = messagebox.askyesno(
            "Confirm Delete",
            f"Are you sure you want to delete network '{network_address}'?",
            parent=self.dhcp_window_frame
        )

        if not confirm:
            return

        # Delete the network
        try:
            url = f"https://{self.ip}/rest/ip/dhcp-server/network/remove"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}
            payload = {".id": network_id}

            response = requests.post(url, headers=headers, json=payload, verify=False)
            response.raise_for_status()

            messagebox.showinfo(
                "Success",
                f"DHCP network '{network_address}' deleted successfully!",
                parent=self.dhcp_window_frame
            )

            self.load_dhcp_networks()

        except requests.exceptions.RequestException as e:
            messagebox.showerror(
                "Error",
                f"Failed to delete DHCP network: {e}",
                parent=self.dhcp_window_frame
            )



    def release_dhcp_lease(self):
        """Release selected DHCP lease"""
        selected = self.leases_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a DHCP lease to release.",
                                   parent=self.dhcp_window_frame)
            return

        lease_id = self.leases_tree.item(selected[0])["values"][0]
        lease_ip = self.leases_tree.item(selected[0])["values"][1]

        # Confirm action
        confirm = messagebox.askyesno(
            "Confirm Release Lease",
            f"Are you sure you want to release lease {lease_ip}?",
            parent=self.dhcp_window_frame
        )

        if not confirm:
            return

        # Release the lease
        try:
            url = f"https://{self.ip}/rest/ip/dhcp-server/lease/remove"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}
            payload = {".id": lease_id}

            response = requests.post(url, headers=headers, json=payload, verify=False)
            response.raise_for_status()

            messagebox.showinfo(
                "Success",
                f"DHCP lease {lease_ip} released successfully!",
                parent=self.dhcp_window_frame
            )

            self.load_dhcp_leases()

        except requests.exceptions.RequestException as e:
            messagebox.showerror(
                "Error",
                f"Failed to release lease: {e}",
                parent=self.dhcp_window_frame
            )