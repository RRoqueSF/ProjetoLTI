
import requests
import tkinter as tk
from tkinter import ttk, messagebox



class DNSWindow:
    def __init__(self, ip, user, password, parent_frame):
        self.ip = ip
        self.user = user
        self.password = password

        self.dns_window_frame = tk.Frame(parent_frame, bg="white")
        self.dns_window_frame.pack(fill=tk.BOTH, expand=True)

        # Create notebook for tabbed interface
        self.notebook = ttk.Notebook(self.dns_window_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create tabs
        self.dns_settings_frame = ttk.Frame(self.notebook)
        self.static_dns_frame = ttk.Frame(self.notebook)
        self.dns_cache_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.dns_settings_frame, text="DNS Settings")
        self.notebook.add(self.static_dns_frame, text="Static DNS")
        self.notebook.add(self.dns_cache_frame, text="DNS Cache")

        # Setup each tab
        self.setup_dns_settings_tab()
        self.setup_static_dns_tab()
        self.setup_dns_cache_tab()

    def setup_dns_settings_tab(self):
        # Frame for current settings display
        settings_display_frame = ttk.LabelFrame(self.dns_settings_frame, text="Current DNS Configuration")
        settings_display_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Settings display
        self.settings_text = tk.Text(settings_display_frame, height=8, width=50)
        self.settings_text.pack(padx=10, pady=10)
        self.settings_text.config(state=tk.DISABLED)

        # Frame for editing DNS settings
        edit_frame = ttk.LabelFrame(self.dns_settings_frame, text="Configure DNS Servers")
        edit_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Primary DNS
        ttk.Label(edit_frame, text="Primary DNS Server:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.primary_dns_entry = ttk.Entry(edit_frame, width=20)
        self.primary_dns_entry.grid(row=0, column=1, padx=5, pady=5)

        # Secondary DNS
        ttk.Label(edit_frame, text="Secondary DNS Server:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.secondary_dns_entry = ttk.Entry(edit_frame, width=20)
        self.secondary_dns_entry.grid(row=1, column=1, padx=5, pady=5)

        # Allow remote requests
        self.allow_remote_var = tk.BooleanVar()
        ttk.Checkbutton(edit_frame, text="Allow Remote Requests", variable=self.allow_remote_var).grid(row=2, column=0,
                                                                                                       columnspan=2,
                                                                                                       padx=5, pady=5,
                                                                                                       sticky="w")

        # Max UDP packet size
        ttk.Label(edit_frame, text="Max UDP Packet Size:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.max_udp_entry = ttk.Entry(edit_frame, width=10)
        self.max_udp_entry.grid(row=3, column=1, padx=5, pady=5, sticky="w")
        self.max_udp_entry.insert(0, "4096")

        # Cache size
        ttk.Label(edit_frame, text="Cache Size (KB):").grid(row=4, column=0, padx=5, pady=5, sticky="w")
        self.cache_size_entry = ttk.Entry(edit_frame, width=10)
        self.cache_size_entry.grid(row=4, column=1, padx=5, pady=5, sticky="w")
        self.cache_size_entry.insert(0, "2048")

        # Buttons frame
        button_frame = ttk.Frame(edit_frame)
        button_frame.grid(row=5, column=0, columnspan=2, padx=5, pady=10)

        # Buttons
        ttk.Button(button_frame, text="Load Current Settings", command=self.load_dns_settings).pack(side=tk.LEFT,
                                                                                                    padx=5)
        ttk.Button(button_frame, text="Apply Settings", command=self.apply_dns_settings).pack(side=tk.LEFT, padx=5)

        # Load settings on initialization
        self.load_dns_settings()

    def setup_static_dns_tab(self):
        # Frame for static DNS entries list
        list_frame = ttk.Frame(self.static_dns_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create treeview for static DNS entries
        self.static_dns_tree = ttk.Treeview(list_frame, columns=("Name", "IP Address", "TTL", "Comment"),
                                            show="headings")
        self.static_dns_tree.heading("Name", text="Name")
        self.static_dns_tree.heading("IP Address", text="IP Address")
        self.static_dns_tree.heading("TTL", text="TTL")
        self.static_dns_tree.heading("Comment", text="Comment")

        self.static_dns_tree.column("Name", width=150)
        self.static_dns_tree.column("IP Address", width=150)
        self.static_dns_tree.column("TTL", width=100)
        self.static_dns_tree.column("Comment", width=150)

        self.static_dns_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.static_dns_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.static_dns_tree.configure(yscrollcommand=scrollbar.set)

        # Button frame
        button_frame = ttk.Frame(self.static_dns_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(button_frame, text="Add Static Entry", command=self.add_static_dns_entry).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Edit Selected", command=self.edit_static_dns_entry).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete Selected", command=self.delete_static_dns_entry).pack(side=tk.LEFT,
                                                                                                    padx=5)
        ttk.Button(button_frame, text="Refresh List", command=self.load_static_dns_entries).pack(side=tk.LEFT, padx=5)

        # Load entries on initialization
        self.load_static_dns_entries()

    def setup_dns_cache_tab(self):
        # Frame for cache controls
        control_frame = ttk.Frame(self.dns_cache_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(control_frame, text="Flush DNS Cache", command=self.flush_dns_cache).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="View Current Cache", command=self.view_dns_cache).pack(side=tk.LEFT, padx=5)

        # Frame for cache statistics
        stats_frame = ttk.LabelFrame(self.dns_cache_frame, text="Cache Statistics")
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)


        ttk.Label(stats_frame, text="Cache Entries:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.entries_label = ttk.Label(stats_frame, text="0")
        self.entries_label.grid(row=1, column=1, sticky="w", padx=5, pady=2)


        # Cache entries display
        cache_list_frame = ttk.LabelFrame(self.dns_cache_frame, text="Cache Entries")
        cache_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create treeview for cache entries
        self.cache_tree = ttk.Treeview(cache_list_frame, columns=("Name", "Type", "TTL"), show="headings")
        self.cache_tree.heading("Name", text="Name")
        self.cache_tree.heading("Type", text="Type")
        self.cache_tree.heading("TTL", text="TTL")

        self.cache_tree.column("Name", width=250)
        self.cache_tree.column("Type", width=100)
        self.cache_tree.column("TTL", width=100)

        self.cache_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Add scrollbar
        cache_scrollbar = ttk.Scrollbar(cache_list_frame, orient=tk.VERTICAL, command=self.cache_tree.yview)
        cache_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.cache_tree.configure(yscrollcommand=cache_scrollbar.set)

        # Load cache stats on initialization
        self.load_cache_stats()

    def load_dns_settings(self):
        import base64
        try:
            url = f"https://{self.ip}/rest/ip/dns"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()

            dns_settings = response.json()
            if isinstance(dns_settings, list) and len(dns_settings) > 0:
                dns_settings = dns_settings[0]  # Take first item if it's a list

            # Update text display
            self.settings_text.config(state=tk.NORMAL)
            self.settings_text.delete(1.0, tk.END)

            # Format the settings display
            settings_display = f"Servers: {dns_settings.get('servers', 'None')}\n"
            settings_display += f"Allow Remote Requests: {dns_settings.get('allow-remote-requests', 'no')}\n"
            settings_display += f"Max UDP Packet Size: {dns_settings.get('max-udp-packet-size', '4096')}\n"
            settings_display += f"Cache Size: {dns_settings.get('cache-size', '2048')} KB\n"
            settings_display += f"Cache Max TTL: {dns_settings.get('cache-max-ttl', '1w')}\n"

            self.settings_text.insert(tk.END, settings_display)
            self.settings_text.config(state=tk.DISABLED)

            # Fill in the form fields
            servers = dns_settings.get('servers', '').split(',')
            self.primary_dns_entry.delete(0, tk.END)
            self.secondary_dns_entry.delete(0, tk.END)

            if len(servers) > 0 and servers[0]:
                self.primary_dns_entry.insert(0, servers[0].strip())
            if len(servers) > 1:
                self.secondary_dns_entry.insert(0, servers[1].strip())

            self.allow_remote_var.set(dns_settings.get('allow-remote-requests', 'no') == 'yes')

            self.max_udp_entry.delete(0, tk.END)
            self.max_udp_entry.insert(0, dns_settings.get('max-udp-packet-size', '4096'))

            self.cache_size_entry.delete(0, tk.END)
            self.cache_size_entry.insert(0, dns_settings.get('cache-size', '2048'))

        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Failed to load DNS settings: {e}", parent=self.dns_window_frame)

    def apply_dns_settings(self):
        import base64
        primary = self.primary_dns_entry.get().strip()
        secondary = self.secondary_dns_entry.get().strip()

        servers = primary
        if secondary:
            servers += f",{secondary}"

        allow_remote = "yes" if self.allow_remote_var.get() else "no"
        max_udp = self.max_udp_entry.get().strip()
        cache_size = self.cache_size_entry.get().strip()

        try:
            url = f"https://{self.ip}/rest/ip/dns/set"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}

            data = {
                "servers": servers,
                "allow-remote-requests": allow_remote,
                "max-udp-packet-size": max_udp,
                "cache-size": cache_size
            }

            response = requests.post(url, headers=headers, json=data, verify=False)
            response.raise_for_status()

            messagebox.showinfo("Success", "DNS settings updated successfully", parent=self.dns_window_frame)
            self.load_dns_settings()  # Refresh the display

        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Failed to update DNS settings: {e}", parent=self.dns_window_frame)

    def load_static_dns_entries(self):
        import base64
        try:
            url = f"https://{self.ip}/rest/ip/dns/static"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()

            static_entries = response.json()

            # Clear existing entries
            for item in self.static_dns_tree.get_children():
                self.static_dns_tree.delete(item)

            # Add entries to tree
            for entry in static_entries:
                self.static_dns_tree.insert("", "end", values=(
                    entry.get('name', ''),
                    entry.get('address', ''),
                    entry.get('ttl', 'default'),
                    entry.get('comment', '')
                ), tags=(entry.get('.id', '')))

        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Failed to load static DNS entries: {e}", parent=self.dns_window_frame)

    def add_static_dns_entry(self):
        add_window = tk.Toplevel(self.dns_window_frame)
        add_window.title("Add Static DNS Entry")
        add_window.geometry("400x250")
        add_window.transient(self.dns_window_frame)
        add_window.grab_set()

        ttk.Label(add_window, text="DNS Name:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        name_entry = ttk.Entry(add_window, width=30)
        name_entry.grid(row=0, column=1, padx=10, pady=5)

        ttk.Label(add_window, text="IP Address:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        ip_entry = ttk.Entry(add_window, width=30)
        ip_entry.grid(row=1, column=1, padx=10, pady=5)

        ttk.Label(add_window, text="TTL (seconds):").grid(row=2, column=0, padx=10, pady=5, sticky="w")
        ttl_entry = ttk.Entry(add_window, width=30)
        ttl_entry.grid(row=2, column=1, padx=10, pady=5)
        ttl_entry.insert(0, "86400")  # Default 1 day

        ttk.Label(add_window, text="Comment:").grid(row=3, column=0, padx=10, pady=5, sticky="w")
        comment_entry = ttk.Entry(add_window, width=30)
        comment_entry.grid(row=3, column=1, padx=10, pady=5)

        def submit_new_entry():
            import base64

            name = name_entry.get().strip()
            ip = ip_entry.get().strip()
            ttl = ttl_entry.get().strip()
            comment = comment_entry.get().strip()

            if not name or not ip:
                messagebox.showwarning("Missing Information", "Both DNS Name and IP Address are required",
                                       parent=add_window)
                return

            try:
                url = f"https://{self.ip}/rest/ip/dns/static/add"
                auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
                headers = {'Authorization': f'Basic {auth}'}

                data = {
                    "name": name,
                    "address": ip
                }

                if ttl:
                    data["ttl"] = ttl
                if comment:
                    data["comment"] = comment

                response = requests.post(url, headers=headers, json=data, verify=False)
                response.raise_for_status()

                messagebox.showinfo("Success", "Static DNS entry added successfully", parent=add_window)
                add_window.destroy()
                self.load_static_dns_entries()  # Refresh list

            except requests.exceptions.RequestException as e:
                messagebox.showerror("Error", f"Failed to add static DNS entry: {e}", parent=add_window)

        button_frame = ttk.Frame(add_window)
        button_frame.grid(row=4, column=0, columnspan=2, pady=15)

        ttk.Button(button_frame, text="Add Entry", command=submit_new_entry).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Cancel", command=add_window.destroy).pack(side=tk.LEFT, padx=10)

    def edit_static_dns_entry(self):
        selected = self.static_dns_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select an entry to edit", parent=self.dns_window_frame)
            return

        # Get the selected item values
        values = self.static_dns_tree.item(selected[0], 'values')
        entry_id = self.static_dns_tree.item(selected[0], 'tags')[0]

        edit_window = tk.Toplevel(self.dns_window_frame)
        edit_window.title("Edit Static DNS Entry")
        edit_window.geometry("400x250")
        edit_window.transient(self.dns_window_frame)
        edit_window.grab_set()

        ttk.Label(edit_window, text="DNS Name:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        name_entry = ttk.Entry(edit_window, width=30)
        name_entry.grid(row=0, column=1, padx=10, pady=5)
        name_entry.insert(0, values[0])

        ttk.Label(edit_window, text="IP Address:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        ip_entry = ttk.Entry(edit_window, width=30)
        ip_entry.grid(row=1, column=1, padx=10, pady=5)
        ip_entry.insert(0, values[1])

        ttk.Label(edit_window, text="TTL (seconds):").grid(row=2, column=0, padx=10, pady=5, sticky="w")
        ttl_entry = ttk.Entry(edit_window, width=30)
        ttl_entry.grid(row=2, column=1, padx=10, pady=5)
        ttl_entry.insert(0, values[2] if values[2] != "default" else "86400")

        ttk.Label(edit_window, text="Comment:").grid(row=3, column=0, padx=10, pady=5, sticky="w")
        comment_entry = ttk.Entry(edit_window, width=30)
        comment_entry.grid(row=3, column=1, padx=10, pady=5)
        comment_entry.insert(0, values[3])

        def submit_edit():
            import base64

            name = name_entry.get().strip()
            ip = ip_entry.get().strip()
            ttl = ttl_entry.get().strip()
            comment = comment_entry.get().strip()

            if not name or not ip:
                messagebox.showwarning("Missing Information", "Both DNS Name and IP Address are required",
                                       parent=edit_window)
                return

            try:
                url = f"https://{self.ip}/rest/ip/dns/static/set"
                auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
                headers = {'Authorization': f'Basic {auth}'}

                data = {
                    ".id": entry_id,
                    "name": name,
                    "address": ip
                }

                if ttl:
                    data["ttl"] = ttl
                if comment:
                    data["comment"] = comment

                response = requests.post(url, headers=headers, json=data, verify=False)
                response.raise_for_status()

                messagebox.showinfo("Success", "Static DNS entry updated successfully", parent=edit_window)
                edit_window.destroy()
                self.load_static_dns_entries()  # Refresh list

            except requests.exceptions.RequestException as e:
                messagebox.showerror("Error", f"Failed to update static DNS entry: {e}", parent=edit_window)

        button_frame = ttk.Frame(edit_window)
        button_frame.grid(row=4, column=0, columnspan=2, pady=15)

        ttk.Button(button_frame, text="Update Entry", command=submit_edit).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Cancel", command=edit_window.destroy).pack(side=tk.LEFT, padx=10)

    def delete_static_dns_entry(self):
        selected = self.static_dns_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select an entry to delete", parent=self.dns_window_frame)
            return

        # Get the selected item values for confirmation
        values = self.static_dns_tree.item(selected[0], 'values')
        entry_id = self.static_dns_tree.item(selected[0], 'tags')[0]

        # Ask for confirmation
        confirm = messagebox.askyesno(
            "Confirm Deletion",
            f"Are you sure you want to delete the static DNS entry for '{values[0]}'?",
            parent=self.dns_window_frame
        )

        if confirm:
            import base64
            try:
                url = f"https://{self.ip}/rest/ip/dns/static/remove"
                auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
                headers = {'Authorization': f'Basic {auth}'}

                data = {
                    ".id": entry_id
                }

                response = requests.post(url, headers=headers, json=data, verify=False)
                response.raise_for_status()

                messagebox.showinfo("Success", "Static DNS entry deleted successfully", parent=self.dns_window_frame)
                self.load_static_dns_entries()  # Refresh list

            except requests.exceptions.RequestException as e:
                messagebox.showerror("Error", f"Failed to delete static DNS entry: {e}", parent=self.dns_window_frame)

    def flush_dns_cache(self):
        import base64
        confirm = messagebox.askyesno(
            "Confirm Flush",
            "Are you sure you want to flush the DNS cache?",
            parent=self.dns_window_frame
        )

        if confirm:
            try:
                url = f"https://{self.ip}/rest/ip/dns/cache/flush"
                auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
                headers = {'Authorization': f'Basic {auth}'}

                response = requests.post(url, headers=headers, verify=False)
                response.raise_for_status()

                messagebox.showinfo("Success", "DNS cache flushed successfully", parent=self.dns_window_frame)
                self.load_cache_stats()  # Refresh stats
                self.view_dns_cache()  # Refresh cache view

            except requests.exceptions.RequestException as e:
                messagebox.showerror("Error", f"Failed to flush DNS cache: {e}", parent=self.dns_window_frame)

    def load_cache_stats(self):
        import base64
        try:
            url = f"https://{self.ip}/rest/ip/dns/cache"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()

            # Process response to extract statistics
            cache_data = response.json()
            print(cache_data)

            # Pegamos o primeiro item da lista
            data = cache_data[0] if cache_data else {}

            # Atualizamos os labels com os dados do dicionário
            self.entries_label.config(text=str(len(cache_data)))


        except requests.exceptions.RequestException as e:
            self.entries_label.config(text="Error")

    def view_dns_cache(self):
        import base64
        try:
            url = f"https://{self.ip}/rest/ip/dns/cache/all"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()

            cache_entries = response.json()

            # Clear existing entries
            for item in self.cache_tree.get_children():
                self.cache_tree.delete(item)

            # Add entries to tree
            for entry in cache_entries:
                self.cache_tree.insert("", "end", values=(
                    entry.get('name', ''),
                    entry.get('type', ''),
                    entry.get('ttl', '')
                ))

        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Failed to retrieve DNS cache entries: {e}", parent=self.dns_window_frame)