import base64
import re
import json
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
        self.static_dns_tree = ttk.Treeview(list_frame, columns=("Name", "Type", "Value", "TTL", "Comment"),
                                          show="headings")
        self.static_dns_tree.heading("Name", text="Name")
        self.static_dns_tree.heading("Type", text="Type")
        self.static_dns_tree.heading("Value", text="Value")
        self.static_dns_tree.heading("TTL", text="TTL")
        self.static_dns_tree.heading("Comment", text="Comment")

        self.static_dns_tree.column("Name", width=150)
        self.static_dns_tree.column("Type", width=60)
        self.static_dns_tree.column("Value", width=150)
        self.static_dns_tree.column("TTL", width=60)
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
                record_type = entry.get('type', 'A')
                value = ""

                # Determine the value based on record type
                if record_type == 'A' or record_type == 'AAAA':
                    value = entry.get('address', '')
                elif record_type == 'CNAME':
                    value = entry.get('cname', '')
                elif record_type == 'MX':
                    value = f"{entry.get('mx-preference', '10')} {entry.get('mx-exchange', '')}"
                elif record_type == 'TXT':
                    value = entry.get('text', '')
                elif record_type == 'NS':
                    value = entry.get('ns', '')
                elif record_type == 'SRV':
                    value = entry.get('srv-service', '')
                elif record_type == 'PTR':
                    value = entry.get('ptr', '')

                self.static_dns_tree.insert("", "end", values=(
                    entry.get('name', ''),
                    record_type,
                    value,
                    entry.get('ttl', 'default'),
                    entry.get('comment', '')
                ), tags=(entry.get('.id', '')))

        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Failed to load static DNS entries: {e}", parent=self.dns_window_frame)

    def validate_dns_record(self, record_type, address):
        """
        Validates that the address/value format matches the expected format for the record type.
        Returns (is_valid, error_message)
        """
        if record_type == "A":
            # Simple regex for IPv4 format
            ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
            if not ipv4_pattern.match(address):
                return False, "A records require a valid IPv4 address (e.g., 192.168.1.1)"

        elif record_type == "AAAA":
            # Very basic IPv6 check - not comprehensive
            if ':' not in address:
                return False, "AAAA records require a valid IPv6 address"

        elif record_type == "MX":
            # MX should have priority and hostname
            parts = address.split()
            if len(parts) < 2:
                return False, "MX records should include priority and hostname (e.g., '10 mail.example.com')"

            if not parts[0].isdigit():
                return False, "MX record priority should be a number"
                
            # Validate hostname portion
            hostname = " ".join(parts[1:])
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,61}[a-zA-Z0-9])?)*\.?$', hostname):
                return False, "MX record hostname is not valid (e.g., mail.example.com)"

        elif record_type == "PTR":
            # PTR record should be a valid hostname
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,61}[a-zA-Z0-9])?)*\.?$', address):
                return False, "PTR records require a valid hostname (e.g., host.example.com)"
        
        # For other record types, we'll accept anything for now
        # Could add more validation as needed

        return True, ""  # Valid with no error message

    def format_dns_record_data(self, name, record_type, address, ttl=None, comment=None, entry_id=None):
        """
        Format DNS record data based on the record type.
        Returns a dictionary with the appropriate fields for the MikroTik API.
        """
        data = {}

        # Add ID if provided (for updates)
        if entry_id:
            data[".id"] = entry_id

        # Common fields
        data["name"] = name
        data["type"] = record_type  # Always set the type field

        # Set type-specific fields
        if record_type == "A":
            # A record - IPv4 address
            data["address"] = address

        elif record_type == "AAAA":
            # AAAA record - IPv6 address
            data["address"] = address

        elif record_type == "CNAME":
            # CNAME record - hostname
            # Add trailing dot if not present for FQDN
            if not address.endswith('.') and '.' in address:
                address = f"{address}."
            data["cname"] = address

        elif record_type == "MX":
            # MX record - mail server hostname and priority
            parts = address.split()

            # Extract priority and hostname
            priority = "10"  # Default priority
            mx_host = address
            
            if len(parts) >= 2 and parts[0].isdigit():
                priority = parts[0]
                mx_host = " ".join(parts[1:])
            
            # Clean up hostname - MikroTik requires no trailing dot
            mx_host = mx_host.strip()
            if mx_host.endswith('.'):
                mx_host = mx_host[:-1]
            
            # Set the correct fields for MikroTik MX records
            data["name"] = name  # Keep original name
            data["type"] = "MX"
            data["mx-preference"] = priority
            data["mx-exchange"] = mx_host

        elif record_type == "TXT":
            # TXT record - text data
            data["text"] = address

        elif record_type == "NS":
            # NS record - nameserver hostname
            if not address.endswith('.') and '.' in address:
                address = f"{address}."
            data["ns"] = address

        elif record_type == "SRV":
            # SRV record
            data["srv-service"] = address

        elif record_type == "PTR":
            # PTR record - hostname for reverse DNS
            # MikroTik requires no trailing dot
            address = address.strip()
            if address.endswith('.'):
                address = address[:-1]
                
            data["name"] = name  # The IP in reverse notation
            data["type"] = "PTR"
            data["ptr-name"] = address  # Target hostname - this is the correct field name for MikroTik

        # Add optional fields if provided
        if ttl and ttl != 'default':
            data["ttl"] = ttl
        if comment:
            data["comment"] = comment

        return data

    def add_static_dns_entry(self):
        add_window = tk.Toplevel(self.dns_window_frame)
        add_window.title("Add Static DNS Entry")
        add_window.geometry("500x400")  # Increased size for additional fields
        add_window.transient(self.dns_window_frame)
        add_window.grab_set()

        ttk.Label(add_window, text="DNS Name:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        name_entry = ttk.Entry(add_window, width=30)
        name_entry.grid(row=0, column=1, padx=10, pady=5)

        # DNS Record Type dropdown
        ttk.Label(add_window, text="Record Type:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        record_type_var = tk.StringVar(value="A")
        record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "PTR"]
        record_type_dropdown = ttk.Combobox(add_window, textvariable=record_type_var, values=record_types, width=28,
                                          state="readonly")
        record_type_dropdown.grid(row=1, column=1, padx=10, pady=5)

        # Dynamic label for address field that changes based on record type
        address_label = ttk.Label(add_window, text="IP Address:")
        address_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")
        address_entry = ttk.Entry(add_window, width=30)
        address_entry.grid(row=2, column=1, padx=10, pady=5)

        ttk.Label(add_window, text="TTL (seconds):").grid(row=3, column=0, padx=10, pady=5, sticky="w")
        ttl_entry = ttk.Entry(add_window, width=30)
        ttl_entry.grid(row=3, column=1, padx=10, pady=5)
        ttl_entry.insert(0, "86400")  # Default 1 day

        ttk.Label(add_window, text="Comment:").grid(row=4, column=0, padx=10, pady=5, sticky="w")
        comment_entry = ttk.Entry(add_window, width=30)
        comment_entry.grid(row=4, column=1, padx=10, pady=5)

        # Help text area
        help_frame = ttk.LabelFrame(add_window, text="Format Help")
        help_frame.grid(row=5, column=0, columnspan=2, padx=10, pady=5, sticky="ew")

        help_text = tk.Text(help_frame, height=5, width=50, wrap=tk.WORD)
        help_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        help_text.insert(tk.END, "A: IPv4 address (e.g., 192.168.1.1)\n"
                               "AAAA: IPv6 address\n"
                               "CNAME: Domain name (e.g., example.com)\n"
                               "MX: Priority and hostname (e.g., 10 mail.example.com)")
        help_text.config(state=tk.DISABLED)

        # Update help and field label based on selected record type
        def update_help_text(*args):
            record_type = record_type_var.get()

            if record_type == "A":
                address_label.config(text="IP Address:")
                help_text.config(state=tk.NORMAL)
                help_text.delete(1.0, tk.END)
                help_text.insert(tk.END, "Enter a valid IPv4 address (e.g., 192.168.1.1)")

            elif record_type == "AAAA":
                address_label.config(text="IPv6 Address:")
                help_text.config(state=tk.NORMAL)
                help_text.delete(1.0, tk.END)
                help_text.insert(tk.END, "Enter a valid IPv6 address (e.g., 2001:db8::1)")

            elif record_type == "CNAME":
                address_label.config(text="Canonical Name:")
                help_text.config(state=tk.NORMAL)
                help_text.delete(1.0, tk.END)
                help_text.insert(tk.END, "Enter the target domain name (e.g., example.com)")

            elif record_type == "MX":
                address_label.config(text="Mail Server:")
                help_text.config(state=tk.NORMAL)
                help_text.delete(1.0, tk.END)
                help_text.insert(tk.END, "Enter priority and mail server (e.g., 10 mail.example.com)")

            elif record_type == "TXT":
                address_label.config(text="Text Value:")
                help_text.config(state=tk.NORMAL)
                help_text.delete(1.0, tk.END)
                help_text.insert(tk.END, "Enter text value (e.g., v=spf1 include:_spf.google.com ~all)")

            elif record_type == "NS":
                address_label.config(text="Nameserver:")
                help_text.config(state=tk.NORMAL)
                help_text.delete(1.0, tk.END)
                help_text.insert(tk.END, "Enter nameserver domain (e.g., ns1.example.com)")

            elif record_type == "SRV":
                address_label.config(text="Service:")
                help_text.config(state=tk.NORMAL)
                help_text.delete(1.0, tk.END)
                help_text.insert(tk.END, "Enter priority weight port target (e.g., 10 5 5060 sip.example.com)")

            elif record_type == "PTR":
                address_label.config(text="Domain Name:")
                help_text.config(state=tk.NORMAL)
                help_text.delete(1.0, tk.END)
                help_text.insert(tk.END, "Enter pointer domain name (e.g., hostname.example.com)")

            help_text.config(state=tk.DISABLED)

        # Bind the function to the dropdown
        record_type_var.trace_add("write", update_help_text)

        # Call once to set initial help text
        update_help_text()

        def submit_new_entry():
            name = name_entry.get().strip()
            record_type = record_type_var.get()
            address_value = address_entry.get().strip()
            ttl = ttl_entry.get().strip()
            comment = comment_entry.get().strip()

            if not name or not address_value:
                messagebox.showwarning("Missing Information",
                                     f"Both DNS Name and {address_label['text'].replace(':', '')} are required",
                                     parent=add_window)
                return

            # Validate the record format
            is_valid, error_message = self.validate_dns_record(record_type, address_value)
            if not is_valid:
                messagebox.showwarning("Invalid Format",
                                     f"The {address_label['text'].replace(':', '')} has an invalid format:\n{error_message}",
                                     parent=add_window)
                # Let the user decide if they want to correct it
                proceed = messagebox.askyesno("Proceed Anyway?",
                                            "Do you want to proceed with the current value anyway?",
                                            parent=add_window)
                if not proceed:
                    return

            try:
                url = f"https://{self.ip}/rest/ip/dns/static/add"
                auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
                headers = {'Authorization': f'Basic {auth}'}

                # Format data according to record type
                data = self.format_dns_record_data(name, record_type, address_value, ttl, comment)

                # Add more detail to the log before sending
                print(f"Sending DNS {record_type} record request to {url}")
                print(f"Request Headers: {headers}")
                print(f"Request JSON Data: {json.dumps(data, indent=2)}")

                response = requests.post(url, headers=headers, json=data, verify=False)

                # Print full response for debugging
                print(f"API Response Status: {response.status_code}")
                print(f"API Response Headers: {response.headers}")
                print(f"API Response Body: {response.text}")

                # Check for any error in the response
                if response.status_code >= 400:
                    error_msg = f"Status Code: {response.status_code}\nResponse: {response.text}"
                    print(f"API Error: {error_msg}")  # Debug info

                    # Add more user-friendly error explanation
                    friendly_error = "An error occurred while adding the DNS record."
                    if "already have" in response.text.lower():
                        friendly_error += "\nA record with this name may already exist."
                    elif "invalid" in response.text.lower():
                        friendly_error += f"\nInvalid format for {record_type} record."

                    messagebox.showerror("API Error",
                                       f"{friendly_error}\n\nDetails:\n{error_msg}",
                                       parent=add_window)
                    return

                # If we made it here, the request was successful
                response.raise_for_status()
                messagebox.showinfo("Success", f"{record_type} DNS entry added successfully", parent=add_window)
                print(f"Successfully added {record_type} record: {name}")
                self.load_static_dns_entries()  # Refresh the list
                add_window.destroy()

            except requests.exceptions.RequestException as e:
                error_msg = str(e)
                print(f"Request Exception: {error_msg}")  # Debug info
                messagebox.showerror("Error", f"Failed to add DNS entry: {error_msg}", parent=add_window)

        # Add buttons
        button_frame = ttk.Frame(add_window)
        button_frame.grid(row=6, column=0, columnspan=2, pady=10)
        ttk.Button(button_frame, text="Add", command=submit_new_entry).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=add_window.destroy).pack(side=tk.LEFT, padx=5)

    def edit_static_dns_entry(self):
        selected = self.static_dns_tree.selection()
        if not selected:
            messagebox.showinfo("Selection Required", "Please select an entry to edit",
                              parent=self.dns_window_frame)
            return

        # Get the selected item's values
        values = self.static_dns_tree.item(selected[0], 'values')
        entry_id = self.static_dns_tree.item(selected[0], 'tags')[0]  # Get the ID from tags

        # Create edit window
        edit_window = tk.Toplevel(self.dns_window_frame)
        edit_window.title("Edit Static DNS Entry")
        edit_window.geometry("500x400")
        edit_window.transient(self.dns_window_frame)
        edit_window.grab_set()

        # Create form fields
        ttk.Label(edit_window, text="DNS Name:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        name_entry = ttk.Entry(edit_window, width=30)
        name_entry.grid(row=0, column=1, padx=10, pady=5)
        name_entry.insert(0, values[0])

        # DNS Record Type dropdown
        ttk.Label(edit_window, text="Record Type:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        record_type_var = tk.StringVar(value=values[1])
        record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "PTR"]
        record_type_dropdown = ttk.Combobox(edit_window, textvariable=record_type_var, values=record_types,
                                          width=28,
                                          state="readonly")
        record_type_dropdown.grid(row=1, column=1, padx=10, pady=5)

        # Address/Value field
        address_label = ttk.Label(edit_window, text="Value:")
        address_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")
        address_entry = ttk.Entry(edit_window, width=30)
        address_entry.grid(row=2, column=1, padx=10, pady=5)
        address_entry.insert(0, values[2])

        # TTL field
        ttk.Label(edit_window, text="TTL (seconds):").grid(row=3, column=0, padx=10, pady=5, sticky="w")
        ttl_entry = ttk.Entry(edit_window, width=30)
        ttl_entry.grid(row=3, column=1, padx=10, pady=5)
        ttl_entry.insert(0, values[3])

        # Comment field
        ttk.Label(edit_window, text="Comment:").grid(row=4, column=0, padx=10, pady=5, sticky="w")
        comment_entry = ttk.Entry(edit_window, width=30)
        comment_entry.grid(row=4, column=1, padx=10, pady=5)
        comment_entry.insert(0, values[4])

        # Help text area
        help_frame = ttk.LabelFrame(edit_window, text="Format Help")
        help_frame.grid(row=5, column=0, columnspan=2, padx=10, pady=5, sticky="ew")

        help_text = tk.Text(help_frame, height=5, width=50, wrap=tk.WORD)
        help_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        help_text.config(state=tk.DISABLED)

        # Update help and field label based on selected record type
        def update_help_text(*args):

            record_type = record_type_var.get()

            if record_type == "A":
                address_label.config(text="IP Address:")
                help_text.config(state=tk.NORMAL)
                help_text.delete(1.0, tk.END)
                help_text.insert(tk.END, "Enter a valid IPv4 address (e.g., 192.168.1.1)")

            elif record_type == "AAAA":
                address_label.config(text="IPv6 Address:")
                help_text.config(state=tk.NORMAL)
                help_text.delete(1.0, tk.END)
                help_text.insert(tk.END, "Enter a valid IPv6 address (e.g., 2001:db8::1)")

            elif record_type == "CNAME":
                address_label.config(text="Canonical Name:")
                help_text.config(state=tk.NORMAL)
                help_text.delete(1.0, tk.END)
                help_text.insert(tk.END, "Enter the target domain name (e.g., example.com)")

            elif record_type == "MX":
                address_label.config(text="Mail Server:")
                help_text.config(state=tk.NORMAL)
                help_text.delete(1.0, tk.END)
                help_text.insert(tk.END, "Enter priority and mail server (e.g., 10 mail.example.com)")

            elif record_type == "TXT":
                address_label.config(text="Text Value:")
                help_text.config(state=tk.NORMAL)
                help_text.delete(1.0, tk.END)
                help_text.insert(tk.END, "Enter text value (e.g., v=spf1 include:_spf.google.com ~all)")

            elif record_type == "NS":
                address_label.config(text="Nameserver:")
                help_text.config(state=tk.NORMAL)
                help_text.delete(1.0, tk.END)
                help_text.insert(tk.END, "Enter nameserver domain (e.g., ns1.example.com)")

            elif record_type == "SRV":
                address_label.config(text="Service:")
                help_text.config(state=tk.NORMAL)
                help_text.delete(1.0, tk.END)
                help_text.insert(tk.END, "Enter priority weight port target (e.g., 10 5 5060 sip.example.com)")

            elif record_type == "PTR":
                address_label.config(text="Domain Name:")
                help_text.insert(tk.END, "Enter domain name (e.g., hostname.example.com)")
                help_text.config(state=tk.DISABLED)

            record_type_var.trace_add("write", update_help_text)
            update_help_text()

        def submit_edited_entry():
            name = name_entry.get().strip()
            record_type = record_type_var.get()
            address_value = address_entry.get().strip()
            ttl = ttl_entry.get().strip()
            comment = comment_entry.get().strip()

            if not name or not address_value:
                messagebox.showwarning("Missing Information",
                                       f"Both DNS Name and {address_label['text'].replace(':', '')} are required",
                                       parent=edit_window)
                return

            # Validate the record format
            is_valid, error_message = self.validate_dns_record(record_type, address_value)
            if not is_valid:
                messagebox.showwarning("Invalid Format",
                                       f"The {address_label['text'].replace(':', '')} has an invalid format:\n{error_message}",
                                       parent=edit_window)
                proceed = messagebox.askyesno("Proceed Anyway?",
                                              "Do you want to proceed with the current value anyway?",
                                              parent=edit_window)
                if not proceed:
                    return

            try:
                url = f"https://{self.ip}/rest/ip/dns/static/set"
                auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
                headers = {'Authorization': f'Basic {auth}'}

                # Format data according to record type, including the entry ID
                data = self.format_dns_record_data(name, record_type, address_value, ttl, comment, entry_id)

                print(f"Sending DNS update request to {url}")
                print(f"Request JSON Data: {json.dumps(data, indent=2)}")

                response = requests.post(url, headers=headers, json=data, verify=False)

                # Print full response for debugging
                print(f"API Response Status: {response.status_code}")
                print(f"API Response Body: {response.text}")

                # Check for any error in the response
                if response.status_code >= 400:
                    error_msg = f"Status Code: {response.status_code}\nResponse: {response.text}"
                    print(f"API Error: {error_msg}")

                    friendly_error = "An error occurred while updating the DNS record."
                    if "not found" in response.text.lower():
                        friendly_error += "\nThe record to update was not found."
                    elif "invalid" in response.text.lower():
                        friendly_error += f"\nInvalid format for {record_type} record."

                    messagebox.showerror("API Error",
                                         f"{friendly_error}\n\nDetails:\n{error_msg}",
                                         parent=edit_window)
                    return

                response.raise_for_status()
                messagebox.showinfo("Success", f"DNS entry updated successfully", parent=edit_window)
                self.load_static_dns_entries()  # Refresh the list
                edit_window.destroy()

            except requests.exceptions.RequestException as e:
                error_msg = str(e)
                print(f"Request Exception: {error_msg}")
                messagebox.showerror("Error", f"Failed to update DNS entry: {error_msg}", parent=edit_window)

            # Add buttons

        button_frame = ttk.Frame(edit_window)
        button_frame.grid(row=6, column=0, columnspan=2, pady=10)
        ttk.Button(button_frame, text="Update", command=submit_edited_entry).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=edit_window.destroy).pack(side=tk.LEFT, padx=5)

    def delete_static_dns_entry(self):
        selected = self.static_dns_tree.selection()
        if not selected:
            messagebox.showinfo("Selection Required", "Please select an entry to delete",
                                parent=self.dns_window_frame)
            return

        # Get the selected item's values for confirmation
        values = self.static_dns_tree.item(selected[0], 'values')
        entry_id = self.static_dns_tree.item(selected[0], 'tags')[0]  # Get the ID from tags

        # Confirm deletion
        confirm = messagebox.askyesno("Confirm Deletion",
                                      f"Are you sure you want to delete the DNS entry for '{values[0]}'?",
                                      parent=self.dns_window_frame)
        if not confirm:
            return

        try:
            url = f"https://{self.ip}/rest/ip/dns/static/remove"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}

            data = {".id": entry_id}

            print(f"Sending DNS delete request to {url}")
            print(f"Request JSON Data: {json.dumps(data, indent=2)}")

            response = requests.post(url, headers=headers, json=data, verify=False)

            # Print full response for debugging
            print(f"API Response Status: {response.status_code}")
            print(f"API Response Body: {response.text}")

            if response.status_code >= 400:
                error_msg = f"Status Code: {response.status_code}\nResponse: {response.text}"
                print(f"API Error: {error_msg}")

                friendly_error = "An error occurred while deleting the DNS record."
                if "not found" in response.text.lower():
                    friendly_error += "\nThe record to delete was not found."

                messagebox.showerror("API Error",
                                     f"{friendly_error}\n\nDetails:\n{error_msg}",
                                     parent=self.dns_window_frame)
                return

            response.raise_for_status()
            messagebox.showinfo("Success", "DNS entry deleted successfully", parent=self.dns_window_frame)
            self.load_static_dns_entries()  # Refresh the list

        except requests.exceptions.RequestException as e:
            error_msg = str(e)
            print(f"Request Exception: {error_msg}")
            messagebox.showerror("Error", f"Failed to delete DNS entry: {error_msg}", parent=self.dns_window_frame)

    def flush_dns_cache(self):
        """Flush the DNS cache on the router"""
        confirm = messagebox.askyesno("Confirm Flush",
                                      "Are you sure you want to flush the DNS cache?",
                                      parent=self.dns_window_frame)
        if not confirm:
            return

        try:
            url = f"https://{self.ip}/rest/ip/dns/cache/flush"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}

            response = requests.post(url, headers=headers, verify=False)
            response.raise_for_status()

            messagebox.showinfo("Success", "DNS cache flushed successfully", parent=self.dns_window_frame)
            self.load_cache_stats()  # Refresh the cache stats

        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Failed to flush DNS cache: {e}", parent=self.dns_window_frame)


    def view_dns_cache(self):
        """View current DNS cache entries"""
        try:
            # Try the standard endpoint
            url = f"https://{self.ip}/rest/ip/dns/cache"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}

            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()

            cache_entries = response.json()

            # Debug info
            print(f"Cache response status: {response.status_code}")
            print(f"Cache entries received: {len(cache_entries) if isinstance(cache_entries, list) else 'Not a list'}")

            # Clear existing entries
            for item in self.cache_tree.get_children():
                self.cache_tree.delete(item)

            # Add entries to tree if we got a list
            if isinstance(cache_entries, list):
                for entry in cache_entries:
                    name = entry.get('name', '')
                    type_field = entry.get('type', '')
                    ttl = entry.get('ttl', '')

                    self.cache_tree.insert("", "end", values=(name, type_field, ttl))

                # Update entries count
                self.entries_label.config(text=str(len(cache_entries)))
            else:
                # If not a list, it may be a single object or error
                print(f"Unexpected cache response format: {cache_entries}")
                messagebox.showinfo("Info", "No cache entries found or unsupported format.", parent=self.dns_window_frame)
                self.entries_label.config(text="0")

        except requests.exceptions.RequestException as e:
            print(f"Cache retrieval error: {e}")
            messagebox.showerror("Error", f"Failed to retrieve DNS cache: {e}", parent=self.dns_window_frame)
            self.entries_label.config(text="Error")


    def load_cache_stats(self):
        """Load DNS cache statistics"""
        try:
            # First check if there's a specific stats endpoint
            url = f"https://{self.ip}/rest/ip/dns/cache/all"  # Try alternative endpoint
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}

            try:
                response = requests.get(url, headers=headers, verify=False)
                response.raise_for_status()

                # If successful, process the response
                cache_stats = response.json()

                # Try to determine entry count
                entry_count = 0
                if isinstance(cache_stats, dict):
                    entry_count = cache_stats.get('total-entries', 0)
                elif isinstance(cache_stats, list):
                    entry_count = len(cache_stats)

                # Update entries count
                self.entries_label.config(text=str(entry_count))

            except requests.exceptions.RequestException:
                # If the specific stats endpoint fails, fall back to regular cache endpoint
                print("Stats endpoint failed, falling back to regular cache view")
                self.view_dns_cache()  # This will also update the entry count

        except Exception as e:
            print(f"Error loading cache stats: {e}")
            self.entries_label.config(text="N/A")