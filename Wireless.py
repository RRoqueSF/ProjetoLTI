import tkinter as tk
from tkinter import ttk, messagebox
import requests
import urllib.parse


class WirelessWindow:
    def __init__(self, ip, user, password, parent_frame):
        self.ip = ip
        self.user = user
        self.password = password
        self.parent_frame = parent_frame

        # Create main frame
        self.main_frame = ttk.Frame(parent_frame)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Title label
        ttk.Label(self.main_frame, text="Wireless Networks Management", font=("Arial", 14, "bold")).pack(pady=10)

        # Buttons frame
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(pady=5, fill=tk.X)

        # Refresh, Add, and Remove buttons
        ttk.Button(button_frame, text="Refresh", command=self.refresh_wireless_list).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Add Wireless Network", command=self.add_wireless_network).pack(side=tk.LEFT,
                                                                                                      padx=5)
        ttk.Button(button_frame, text="Remove Wireless Network", command=self.delete_wireless_network).pack(
            side=tk.LEFT, padx=5)

        # Create treeview for wireless interfaces
        self.tree_frame = ttk.Frame(self.main_frame)
        self.tree_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.wireless_tree = ttk.Treeview(self.tree_frame, columns=(
            "name", "mac_address", "mode", "ssid", "enabled", "band", "channel_width", "frequency", "id"))

        # Define column headings
        self.wireless_tree.heading("#0", text="ID")
        self.wireless_tree.heading("name", text="Interface Name")
        self.wireless_tree.heading("mac_address", text="MAC Address")
        self.wireless_tree.heading("mode", text="Mode")
        self.wireless_tree.heading("ssid", text="SSID")
        self.wireless_tree.heading("enabled", text="Enabled")
        self.wireless_tree.heading("band", text="Band")
        self.wireless_tree.heading("channel_width", text="Channel Width")
        self.wireless_tree.heading("frequency", text="Frequency")
        self.wireless_tree.heading("id", text="Resource ID")

        # Set column widths
        self.wireless_tree.column("#0", width=50, stretch=tk.NO)
        self.wireless_tree.column("name", width=100, stretch=tk.YES)
        self.wireless_tree.column("mac_address", width=150, stretch=tk.YES)
        self.wireless_tree.column("mode", width=100, stretch=tk.YES)
        self.wireless_tree.column("ssid", width=120, stretch=tk.YES)
        self.wireless_tree.column("enabled", width=80, stretch=tk.YES)
        self.wireless_tree.column("band", width=80, stretch=tk.YES)
        self.wireless_tree.column("channel_width", width=100, stretch=tk.YES)
        self.wireless_tree.column("frequency", width=80, stretch=tk.YES)
        self.wireless_tree.column("id", width=0, stretch=tk.NO)  # Hide this column but use it for resource ID

        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.tree_frame, orient=tk.VERTICAL, command=self.wireless_tree.yview)
        self.wireless_tree.configure(yscroll=scrollbar.set)

        # Pack tree and scrollbar
        self.wireless_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bind double click event to edit
        self.wireless_tree.bind("<Double-1>", self.edit_wireless_network)

        # Context menu for additional options
        self.context_menu = tk.Menu(self.wireless_tree, tearoff=0)
        self.context_menu.add_command(label="Enable", command=lambda: self.toggle_wireless_status(True))
        self.context_menu.add_command(label="Disable", command=lambda: self.toggle_wireless_status(False))
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Edit", command=self.edit_wireless_network)
        self.context_menu.add_command(label="Remove", command=self.delete_wireless_network)

        # Bind right-click to show context menu
        self.wireless_tree.bind("<Button-3>", self.show_context_menu)

        # Load available physical interfaces and wireless interfaces
        self.physical_interfaces = self.get_physical_interfaces()
        self.refresh_wireless_list()

    def get_physical_interfaces(self):
        """Get list of physical interfaces from the router"""
        interfaces = []
        try:
            url = f"https://{self.ip}/rest/interface"
            response = requests.get(url, auth=(self.user, self.password), verify=False)

            if response.status_code == 200:
                all_interfaces = response.json()
                # Filter to get only physical interfaces (wlan, ether, etc.)
                interfaces = [iface.get("name") for iface in all_interfaces
                              if iface.get("type") in ["wlan", "ether"]]
            else:
                messagebox.showerror("Error", f"Failed to retrieve interfaces. Status code: {response.status_code}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to retrieve interfaces: {str(e)}")

        return interfaces

    def refresh_wireless_list(self):
        # Clear existing items
        for item in self.wireless_tree.get_children():
            self.wireless_tree.delete(item)

        try:
            # Get wireless interfaces from MikroTik
            url = f"https://{self.ip}/rest/interface/wireless"
            response = requests.get(url, auth=(self.user, self.password), verify=False)

            if response.status_code == 200:
                wireless_interfaces = response.json()

                # Insert into treeview
                for i, wlan in enumerate(wireless_interfaces):
                    self.wireless_tree.insert("", tk.END, text=str(i + 1),
                                              values=(
                                                  wlan.get("name", ""),
                                                  wlan.get("mac-address", ""),
                                                  wlan.get("mode", ""),
                                                  wlan.get("ssid", ""),
                                                  "Yes" if wlan.get("disabled") == "false" else "No",
                                                  wlan.get("band", ""),
                                                  wlan.get("channel-width", ""),
                                                  wlan.get("frequency", ""),
                                                  wlan.get(".id", "")  # Store the resource ID
                                              ))
            else:
                messagebox.showerror("Error",
                                     f"Failed to retrieve wireless interfaces. Status code: {response.status_code}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to retrieve wireless interfaces: {str(e)}")

    def show_context_menu(self, event):
        # Select row under mouse
        item = self.wireless_tree.identify_row(event.y)
        if item:
            self.wireless_tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def toggle_wireless_status(self, enable):
        selected_item = self.wireless_tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a wireless interface")
            return

        item_id = selected_item[0]
        values = self.wireless_tree.item(item_id, "values")
        name = values[0]
        resource_id = values[8]  # Get the resource ID from the hidden column

        try:
            url = f"https://{self.ip}/rest/interface/wireless/{resource_id}"
            data = {"disabled": "false" if enable else "true"}

            response = requests.patch(url, json=data, auth=(self.user, self.password), verify=False)

            if response.status_code == 200:
                messagebox.showinfo("Success",
                                    f"Wireless interface {name} {'enabled' if enable else 'disabled'} successfully")
                self.refresh_wireless_list()
            else:
                messagebox.showerror("Error",
                                     f"Failed to update wireless interface. Status code: {response.status_code}\n{response.text}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to update wireless interface: {str(e)}")

    def add_wireless_network(self):
        # Create a dialog window for adding a new wireless network
        add_window = tk.Toplevel(self.parent_frame)
        add_window.title("Add Wireless Network")
        add_window.geometry("400x550")
        add_window.grab_set()  # Make window modal

        # Create form fields
        ttk.Label(add_window, text="Interface Name:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        name_entry = ttk.Entry(add_window, width=30)
        name_entry.grid(row=0, column=1, padx=10, pady=5)

        # Master Interface field (required as per error message)
        ttk.Label(add_window, text="Master Interface:*").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        master_combo = ttk.Combobox(add_window, values=self.physical_interfaces, width=27)
        master_combo.grid(row=1, column=1, padx=10, pady=5)
        if self.physical_interfaces:
            master_combo.current(0)  # Select first interface by default

        ttk.Label(add_window, text="SSID:").grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
        ssid_entry = ttk.Entry(add_window, width=30)
        ssid_entry.grid(row=2, column=1, padx=10, pady=5)

        ttk.Label(add_window, text="Mode:").grid(row=3, column=0, sticky=tk.W, padx=10, pady=5)
        mode_combo = ttk.Combobox(add_window, values=["ap", "station", "station-bridge"], width=27)
        mode_combo.grid(row=3, column=1, padx=10, pady=5)
        mode_combo.current(0)  # Set default to "ap" (Access Point)

        ttk.Label(add_window, text="Band:").grid(row=4, column=0, sticky=tk.W, padx=10, pady=5)
        band_combo = ttk.Combobox(
            add_window,
            values=[
                "2ghz-b", "2ghz-b/g", "2ghz-b/g/n",
                "5ghz-a", "5ghz-a/n", "5ghz-a/n/ac"
            ],
            width=27
        )

        band_combo.grid(row=4, column=1, padx=10, pady=5)
        band_combo.current(0)  # Set default to 2.4GHz

        ttk.Label(add_window, text="Channel Width:").grid(row=5, column=0, sticky=tk.W, padx=10, pady=5)
        channel_width_combo = ttk.Combobox(add_window, values=[
            "20mhz",
            "20/40mhz-ht20",
            "20/40mhz-ht40",
            "20/40/80mhz",
            "80mhz",
            "80+80mhz",
            "160mhz"
        ], width=27)

        channel_width_combo.grid(row=5, column=1, padx=10, pady=5)
        channel_width_combo.current(0)

        ttk.Label(add_window, text="Frequency:").grid(row=6, column=0, sticky=tk.W, padx=10, pady=5)
        frequency_entry = ttk.Entry(add_window, width=30)
        frequency_entry.grid(row=6, column=1, padx=10, pady=5)
        frequency_entry.insert(0, "2412")  # Default frequency

        ttk.Label(add_window, text="Security Profile:").grid(row=7, column=0, sticky=tk.W, padx=10, pady=5)
        security_entry = ttk.Entry(add_window, width=30)
        security_entry.grid(row=7, column=1, padx=10, pady=5)
        security_entry.insert(0, "default")

        # Status (Enabled/Disabled)
        ttk.Label(add_window, text="Status:").grid(row=8, column=0, sticky=tk.W, padx=10, pady=5)
        status_var = tk.StringVar(value="enabled")
        ttk.Radiobutton(add_window, text="Enabled", variable=status_var, value="enabled").grid(row=8, column=1,
                                                                                               sticky=tk.W, padx=10)
        ttk.Radiobutton(add_window, text="Disabled", variable=status_var, value="disabled").grid(row=9, column=1,
                                                                                                 sticky=tk.W, padx=10)

        # Required field notice
        ttk.Label(add_window, text="* Required fields", font=("Arial", 8)).grid(row=10, column=0, columnspan=2,
                                                                                sticky=tk.W, padx=10, pady=5)

        # Save button
        def save_wireless():
            # Get values from form
            name = name_entry.get().strip()
            master_interface = master_combo.get()
            ssid = ssid_entry.get().strip()
            mode = mode_combo.get()
            band = band_combo.get()
            channel_width = channel_width_combo.get()
            frequency = frequency_entry.get().strip()
            security = security_entry.get().strip()
            status = status_var.get()

            # Validate inputs
            if not name or not master_interface or not ssid:
                messagebox.showwarning("Warning", "Interface Name, Master Interface, and SSID are required",
                                       parent=add_window)
                return

            # Prepare data for API request
            data = {
                "name": name,
                "master-interface": master_interface,
                "ssid": ssid,
                "mode": mode,
                "band": band,
                "channel-width": channel_width,
                "frequency": frequency,
                "security-profile": security,
                "disabled": "true" if status == "disabled" else "false"
            }

            try:
                # Send request to create wireless interface
                url = f"https://{self.ip}/rest/interface/wireless"
                response = requests.put(url, json=data, auth=(self.user, self.password), verify=False)

                if response.status_code in [200, 201]:
                    messagebox.showinfo("Success", f"Wireless interface {name} created successfully", parent=add_window)
                    add_window.destroy()
                    self.refresh_wireless_list()
                else:
                    messagebox.showerror("Error",
                                         f"Failed to create wireless interface. Status code: {response.status_code}\n{response.text}",
                                         parent=add_window)

            except Exception as e:
                messagebox.showerror("Error", f"Failed to create wireless interface: {str(e)}", parent=add_window)

        ttk.Button(add_window, text="Save", command=save_wireless).grid(row=11, column=0, columnspan=2, pady=20)

    def edit_wireless_network(self, event=None):
        selected_item = self.wireless_tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a wireless interface")
            return

        item_id = selected_item[0]
        values = self.wireless_tree.item(item_id, "values")

        # Get current values
        name = values[0]
        mac_address = values[1]
        current_mode = values[2]
        current_ssid = values[3]
        current_status = values[4]
        current_band = values[5]
        current_channel_width = values[6]
        current_frequency = values[7]
        resource_id = values[8]  # Get the resource ID from the hidden column

        # Fetch additional details
        try:
            url = f"https://{self.ip}/rest/interface/wireless/{resource_id}"
            response = requests.get(url, auth=(self.user, self.password), verify=False)

            if response.status_code == 200:
                details = response.json()
                current_master = details.get("master-interface", "")
                current_security = details.get("security-profile", "default")
            else:
                messagebox.showerror("Error",
                                     f"Failed to fetch interface details. Status code: {response.status_code}\n{response.text}")
                return

        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch interface details: {str(e)}")
            return

        # Create a dialog window for editing
        edit_window = tk.Toplevel(self.parent_frame)
        edit_window.title(f"Edit Wireless Network - {name}")
        edit_window.geometry("400x550")
        edit_window.grab_set()  # Make window modal

        # Create form fields
        ttk.Label(edit_window, text="Interface Name:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        name_entry = ttk.Entry(edit_window, width=30)
        name_entry.grid(row=0, column=1, padx=10, pady=5)
        name_entry.insert(0, name)
        name_entry.configure(state="readonly")  # Cannot change name

        ttk.Label(edit_window, text="MAC Address:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        mac_entry = ttk.Entry(edit_window, width=30)
        mac_entry.grid(row=1, column=1, padx=10, pady=5)
        mac_entry.insert(0, mac_address)
        mac_entry.configure(state="readonly")  # Cannot change MAC

        # Resource ID (hidden from user but stored for reference)
        resource_id_var = tk.StringVar(value=resource_id)

        # Master Interface field
        ttk.Label(edit_window, text="Master Interface:*").grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
        master_combo = ttk.Combobox(edit_window, values=self.physical_interfaces, width=27)
        master_combo.grid(row=2, column=1, padx=10, pady=5)
        if current_master in self.physical_interfaces:
            master_combo.set(current_master)
        elif self.physical_interfaces:
            master_combo.current(0)

        ttk.Label(edit_window, text="SSID:").grid(row=3, column=0, sticky=tk.W, padx=10, pady=5)
        ssid_entry = ttk.Entry(edit_window, width=30)
        ssid_entry.grid(row=3, column=1, padx=10, pady=5)
        ssid_entry.insert(0, current_ssid)

        ttk.Label(edit_window, text="Mode:").grid(row=4, column=0, sticky=tk.W, padx=10, pady=5)
        mode_combo = ttk.Combobox(edit_window, values=["ap", "station", "station-bridge"], width=27)
        mode_combo.grid(row=4, column=1, padx=10, pady=5)
        mode_combo.set(current_mode)

        ttk.Label(edit_window, text="Band:").grid(row=5, column=0, sticky=tk.W, padx=10, pady=5)
        band_combo = ttk.Combobox(
            edit_window,
            values=[
                "2ghz-b", "2ghz-b/g", "2ghz-b/g/n",
                "5ghz-a", "5ghz-a/n", "5ghz-a/n/ac"
            ],
            width=27
        )

        band_combo.grid(row=5, column=1, padx=10, pady=5)
        band_combo.set(current_band)

        ttk.Label(edit_window, text="Channel Width:").grid(row=6, column=0, sticky=tk.W, padx=10, pady=5)
        channel_width_combo = ttk.Combobox(edit_window, values=[
            "20mhz",
            "20/40mhz-ht20",
            "20/40mhz-ht40",
            "20/40/80mhz",
            "80mhz",
            "80+80mhz",
            "160mhz"
        ], width=27)

        channel_width_combo.grid(row=6, column=1, padx=10, pady=5)
        channel_width_combo.set(current_channel_width)

        ttk.Label(edit_window, text="Frequency:").grid(row=7, column=0, sticky=tk.W, padx=10, pady=5)
        frequency_entry = ttk.Entry(edit_window, width=30)
        frequency_entry.grid(row=7, column=1, padx=10, pady=5)
        frequency_entry.insert(0, current_frequency)

        ttk.Label(edit_window, text="Security Profile:").grid(row=8, column=0, sticky=tk.W, padx=10, pady=5)
        security_entry = ttk.Entry(edit_window, width=30)
        security_entry.grid(row=8, column=1, padx=10, pady=5)
        security_entry.insert(0, current_security)

        # Status (Enabled/Disabled)
        ttk.Label(edit_window, text="Status:").grid(row=9, column=0, sticky=tk.W, padx=10, pady=5)
        status_var = tk.StringVar(value="enabled" if current_status == "Yes" else "disabled")
        ttk.Radiobutton(edit_window, text="Enabled", variable=status_var, value="enabled").grid(row=9, column=1,
                                                                                                sticky=tk.W, padx=10)
        ttk.Radiobutton(edit_window, text="Disabled", variable=status_var, value="disabled").grid(row=10, column=1,
                                                                                                  sticky=tk.W, padx=10)

        # Required field notice
        ttk.Label(edit_window, text="* Required fields", font=("Arial", 8)).grid(row=11, column=0, columnspan=2,
                                                                                 sticky=tk.W, padx=10, pady=5)

        # Save button
        def save_wireless():
            # Get values from form
            master_interface = master_combo.get()
            ssid = ssid_entry.get().strip()
            mode = mode_combo.get()
            band = band_combo.get()
            channel_width = channel_width_combo.get()
            frequency = frequency_entry.get().strip()
            security = security_entry.get().strip()
            status = status_var.get()
            res_id = resource_id_var.get()

            # Validate inputs
            if not master_interface or not ssid:
                messagebox.showwarning("Warning", "Master Interface and SSID are required", parent=edit_window)
                return

            # Prepare data for API request
            data = {
                ".id": res_id,  # Include the resource ID in the data
                "master-interface": master_interface,
                "ssid": ssid,
                "mode": mode,
                "band": band,
                "channel-width": channel_width,
                "frequency": frequency,
                "security-profile": security,
                "disabled": "true" if status == "disabled" else "false"
            }

            try:
                # Send request to update wireless interface
                url = f"https://{self.ip}/rest/interface/wireless/{res_id}"
                response = requests.patch(url, json=data, auth=(self.user, self.password), verify=False)

                if response.status_code == 200:
                    messagebox.showinfo("Success", f"Wireless interface {name} updated successfully",
                                        parent=edit_window)
                    edit_window.destroy()
                    self.refresh_wireless_list()
                else:
                    error_message = f"Failed to update wireless interface. Status code: {response.status_code}"
                    try:
                        error_details = response.json()
                        error_message += f"\nDetails: {error_details}"
                    except:
                        error_message += f"\nResponse: {response.text}"

                    messagebox.showerror("Error", error_message, parent=edit_window)

            except Exception as e:
                messagebox.showerror("Error", f"Failed to update wireless interface: {str(e)}", parent=edit_window)

        ttk.Button(edit_window, text="Save", command=save_wireless).grid(row=12, column=0, columnspan=2, pady=20)

    def delete_wireless_network(self):
        selected_item = self.wireless_tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a wireless interface to remove")
            return

        item_id = selected_item[0]
        values = self.wireless_tree.item(item_id, "values")
        name = values[0]
        resource_id = values[8]  # Get the resource ID from the hidden column

        if messagebox.askyesno("Confirm Remove", f"Are you sure you want to remove wireless interface '{name}'?"):
            try:
                url = f"https://{self.ip}/rest/interface/wireless/{resource_id}"
                response = requests.delete(url, auth=(self.user, self.password), verify=False)

                if response.status_code == 204:
                    messagebox.showinfo("Success", f"Wireless interface {name} removed successfully")
                    self.refresh_wireless_list()
                else:
                    messagebox.showerror("Error",
                                         f"Failed to remove wireless interface. Status code: {response.status_code}\n{response.text}")

            except Exception as e:
                messagebox.showerror("Error", f"Failed to remove wireless interface: {str(e)}")