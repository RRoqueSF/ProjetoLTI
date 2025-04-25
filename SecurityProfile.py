import base64

import requests
import tkinter as tk
from tkinter import ttk, messagebox

class SecurityProfilesWindow:
    """
    A window for managing wireless security profiles.
    
    This class provides a user interface for viewing, creating, editing, and deleting
    security profiles for wireless networks. It handles the display of security profile
    information and manages API interactions for profile operations.
    """
    def __init__(self, ip, user, password, parent_frame):
        self.ip = ip
        self.user = user
        self.password = password

        self.security_window_frame = tk.Frame(parent_frame, bg="white")
        self.security_window_frame.pack(fill=tk.BOTH, expand=True)

        # Treeview to display security profiles in a more structured format
        self.security_profiles_tree = ttk.Treeview(self.security_window_frame, columns=(
        "ID", "Name", "Encryption", "WPA2 Key", "PMKID", "MAC Auth", "GCiphers"), show="headings")
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
        self.create_security_button = ttk.Button(self.buttons_frame, text="Create Security Profile",
                                                 command=self.create_security_profile_popup)
        self.create_security_button.pack(side=tk.LEFT, padx=5)
        self.edit_security_button = ttk.Button(self.buttons_frame, text="Edit Security Profile",
                                               command=self.edit_security_profile_popup)
        self.edit_security_button.pack(side=tk.LEFT, padx=5)
        self.delete_security_button = ttk.Button(self.buttons_frame, text="Delete Security Profile",
                                                 command=self.delete_security_profile)
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
        popup.title("Create Security Profile")
        popup.geometry("400x280")
        popup.configure(bg="white")

        content = ttk.Frame(popup, padding=10)
        content.pack(fill="both", expand=True)
        content.columnconfigure(1, weight=1)

        # Profile Name
        ttk.Label(content, text="Profile Name:").grid(row=0, column=0, sticky="w", pady=5)
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
        mac_checkbox = ttk.Checkbutton(content, text="MAC Authentication", variable=mac_auth_var)
        mac_checkbox.grid(row=3, column=0, columnspan=2, sticky="w", pady=5)

        def submit():
            name_valor = name_entry.get()
            password_valor = key_entry.get()
            pmkid_off = "yes" if pmkid_var.get() else "no"
            mac_off = "yes" if mac_auth_var.get() else "no"

            if not name_valor or not password_valor:
                messagebox.showwarning("Required Fields", "Please fill in all fields.")
                return
            
            if not 8 <= len(password_valor) <= 64:
                messagebox.showwarning("Invalid Password", "WPA2 key must be between 8 and 64 characters.")
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
                messagebox.showinfo("Success", "Security profile created successfully.")
                popup.destroy()
            except requests.exceptions.RequestException as e:
                messagebox.showerror("Error", f"{e}", parent=popup)

        ttk.Button(content, text="Create Profile", command=submit).grid(row=4, column=0, columnspan=2, pady=15)

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
        popup.title("Edit Security Profile")
        popup.geometry("400x280")
        popup.configure(bg="white")

        content = ttk.Frame(popup, padding=10)
        content.pack(fill="both", expand=True)
        content.columnconfigure(1, weight=1)

        # Profile Name
        ttk.Label(content, text="Profile Name:").grid(row=0, column=0, sticky="w", pady=5)
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
            """
            Handles the submission of the edited security profile form.
            
            This function validates the form input, prepares the data for submission,
            and sends the updated security profile to the API.
            """
            name_valor = name_entry.get()
            password_valor = key_entry.get()
            pmkid_off = "yes" if pmkid_var.get() else "no"
            mac_off = "yes" if mac_auth_var.get() else "no"

            if not name_valor or not password_valor:
                messagebox.showwarning("Required Fields", "Please fill in all fields.")
                return
            
            if not 8 <= len(password_valor) <= 64:
                messagebox.showwarning("Invalid Password", "WPA2 key must be between 8 and 64 characters.")
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
                messagebox.showinfo("Success", "Profile updated successfully.")
                popup.destroy()
            except requests.exceptions.RequestException as e:
                messagebox.showerror("Error", f"{e}", parent=popup)

        ttk.Button(content, text="Save Changes", command=submit_edit).grid(row=4, column=0, columnspan=2, pady=15)

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
            messagebox.showinfo("Success", "Profile deleted successfully.")
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"{e}", parent=self.security_window_frame)

    def on_double_click_security_profile(self, event):
        selected_item = self.security_profiles_tree.selection()
        if selected_item:
            selected_profile = self.security_profiles_tree.item(selected_item)["values"]
            profile_info = "\n".join(f"{col}: {val}" for col, val in zip(
                ["ID", "Name", "Encryption", "WPA2 Key", "PMKID", "MAC Auth", "WPA3"], selected_profile))
            messagebox.showinfo("Security Profile Info", profile_info, parent=self.security_window_frame)