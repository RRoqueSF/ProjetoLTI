import base64
import tkinter as tk
from tkinter import ttk, messagebox
from requests import *



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
        
        url = f"http://{ip}/rest/interface"
        try:
            response = get(url, auth=(user, password), timeout=5)
            if response.status_code == 200:
                self.root.destroy()
                NetworkAdmin(ip, user, password)
            else:
                messagebox.showerror("Login Failed", f"Error: {response.status_code}\n{response.text}")
        except exceptions.RequestException as e:
            messagebox.showerror("Connection Error", f"{str(e)}")

class NetworkAdmin:
    def __init__(self, ip, user, password):
        self.ip = ip
        self.user = user
        self.password = password
        
        self.admin_window = tk.Tk()
        self.admin_window.title("Network Administration")
        self.admin_window.geometry("800x400")
        
        # Create the left side menu (Frame)
        self.menu_frame = tk.Frame(self.admin_window, width=200, bg="lightgray")
        self.menu_frame.pack(side=tk.LEFT, fill=tk.Y)
        
        # Create the right side content frame (Frame)
        self.content_frame = tk.Frame(self.admin_window, bg="white")
        self.content_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Menu Buttons
        self.menu_button_interfaces = ttk.Button(self.menu_frame, text="Interface Management", command=self.show_interfaces_window)
        self.menu_button_interfaces.pack(pady=10, fill=tk.X)
        
        self.menu_button_dns = ttk.Button(self.menu_frame, text="DNS Management", command=self.show_dns_window)
        self.menu_button_dns.pack(pady=10, fill=tk.X)

        self.admin_window.mainloop()

    def show_interfaces_window(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()  # Clear previous content
        InterfacesWindow(self.ip, self.user, self.password, self.content_frame)

    def show_dns_window(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()  # Clear previous content
        DNSWindow(self.ip, self.user, self.password, self.content_frame)

class InterfacesWindow:
    def __init__(self, ip, user, password, parent_frame):
        self.ip = ip
        self.user = user
        self.password = password
        
        self.interface_window_frame = tk.Frame(parent_frame, bg="white")
        self.interface_window_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create a notebook (tabbed window)
        self.notebook = ttk.Notebook(self.interface_window_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create two frames (one for all interfaces, one for wireless interfaces)
        self.all_interfaces_frame = ttk.Frame(self.notebook)
        self.wireless_interfaces_frame = ttk.Frame(self.notebook)
        
        # Add the frames as tabs
        self.notebook.add(self.all_interfaces_frame, text="All Interfaces")
        self.notebook.add(self.wireless_interfaces_frame, text="Wireless Interfaces")
        
        # Create listboxes for both frames
        self.all_listbox = tk.Listbox(self.all_interfaces_frame, width=60, height=15)
        self.all_listbox.pack(pady=5)
        self.all_listbox.bind("<Double-Button-1>", self.on_double_click)
        
        self.wireless_listbox = tk.Listbox(self.wireless_interfaces_frame, width=60, height=15)
        self.wireless_listbox.pack(pady=5)
        self.wireless_listbox.bind("<Double-Button-1>", self.on_double_click)
        
        # Create buttons for activation and deactivation
        self.activate_button = ttk.Button(self.interface_window_frame, text="Activate", command=self.activate_interface)
        self.activate_button.pack(side=tk.LEFT, padx=10, pady=5)
        
        self.deactivate_button = ttk.Button(self.interface_window_frame, text="Deactivate", command=self.deactivate_interface)
        self.deactivate_button.pack(side=tk.RIGHT, padx=10, pady=5)
        
        self.load_interfaces()
        self.load_interfaces_wireless()  # Add wireless interface loading function

    def load_interfaces(self):
        try:
            url = f"http://{self.ip}/rest/interface"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}
            
            # Get all interfaces
            response = get(url, headers=headers, verify=False)
            response.raise_for_status()
            interfaces = response.json()

            # Clear current list
            self.all_listbox.delete(0, tk.END)

            # Insert interfaces into the listboxes
            for interface in interfaces:
                interface_info = f"ID: {interface['.id']} | {interface['name']} | Disabled: {interface['disabled']}"
                self.all_listbox.insert(tk.END, interface_info)

        except exceptions.RequestException as e:
            messagebox.showerror("Error", f"{e}", parent=self.interface_window_frame)

    def load_interfaces_wireless(self):
        try:
            url = f"http://{self.ip}/rest/interface"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}
            
            # Get all interfaces
            response = get(url, headers=headers, verify=False)
            response.raise_for_status()
            interfaces = response.json()

            # Clear current list
            self.wireless_listbox.delete(0, tk.END)

            # Insert only wireless interfaces into the wireless listbox
            for interface in interfaces:
                if 'wlan' in interface['type'].lower():  # Assuming the type key contains wireless info
                    interface_info = f"ID: {interface['.id']} | {interface['name']} | Disabled: {interface['disabled']}"
                    self.wireless_listbox.insert(tk.END, interface_info)

        except exceptions.RequestException as e:
            messagebox.showerror("Error", f"{e}", parent=self.interface_window_frame)

    def on_double_click(self, event):
        selected_index = self.all_listbox.curselection() or self.wireless_listbox.curselection()
        if selected_index:
            selected_text = (self.all_listbox.get(selected_index) if self.all_listbox.curselection() 
                             else self.wireless_listbox.get(selected_index))
            messagebox.showinfo("Interface Info", selected_text, parent=self.interface_window_frame)
    
    def activate_interface(self):
        self.toggle_interface(False)
    
    def deactivate_interface(self):
        self.toggle_interface(True)
    
    def toggle_interface(self, disable):
        # Check both listboxes
        selected_index = self.all_listbox.curselection() or self.wireless_listbox.curselection()
        if not selected_index:
            messagebox.showerror("Error", "No interface selected!", parent=self.interface_window_frame)
            return
        
        selected_text = (self.all_listbox.get(selected_index) if self.all_listbox.curselection() 
                         else self.wireless_listbox.get(selected_index))
        interface_id = selected_text.split("ID: ")[1].split(" | ")[0].strip()
        
        url = f"http://{self.ip}/rest/interface/set"
        auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
        headers = {'Authorization': f'Basic {auth}'}
        data = {".id": interface_id, "disabled": disable}
        
        try:
            response = post(url, headers=headers, json=data, verify=False)
            response.raise_for_status()
            messagebox.showinfo("Success", "Interface updated successfully!", parent=self.interface_window_frame)
            self.load_interfaces()
            self.load_interfaces_wireless()  # Reload both interfaces after update
        except exceptions.RequestException as e:
            messagebox.showerror("Error", f"{e}", parent=self.interface_window_frame)

# DNS window placeholder
class DNSWindow:
    def __init__(self, ip, user, password, parent_frame):
        self.dns_window_frame = tk.Frame(parent_frame, bg="white")
        self.dns_window_frame.pack(fill=tk.BOTH, expand=True)

        label = ttk.Label(self.dns_window_frame, text="DNS Management Feature (Coming Soon)", font=("Arial", 14))
        label.pack(pady=20)

if __name__ == "__main__":
    root = tk.Tk()
    app = MikroTikLogin(root)
    root.mainloop()

