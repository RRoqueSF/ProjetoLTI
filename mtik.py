import sys
from WireGuard import *
from SecurityProfile import *
from Interfaces import *
from DNS import *
from DHCP import *
from IpAddress import *
import requests
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import urllib3

from StaticRoutes import StaticRoutesWindow
from SystemManagement import SystemManagementWindow
from Wireless import *

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class MikroTikLogin:
    def __init__(self, root):
        self.root = root
        self.root.title("MikroTik API Login")
        self.root.geometry("1200x600")

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

        # ip = self.ip_input.get().strip()
        # user = self.user_input.get().strip()
        # password = self.pass_input.get().strip()
        ip = "10.20.30.1"
        user = "admin"
        password = "ubuntu123"

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
        self.menu_button_interfaces = ttk.Button(self.menu_frame, text="Interface Management",
                                                 command=self.show_interfaces_window)
        self.menu_button_interfaces.pack(pady=10, fill=tk.X)

        self.menu_button_dns = ttk.Button(self.menu_frame, text="DNS Management", command=self.show_dns_window)
        self.menu_button_dns.pack(pady=10, fill=tk.X)

        self.menu_button_dhcp = ttk.Button(self.menu_frame, text="DHCP Management", command=self.show_dhcp_window)
        self.menu_button_dhcp.pack(pady=10, fill=tk.X)

        self.menu_button_dhcp = ttk.Button(self.menu_frame, text="Ip Addresses", command=self.show_ipAddresses_window)
        self.menu_button_dhcp.pack(pady=10, fill=tk.X)

        self.menu_button_dhcp = ttk.Button(self.menu_frame, text="Static Routes",
                                           command=self.show_static_routes_window)
        self.menu_button_dhcp.pack(pady=10, fill=tk.X)

        # Add Security Profiles button to the side menu
        self.menu_button_security = ttk.Button(self.menu_frame, text="Security Profiles",
                                               command=self.show_security_profiles_window)
        self.menu_button_security.pack(pady=10, fill=tk.X)

        self.menu_button_security = ttk.Button(self.menu_frame, text="Wireless",
                                               command=self.show_wireless_window)
        self.menu_button_security.pack(pady=10, fill=tk.X)

        self.menu_button_security = ttk.Button(self.menu_frame, text="System Management",
                                               command=self.show_system_management_window)
        self.menu_button_security.pack(pady=10, fill=tk.X)

        self.menu_button_security = ttk.Button(self.menu_frame, text="WireGuard",
                                               command=self.show_wireguard_window)
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

    def show_static_routes_window(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        StaticRoutesWindow(self.ip, self.user, self.password, self.content_frame)

    def show_wireless_window(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        WirelessWindow(self.ip, self.user, self.password, self.content_frame)

    def show_system_management_window(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        SystemManagementWindow(self.ip, self.user, self.password, self.content_frame)

    def show_wireguard_window(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        WireGuardWindow(self.ip, self.user, self.password, self.content_frame)
if __name__ == "__main__":
    root = tk.Tk()
    app = MikroTikLogin(root)
    root.mainloop()
