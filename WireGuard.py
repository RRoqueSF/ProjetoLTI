import tkinter as tk
from tkinter import ttk, messagebox
import requests
import json


class WireGuardWindow:
    def __init__(self, ip, user, password, parent_frame):
        self.ip = ip
        self.user = user
        self.password = password
        self.parent_frame = parent_frame

        self.setup_ui()
        self.load_wireguard_interfaces()

    def setup_ui(self):
        # Clear the parent frame
        for widget in self.parent_frame.winfo_children():
            widget.destroy()

        # Main container
        self.main_frame = ttk.Frame(self.parent_frame)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Interface Management Section
        interface_frame = ttk.LabelFrame(self.main_frame, text="WireGuard Interfaces")
        interface_frame.pack(fill=tk.X, padx=5, pady=5)

        # Interface List
        self.interface_tree = ttk.Treeview(interface_frame,
                                           columns=('name', 'private_key', 'public_key', 'listen_port', 'mtu'),
                                           show='headings')
        self.interface_tree.heading('name', text='Name')
        self.interface_tree.heading('private_key', text='Private Key')
        self.interface_tree.heading('public_key', text='Public Key')
        self.interface_tree.heading('listen_port', text='Port')
        self.interface_tree.heading('mtu', text='MTU')
        self.interface_tree.pack(fill=tk.X, padx=5, pady=5)

        # Interface Buttons
        btn_frame = ttk.Frame(interface_frame)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(btn_frame, text="Add Interface", command=self.add_interface).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Remove Interface", command=self.remove_interface).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Refresh", command=self.load_wireguard_interfaces).pack(side=tk.RIGHT, padx=2)

        # Peers Section
        peers_frame = ttk.LabelFrame(self.main_frame, text="WireGuard Peers")
        peers_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Peers List
        self.peers_tree = ttk.Treeview(peers_frame, columns=('interface', 'public_key', 'allowed_address', 'endpoint'),
                                       show='headings')
        self.peers_tree.heading('interface', text='Interface')
        self.peers_tree.heading('public_key', text='Public Key')
        self.peers_tree.heading('allowed_address', text='Allowed Address')
        self.peers_tree.heading('endpoint', text='Endpoint')
        self.peers_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Peers Buttons
        peer_btn_frame = ttk.Frame(peers_frame)
        peer_btn_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(peer_btn_frame, text="Add Peer", command=self.add_peer).pack(side=tk.LEFT, padx=2)
        ttk.Button(peer_btn_frame, text="Remove Peer", command=self.remove_peer).pack(side=tk.LEFT, padx=2)
        ttk.Button(peer_btn_frame, text="Refresh Peers", command=self.load_wireguard_peers).pack(side=tk.RIGHT, padx=2)

    def load_wireguard_interfaces(self):
        try:
            response = requests.get(
                f"https://{self.ip}/rest/interface/wireguard",
                auth=(self.user, self.password),
                verify=False
            )

            if response.status_code == 200:
                # Clear existing items
                for item in self.interface_tree.get_children():
                    self.interface_tree.delete(item)

                # Add new items
                for interface in response.json():
                    self.interface_tree.insert('', 'end', values=(
                        interface.get('name', ''),
                        interface.get('private-key', '')[:10] + '...' if interface.get('private-key') else '',
                        interface.get('public-key', '')[:10] + '...' if interface.get('public-key') else '',
                        interface.get('listen-port', ''),
                        interface.get('mtu', '')
                    ))

                # Load peers after interfaces are loaded
                self.load_wireguard_peers()
            else:
                messagebox.showerror("Error", f"Failed to load WireGuard interfaces: {response.text}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to connect: {str(e)}")

    def load_wireguard_peers(self):
        try:
            response = requests.get(
                f"https://{self.ip}/rest/interface/wireguard/peers",
                auth=(self.user, self.password),
                verify=False
            )

            if response.status_code == 200:
                # Clear existing items
                for item in self.peers_tree.get_children():
                    self.peers_tree.delete(item)

                # Add new items
                for peer in response.json():
                    self.peers_tree.insert('', 'end', values=(
                        peer.get('interface', ''),
                        peer.get('public-key', '')[:10] + '...' if peer.get('public-key') else '',
                        peer.get('allowed-address', ''),
                        peer.get('endpoint-address', '') + ':' + peer.get('endpoint-port', '') if peer.get(
                            'endpoint-address') else ''
                    ))
            else:
                messagebox.showerror("Error", f"Failed to load WireGuard peers: {response.text}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to connect: {str(e)}")

    def add_interface(self):
        dialog = tk.Toplevel()
        dialog.title("Add WireGuard Interface")

        ttk.Label(dialog, text="Interface Name:").grid(row=0, column=0, padx=5, pady=5)
        name_entry = ttk.Entry(dialog)
        name_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(dialog, text="Listen Port:").grid(row=1, column=0, padx=5, pady=5)
        port_entry = ttk.Entry(dialog)
        port_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(dialog, text="MTU:").grid(row=2, column=0, padx=5, pady=5)
        mtu_entry = ttk.Entry(dialog)
        mtu_entry.grid(row=2, column=1, padx=5, pady=5)
        mtu_entry.insert(0, "1420")  # Default MTU

        def on_submit():
            name = name_entry.get().strip()
            port = port_entry.get().strip()
            mtu = mtu_entry.get().strip()

            if not name or not port:
                messagebox.showwarning("Input Error", "Name and Port are required")
                return

            try:
                data = {
                    "name": name,
                    "listen-port": int(port),
                    "mtu": int(mtu) if mtu else 1420
                }

                response = requests.put(
                    f"https://{self.ip}/rest/interface/wireguard",
                    auth=(self.user, self.password),
                    json=data,
                    verify=False
                )

                if response.status_code == 201:
                    messagebox.showinfo("Success", "Interface added successfully")
                    self.load_wireguard_interfaces()
                    dialog.destroy()
                else:
                    messagebox.showerror("Error", f"Failed to add interface: {response.text}")

            except ValueError:
                messagebox.showerror("Error", "Port and MTU must be numbers")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to add interface: {str(e)}")

        ttk.Button(dialog, text="Add", command=on_submit).grid(row=3, column=1, padx=5, pady=5, sticky=tk.E)

    def remove_interface(self):
        selected = self.interface_tree.selection()
        if not selected:
            messagebox.showwarning("Selection Error", "Please select an interface to remove")
            return

        interface_name = self.interface_tree.item(selected[0])['values'][0]

        if messagebox.askyesno("Confirm", f"Are you sure you want to remove interface {interface_name}?"):
            try:
                response = requests.delete(
                    f"https://{self.ip}/rest/interface/wireguard/{interface_name}",
                    auth=(self.user, self.password),
                    verify=False
                )

                if response.status_code == 204:
                    messagebox.showinfo("Success", "Interface removed successfully")
                    self.load_wireguard_interfaces()
                else:
                    messagebox.showerror("Error", f"Failed to remove interface: {response.text}")

            except Exception as e:
                messagebox.showerror("Error", f"Failed to remove interface: {str(e)}")

    def add_peer(self):
        dialog = tk.Toplevel()
        dialog.title("Add WireGuard Peer")

        # Get interface names for dropdown
        interfaces = []
        for child in self.interface_tree.get_children():
            interfaces.append(self.interface_tree.item(child)['values'][0])

        if not interfaces:
            messagebox.showwarning("Error", "No WireGuard interfaces available")
            dialog.destroy()
            return

        ttk.Label(dialog, text="Interface:").grid(row=0, column=0, padx=5, pady=5)
        interface_combo = ttk.Combobox(dialog, values=interfaces)
        interface_combo.grid(row=0, column=1, padx=5, pady=5)
        interface_combo.current(0)

        ttk.Label(dialog, text="Public Key:").grid(row=1, column=0, padx=5, pady=5)
        pubkey_entry = ttk.Entry(dialog)
        pubkey_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(dialog, text="Allowed Addresses (comma separated):").grid(row=2, column=0, padx=5, pady=5)
        allowed_entry = ttk.Entry(dialog)
        allowed_entry.grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(dialog, text="Endpoint Address:").grid(row=3, column=0, padx=5, pady=5)
        endpoint_entry = ttk.Entry(dialog)
        endpoint_entry.grid(row=3, column=1, padx=5, pady=5)

        ttk.Label(dialog, text="Endpoint Port:").grid(row=4, column=0, padx=5, pady=5)
        port_entry = ttk.Entry(dialog)
        port_entry.grid(row=4, column=1, padx=5, pady=5)

        def on_submit():
            interface = interface_combo.get().strip()
            pubkey = pubkey_entry.get().strip()
            allowed = allowed_entry.get().strip()
            endpoint = endpoint_entry.get().strip()
            port = port_entry.get().strip()

            if not interface or not pubkey or not allowed:
                messagebox.showwarning("Input Error", "Interface, Public Key and Allowed Addresses are required")
                return

            try:
                data = {
                    "interface": interface,
                    "public-key": pubkey,
                    "allowed-address": allowed
                }

                if endpoint:
                    data["endpoint-address"] = endpoint
                    if port:
                        data["endpoint-port"] = int(port)

                response = requests.put(
                    f"https://{self.ip}/rest/interface/wireguard/peers",
                    auth=(self.user, self.password),
                    json=data,
                    verify=False
                )

                if response.status_code == 201:
                    messagebox.showinfo("Success", "Peer added successfully")
                    self.load_wireguard_peers()
                    dialog.destroy()
                else:
                    messagebox.showerror("Error", f"Failed to add peer: {response.text}")

            except ValueError:
                messagebox.showerror("Error", "Port must be a number")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to add peer: {str(e)}")

        ttk.Button(dialog, text="Add", command=on_submit).grid(row=5, column=1, padx=5, pady=5, sticky=tk.E)

    def remove_peer(self):
        selected = self.peers_tree.selection()
        if not selected:
            messagebox.showwarning("Selection Error", "Please select a peer to remove")
            return

        peer_id = self.peers_tree.item(selected[0])['values'][1]  # Using public key as identifier

        if messagebox.askyesno("Confirm", f"Are you sure you want to remove this peer?"):
            try:
                # First we need to get the peer's .id from the API
                response = requests.get(
                    f"https://{self.ip}/rest/interface/wireguard/peers",
                    auth=(self.user, self.password),
                    verify=False
                )

                if response.status_code == 200:
                    peer_to_delete = None
                    for peer in response.json():
                        if peer.get('public-key', '').startswith(peer_id.split('...')[0]):
                            peer_to_delete = peer.get('.id')
                            break

                    if peer_to_delete:
                        del_response = requests.delete(
                            f"https://{self.ip}/rest/interface/wireguard/peers/{peer_to_delete}",
                            auth=(self.user, self.password),
                            verify=False
                        )

                        if del_response.status_code == 204:
                            messagebox.showinfo("Success", "Peer removed successfully")
                            self.load_wireguard_peers()
                        else:
                            messagebox.showerror("Error", f"Failed to remove peer: {del_response.text}")
                    else:
                        messagebox.showerror("Error", "Could not find peer to delete")
                else:
                    messagebox.showerror("Error", f"Failed to get peers list: {response.text}")

            except Exception as e:
                messagebox.showerror("Error", f"Failed to remove peer: {str(e)}")