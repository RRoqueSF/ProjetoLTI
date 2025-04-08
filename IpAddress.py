import requests
import tkinter as tk
from tkinter import ttk, messagebox

import base64


class IPAddressWindow:
    def __init__(self, ip, user, password, parent_frame):
        self.ip = ip
        self.user = user
        self.password = password

        self.ip_window_frame = tk.Frame(parent_frame, bg="white")
        self.ip_window_frame.pack(fill=tk.BOTH, expand=True)

        # Treeview para listar endereços IP
        self.tree = ttk.Treeview(self.ip_window_frame,
                                 columns=("ID", "Address", "Network", "Interface", "Comment"),
                                 show="headings")

        self.tree.heading("ID", text="ID")
        self.tree.heading("Address", text="Endereço IP")
        self.tree.heading("Network", text="Rede")
        self.tree.heading("Interface", text="Interface")
        self.tree.heading("Comment", text="Comentário")

        self.tree.column("ID", width=50)
        self.tree.column("Address", width=120)
        self.tree.column("Network", width=120)
        self.tree.column("Interface", width=100)
        self.tree.column("Comment", width=150)

        self.tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Botões de ação
        button_frame = tk.Frame(self.ip_window_frame, bg="white")
        button_frame.pack(fill=tk.X, pady=5)

        ttk.Button(button_frame, text="Atualizar", command=self.load_ip_addresses).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Adicionar", command=self.add_ip_address).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Editar", command=self.edit_ip_address).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Remover", command=self.delete_ip_address).pack(side=tk.LEFT, padx=5)

        # Carregar endereços IP inicialmente
        self.load_ip_addresses()

    def load_ip_addresses(self):
        """Carrega a lista de endereços IP do MikroTik"""
        try:
            url = f"https://{self.ip}/rest/ip/address"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}

            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            addresses = response.json()

            # Limpar a treeview
            for item in self.tree.get_children():
                self.tree.delete(item)

            # Adicionar os endereços
            for addr in addresses:
                self.tree.insert("", tk.END, values=(
                    addr.get('.id', ''),
                    addr.get('address', ''),
                    addr.get('network', ''),
                    addr.get('interface', ''),
                    addr.get('comment', '')
                ))

        except requests.exceptions.RequestException as e:
            messagebox.showerror("Erro", f"Falha ao carregar endereços IP: {e}", parent=self.ip_window_frame)

    def add_ip_address(self):
        """Janela para adicionar novo endereço IP"""
        add_window = tk.Toplevel(self.ip_window_frame)
        add_window.title("Adicionar Endereço IP")
        add_window.geometry("400x300")

        # Obter interfaces disponíveis
        interfaces = self.get_interfaces()

        # Campos do formulário
        ttk.Label(add_window, text="Endereço IP (ex: 192.168.1.1/24):").pack(pady=5)
        address_entry = ttk.Entry(add_window, width=30)
        address_entry.pack(pady=5)

        ttk.Label(add_window, text="Interface:").pack(pady=5)
        interface_combo = ttk.Combobox(add_window, values=interfaces, width=28)
        interface_combo.pack(pady=5)

        ttk.Label(add_window, text="Rede (opcional):").pack(pady=5)
        network_entry = ttk.Entry(add_window, width=30)
        network_entry.pack(pady=5)

        ttk.Label(add_window, text="Comentário (opcional):").pack(pady=5)
        comment_entry = ttk.Entry(add_window, width=30)
        comment_entry.pack(pady=5)

        def submit():
            address = address_entry.get().strip()
            interface = interface_combo.get().strip()
            network = network_entry.get().strip()
            comment = comment_entry.get().strip()

            if not address or not interface:
                messagebox.showwarning("Campos obrigatórios", "Endereço IP e Interface são obrigatórios.",
                                       parent=add_window)
                return

            payload = {
                "address": address,
                "interface": interface
            }

            if network:
                payload["network"] = network
            if comment:
                payload["comment"] = comment

            try:
                url = f"https://{self.ip}/rest/ip/address/add"
                auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
                headers = {'Authorization': f'Basic {auth}'}

                response = requests.post(url, headers=headers, json=payload, verify=False)
                response.raise_for_status()

                messagebox.showinfo("Sucesso", "Endereço IP adicionado com sucesso!", parent=add_window)
                add_window.destroy()
                self.load_ip_addresses()

            except requests.exceptions.RequestException as e:
                messagebox.showerror("Erro", f"Falha ao adicionar endereço IP: {e}", parent=add_window)

        button_frame = ttk.Frame(add_window)
        button_frame.pack(pady=10)

        ttk.Button(button_frame, text="Adicionar", command=submit).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancelar", command=add_window.destroy).pack(side=tk.LEFT, padx=5)

    def edit_ip_address(self):
        """Editar endereço IP existente"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Nenhum selecionado", "Por favor selecione um endereço IP para editar.",
                                   parent=self.ip_window_frame)
            return

        addr_id = self.tree.item(selected[0])["values"][0]

        try:
            # Obter detalhes do endereço IP
            url = f"https://{self.ip}/rest/ip/address/{addr_id}"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}

            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            addr_data = response.json()

            # Janela de edição
            edit_window = tk.Toplevel(self.ip_window_frame)
            edit_window.title("Editar Endereço IP")
            edit_window.geometry("400x300")

            # Obter interfaces disponíveis
            interfaces = self.get_interfaces()

            # Campos do formulário
            ttk.Label(edit_window, text="Endereço IP:").pack(pady=5)
            address_entry = ttk.Entry(edit_window, width=30)
            address_entry.insert(0, addr_data.get('address', ''))
            address_entry.pack(pady=5)

            ttk.Label(edit_window, text="Interface:").pack(pady=5)
            interface_combo = ttk.Combobox(edit_window, values=interfaces, width=28)
            interface_combo.set(addr_data.get('interface', ''))
            interface_combo.pack(pady=5)

            ttk.Label(edit_window, text="Rede:").pack(pady=5)
            network_entry = ttk.Entry(edit_window, width=30)
            network_entry.insert(0, addr_data.get('network', ''))
            network_entry.pack(pady=5)

            ttk.Label(edit_window, text="Comentário:").pack(pady=5)
            comment_entry = ttk.Entry(edit_window, width=30)
            comment_entry.insert(0, addr_data.get('comment', ''))
            comment_entry.pack(pady=5)

            def submit():
                address = address_entry.get().strip()
                interface = interface_combo.get().strip()
                network = network_entry.get().strip()
                comment = comment_entry.get().strip()

                if not address or not interface:
                    messagebox.showwarning("Campos obrigatórios", "Endereço IP e Interface são obrigatórios.",
                                           parent=edit_window)
                    return

                payload = {
                    ".id": addr_id,
                    "address": address,
                    "interface": interface
                }

                if network:
                    payload["network"] = network
                if comment:
                    payload["comment"] = comment

                try:
                    url = f"https://{self.ip}/rest/ip/address/set"
                    auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
                    headers = {'Authorization': f'Basic {auth}'}

                    response = requests.post(url, headers=headers, json=payload, verify=False)
                    response.raise_for_status()

                    messagebox.showinfo("Sucesso", "Endereço IP atualizado com sucesso!", parent=edit_window)
                    edit_window.destroy()
                    self.load_ip_addresses()

                except requests.exceptions.RequestException as e:
                    messagebox.showerror("Erro", f"Falha ao atualizar endereço IP: {e}", parent=edit_window)

            button_frame = ttk.Frame(edit_window)
            button_frame.pack(pady=10)

            ttk.Button(button_frame, text="Atualizar", command=submit).pack(side=tk.LEFT, padx=5)
            ttk.Button(button_frame, text="Cancelar", command=edit_window.destroy).pack(side=tk.LEFT, padx=5)

        except requests.exceptions.RequestException as e:
            messagebox.showerror("Erro", f"Falha ao obter detalhes do endereço IP: {e}", parent=self.ip_window_frame)

    def delete_ip_address(self):
        """Remover endereço IP"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Nenhum selecionado", "Por favor selecione um endereço IP para remover.",
                                   parent=self.ip_window_frame)
            return

        addr_id = self.tree.item(selected[0])["values"][0]
        addr_ip = self.tree.item(selected[0])["values"][1]

        confirm = messagebox.askyesno(
            "Confirmar remoção",
            f"Tem certeza que deseja remover o endereço {addr_ip}?",
            parent=self.ip_window_frame
        )

        if not confirm:
            return

        try:
            url = f"https://{self.ip}/rest/ip/address/remove"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}
            payload = {".id": addr_id}

            response = requests.post(url, headers=headers, json=payload, verify=False)
            response.raise_for_status()

            messagebox.showinfo("Sucesso", f"Endereço {addr_ip} removido com sucesso!", parent=self.ip_window_frame)
            self.load_ip_addresses()

        except requests.exceptions.RequestException as e:
            messagebox.showerror("Erro", f"Falha ao remover endereço IP: {e}", parent=self.ip_window_frame)

    def get_interfaces(self):
        """Obter lista de interfaces disponíveis"""
        try:
            url = f"https://{self.ip}/rest/interface"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}

            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()

            interfaces = [iface.get('name', '') for iface in response.json()]
            return interfaces

        except requests.exceptions.RequestException:
            return ["ether1", "ether2", "wlan1", "wlan2"]  # Fallback