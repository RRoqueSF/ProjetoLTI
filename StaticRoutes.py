import requests
import tkinter as tk
from tkinter import ttk, messagebox
import base64

class StaticRoutesWindow:
    def __init__(self, ip, user, password, parent_frame):
        self.ip = ip
        self.user = user
        self.password = password

        self.routes_window_frame = tk.Frame(parent_frame, bg="white")
        self.routes_window_frame.pack(fill=tk.BOTH, expand=True)

        # Treeview para listar rotas estáticas
        self.tree = ttk.Treeview(self.routes_window_frame,
                                 columns=("ID", "Destination", "Gateway", "Distance", "Comment"),
                                 show="headings")

        self.tree.heading("ID", text="ID")
        self.tree.heading("Destination", text="Destino")
        self.tree.heading("Gateway", text="Gateway")
        self.tree.heading("Distance", text="Distância")
        self.tree.heading("Comment", text="Comentário")

        self.tree.column("ID", width=50)
        self.tree.column("Destination", width=150)
        self.tree.column("Gateway", width=120)
        self.tree.column("Distance", width=80)
        self.tree.column("Comment", width=150)

        self.tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Botões de ação
        button_frame = tk.Frame(self.routes_window_frame, bg="white")
        button_frame.pack(fill=tk.X, pady=5)

        ttk.Button(button_frame, text="Atualizar", command=self.load_static_routes).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Adicionar", command=self.add_static_route).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Editar", command=self.edit_static_route).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Remover", command=self.delete_static_route).pack(side=tk.LEFT, padx=5)

        # Carregar rotas inicialmente
        self.load_static_routes()

    def load_static_routes(self):
        """Carrega a lista de rotas estáticas do MikroTik"""
        try:
            url = f"https://{self.ip}/rest/ip/route"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}

            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            routes = response.json()

            # Limpar a treeview
            for item in self.tree.get_children():
                self.tree.delete(item)

            # Adicionar apenas rotas estáticas (type=blackhole ou sem type)
            for route in routes:
                if route.get('type', '') in ['blackhole', '']:  # Filtra rotas estáticas
                    self.tree.insert("", tk.END, values=(
                        route.get('.id', ''),
                        route.get('dst-address', ''),
                        route.get('gateway', ''),
                        route.get('distance', ''),
                        route.get('comment', '')
                    ))

        except requests.exceptions.RequestException as e:
            messagebox.showerror("Erro", f"Falha ao carregar rotas estáticas: {e}", parent=self.routes_window_frame)

    def add_static_route(self):
        """Janela para adicionar nova rota estática"""
        add_window = tk.Toplevel(self.routes_window_frame)
        add_window.title("Adicionar Rota Estática")
        add_window.geometry("400x250")

        # Campos do formulário
        ttk.Label(add_window, text="Endereço de Destino (ex: 192.168.1.0/24):").pack(pady=5)
        dst_entry = ttk.Entry(add_window, width=30)
        dst_entry.pack(pady=5)

        ttk.Label(add_window, text="Gateway (ex: 192.168.0.1):").pack(pady=5)
        gateway_entry = ttk.Entry(add_window, width=30)
        gateway_entry.pack(pady=5)

        ttk.Label(add_window, text="Distância (opcional):").pack(pady=5)
        distance_entry = ttk.Entry(add_window, width=30)
        distance_entry.insert(0, "1")  # Valor padrão
        distance_entry.pack(pady=5)

        ttk.Label(add_window, text="Comentário (opcional):").pack(pady=5)
        comment_entry = ttk.Entry(add_window, width=30)
        comment_entry.pack(pady=5)

        def submit():
            dst_address = dst_entry.get().strip()
            gateway = gateway_entry.get().strip()
            distance = distance_entry.get().strip()
            comment = comment_entry.get().strip()

            if not dst_address or not gateway:
                messagebox.showwarning("Campos obrigatórios", "Destino e Gateway são obrigatórios.", parent=add_window)
                return

            payload = {
                "dst-address": dst_address,
                "gateway": gateway,
                "distance": distance or "1"  # Usa 1 como padrão se vazio
            }

            if comment:
                payload["comment"] = comment

            try:
                url = f"https://{self.ip}/rest/ip/route/add"
                auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
                headers = {'Authorization': f'Basic {auth}'}

                response = requests.post(url, headers=headers, json=payload, verify=False)
                response.raise_for_status()

                messagebox.showinfo("Sucesso", "Rota estática adicionada com sucesso!", parent=add_window)
                add_window.destroy()
                self.load_static_routes()

            except requests.exceptions.RequestException as e:
                messagebox.showerror("Erro", f"Falha ao adicionar rota estática: {e}", parent=add_window)

        button_frame = ttk.Frame(add_window)
        button_frame.pack(pady=10)

        ttk.Button(button_frame, text="Adicionar", command=submit).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancelar", command=add_window.destroy).pack(side=tk.LEFT, padx=5)

    def edit_static_route(self):
        """Editar rota estática existente"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Nenhum selecionado", "Por favor selecione uma rota para editar.",
                                   parent=self.routes_window_frame)
            return

        route_id = self.tree.item(selected[0])["values"][0]

        try:
            # Obter detalhes da rota
            url = f"https://{self.ip}/rest/ip/route/{route_id}"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}

            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            route_data = response.json()

            # Janela de edição
            edit_window = tk.Toplevel(self.routes_window_frame)
            edit_window.title("Editar Rota Estática")
            edit_window.geometry("400x250")

            # Campos do formulário
            ttk.Label(edit_window, text="Endereço de Destino:").pack(pady=5)
            dst_entry = ttk.Entry(edit_window, width=30)
            dst_entry.insert(0, route_data.get('dst-address', ''))
            dst_entry.pack(pady=5)

            ttk.Label(edit_window, text="Gateway:").pack(pady=5)
            gateway_entry = ttk.Entry(edit_window, width=30)
            gateway_entry.insert(0, route_data.get('gateway', ''))
            gateway_entry.pack(pady=5)

            ttk.Label(edit_window, text="Distância:").pack(pady=5)
            distance_entry = ttk.Entry(edit_window, width=30)
            distance_entry.insert(0, route_data.get('distance', '1'))
            distance_entry.pack(pady=5)

            ttk.Label(edit_window, text="Comentário:").pack(pady=5)
            comment_entry = ttk.Entry(edit_window, width=30)
            comment_entry.insert(0, route_data.get('comment', ''))
            comment_entry.pack(pady=5)

            def submit():
                dst_address = dst_entry.get().strip()
                gateway = gateway_entry.get().strip()
                distance = distance_entry.get().strip()
                comment = comment_entry.get().strip()

                if not dst_address or not gateway:
                    messagebox.showwarning("Campos obrigatórios", "Destino e Gateway são obrigatórios.",
                                           parent=edit_window)
                    return

                payload = {
                    ".id": route_id,
                    "dst-address": dst_address,
                    "gateway": gateway,
                    "distance": distance or "1"
                }

                if comment:
                    payload["comment"] = comment

                try:
                    url = f"https://{self.ip}/rest/ip/route/set"
                    auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
                    headers = {'Authorization': f'Basic {auth}'}

                    response = requests.post(url, headers=headers, json=payload, verify=False)
                    response.raise_for_status()

                    messagebox.showinfo("Sucesso", "Rota estática atualizada com sucesso!", parent=edit_window)
                    edit_window.destroy()
                    self.load_static_routes()

                except requests.exceptions.RequestException as e:
                    messagebox.showerror("Erro", f"Falha ao atualizar rota estática: {e}", parent=edit_window)

            button_frame = ttk.Frame(edit_window)
            button_frame.pack(pady=10)

            ttk.Button(button_frame, text="Atualizar", command=submit).pack(side=tk.LEFT, padx=5)
            ttk.Button(button_frame, text="Cancelar", command=edit_window.destroy).pack(side=tk.LEFT, padx=5)

        except requests.exceptions.RequestException as e:
            messagebox.showerror("Erro", f"Falha ao obter detalhes da rota: {e}", parent=self.routes_window_frame)

    def delete_static_route(self):
        """Remover rota estática"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Nenhum selecionado", "Por favor selecione uma rota para remover.",
                                   parent=self.routes_window_frame)
            return

        route_id = self.tree.item(selected[0])["values"][0]
        route_dst = self.tree.item(selected[0])["values"][1]

        confirm = messagebox.askyesno(
            "Confirmar remoção",
            f"Tem certeza que deseja remover a rota para {route_dst}?",
            parent=self.routes_window_frame
        )

        if not confirm:
            return

        try:
            url = f"https://{self.ip}/rest/ip/route/remove"
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("utf-8")
            headers = {'Authorization': f'Basic {auth}'}
            payload = {".id": route_id}

            response = requests.post(url, headers=headers, json=payload, verify=False)
            response.raise_for_status()

            messagebox.showinfo("Sucesso", f"Rota para {route_dst} removida com sucesso!",
                                parent=self.routes_window_frame)
            self.load_static_routes()

        except requests.exceptions.RequestException as e:
            messagebox.showerror("Erro", f"Falha ao remover rota estática: {e}", parent=self.routes_window_frame)