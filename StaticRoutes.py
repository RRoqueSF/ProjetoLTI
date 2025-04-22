import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import requests


class StaticRoutesWindow:
    def __init__(self, ip, user, password, parent_frame):
        self.ip = ip
        self.user = user
        self.password = password
        self.parent_frame = parent_frame

        # Title for the window
        self.title_label = ttk.Label(parent_frame, text="Static Routes Management", font=("Arial", 14, "bold"))
        self.title_label.pack(pady=10)

        # Frame for buttons
        self.button_frame = ttk.Frame(parent_frame)
        self.button_frame.pack(pady=5, fill=tk.X)

        # Buttons for actions
        self.refresh_button = ttk.Button(self.button_frame, text="Refresh", command=self.load_routes)
        self.refresh_button.pack(side=tk.LEFT, padx=5)

        self.add_button = ttk.Button(self.button_frame, text="Add Route", command=self.add_route)
        self.add_button.pack(side=tk.LEFT, padx=5)

        self.edit_button = ttk.Button(self.button_frame, text="Edit Route", command=self.edit_route)
        self.edit_button.pack(side=tk.LEFT, padx=5)

        self.delete_button = ttk.Button(self.button_frame, text="Delete Route", command=self.delete_route)
        self.delete_button.pack(side=tk.LEFT, padx=5)

        # Create a frame to hold the treeview and scrollbar
        tree_frame = ttk.Frame(parent_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create treeview for routes
        self.routes_tree = ttk.Treeview(tree_frame, columns=("id", "dst_address", "gateway", "distance", "comment"),
                                        show="headings")

        # Configure columns
        self.routes_tree.heading("id", text="ID")
        self.routes_tree.heading("dst_address", text="Destination Address")
        self.routes_tree.heading("gateway", text="Gateway")
        self.routes_tree.heading("distance", text="Distance")
        self.routes_tree.heading("comment", text="Comment")

        # Set column widths
        self.routes_tree.column("id", width=50)
        self.routes_tree.column("dst_address", width=150)
        self.routes_tree.column("gateway", width=150)
        self.routes_tree.column("distance", width=70)
        self.routes_tree.column("comment", width=200)

        # Add scrollbar
        self.scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.routes_tree.yview)
        self.routes_tree.configure(yscroll=self.scrollbar.set)

        # Pack the scrollbar and treeview properly
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.routes_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Status label
        self.status_label = ttk.Label(parent_frame, text="")
        self.status_label.pack(pady=5)

        # Load routes on initialization
        self.load_routes()

    def load_routes(self):
        """Load all static routes from MikroTik"""
        # Clear existing items
        for item in self.routes_tree.get_children():
            self.routes_tree.delete(item)

        # Set status
        self.status_label.config(text="Loading routes...")

        try:
            # API endpoint for static routes
            url = f"https://{self.ip}/rest/ip/route"
            response = requests.get(url, auth=(self.user, self.password), verify=False, timeout=5)

            if response.status_code == 200:
                routes = response.json()
                count = 0

                # Debug message
                print(f"Retrieved {len(routes)} routes from API")

                # Let's print the full first route to see its structure
                if routes and len(routes) > 0:
                    print("First route structure:")
                    print(routes[0])

                for route in routes:
                    # Check if the route is a dictionary
                    if not isinstance(route, dict):
                        print(f"Skipping non-dictionary route: {route}")
                        continue

                    # Extract route information, handling different possible key formats
                    route_id = route.get('.id') or route.get('id') or route.get('.uid') or ''
                    dst_address = route.get('dst-address') or route.get('dst_addr') or ''
                    gateway = route.get('gateway') or ''
                    distance = route.get('distance') or ''
                    comment = route.get('comment') or ''
                    routing_type = route.get('routing-mark') or ''

                    # Additional debugging
                    print(f"Route details: ID={route_id}, DST={dst_address}, GW={gateway}, Type={routing_type}")

                    # Insert into treeview - let's show all routes, not just static ones
                    self.routes_tree.insert("", tk.END, values=(
                        route_id, dst_address, gateway, distance, comment
                    ))
                    count += 1

                self.status_label.config(text=f"Loaded {count} routes")
                print(f"Displayed {count} routes in treeview")
            else:
                error_msg = f"Error loading routes: {response.status_code}"
                self.status_label.config(text=error_msg)
                print(error_msg)
                print(f"Response content: {response.text}")
                messagebox.showerror("Error", f"Failed to load routes: {response.status_code}\n{response.text}")

        except Exception as e:
            error_msg = f"Error: {str(e)}"
            self.status_label.config(text=error_msg)
            print(error_msg)
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def add_route(self):
        """Add a new static route"""
        # Create a dialog window for adding a route
        add_dialog = tk.Toplevel(self.parent_frame)
        add_dialog.title("Add Static Route")
        add_dialog.geometry("400x300")
        add_dialog.grab_set()  # Modal dialog

        # Input fields
        ttk.Label(add_dialog, text="Destination Address:").grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
        dst_address_var = tk.StringVar()
        dst_address_entry = ttk.Entry(add_dialog, textvariable=dst_address_var, width=30)
        dst_address_entry.grid(row=0, column=1, padx=10, pady=5, sticky=tk.W)

        ttk.Label(add_dialog, text="Gateway:").grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)
        gateway_var = tk.StringVar()
        gateway_entry = ttk.Entry(add_dialog, textvariable=gateway_var, width=30)
        gateway_entry.grid(row=1, column=1, padx=10, pady=5, sticky=tk.W)

        ttk.Label(add_dialog, text="Distance:").grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)
        distance_var = tk.StringVar(value="1")
        distance_entry = ttk.Entry(add_dialog, textvariable=distance_var, width=30)
        distance_entry.grid(row=2, column=1, padx=10, pady=5, sticky=tk.W)

        ttk.Label(add_dialog, text="Comment:").grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)
        comment_var = tk.StringVar()
        comment_entry = ttk.Entry(add_dialog, textvariable=comment_var, width=30)
        comment_entry.grid(row=3, column=1, padx=10, pady=5, sticky=tk.W)

        def submit_route():
            # Get values from entry fields
            dst_address = dst_address_var.get().strip()
            gateway = gateway_var.get().strip()
            distance = distance_var.get().strip()
            comment = comment_var.get().strip()

            # Validate input
            if not dst_address or not gateway:
                messagebox.showerror("Input Error", "Destination address and gateway are required.", parent=add_dialog)
                return

            # Prepare route data
            route_data = {
                "dst-address": dst_address,
                "gateway": gateway,
            }

            if distance:
                route_data["distance"] = distance

            if comment:
                route_data["comment"] = comment

            try:
                url = f"https://{self.ip}/rest/ip/route"
                response = requests.put(url, json=route_data, auth=(self.user, self.password), verify=False, timeout=5)

                if response.status_code == 201:
                    messagebox.showinfo("Success", "Route added successfully!", parent=add_dialog)
                    add_dialog.destroy()
                    self.load_routes()  # Refresh the route list
                else:
                    messagebox.showerror("Error", f"Failed to add route: {response.status_code}\n{response.text}",
                                         parent=add_dialog)

            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {str(e)}", parent=add_dialog)

        # Submit and Cancel buttons
        submit_button = ttk.Button(add_dialog, text="Add Route", command=submit_route)
        submit_button.grid(row=4, column=0, padx=10, pady=20)

        cancel_button = ttk.Button(add_dialog, text="Cancel", command=add_dialog.destroy)
        cancel_button.grid(row=4, column=1, padx=10, pady=20)

    def edit_route(self):
        """Edit a selected static route"""
        # Get selected item
        selected_item = self.routes_tree.selection()

        if not selected_item:
            messagebox.showwarning("Selection Required", "Please select a route to edit.")
            return

        # Get route details
        route_id = self.routes_tree.item(selected_item[0], "values")[0]

        try:
            # Get current route data
            url = f"https://{self.ip}/rest/ip/route/{route_id}"
            response = requests.get(url, auth=(self.user, self.password), verify=False, timeout=5)

            if response.status_code != 200:
                messagebox.showerror("Error", f"Failed to get route data: {response.status_code}")
                return

            route_data = response.json()

            # Create edit dialog
            edit_dialog = tk.Toplevel(self.parent_frame)
            edit_dialog.title("Edit Static Route")
            edit_dialog.geometry("400x300")
            edit_dialog.grab_set()  # Modal dialog

            # Input fields with current values
            ttk.Label(edit_dialog, text="Destination Address:").grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
            dst_address_var = tk.StringVar(value=route_data.get('dst-address', ''))
            dst_address_entry = ttk.Entry(edit_dialog, textvariable=dst_address_var, width=30)
            dst_address_entry.grid(row=0, column=1, padx=10, pady=5, sticky=tk.W)

            ttk.Label(edit_dialog, text="Gateway:").grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)
            gateway_var = tk.StringVar(value=route_data.get('gateway', ''))
            gateway_entry = ttk.Entry(edit_dialog, textvariable=gateway_var, width=30)
            gateway_entry.grid(row=1, column=1, padx=10, pady=5, sticky=tk.W)

            ttk.Label(edit_dialog, text="Distance:").grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)
            distance_var = tk.StringVar(value=route_data.get('distance', '1'))
            distance_entry = ttk.Entry(edit_dialog, textvariable=distance_var, width=30)
            distance_entry.grid(row=2, column=1, padx=10, pady=5, sticky=tk.W)

            ttk.Label(edit_dialog, text="Comment:").grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)
            comment_var = tk.StringVar(value=route_data.get('comment', ''))
            comment_entry = ttk.Entry(edit_dialog, textvariable=comment_var, width=30)
            comment_entry.grid(row=3, column=1, padx=10, pady=5, sticky=tk.W)

            def update_route():
                # Get values from entry fields
                dst_address = dst_address_var.get().strip()
                gateway = gateway_var.get().strip()
                distance = distance_var.get().strip()
                comment = comment_var.get().strip()

                # Validate input
                if not dst_address or not gateway:
                    messagebox.showerror("Input Error", "Destination address and gateway are required.",
                                         parent=edit_dialog)
                    return

                # Prepare updated route data
                updated_data = {
                    "dst-address": dst_address,
                    "gateway": gateway,
                }

                if distance:
                    updated_data["distance"] = distance

                if comment:
                    updated_data["comment"] = comment

                try:
                    url = f"https://{self.ip}/rest/ip/route/{route_id}"
                    response = requests.patch(url, json=updated_data, auth=(self.user, self.password), verify=False,
                                              timeout=5)

                    # Accept both 200 and 204 as success codes
                    if response.status_code in [200, 204]:
                        messagebox.showinfo("Success", "Route updated successfully!", parent=edit_dialog)
                        edit_dialog.destroy()
                        self.load_routes()  # Refresh the route list
                    else:
                        messagebox.showerror("Error",
                                             f"Failed to update route: {response.status_code}\n{response.text}",
                                             parent=edit_dialog)

                except Exception as e:
                    messagebox.showerror("Error", f"An error occurred: {str(e)}", parent=edit_dialog)

            # Submit and Cancel buttons
            update_button = ttk.Button(edit_dialog, text="Update Route", command=update_route)
            update_button.grid(row=4, column=0, padx=10, pady=20)

            cancel_button = ttk.Button(edit_dialog, text="Cancel", command=edit_dialog.destroy)
            cancel_button.grid(row=4, column=1, padx=10, pady=20)

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")


    def delete_route(self):
        """Delete a selected static route"""
        # Get selected item
        selected_item = self.routes_tree.selection()

        if not selected_item:
            messagebox.showwarning("Selection Required", "Please select a route to delete.")
            return

        # Get route ID and details for confirmation
        route_values = self.routes_tree.item(selected_item[0], "values")
        route_id = route_values[0]
        dst_address = route_values[1]
        gateway = route_values[2]

        # Confirm deletion
        confirm = messagebox.askyesno(
            "Confirm Deletion",
            f"Are you sure you want to delete the route:\n\nDestination: {dst_address}\nGateway: {gateway}"
        )

        if not confirm:
            return

        try:
            url = f"https://{self.ip}/rest/ip/route/{route_id}"
            response = requests.delete(url, auth=(self.user, self.password), verify=False, timeout=5)

            if response.status_code == 204:
                messagebox.showinfo("Success", "Route deleted successfully!")
                self.load_routes()  # Refresh the route list
            else:
                messagebox.showerror("Error", f"Failed to delete route: {response.status_code}\n{response.text}")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")