from __future__ import annotations

import json
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path


class SealGUI(tk.Tk):
    """Seal desktop GUI — tkinter vault browser."""

    def __init__(self, vault_path=None, **kwargs):
        super().__init__(**kwargs)
        self.title("Seal — Local Vault")
        self.geometry("700x500")
        self.vault_path = vault_path
        self.vault = None
        self._build_ui()
        self._show_login()

    def _build_ui(self):
        menubar = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Open Vault", command=self._show_login)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Verify Integrity", command=self._verify)
        tools_menu.add_command(label="Password Generator", command=self._generator)
        menubar.add_cascade(label="Tools", menu=tools_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=lambda: messagebox.showinfo(
            "Seal", "Seal — Local Vault\nEncrypted file storage with audit trail."
        ))
        menubar.add_cascade(label="Help", menu=help_menu)
        self.config(menu=menubar)

        self.tree = ttk.Treeview(self, columns=("ns", "item"), show="headings", height=20)
        self.tree.heading("ns", text="Namespace")
        self.tree.heading("item", text="Item")
        self.tree.column("ns", width=120)
        self.tree.column("item", width=200)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0), pady=5)

        self.detail_frame = tk.Frame(self, bd=1, relief=tk.SUNKEN)
        self.detail_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.detail_label = tk.Label(self.detail_frame, text="Select an entry", font=("Consolas", 11, "bold"))
        self.detail_label.pack(anchor=tk.W, padx=5, pady=(5, 0))
        self.detail_text = tk.Text(self.detail_frame, wrap=tk.WORD, font=("Consolas", 10))
        self.detail_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.status_var = tk.StringVar(value="Not connected")
        status_bar = tk.Label(self, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.tree.bind("<<TreeviewSelect>>", self._on_select)

    def _show_login(self):
        dialog = LoginDialog(self)
        self.wait_window(dialog)
        if dialog.result:
            self._connect(dialog.result)

    def _connect(self, passphrase):
        from aegis.crypt_storage import AegisVault
        try:
            path = self.vault_path or Path.cwd()
            self.vault = AegisVault(path, passphrase)
            self.status_var.set(f"Connected: {path}")
            self._refresh_tree()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _refresh_tree(self):
        self.tree.delete(*self.tree.get_children())
        if not self.vault:
            return
        for ns in ["personal", "work", "archive"]:
            try:
                items = self.vault.list_items(ns)
                for item in items:
                    self.tree.insert("", tk.END, values=(ns, item))
            except Exception:
                pass
        count = len(self.tree.get_children())
        self.status_var.set(f"{count} entries loaded")

    def _on_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        ns, item_id = self.tree.item(sel[0], "values")
        try:
            data = self.vault.load(ns, item_id)
            self.detail_label.config(text=f"{ns}/{item_id}")
            self.detail_text.delete("1.0", tk.END)
            self.detail_text.insert(tk.END, json.dumps(data, indent=2))
        except Exception as e:
            self.detail_text.delete("1.0", tk.END)
            self.detail_text.insert(tk.END, f"Error: {e}")

    def _verify(self):
        from aegis.audit import AuditLog
        from aegis.canary import CanaryManager
        if not self.vault:
            messagebox.showwarning("No Vault", "Open a vault first.")
            return
        try:
            audit = AuditLog(self.vault._base_path)
            chain_ok = audit.verify()
            count = audit.entry_count
        except Exception:
            chain_ok, count = False, 0
        try:
            canary = CanaryManager(self.vault._base_path)
            triggered = canary.check_all()
        except Exception:
            triggered = []
        status = "VALID" if chain_ok else "BROKEN"
        canary_status = "CLEAN" if not triggered else f"{len(triggered)} TRIGGERED"
        messagebox.showinfo("Vault Integrity",
            f"Audit Chain: {status} ({count} entries)\nCanary: {canary_status}")

    def _generator(self):
        PasswordGeneratorDialog(self)


class LoginDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Unlock Vault")
        self.geometry("350x150")
        self.resizable(False, False)
        self.result = None

        tk.Label(self, text="Master Passphrase:", font=("Arial", 11)).pack(pady=(15, 5))
        self.pw_entry = tk.Entry(self, show="*", width=30, font=("Arial", 11))
        self.pw_entry.pack(pady=5)
        self.pw_entry.focus_set()

        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Unlock", width=10, command=self._submit, default=tk.ACTIVE).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Cancel", width=10, command=self.destroy).pack(side=tk.LEFT, padx=5)

        self.bind("<Return>", lambda e: self._submit())

    def _submit(self):
        pw = self.pw_entry.get()
        if pw:
            self.result = pw
            self.destroy()


class PasswordGeneratorDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Password Generator")
        self.geometry("400x200")

        import secrets, string

        tk.Label(self, text="Length:", font=("Arial", 11)).pack(pady=(15, 5))
        self.length_var = tk.IntVar(value=24)
        tk.Scale(self, from_=8, to=64, variable=self.length_var, orient=tk.HORIZONTAL, length=300).pack()

        self.result_var = tk.StringVar()
        tk.Entry(self, textvariable=self.result_var, width=40, font=("Consolas", 11)).pack(pady=5)

        def generate():
            n = self.length_var.get()
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
            self.result_var.set("".join(secrets.choice(alphabet) for _ in range(n)))

        def copy():
            self.clipboard_clear()
            self.clipboard_append(self.result_var.get())

        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text="Generate", command=generate).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Copy", command=copy).pack(side=tk.LEFT, padx=5)

        generate()
