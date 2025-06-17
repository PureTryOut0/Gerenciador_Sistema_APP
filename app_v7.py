import os
import shutil
import json
import logging
import platform
import subprocess
import threading
import time
import hashlib
import math
from datetime import datetime, timedelta
from tkinter import (Tk, Toplevel, Label, Entry, Button, Frame, Scrollbar, messagebox,
                     filedialog, simpledialog, PhotoImage, Canvas, StringVar, Menu, Text)
from tkinter import ttk
from PIL import Image, ImageTk

# --- Dependências de Pré-visualização ---
try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None
try:
    import ezdxf
    from ezdxf.addons.drawing import RenderContext, Frontend
    from ezdxf.addons.drawing.matplotlib import MatplotlibBackend
except ImportError:
    ezdxf = None
try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
except ImportError:
    plt = None
try:
    import openpyxl
except ImportError:
    openpyxl = None

# --- Configurações Globais ---
ROOT_DIR = "Disco_Local"
TRASH_DIR = os.path.join(ROOT_DIR, "Lixeira")
SPREADSHEETS_DIR = os.path.join(ROOT_DIR, "Planilhas")
METADATA_FILE = os.path.join(ROOT_DIR, "app_metadata.json")
USERS_FILE = os.path.join(ROOT_DIR, "users.json")
LOG_FILE = os.path.join(ROOT_DIR, "app_log.txt")
AUDIT_LOG_FILE = os.path.join(ROOT_DIR, "audit_log.txt")
COMPANY_DIRS = ["Desenhos", "Empresas", "Orçamentos", "Projetos Testes"]
MANAGEABLE_TABS = COMPANY_DIRS + ["Planilhas", "Lixeira"]
TEXT_PREVIEW_EXT = ['.txt', '.log', '.py', '.json', '.md', '.csv']

# --- Funções de Segurança e Usuário ---
def hash_password(password):
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt.hex() + ':' + key.hex()

def verify_password(stored_password, provided_password):
    if not stored_password or ':' not in stored_password: return False
    try:
        salt_hex, key_hex = stored_password.split(':')
        salt = bytes.fromhex(salt_hex)
        key_from_storage = bytes.fromhex(key_hex)
        new_key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
        return key_from_storage == new_key
    except (ValueError, TypeError, AttributeError): return False

def read_users():
    if not os.path.exists(USERS_FILE): return {}
    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f: return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError): return {}

def write_users(data):
    with open(USERS_FILE, 'w', encoding='utf-8') as f: json.dump(data, f, indent=4, ensure_ascii=False)

# --- Funções Auxiliares e de Configuração ---
def setup_environment():
    os.makedirs(ROOT_DIR, exist_ok=True)
    os.makedirs(TRASH_DIR, exist_ok=True)
    os.makedirs(SPREADSHEETS_DIR, exist_ok=True)
    for dir_name in COMPANY_DIRS: os.makedirs(os.path.join(ROOT_DIR, dir_name), exist_ok=True)
    if not os.path.exists(METADATA_FILE):
        with open(METADATA_FILE, 'w', encoding='utf-8') as f: json.dump({"next_company_id": 1, "trash": {}}, f, indent=4)
    if not os.path.exists(USERS_FILE):
        users = {"Draco182019": {"password": hash_password("Draco182019"), "role": "admin"}}
        write_users(users)
    
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s',
                        handlers=[logging.FileHandler(LOG_FILE, 'a', 'utf-8'), logging.StreamHandler()])
    logging.info("Aplicação iniciada e ambiente verificado.")

    audit_logger = logging.getLogger('AuditLogger')
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False
    audit_handler = logging.FileHandler(AUDIT_LOG_FILE, 'a', 'utf-8')
    audit_formatter = logging.Formatter('%(asctime)s - [USUÁRIO: %(user)s] - %(message)s', datefmt='%d/%m/%Y %H:%M:%S')
    audit_handler.setFormatter(audit_formatter)
    if not audit_logger.hasHandlers(): audit_logger.addHandler(audit_handler)

def log_user_action(username, action, details=""):
    logger = logging.getLogger('AuditLogger')
    log_record = {'user': username or "Sistema"}
    logger.info(f"{action} - {details}", extra=log_record)

def read_metadata():
    try:
        with open(METADATA_FILE, 'r', encoding='utf-8') as f: return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError): return {"next_company_id": 1, "trash": {}}

def write_metadata(data):
    with open(METADATA_FILE, 'w', encoding='utf-8') as f: json.dump(data, f, indent=4, ensure_ascii=False)

def open_file_with_default_app(filepath):
    try:
        if platform.system() == "Windows": os.startfile(filepath)
        elif platform.system() == "Darwin": subprocess.Popen(["open", filepath])
        else: subprocess.Popen(["xdg-open", filepath])
        logging.info(f"Arquivo aberto: {filepath}")
    except Exception as e:
        messagebox.showerror("Erro ao Abrir", f"Não foi possível abrir o arquivo:\n{e}")
        logging.error(f"Falha ao abrir o arquivo {filepath}: {e}")

def format_size(size_bytes):
    if size_bytes == 0: return "0 B"
    size_name = ("B", "KB", "MB", "GB", "TB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"

def get_folder_details(folder_path):
    total_size, total_files, total_folders = 0, 0, 0
    try:
        for dirpath, dirnames, filenames in os.walk(folder_path):
            total_folders += len(dirnames)
            total_files += len(filenames)
            for f in filenames:
                fp = os.path.join(dirpath, f)
                if not os.path.islink(fp): total_size += os.path.getsize(fp)
    except OSError: return 0, 0, 0
    return total_size, total_files, total_folders

class ToolTip:
    def __init__(self, widget, text):
        self.widget, self.text, self.tooltip_window = widget, text, None
        self.widget.bind("<Enter>", self.show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)
    def show_tooltip(self, event=None):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25; y += self.widget.winfo_rooty() + 20
        self.tooltip_window = Toplevel(self.widget)
        self.tooltip_window.wm_overrideredirect(True); self.tooltip_window.wm_geometry(f"+{x}+{y}")
        label = Label(self.tooltip_window, text=self.text, justify='left', background="#ffffe0", relief='solid', borderwidth=1, font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)
    def hide_tooltip(self, event=None):
        if self.tooltip_window: self.tooltip_window.destroy()
        self.tooltip_window = None

# --- RECURSO: JANELA DE MUDANÇA DE SENHA ---
class ChangePasswordWindow(Toplevel):
    def __init__(self, parent, app_controller):
        super().__init__(parent)
        self.app = app_controller
        self.title("Alterar Senha")
        self.transient(parent); self.grab_set()
        
        frame = ttk.Frame(self, padding=20)
        frame.pack(expand=True, fill='both')

        ttk.Label(frame, text="Senha Atual:").grid(row=0, column=0, sticky='w', pady=5)
        self.current_pass_entry = ttk.Entry(frame, show="*", width=30)
        self.current_pass_entry.grid(row=0, column=1, pady=5)

        ttk.Label(frame, text="Nova Senha:").grid(row=1, column=0, sticky='w', pady=5)
        self.new_pass_entry = ttk.Entry(frame, show="*", width=30)
        self.new_pass_entry.grid(row=1, column=1, pady=5)

        ttk.Label(frame, text="Confirmar Nova Senha:").grid(row=2, column=0, sticky='w', pady=5)
        self.confirm_pass_entry = ttk.Entry(frame, show="*", width=30)
        self.confirm_pass_entry.grid(row=2, column=1, pady=5)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Salvar", command=self.save_password).pack(side='left', padx=10)
        ttk.Button(btn_frame, text="Cancelar", command=self.destroy).pack(side='left', padx=10)
    
    def save_password(self):
        current_pass = self.current_pass_entry.get()
        new_pass = self.new_pass_entry.get()
        confirm_pass = self.confirm_pass_entry.get()

        users = read_users()
        user_data = users.get(self.app.current_user)

        if not verify_password(user_data.get("password"), current_pass):
            messagebox.showerror("Erro", "A senha atual está incorreta.", parent=self)
            return
        if not new_pass or new_pass != confirm_pass:
            messagebox.showerror("Erro", "A nova senha e a confirmação não correspondem.", parent=self)
            return
        if len(new_pass) < 6:
            messagebox.showwarning("Senha Fraca", "Para sua segurança, a senha deve ter pelo menos 6 caracteres.", parent=self)
            return

        users[self.app.current_user]["password"] = hash_password(new_pass)
        write_users(users)
        log_user_action(self.app.current_user, "ALTERAÇÃO DE SENHA", "Senha alterada com sucesso.")
        messagebox.showinfo("Sucesso", "Sua senha foi alterada com sucesso.", parent=self)
        self.destroy()

# --- RECURSO: JANELA DE BUSCA GLOBAL ---
class SearchResultsWindow(Toplevel):
    def __init__(self, parent, app_controller):
        super().__init__(parent)
        self.app = app_controller
        self.title("Resultados da Busca")
        self.geometry("800x500")
        self.transient(parent); self.grab_set()

        self.tree = self.create_treeview(self, columns=("Tipo", "Localização"))
        self.tree.heading("#0", text="Nome")
        self.tree.heading("Tipo", text="Tipo")
        self.tree.heading("Localização", text="Localização")
        self.tree.column("#0", width=250)
        self.tree.column("Tipo", width=80, anchor='center')
        self.tree.column("Localização", width=420)
        self.tree.bind('<Double-1>', self.on_result_select)

        self.status_label = ttk.Label(self, text="Buscando...")
        self.status_label.pack(pady=5)
    
    def create_treeview(self, parent, columns):
        frame = ttk.Frame(parent); frame.pack(expand=True, fill='both', padx=10, pady=10)
        tree = ttk.Treeview(frame, columns=columns, show='tree headings')
        ysb = ttk.Scrollbar(frame, orient='vertical', command=tree.yview)
        tree.configure(yscrollcommand=ysb.set)
        tree.pack(side='left', expand=True, fill='both')
        ysb.pack(side='right', fill='y')
        return tree

    def populate_results(self, results):
        self.tree.delete(*self.tree.get_children())
        for result_type, data in results:
            if result_type == 'company':
                company_folder_name = data
                try: _, company_name = company_folder_name.split("_", 1)
                except ValueError: company_name = company_folder_name
                self.tree.insert("", "end", text=company_name, values=("Empresa", "N/A"), iid=company_folder_name, tags=('company',))
            elif result_type == 'file':
                file_path = data
                dir_path, filename = os.path.split(file_path)
                self.tree.insert("", "end", text=filename, values=("Arquivo", dir_path), iid=file_path, tags=('file',))
        
        self.status_label.config(text=f"{len(results)} resultado(s) encontrado(s).")
    
    def on_result_select(self, event=None):
        selected_item = self.tree.focus()
        if not selected_item: return
        
        tags = self.tree.item(selected_item, 'tags')
        if not tags: return

        if 'file' in tags:
            self.app.navigate_to_path(selected_item)
            self.destroy()
        elif 'company' in tags:
            self.app.navigate_to_company(selected_item)
            self.destroy()

# --- RECURSO: JANELA DE PROPRIEDADES ---
class PropertiesWindow(Toplevel):
    def __init__(self, parent, title, properties_dict):
        super().__init__(parent)
        self.title(title); self.transient(parent); self.grab_set()
        self.geometry("450x300"); self.resizable(False, False)
        
        main_frame = ttk.Frame(self, padding=15)
        main_frame.pack(expand=True, fill='both')

        for i, (key, value) in enumerate(properties_dict.items()):
            key_label = ttk.Label(main_frame, text=f"{key}:", font=("Helvetica", 10, "bold"))
            key_label.grid(row=i, column=0, sticky="ne", padx=5, pady=2)
            value_label = ttk.Label(main_frame, text=value, wraplength=300, justify="left")
            value_label.grid(row=i, column=1, sticky="nw", padx=5, pady=2)
            main_frame.grid_columnconfigure(1, weight=1)
            
        close_button = ttk.Button(self, text="Fechar", command=self.destroy)
        close_button.pack(pady=(0, 15))
        self.protocol("WM_DELETE_WINDOW", self.destroy)

# --- Classe Principal da Aplicação ---
class FileManagerApp(Tk):
    def __init__(self):
        super().__init__()
        self.title("Sistema de Gerenciamento de Arquivos v6.3")
        self.geometry("1280x800"); self.minsize(1024, 768)
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        style = ttk.Style(self); style.theme_use('clam')

        self.current_user = None; self.user_role = None
        self.user_permissions = {}
        self.clipboard_path = None; self.clipboard_operation = None
        self.global_search_var = StringVar()
        
        self.container = ttk.Frame(self)
        self.container.pack(expand=True, fill='both')

        self.show_login_frame()

    def show_login_frame(self):
        for widget in self.container.winfo_children(): widget.destroy()
        self.title("Sistema de Gerenciamento de Arquivos v6.3 - Login")
        self.login_frame = LoginFrame(self.container, self)
        self.login_frame.pack(expand=True)
        
    def attempt_login(self, username, password):
        users = read_users()
        user_data = users.get(username)
        if user_data and verify_password(user_data.get("password"), password):
            self.current_user = username
            self.user_role = user_data.get("role", "user")
            
            # Alerta removido para não ser intrusivo, o menu desabilitado é o feedback.
            # messagebox.showinfo("Login Bem-Sucedido", f"Login realizado com sucesso!\n\nUsuário: {self.current_user}\nFunção Detectada: {self.user_role.upper()}")

            self.user_permissions = {tab: 'edit' for tab in MANAGEABLE_TABS} if self.user_role == 'admin' else user_data.get("permissions", {})
            logging.info(f"Login bem-sucedido para o usuário '{username}' com função '{self.user_role}'.")
            log_user_action(self.current_user, "LOGIN SUCESSO", f"Usuário '{username}' logou no sistema.")
            self.show_main_app_frame()
        else:
            messagebox.showerror("Falha no Login", "Nome de usuário ou senha incorretos.")
            log_user_action(username, "LOGIN FALHA", f"Tentativa de login com usuário '{username}'.")

    def show_main_app_frame(self):
        for widget in self.container.winfo_children(): widget.destroy()
        self.title(f"Sistema de Gerenciamento de Arquivos v6.3 - Logado como: {self.current_user} ({self.user_role})")
        
        top_frame = ttk.Frame(self.container)
        top_frame.pack(fill='x', padx=5, pady=(5,0))
        
        search_bar_frame = ttk.Frame(top_frame)
        search_bar_frame.pack(fill='x', expand=True, side='right')
        
        ttk.Label(search_bar_frame, text="Busca Global:").pack(side='left', padx=(0,5))
        search_entry = ttk.Entry(search_bar_frame, textvariable=self.global_search_var)
        search_entry.pack(side='left', fill='x', expand=True)
        search_entry.bind("<Return>", self.start_global_search)
        
        search_button = ttk.Button(search_bar_frame, text="Buscar", command=self.start_global_search)
        search_button.pack(side='left', padx=5)
        
        self.create_main_menu()

        self.notebook = ttk.Notebook(self.container)
        self.notebook.pack(expand=True, fill='both', padx=5, pady=5)
        self.tabs = {}
        self.create_tabs()

        self.trash_cleanup_thread = threading.Thread(target=self.periodic_trash_cleanup, daemon=True)
        self.trash_cleanup_thread.start()

    def create_main_menu(self): # <-- MODIFICADO
        menubar = Menu(self)
        self.config(menu=menubar)
        
        account_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Conta", menu=account_menu)
        account_menu.add_command(label="Alterar Senha", command=lambda: ChangePasswordWindow(self, self))
        
        # Acesso ao Gerenciamento de Usuários via Menu
        account_menu.add_separator()
        account_menu.add_command(label="Gerenciar Usuários", command=self.open_user_management)
        
        # Desabilita o item de menu se o usuário não for admin
        if self.user_role != 'admin':
            account_menu.entryconfig("Gerenciar Usuários", state="disabled")
        
        account_menu.add_separator()
        account_menu.add_command(label="Sair", command=self.on_closing)

    def open_user_management(self): # <-- NOVO
        """Abre a aba de gerenciamento de usuários se não existir, e a seleciona."""
        if self.user_role != 'admin':
            messagebox.showerror("Acesso Negado", "Apenas administradores podem acessar esta função.")
            return

        if "UserManagement" not in self.tabs or not self.tabs["UserManagement"].parent_frame.winfo_exists():
            # Cria a aba se ela não existir
            self.tabs["UserManagement"] = UserManagementTab(self.notebook, self)
            self.notebook.add(self.tabs["UserManagement"].parent_frame, text="👤 Gerenciar Usuários")
        
        # Seleciona a aba
        self.notebook.select(self.tabs["UserManagement"].parent_frame)

    def start_global_search(self, event=None):
        search_term = self.global_search_var.get()
        if not search_term or len(search_term) < 3:
            messagebox.showinfo("Busca", "Digite pelo menos 3 caracteres para buscar.", parent=self)
            return

        log_user_action(self.current_user, "BUSCA GLOBAL", f"Termo: '{search_term}'")
        results_window = SearchResultsWindow(self, self)
        
        def search_thread_task():
            file_results, company_results = [], set()
            search_term_lower = search_term.lower()

            for root, dirs, files in os.walk(ROOT_DIR):
                if "Lixeira" in root: dirs[:] = []; continue
                
                if os.path.basename(os.path.normpath(root)) in COMPANY_DIRS:
                    for d in dirs:
                        if "_" in d and search_term_lower in d.lower(): company_results.add(d)

                for name in files:
                    if search_term_lower in name.lower(): file_results.append(os.path.join(root, name))
            
            final_results = [('company', c) for c in sorted(list(company_results))] + [('file', f) for f in sorted(file_results)]
            
            self.after(0, results_window.populate_results, final_results)

        threading.Thread(target=search_thread_task, daemon=True).start()
    
    def navigate_to_path(self, path):
        dir_to_show = os.path.dirname(path)
        rel_path = os.path.relpath(dir_to_show, ROOT_DIR)
        top_level_dir = rel_path.split(os.sep)[0]
        
        target_tab_key = None
        for key in self.tabs.keys():
            if top_level_dir.lower() in key.lower() or key.lower() in top_level_dir.lower():
                target_tab_key = key; break
        
        if target_tab_key:
            self.notebook.select([i for i, k in enumerate(self.tabs.keys()) if k == target_tab_key][0])
            tab_widget = self.tabs[target_tab_key]
            if isinstance(tab_widget, FileBrowserTab):
                tab_widget.populate_file_tree(dir_to_show)
                
                for item_id in tab_widget.file_tree.get_children():
                    if tab_widget.file_tree.item(item_id, 'text') == os.path.basename(path):
                        tab_widget.file_tree.selection_set(item_id); tab_widget.file_tree.focus(item_id); tab_widget.file_tree.see(item_id)
                        break

    def navigate_to_company(self, company_folder_name):
        target_tab_key = "Desenhos"
        if target_tab_key in self.tabs:
            self.notebook.select([i for i, k in enumerate(self.tabs.keys()) if k == target_tab_key][0])
            tab_widget = self.tabs[target_tab_key]
            if isinstance(tab_widget, FileBrowserTab):
                if tab_widget.company_tree.exists(company_folder_name):
                    tab_widget.company_tree.selection_set(company_folder_name)
                    tab_widget.company_tree.focus(company_folder_name)
                    tab_widget.company_tree.see(company_folder_name)

    def create_tabs(self): # <-- MODIFICADO
        perm_map = {d: self.user_permissions.get(d, "none") for d in MANAGEABLE_TABS}
        
        if perm_map["Lixeira"] != "none":
            self.tabs["Lixeira"] = TrashManagerTab(self.notebook, self, self.user_role, perm_map["Lixeira"])
            self.notebook.add(self.tabs["Lixeira"].parent_frame, text="🗑️ Lixeira")
        if perm_map["Planilhas"] != "none":
            self.tabs["Planilhas"] = SpreadsheetManagerTab(self.notebook, self, self.user_role, perm_map["Planilhas"])
            self.notebook.add(self.tabs["Planilhas"].parent_frame, text="📊 Planilhas")
        for d in COMPANY_DIRS:
            if perm_map[d] != "none":
                self.tabs[d] = FileBrowserTab(self.notebook, self, os.path.join(ROOT_DIR, d), self.user_role, perm_map[d])
                self.notebook.add(self.tabs[d].parent_frame, text=f"📂 {d}")
        # A criação da aba de UserManagement foi removida daqui e movida para o menu.

    def refresh_all_tabs(self, refresh_companies=False, path_to_refresh=None):
        for tab in self.tabs.values():
            if isinstance(tab, FileBrowserTab):
                if refresh_companies: tab.populate_company_tree()
                current_display_path = os.path.normpath(tab.current_path)
                if path_to_refresh and os.path.normpath(path_to_refresh) == current_display_path:
                    tab.populate_file_tree(current_display_path)
            elif hasattr(tab, 'populate_list'):
                 tab.populate_list()

    def on_closing(self):
        if messagebox.askokcancel("Sair", "Deseja realmente sair da aplicação?"):
            if self.current_user: log_user_action(self.current_user, "LOGOUT", "Usuário fechou a aplicação.")
            self.destroy()

    def periodic_trash_cleanup(self):
        while True:
            time.sleep(3600)
            if self.user_role != 'admin': continue
            
            metadata = read_metadata()
            items_to_remove = [n for n, i in metadata.get("trash", {}).items()
                               if datetime.fromisoformat(i["deleted_at"]) < datetime.now() - timedelta(days=30)]
            if not items_to_remove: continue
            
            log_user_action("Sistema", "LIMPEZA AUTOMÁTICA LIXEIRA", f"Itens com mais de 30 dias excluídos: {items_to_remove}")
            for item_name in items_to_remove: TrashManagerTab.delete_item_permanently(item_name)
            
            if "Lixeira" in self.tabs and self.tabs["Lixeira"].parent_frame.winfo_exists():
                self.tabs["Lixeira"].populate_list()

# --- O restante do código (Classes de Login, Abas, etc.) permanece o mesmo da v6.2, com as modificações aplicadas ---
# --- As classes completas estão incluídas abaixo para garantir a funcionalidade. ---

class LoginFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        frame = ttk.Frame(self, padding="20 40")
        frame.grid(row=0, column=0, sticky="nsew")
        self.columnconfigure(0, weight=1); self.rowconfigure(0, weight=1)
        
        ttk.Label(frame, text="Login do Sistema", font=("Helvetica", 16, "bold")).grid(row=0, column=0, columnspan=2, pady=10)
        ttk.Label(frame, text="Usuário:", font=("Helvetica", 11)).grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.username_entry = ttk.Entry(frame, width=30, font=("Helvetica", 11)); self.username_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=5)
        self.username_entry.focus()
        ttk.Label(frame, text="Senha:", font=("Helvetica", 11)).grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.password_entry = ttk.Entry(frame, width=30, show="*", font=("Helvetica", 11)); self.password_entry.grid(row=2, column=1, sticky="ew", padx=5, pady=5)
        self.password_entry.bind("<Return>", lambda e: self.controller.attempt_login(self.username_entry.get(), self.password_entry.get()))
        
        login_button = ttk.Button(frame, text="Entrar", command=lambda: self.controller.attempt_login(self.username_entry.get(), self.password_entry.get()))
        login_button.grid(row=3, column=0, columnspan=2, pady=20, sticky="ew")

class FileBrowserTab:
    def __init__(self, notebook, main_app, base_path, user_role, permission):
        self.parent_frame = ttk.Frame(notebook)
        self.main_app, self.base_path, self.user_role, self.permission = main_app, base_path, user_role, permission
        self.history = [self.base_path]; self.current_path = self.base_path
        self.preview_widget = None; self._all_file_tree_items = []
        self.load_icons()
        
        paned_window = ttk.PanedWindow(self.parent_frame, orient='horizontal')
        paned_window.pack(expand=True, fill='both')
        self.left_frame = ttk.Frame(paned_window, width=350); paned_window.add(self.left_frame, weight=1)
        self.company_tree_frame = ttk.Frame(self.left_frame); self.company_tree_frame.pack(expand=True, fill='both')
        ttk.Label(self.company_tree_frame, text="Empresas", font=("Helvetica", 10, "bold")).pack(pady=5)
        self.company_tree = self.create_treeview(self.company_tree_frame, ("ID", "Nome")); self.company_tree.heading("ID", text="ID"); self.company_tree.heading("Nome", text="Nome")
        self.company_tree.column("#0", width=0, stretch=False); self.company_tree.column("ID", width=60, anchor='center')
        self.company_tree.bind('<<TreeviewSelect>>', self.on_company_select)
        
        self.preview_frame = ttk.Frame(self.left_frame)
        right_frame = ttk.Frame(paned_window); paned_window.add(right_frame, weight=3)
        self.action_frame = self.create_action_buttons(right_frame); self.action_frame.pack(fill='x', pady=5)
        
        nav_frame = ttk.Frame(right_frame); nav_frame.pack(fill='x', pady=(0, 5))
        self.back_button = self.create_button(nav_frame, '◀ Voltar', self.go_back, "Voltar")
        self.up_button = self.create_button(nav_frame, '▲ Acima', self.go_up, "Pasta pai")
        self.current_path_label = ttk.Label(nav_frame, text="", relief="sunken", anchor="w", padding=5); self.current_path_label.pack(side='left', fill='x', expand=True, padx=5)
        
        search_frame = ttk.Frame(right_frame); search_frame.pack(fill='x', padx=5, pady=(5,0))
        ttk.Label(search_frame, text="🔎 Pesquisar na pasta:").pack(side='left', padx=(0,5))
        self.search_var = StringVar(); self.search_var.trace_add("write", self.filter_files)
        ttk.Entry(search_frame, textvariable=self.search_var).pack(side='left', fill='x', expand=True)
        
        self.file_tree_frame = ttk.Frame(right_frame); self.file_tree_frame.pack(expand=True, fill='both')
        self.file_tree = self.create_treeview(self.file_tree_frame, ("Tipo", "Modificado em"))
        self.file_tree.heading("#0", text="Nome"); self.file_tree.heading("Tipo", text="Tipo"); self.file_tree.heading("Modificado em", text="Modificado em")
        self.file_tree.column("Tipo", width=100, anchor='center'); self.file_tree.column("Modificado em", width=150, anchor='center')
        self.file_tree.bind('<Double-1>', self.on_item_double_click); self.file_tree.bind('<<TreeviewSelect>>', self.on_file_select); self.file_tree.bind('<Button-3>', self.show_context_menu)
        
        self.populate_company_tree()
        self.populate_file_tree(self.base_path)

    def create_action_buttons(self, parent): # <-- MODIFICADO
        frame = ttk.Frame(parent)
        is_admin = self.user_role == 'admin'; can_edit = self.permission == 'edit'
        
        self.create_button(frame, "Nova Empresa", self.create_new_company, "Cria estrutura de pastas para uma empresa.", 'normal' if is_admin else 'disabled')
        if os.path.basename(self.base_path) == "Empresas": # Botão movido para a aba Empresas
            self.create_button(frame, "Excluir Empresa", self.delete_company, "Exclui PERMANENTEMENTE uma empresa.", 'normal' if is_admin else 'disabled')
        
        self.create_button(frame, "Nova Subpasta", self.create_new_subfolder, "Cria subpasta.", 'normal' if can_edit else 'disabled')
        self.create_button(frame, "Carregar Arquivo(s)", self.upload_files, "Carrega arquivos.", 'normal' if can_edit else 'disabled')
        self.create_button(frame, "Carregar Pasta", self.upload_folder, "Carrega uma pasta.", 'normal' if can_edit else 'disabled')
        self.create_button(frame, "Excluir Item", self.delete_item, "Move item para a lixeira.", 'normal' if can_edit else 'disabled')
        return frame

    def show_context_menu(self, event):
        item_id = self.file_tree.identify_row(event.y)
        is_on_item = bool(item_id)
        
        menu = Menu(self.file_tree, tearoff=0)
        can_edit = self.permission == 'edit'

        if is_on_item:
            self.file_tree.selection_set(item_id)
            menu.add_command(label="Abrir", command=self.on_item_double_click)
            menu.add_command(label="Propriedades", command=self.show_properties_window)
            if can_edit:
                menu.add_separator()
                menu.add_command(label="Copiar", command=self.copy_item)
                menu.add_command(label="Recortar", command=self.cut_item)
                menu.add_command(label="Renomear", command=self.rename_item)
                menu.add_separator()
                menu.add_command(label="Excluir para Lixeira", command=self.delete_item)
        
        if can_edit and self.main_app.clipboard_path:
            if is_on_item: menu.add_separator()
            menu.add_command(label="Colar", command=self.paste_item)

        if menu.index('end') is not None:
            menu.tk_popup(event.x_root, event.y_root)

    def copy_item(self):
        selected = self.file_tree.focus()
        if not selected: return
        self.main_app.clipboard_path = os.path.join(self.current_path, self.file_tree.item(selected, 'text'))
        self.main_app.clipboard_operation = 'copy'
        log_user_action(self.main_app.current_user, "COPIAR", f"Item: '{self.main_app.clipboard_path}'")

    def cut_item(self):
        selected = self.file_tree.focus()
        if not selected: return
        self.main_app.clipboard_path = os.path.join(self.current_path, self.file_tree.item(selected, 'text'))
        self.main_app.clipboard_operation = 'cut'
        log_user_action(self.main_app.current_user, "RECORTAR", f"Item: '{self.main_app.clipboard_path}'")
    
    def paste_item(self):
        if not self.main_app.clipboard_path: return
        source_path = self.main_app.clipboard_path
        dest_path = self.current_path
        
        if not os.path.exists(source_path):
            messagebox.showerror("Erro", "O item de origem não existe mais.")
            self.main_app.clipboard_path = None; return

        dest_item_path = os.path.join(dest_path, os.path.basename(source_path))
        if os.path.normpath(source_path) == os.path.normpath(dest_item_path): return

        if os.path.exists(dest_item_path):
            base, ext = os.path.splitext(os.path.basename(source_path))
            dest_item_path = os.path.join(dest_path, f"{base}_copia{ext}")

        try:
            if self.main_app.clipboard_operation == 'copy':
                log_details = f"De: '{source_path}' Para: '{dest_item_path}'"
                if os.path.isdir(source_path): shutil.copytree(source_path, dest_item_path)
                else: shutil.copy2(source_path, dest_item_path)
                log_user_action(self.main_app.current_user, "COLAR (COPIA)", log_details)

            elif self.main_app.clipboard_operation == 'cut':
                log_details = f"De: '{source_path}' Para: '{dest_item_path}'"
                shutil.move(source_path, dest_item_path)
                log_user_action(self.main_app.current_user, "COLAR (MOVE)", log_details)
                self.main_app.refresh_all_tabs(path_to_refresh=os.path.dirname(source_path))
                self.main_app.clipboard_path = None
            
            self.populate_file_tree(dest_path)
        except Exception as e: messagebox.showerror("Erro ao Colar", f"Não foi possível completar a operação:\n{e}")

    def load_icons(self):
        try:
            self.icon_folder = ImageTk.PhotoImage(Image.new('RGBA', (16, 16), (255, 193, 7, 255)))
            self.icon_file = ImageTk.PhotoImage(Image.new('RGBA', (16, 16), (33, 150, 243, 255)))
            self.icon_pdf = ImageTk.PhotoImage(Image.new('RGBA', (16, 16), (244, 67, 54, 255)))
            self.icon_img = ImageTk.PhotoImage(Image.new('RGBA', (16, 16), (76, 175, 80, 255)))
            self.icon_dxf = ImageTk.PhotoImage(Image.new('RGBA', (16, 16), (156, 39, 176, 255)))
            self.icon_text = ImageTk.PhotoImage(Image.new('RGBA', (16, 16), (120, 120, 120, 255)))
        except Exception: self.icon_folder=self.icon_file=self.icon_pdf=self.icon_img=self.icon_dxf=self.icon_text = None

    def get_icon(self, filename):
        if self.icon_folder is None: return None
        ext = os.path.splitext(filename)[1].lower()
        if ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp']: return self.icon_img
        if ext == '.pdf': return self.icon_pdf
        if ext == '.dxf': return self.icon_dxf
        if ext in TEXT_PREVIEW_EXT: return self.icon_text
        return self.icon_file

    def create_treeview(self, parent, columns):
        frame = ttk.Frame(parent); frame.pack(expand=True, fill='both')
        tree = ttk.Treeview(frame, columns=columns, show='tree headings')
        ysb = ttk.Scrollbar(frame, orient='vertical', command=tree.yview)
        tree.configure(yscrollcommand=ysb.set)
        tree.pack(side='left', expand=True, fill='both')
        ysb.pack(side='right', fill='y')
        return tree

    def create_button(self, parent, text, command, tooltip_text, state='normal'):
        button = ttk.Button(parent, text=text, command=command, state=state)
        button.pack(side='left', padx=2)
        ToolTip(button, tooltip_text)
        return button

    def populate_company_tree(self):
        self.clear_tree(self.company_tree)
        try:
            company_base_dir = os.path.join(ROOT_DIR, COMPANY_DIRS[0])
            for item in sorted(os.listdir(company_base_dir)):
                if os.path.isdir(os.path.join(company_base_dir, item)):
                    parts = item.split("_", 1)
                    if len(parts) == 2: self.company_tree.insert("", "end", values=parts, tags=('company',), iid=item)
        except Exception as e: logging.error(f"Erro ao listar empresas: {e}")

    def populate_file_tree(self, path):
        self.current_path = path
        if not self.history or self.history[-1] != path: self.history.append(path)
        self.update_nav_state()
        self.clear_tree(self.file_tree)
        self.hide_preview()
        self.search_var.set("")
        display_path = os.path.relpath(path, ROOT_DIR)
        self.current_path_label.config(text=f" {display_path}")
        self._all_file_tree_items = []
        try:
            items = sorted(os.listdir(path), key=lambda x: (not os.path.isdir(os.path.join(path, x)), x.lower()))
            for name in items:
                full_path = os.path.join(path, name)
                icon = self.get_icon(name)
                if os.path.isdir(full_path):
                    item_id = self.file_tree.insert("", "end", text=name, values=("[Pasta]", ""), tags=('folder',), image=self.icon_folder)
                else:
                    mod_time = datetime.fromtimestamp(os.path.getmtime(full_path)).strftime('%d/%m/%Y %H:%M')
                    file_ext = os.path.splitext(name)[1].upper() or "Arquivo"
                    item_id = self.file_tree.insert("", "end", text=name, values=(file_ext, mod_time), tags=('file',), image=icon)
                self._all_file_tree_items.append(item_id)
        except Exception as e:
            messagebox.showerror("Erro de Acesso", f"Não foi possível acessar:\n{e}")
            self.go_back()
    
    def update_nav_state(self):
        self.back_button.config(state='normal' if len(self.history) > 1 else 'disabled')
        is_root_of_tab = os.path.normpath(self.current_path) == os.path.normpath(self.base_path)
        self.up_button.config(state='disabled' if is_root_of_tab else 'normal')
    
    def clear_tree(self, tree): tree.delete(*tree.get_children())
    
    def filter_files(self, *args):
        search_term = self.search_var.get().lower()
        all_children = set(self.file_tree.get_children(''))
        for item_id in self._all_file_tree_items:
            if item_id not in all_children: self.file_tree.reattach(item_id, '', 'end')
        
        if search_term:
            for item_id in self._all_file_tree_items:
                if self.file_tree.exists(item_id) and search_term not in self.file_tree.item(item_id, 'text').lower():
                    self.file_tree.detach(item_id)
                    
    def create_new_company(self):
        company_name = simpledialog.askstring("Nova Empresa", "Digite o nome da empresa:")
        if not company_name or not company_name.strip(): return
        metadata = read_metadata()
        company_id = metadata.get("next_company_id", 1)
        folder_name = f"{company_id:06d}_{company_name.strip()}"
        try:
            for dir_name in COMPANY_DIRS: os.makedirs(os.path.join(ROOT_DIR, dir_name, folder_name), exist_ok=True)
            metadata["next_company_id"] = company_id + 1
            write_metadata(metadata)
            log_user_action(self.main_app.current_user, "CRIAÇÃO DE EMPRESA", f"Empresa: '{folder_name}'")
            messagebox.showinfo("Sucesso", f"Empresa '{company_name}' criada.")
            self.main_app.refresh_all_tabs(refresh_companies=True)
        except Exception as e: messagebox.showerror("Erro", f"Não foi possível criar a empresa:\n{e}")

    def delete_company(self):
        selected_item = self.company_tree.focus()
        if not selected_item: return messagebox.showwarning("Nenhuma Seleção", "Selecione uma empresa na lista à esquerda para excluir.")
        company_folder_name = selected_item; _, company_name = company_folder_name.split("_", 1)
        
        if not messagebox.askyesno("Confirmar Exclusão", f"Você está prestes a excluir PERMANENTEMENTE a empresa '{company_name}' e TODOS os seus arquivos.\n\nESTA AÇÃO NÃO PODE SER DESFEITA.\n\nDeseja continuar?"): return
        confirmed_name = simpledialog.askstring("Confirmação Final", f"Para confirmar, digite o nome da empresa:\n\n{company_name}")
        if confirmed_name != company_name: return messagebox.showerror("Exclusão Cancelada", "O nome não confere.")

        try:
            for dir_name in COMPANY_DIRS:
                path_to_delete = os.path.join(ROOT_DIR, dir_name, company_folder_name)
                if os.path.exists(path_to_delete): shutil.rmtree(path_to_delete)
            log_user_action(self.main_app.current_user, "EXCLUSÃO PERMANENTE DE EMPRESA", f"Empresa: '{company_folder_name}'")
            messagebox.showinfo("Sucesso", f"A empresa '{company_name}' foi excluída permanentemente.")
            self.main_app.refresh_all_tabs(refresh_companies=True)
        except Exception as e:
            log_user_action(self.main_app.current_user, "FALHA EXCLUSÃO EMPRESA", f"Empresa: {company_name}, Erro: {e}")
            messagebox.showerror("Erro de Exclusão", f"Falha ao excluir a empresa:\n{e}")

    def create_new_subfolder(self):
        folder_name = simpledialog.askstring("Nova Subpasta", "Digite o nome da pasta:")
        if not folder_name or not folder_name.strip(): return
        new_path = os.path.join(self.current_path, folder_name)
        try:
            os.makedirs(new_path)
            log_user_action(self.main_app.current_user, "CRIAÇÃO DE SUBPASTA", f"Pasta: '{new_path}'")
            self.populate_file_tree(self.current_path)
        except FileExistsError: messagebox.showwarning("Pasta Existente", "Uma pasta com este nome já existe.")
        except Exception as e: messagebox.showerror("Erro", f"Não foi possível criar a pasta:\n{e}")

    def upload_files(self):
        files = filedialog.askopenfilenames(title="Selecione os arquivos")
        if not files: return
        for file_path in files:
            try:
                shutil.copy(file_path, self.current_path)
                log_user_action(self.main_app.current_user, "UPLOAD DE ARQUIVO", f"Para: '{self.current_path}'")
            except Exception: pass
        self.populate_file_tree(self.current_path)
        
    def upload_folder(self):
        source_path = filedialog.askdirectory(title="Selecione a pasta para carregar")
        if not source_path: return
        dest_path = os.path.join(self.current_path, os.path.basename(source_path))
        if os.path.exists(dest_path): return messagebox.showwarning("Pasta Existente", "Uma pasta com este nome já existe.")
        try:
            shutil.copytree(source_path, dest_path)
            log_user_action(self.main_app.current_user, "UPLOAD DE PASTA", f"Para: '{dest_path}'")
            self.populate_file_tree(self.current_path)
        except Exception as e: messagebox.showerror("Erro ao Copiar Pasta", f"Não foi possível carregar a pasta:\n{e}")

    def delete_item(self):
        selected_item = self.file_tree.focus()
        if not selected_item: return messagebox.showwarning("Nenhum Item", "Selecione um item para excluir.")
        item_name = self.file_tree.item(selected_item, 'text')
        item_path = os.path.join(self.current_path, item_name)
        if not messagebox.askyesno("Confirmar", f"Mover '{item_name}' para a lixeira?"): return
        try:
            trash_item_name = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{item_name}"
            shutil.move(item_path, os.path.join(TRASH_DIR, trash_item_name))
            metadata = read_metadata()
            metadata.setdefault("trash", {})[trash_item_name] = {"original_path": item_path, "deleted_at": datetime.now().isoformat()}
            write_metadata(metadata)
            log_user_action(self.main_app.current_user, "EXCLUSÃO PARA LIXEIRA", f"Item: '{item_path}'")
            self.populate_file_tree(self.current_path)
            if "Lixeira" in self.main_app.tabs: self.main_app.tabs["Lixeira"].populate_list()
        except Exception as e: messagebox.showerror("Erro ao Excluir", f"Não foi possível mover o item:\n{e}")

    def rename_item(self):
        selected = self.file_tree.focus()
        if not selected: return
        old_name = self.file_tree.item(selected, 'text')
        old_path = os.path.join(self.current_path, old_name)
        new_name = simpledialog.askstring("Renomear", f"Novo nome para '{old_name}':", initialvalue=old_name)
        if not new_name or new_name == old_name: return
        new_path = os.path.join(self.current_path, new_name)
        if os.path.exists(new_path): return messagebox.showwarning("Erro", "Um item com este nome já existe.")
        try:
            os.rename(old_path, new_path)
            log_user_action(self.main_app.current_user, "RENOMEAÇÃO", f"De: '{old_path}' Para: '{new_path}'")
            self.populate_file_tree(self.current_path)
        except Exception as e: messagebox.showerror("Erro ao Renomear", f"Não foi possível renomear:\n{e}")
            
    def go_back(self):
        if len(self.history) > 1:
            self.history.pop()
            self.populate_file_tree(self.history[-1])

    def go_up(self):
        parent_path = os.path.dirname(self.current_path)
        if os.path.normpath(parent_path) != os.path.normpath(self.current_path) and os.path.normpath(parent_path).startswith(os.path.normpath(ROOT_DIR)):
            self.populate_file_tree(parent_path)

    def on_company_select(self, event):
        selected = self.company_tree.focus()
        if not selected: return
        company_path = os.path.join(self.base_path, selected)
        if os.path.isdir(company_path):
            self.history = [self.base_path]; self.populate_file_tree(company_path)

    def on_item_double_click(self, event=None):
        item_id = self.file_tree.focus()
        if not item_id: return
        item_path = os.path.join(self.current_path, self.file_tree.item(item_id, 'text'))
        if os.path.isdir(item_path): self.populate_file_tree(item_path)
        else:
            open_file_with_default_app(item_path)
            log_user_action(self.main_app.current_user, "ABERTURA DE ARQUIVO", f"Arquivo: '{item_path}'")

    def on_file_select(self, event):
        selected = self.file_tree.focus()
        if not selected: return self.hide_preview()
        item_path = os.path.join(self.current_path, self.file_tree.item(selected, 'text'))
        if os.path.isdir(item_path): return self.hide_preview()
        
        ext = os.path.splitext(item_path)[1].lower()
        if ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp']: self.show_image_preview(item_path)
        elif ext == '.pdf' and fitz: self.show_pdf_preview(item_path)
        elif ext == '.dxf' and ezdxf and plt: self.show_dxf_preview(item_path)
        elif ext in TEXT_PREVIEW_EXT: self.show_text_preview(item_path)
        else: self.hide_preview()
            
    def show_preview_frame(self):
        self.company_tree_frame.pack_forget()
        if self.preview_widget: self.preview_widget.destroy()
        self.preview_widget = None
        self.preview_frame.pack(expand=True, fill='both')

    def hide_preview(self):
        if self.preview_widget: self.preview_widget.destroy()
        self.preview_widget = None
        self.preview_frame.pack_forget()
        self.company_tree_frame.pack(expand=True, fill='both')

    def show_image_preview(self, path):
        self.show_preview_frame()
        try:
            w, h = self.left_frame.winfo_width() - 10, self.left_frame.winfo_height() - 40
            img = Image.open(path); img.thumbnail((w if w > 1 else 300, h if h > 1 else 300), Image.Resampling.LANCZOS)
            photo = ImageTk.PhotoImage(img)
            frame = ttk.Frame(self.preview_frame); frame.pack(expand=True, fill='both')
            label = ttk.Label(frame, image=photo); label.pack(pady=10); label.image = photo
            self.preview_widget = frame
        except Exception as e:
            logging.error(f"Erro no preview da imagem {path}: {e}"); self.hide_preview()

    def show_pdf_preview(self, path):
        self.show_preview_frame()
        try:
            doc = fitz.open(path)
            if doc.page_count > 0:
                w = self.left_frame.winfo_width() - 10
                pix = doc.load_page(0).get_pixmap(dpi=150)
                img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples); img.thumbnail((w if w > 1 else 400, 600), Image.Resampling.LANCZOS)
                photo = ImageTk.PhotoImage(img)
                frame = ttk.Frame(self.preview_frame); frame.pack(expand=True, fill='both')
                label = ttk.Label(frame, image=photo); label.pack(pady=10); label.image = photo
                self.preview_widget = frame
            doc.close()
        except Exception as e:
            logging.error(f"Erro no preview do PDF {path}: {e}"); self.hide_preview()

    def show_dxf_preview(self, path):
        self.show_preview_frame()
        try:
            doc = ezdxf.readfile(path); msp = doc.modelspace()
            fig, ax = plt.subplots()
            Frontend(RenderContext(doc), MatplotlibBackend(ax)).draw_layout(msp, finalize=True)
            if not ax.has_data(): raise ValueError("Nenhum dado para plotar no DXF.")
            ax.set_aspect('equal', 'box'); ax.autoscale_view(); fig.tight_layout()
            canvas = FigureCanvasTkAgg(fig, master=self.preview_frame)
            canvas_widget = canvas.get_tk_widget(); canvas_widget.pack(expand=True, fill='both', pady=10)
            self.preview_widget = canvas_widget
            plt.close(fig)
        except Exception as e:
            logging.error(f"Erro ao criar preview do DXF {path}: {e}"); self.hide_preview()

    def show_text_preview(self, path):
        self.show_preview_frame()
        try:
            frame = ttk.Frame(self.preview_frame); frame.pack(expand=True, fill='both')
            text_widget = Text(frame, wrap='word', font=("Courier New", 9), relief='sunken', borderwidth=1)
            ysb = ttk.Scrollbar(frame, orient='vertical', command=text_widget.yview)
            text_widget.config(yscrollcommand=ysb.set)
            ysb.pack(side='right', fill='y'); text_widget.pack(side='left', expand=True, fill='both', padx=5, pady=5)
            
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1024 * 500)
                text_widget.insert('1.0', content)
            
            text_widget.config(state='disabled')
            self.preview_widget = frame
        except Exception as e:
            logging.error(f"Erro no preview de texto {path}: {e}"); self.hide_preview()

    def show_properties_window(self):
        selected_item_id = self.file_tree.focus()
        if not selected_item_id: return
        item_name = self.file_tree.item(selected_item_id, 'text')
        item_path = os.path.join(self.current_path, item_name)
        if not os.path.exists(item_path): return messagebox.showerror("Erro", "O item não existe mais.")
        try:
            stat_info = os.stat(item_path)
            properties = {'Nome': item_name}
            if os.path.isdir(item_path):
                properties['Tipo'] = "Pasta de arquivos"
                size_bytes, num_files, num_folders = get_folder_details(item_path)
                properties['Tamanho'] = format_size(size_bytes)
                properties['Contém'] = f"{num_files} arquivo(s), {num_folders} pasta(s)"
            else:
                properties['Tipo'] = f"Arquivo ({os.path.splitext(item_name)[1].upper() or 'Desconhecido'})"
                properties['Tamanho'] = format_size(stat_info.st_size)
            properties['Localização'] = self.current_path
            properties['Modificado em'] = datetime.fromtimestamp(stat_info.st_mtime).strftime('%d/%m/%Y, %H:%M:%S')
            properties['Criado em'] = datetime.fromtimestamp(stat_info.st_ctime).strftime('%d/%m/%Y, %H:%M:%S')
            PropertiesWindow(self.parent_frame, f"Propriedades de {item_name}", properties)
        except Exception as e: messagebox.showerror("Erro ao ler propriedades", f"Não foi possível obter os detalhes do item:\n{e}")

class BaseTab:
    def __init__(self, notebook, main_app, user_role, permission):
        self.parent_frame = ttk.Frame(notebook)
        self.main_app, self.user_role, self.permission = main_app, user_role, permission
    def create_button(self, parent, text, command, tooltip_text, state='normal'):
        button = ttk.Button(parent, text=text, command=command, state=state); button.pack(side='left', padx=5, pady=5)
        ToolTip(button, tooltip_text)
    def create_treeview(self, parent, columns):
        frame = ttk.Frame(parent); frame.pack(expand=True, fill='both')
        tree = ttk.Treeview(frame, columns=columns, show='tree headings'); tree.pack(side='left', expand=True, fill='both')
        ysb = ttk.Scrollbar(frame, orient='vertical', command=tree.yview); ysb.pack(side='right', fill='y')
        tree.configure(yscrollcommand=ysb.set)
        return tree
class TrashManagerTab(BaseTab):
    def __init__(self, notebook, main_app, user_role, permission):
        super().__init__(notebook, main_app, user_role, permission)
        main_frame = ttk.Frame(self.parent_frame); main_frame.pack(expand=True, fill='both', padx=10, pady=10)
        action_frame = ttk.Frame(main_frame); action_frame.pack(fill='x', pady=5)
        can_edit = self.permission == 'edit'
        self.create_button(action_frame, "Restaurar", self.restore_selected_item, "Devolve item ao local original.", 'normal' if can_edit else 'disabled')
        self.create_button(action_frame, "Excluir Perm.", self.delete_selected_item, "Apaga o item para sempre.", 'normal' if can_edit else 'disabled')
        self.create_button(action_frame, "Esvaziar Lixeira", self.empty_trash, "Apaga TODOS os itens.", 'normal' if can_edit else 'disabled')
        self.tree = self.create_treeview(main_frame, ("Local Original", "Data de Exclusão"))
        self.tree.heading("#0", text="Nome na Lixeira"); self.tree.column("#0", width=300)
        self.tree.heading("Local Original", text="Local Original"); self.tree.column("Local Original", width=450)
        self.tree.heading("Data de Exclusão", text="Data de Exclusão"); self.tree.column("Data de Exclusão", width=150, anchor='center')
        self.populate_list()
    def populate_list(self):
        self.tree.delete(*self.tree.get_children())
        sorted_items = sorted(read_metadata().get("trash", {}).items(), key=lambda i: i[1]['deleted_at'], reverse=True)
        for name, info in sorted_items:
            deleted_at = datetime.fromisoformat(info['deleted_at']).strftime('%d/%m/%Y %H:%M')
            self.tree.insert("", "end", text=f" {name}", values=(info.get('original_path', 'N/A'), deleted_at), iid=name)
    def restore_selected_item(self):
        selected = self.tree.focus()
        if not selected: return messagebox.showwarning("Nenhuma Seleção", "Selecione um item para restaurar.")
        metadata = read_metadata(); item_info = metadata["trash"].get(selected)
        if not item_info: return
        original_path = item_info["original_path"]
        os.makedirs(os.path.dirname(original_path), exist_ok=True)
        if os.path.exists(original_path): return messagebox.showerror("Erro", f"O caminho '{original_path}' já está ocupado.")
        try:
            shutil.move(os.path.join(TRASH_DIR, selected), original_path)
            del metadata["trash"][selected]; write_metadata(metadata)
            log_user_action(self.main_app.current_user, "RESTAURAÇÃO DE ITEM", f"Item '{selected}' restaurado para '{original_path}'")
            self.populate_list(); self.main_app.refresh_all_tabs(path_to_refresh=os.path.dirname(original_path))
        except Exception as e: messagebox.showerror("Erro ao Restaurar", f"Não foi possível restaurar o item:\n{e}")
    def delete_selected_item(self):
        selected = self.tree.focus()
        if not selected: return messagebox.showwarning("Nenhuma Seleção", "Selecione um item para excluir.")
        if not messagebox.askyesno("Confirmar Exclusão", f"Excluir '{selected}' permanentemente?"): return
        log_user_action(self.main_app.current_user, "EXCLUSÃO PERMANENTE DA LIXEIRA", f"Item: '{selected}'")
        if self.delete_item_permanently(selected): self.populate_list()
    def empty_trash(self):
        if not read_metadata().get("trash"): return messagebox.showinfo("Lixeira", "A lixeira já está vazia.")
        if not messagebox.askyesno("Confirmar Esvaziar", "Excluir TODOS os itens da lixeira permanentemente?"): return
        log_user_action(self.main_app.current_user, "ESVAZIAMENTO DA LIXEIRA", "Todos os itens excluídos.")
        for item_name in list(read_metadata().get("trash", {}).keys()): self.delete_item_permanently(item_name)
        self.populate_list(); messagebox.showinfo("Sucesso", "A lixeira foi esvaziada.")
    @staticmethod
    def delete_item_permanently(trash_item_name):
        try:
            trash_path = os.path.join(TRASH_DIR, trash_item_name)
            if os.path.isdir(trash_path): shutil.rmtree(trash_path)
            elif os.path.isfile(trash_path): os.remove(trash_path)
            metadata = read_metadata()
            if "trash" in metadata and trash_item_name in metadata["trash"]:
                del metadata["trash"][trash_item_name]; write_metadata(metadata)
            logging.info(f"Item excluído permanentemente: {trash_item_name}")
            return True
        except Exception as e:
            logging.error(f"Falha ao excluir permanentemente '{trash_item_name}': {e}"); return False
class SpreadsheetManagerTab(BaseTab):
    def __init__(self, notebook, main_app, user_role, permission):
        super().__init__(notebook, main_app, user_role, permission)
        main_frame = ttk.Frame(self.parent_frame); main_frame.pack(expand=True, fill='both', padx=10, pady=10)
        action_frame = ttk.Frame(main_frame); action_frame.pack(fill='x', pady=5)
        can_edit = self.permission == 'edit'
        self.create_button(action_frame, "Nova Planilha", self.create_new_spreadsheet, "Cria um novo arquivo Excel.", 'normal' if can_edit else 'disabled')
        self.create_button(action_frame, "Carregar Planilha(s)", self.upload_spreadsheet, "Copia planilhas para a pasta do sistema.", 'normal' if can_edit else 'disabled')
        self.create_button(action_frame, "Abrir", self.open_spreadsheet, "Abre a planilha selecionada.")
        self.create_button(action_frame, "Excluir", self.delete_spreadsheet, "Move a planilha para a lixeira.", 'normal' if can_edit else 'disabled')
        self.tree = self.create_treeview(main_frame, ("Tamanho", "Modificado em"))
        self.tree.heading("#0", text="Nome do Arquivo"); self.tree.column("#0", width=350)
        self.tree.heading("Tamanho", text="Tamanho (KB)"); self.tree.column("Tamanho", width=120, anchor='e')
        self.tree.heading("Modificado em", text="Modificado em"); self.tree.column("Modificado em", width=150, anchor='center')
        self.tree.bind('<Double-1>', lambda e: self.open_spreadsheet())
        self.populate_list()
    def populate_list(self):
        self.tree.delete(*self.tree.get_children())
        try:
            for filename in sorted(os.listdir(SPREADSHEETS_DIR)):
                if filename.lower().endswith(('.xlsx', '.csv')):
                    path = os.path.join(SPREADSHEETS_DIR, filename); stat = os.stat(path)
                    self.tree.insert("", "end", text=f" {filename}", values=(f"{stat.st_size/1024:.2f}", datetime.fromtimestamp(stat.st_mtime).strftime('%d/%m/%Y %H:%M')))
        except Exception as e: logging.error(f"Erro ao listar planilhas: {e}")
    
    def upload_spreadsheet(self):
        files = filedialog.askopenfilenames(title="Selecione as planilhas", filetypes=[("Planilhas", "*.xlsx;*.csv"), ("Todos", "*.*")])
        if not files: return
        uploaded_count = 0
        for file_path in files:
            dest_path = os.path.join(SPREADSHEETS_DIR, os.path.basename(file_path))
            if os.path.exists(dest_path) and not messagebox.askyesno("Arquivo Existente", f"'{os.path.basename(file_path)}' já existe.\nDeseja sobrescrevê-lo?"):
                continue
            try:
                shutil.copy(file_path, dest_path)
                log_user_action(self.main_app.current_user, "UPLOAD DE PLANILHA", f"De: '{file_path}' Para: '{dest_path}'")
                uploaded_count += 1
            except Exception as e: messagebox.showerror("Erro no Upload", f"Falha ao carregar '{os.path.basename(file_path)}':\n{e}")
        if uploaded_count > 0:
            messagebox.showinfo("Sucesso", f"{uploaded_count} planilha(s) carregada(s) com sucesso."); self.populate_list()

    def create_new_spreadsheet(self):
        if not openpyxl: return messagebox.showerror("Dependência Faltando", "'openpyxl' é necessária.")
        filename = simpledialog.askstring("Nova Planilha", "Nome do arquivo (sem extensão):")
        if not filename or not filename.strip(): return
        path = os.path.join(SPREADSHEETS_DIR, f"{filename}.xlsx")
        if os.path.exists(path): return messagebox.showwarning("Arquivo Existente", "Um arquivo com este nome já existe.")
        try:
            openpyxl.Workbook().save(path)
            log_user_action(self.main_app.current_user, "CRIAÇÃO DE PLANILHA", f"Planilha: '{path}'")
            self.populate_list()
            if messagebox.askyesno("Abrir", "Deseja abri-la agora?"): open_file_with_default_app(path)
        except Exception as e: messagebox.showerror("Erro", f"Não foi possível criar a planilha:\n{e}")
    def open_spreadsheet(self):
        selected = self.tree.focus()
        if not selected: return
        filepath = os.path.join(SPREADSHEETS_DIR, self.tree.item(selected, 'text').strip())
        open_file_with_default_app(filepath)
        log_user_action(self.main_app.current_user, "ABERTURA DE PLANILHA", f"Planilha: '{filepath}'")
    def delete_spreadsheet(self):
        selected = self.tree.focus()
        if not selected: return
        filename = self.tree.item(selected, 'text').strip()
        if not messagebox.askyesno("Confirmar", f"Mover '{filename}' para a lixeira?"): return
        try:
            item_path = os.path.join(SPREADSHEETS_DIR, filename)
            trash_item_name = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
            shutil.move(item_path, os.path.join(TRASH_DIR, trash_item_name))
            metadata = read_metadata()
            metadata.setdefault("trash", {})[trash_item_name] = {"original_path": item_path, "deleted_at": datetime.now().isoformat()}; write_metadata(metadata)
            log_user_action(self.main_app.current_user, "EXCLUSÃO DE PLANILHA", f"Planilha movida para lixeira: '{item_path}'")
            self.populate_list()
            if "Lixeira" in self.main_app.tabs: self.main_app.tabs["Lixeira"].populate_list()
        except Exception as e: messagebox.showerror("Erro ao Excluir", f"Não foi possível mover a planilha:\n{e}")
class UserManagementTab(BaseTab):
    def __init__(self, notebook, main_app):
        super().__init__(notebook, main_app, 'admin', 'edit')
        main_frame = ttk.Frame(self.parent_frame); main_frame.pack(expand=True, fill='both', padx=10, pady=10)
        action_frame = ttk.Frame(main_frame); action_frame.pack(fill='x', pady=5)
        self.create_button(action_frame, "Adicionar Usuário", self.add_user, "Adiciona um novo usuário.")
        self.edit_perms_button = self.create_button(action_frame, "Editar Permissões", self.edit_user_permissions, "Edita permissões.", state='disabled')
        self.create_button(action_frame, "Remover Usuário", self.remove_user, "Remove o usuário.")
        self.tree = self.create_treeview(main_frame, ("Função",))
        self.tree.heading("#0", text="Nome de Usuário"); self.tree.column("#0", width=300)
        self.tree.heading("Função", text="Função"); self.tree.column("Função", width=150, anchor='center')
        self.tree.bind('<<TreeviewSelect>>', self.on_user_select)
        self.populate_user_list()
    def on_user_select(self, event):
        selected = self.tree.focus()
        if not selected: return self.edit_perms_button.config(state='disabled')
        user_data = read_users().get(selected, {})
        self.edit_perms_button.config(state='normal' if user_data.get("role") != "admin" else 'disabled')
    def add_user(self): PermissionsEditorWindow(self.parent_frame, self)
    def edit_user_permissions(self):
        selected = self.tree.focus()
        if selected: PermissionsEditorWindow(self.parent_frame, self, username=selected)
    def populate_user_list(self):
        self.tree.delete(*self.tree.get_children())
        for username, data in read_users().items():
            self.tree.insert("", "end", text=username, values=(data.get('role', 'N/A'),), iid=username)
        self.edit_perms_button.config(state='disabled')
    def remove_user(self):
        selected = self.tree.focus()
        if not selected: return messagebox.showwarning("Nenhuma Seleção", "Selecione um usuário para remover.")
        if selected == self.main_app.current_user: return messagebox.showerror("Erro", "Não é possível remover o usuário logado.")
        users = read_users()
        if users.get(selected, {}).get("role") == "admin": return messagebox.showerror("Erro", "Contas de administrador não podem ser removidas.")
        if not messagebox.askyesno("Confirmar Remoção", f"Tem certeza que deseja remover o usuário '{selected}'?"): return
        if selected in users:
            del users[selected]; write_users(users)
            log_user_action(self.main_app.current_user, "REMOÇÃO DE USUÁRIO", f"Usuário '{selected}' foi removido.")
            self.populate_user_list(); messagebox.showinfo("Sucesso", f"Usuário '{selected}' removido.")
class PermissionsEditorWindow(Toplevel):
    def __init__(self, parent, user_mgmt_tab, username=None):
        super().__init__(parent)
        self.user_mgmt_tab, self.username, self.is_new_user = user_mgmt_tab, username, username is None
        self.title("Editar Permissões" if not self.is_new_user else "Adicionar Usuário")
        self.transient(parent); self.grab_set()
        
        self.permission_vars, self.role_var = {}, StringVar(value='user')
        self.users_data = read_users()
        current_perms = self.users_data.get(self.username, {}).get("permissions", {})

        details_frame = ttk.LabelFrame(self, text="Detalhes", padding=10); details_frame.pack(padx=10, pady=10, fill="x")
        ttk.Label(details_frame, text="Usuário:").grid(row=0, column=0, sticky='w', pady=2)
        self.username_entry = ttk.Entry(details_frame, width=40); self.username_entry.grid(row=0, column=1, pady=2)
        if not self.is_new_user: self.username_entry.insert(0, self.username); self.username_entry.config(state='readonly')
        ttk.Label(details_frame, text="Senha:").grid(row=1, column=0, sticky='w', pady=2)
        self.password_entry = ttk.Entry(details_frame, width=40, show="*"); self.password_entry.grid(row=1, column=1, pady=2)
        if not self.is_new_user: self.password_entry.insert(0, "(não alterada)")
        ttk.Label(details_frame, text="Função:").grid(row=2, column=0, sticky='w', pady=2)
        self.role_combobox = ttk.Combobox(details_frame, textvariable=self.role_var, values=['user', 'admin'], state='readonly'); self.role_combobox.grid(row=2, column=1, sticky='ew', pady=2)
        if not self.is_new_user: self.role_combobox.set(self.users_data.get(self.username, {}).get("role", "user")); self.role_combobox.config(state='disabled')

        self.permissions_frame = ttk.LabelFrame(self, text="Permissões", padding=10); self.permissions_frame.pack(padx=10, pady=10, fill="x")
        perm_map = {"edit": "Edição", "view": "Visualização", "none": "Nenhum"}
        rev_perm_map = {v: k for k, v in perm_map.items()}
        for i, tab_name in enumerate(MANAGEABLE_TABS):
            ttk.Label(self.permissions_frame, text=f"{tab_name}:").grid(row=i, column=0, sticky='w', padx=2, pady=2)
            perm_var = StringVar(); cb = ttk.Combobox(self.permissions_frame, textvariable=perm_var, values=list(perm_map.values()), state='readonly')
            cb.set(perm_map[current_perms.get(tab_name, 'none')]); cb.grid(row=i, column=1, sticky='ew', padx=2, pady=2)
            self.permission_vars[tab_name] = (perm_var, rev_perm_map)

        action_frame = ttk.Frame(self); action_frame.pack(pady=10)
        ttk.Button(action_frame, text="Salvar", command=self.save).pack(side='left', padx=10)
        ttk.Button(action_frame, text="Cancelar", command=self.destroy).pack(side='left', padx=10)
        self.role_var.trace_add('write', self.toggle_permissions_frame); self.toggle_permissions_frame()
    def toggle_permissions_frame(self, *args):
        state = 'disabled' if self.role_var.get() == 'admin' else 'normal'
        for child in self.permissions_frame.winfo_children(): child.config(state=state)
    def save(self):
        if self.is_new_user:
            new_user = self.username_entry.get().strip(); new_pass = self.password_entry.get(); new_role = self.role_var.get()
            if not new_user or not new_pass: return messagebox.showerror("Erro", "Usuário e senha são obrigatórios.", parent=self)
            if new_user in self.users_data: return messagebox.showerror("Erro", "Nome de usuário já existe.", parent=self)
            self.username = new_user
            self.users_data[self.username] = {"password": hash_password(new_pass), "role": new_role, "permissions": {}}
            log_user_action(self.user_mgmt_tab.main_app.current_user, "CRIAÇÃO DE USUÁRIO", f"Usuário: '{new_user}', Função: '{new_role}'")
        else:
            if self.password_entry.get() != "(não alterada)":
                self.users_data[self.username]["password"] = hash_password(self.password_entry.get())
                log_user_action(self.user_mgmt_tab.main_app.current_user, "ALTERAÇÃO DE SENHA (ADMIN)", f"Senha alterada para o usuário '{self.username}'")
        
        if self.users_data[self.username]['role'] != 'admin':
            new_perms = {tab: r_map[p_var.get()] for tab, (p_var, r_map) in self.permission_vars.items()}
            self.users_data[self.username]["permissions"] = new_perms
        else: self.users_data[self.username]["permissions"] = {}
        
        write_users(self.users_data)
        log_user_action(self.user_mgmt_tab.main_app.current_user, "ATUALIZAÇÃO DE PERMISSÕES", f"Permissões salvas para '{self.username}'")
        messagebox.showinfo("Sucesso", f"Dados para '{self.username}' salvos.", parent=self)
        self.user_mgmt_tab.populate_user_list(); self.destroy()

if __name__ == "__main__":
    missing_deps = []
    if not fitz: missing_deps.append("PyMuPDF (preview de PDF)")
    if not ezdxf or not plt: missing_deps.append("ezdxf e matplotlib (preview de DXF)")
    if not openpyxl: missing_deps.append("openpyxl (criar .xlsx)")
    if missing_deps:
        msg = "Atenção: Dependências opcionais não encontradas:\n\n" + "\n".join(f"- {dep}" for dep in missing_deps)
        root = Tk(); root.withdraw(); messagebox.showwarning("Dependências Opcionais", msg); root.destroy()

    setup_environment()
    app = FileManagerApp()
    app.mainloop()