import os
import shutil
import json
import logging
import platform
import subprocess
import threading
import time
import hashlib
from datetime import datetime, timedelta
from tkinter import (Tk, Toplevel, Label, Entry, Button, Frame, Scrollbar, messagebox,
                     filedialog, simpledialog, PhotoImage, Canvas, StringVar, Menu)
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
AUDIT_LOG_FILE = os.path.join(ROOT_DIR, "audit_log.txt") # <-- NOVO
COMPANY_DIRS = ["Desenhos", "Empresas", "Orçamentos", "Projetos Testes"]
MANAGEABLE_TABS = COMPANY_DIRS + ["Planilhas", "Lixeira"]


# --- Funções de Segurança e Usuário ---
def hash_password(password):
    """Gera um hash seguro para a senha com um salt."""
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt.hex() + ':' + key.hex()

def verify_password(stored_password, provided_password):
    """Verifica se a senha fornecida corresponde ao hash armazenado."""
    if not stored_password or ':' not in stored_password:
        return False
    try:
        salt_hex, key_hex = stored_password.split(':')
        salt = bytes.fromhex(salt_hex)
        key_from_storage = bytes.fromhex(key_hex)
        new_key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
        return key_from_storage == new_key
    except (ValueError, TypeError, AttributeError):
        return False

def read_users():
    """Lê o arquivo de usuários."""
    if not os.path.exists(USERS_FILE): return {}
    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def write_users(data):
    """Escreve no arquivo de usuários."""
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

# --- Funções Auxiliares e de Configuração ---
def setup_environment(): # <-- MODIFICADO
    """Garante que a estrutura de diretórios e arquivos essenciais exista."""
    os.makedirs(ROOT_DIR, exist_ok=True)
    os.makedirs(TRASH_DIR, exist_ok=True)
    os.makedirs(SPREADSHEETS_DIR, exist_ok=True)
    for dir_name in COMPANY_DIRS:
        os.makedirs(os.path.join(ROOT_DIR, dir_name), exist_ok=True)
    if not os.path.exists(METADATA_FILE):
        with open(METADATA_FILE, 'w', encoding='utf-8') as f:
            json.dump({"next_company_id": 1, "trash": {}}, f, indent=4)
    if not os.path.exists(USERS_FILE):
        admin_user = "Draco182019"
        admin_pass = "Draco182019"
        users = {
            admin_user: {
                "password": hash_password(admin_pass),
                "role": "admin"
            }
        }
        write_users(users)

    # Configuração do Log de Aplicação (para depuração)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s',
                        handlers=[logging.FileHandler(LOG_FILE, 'a', 'utf-8'), logging.StreamHandler()])
    logging.info("Aplicação iniciada e ambiente verificado.")

    # Configuração do Log de Auditoria (para ações do usuário)
    audit_logger = logging.getLogger('AuditLogger')
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False
    audit_handler = logging.FileHandler(AUDIT_LOG_FILE, 'a', 'utf-8')
    audit_formatter = logging.Formatter('%(asctime)s - [USUÁRIO: %(user)s] - %(message)s', datefmt='%d/%m/%Y %H:%M:%S')
    audit_handler.setFormatter(audit_formatter)
    if not audit_logger.hasHandlers():
        audit_logger.addHandler(audit_handler)

def log_user_action(username, action, details=""): # <-- NOVO
    """Registra uma ação do usuário no log de auditoria."""
    logger = logging.getLogger('AuditLogger')
    log_record = {'user': username or "Sistema"}
    logger.info(f"{action} - {details}", extra=log_record)

def read_metadata():
    """Lê o arquivo de metadados."""
    try:
        with open(METADATA_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"next_company_id": 1, "trash": {}}

def write_metadata(data):
    """Escreve no arquivo de metadados."""
    with open(METADATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def open_file_with_default_app(filepath):
    """Abre um arquivo com o aplicativo padrão do sistema operacional."""
    try:
        if platform.system() == "Windows":
            os.startfile(filepath)
        elif platform.system() == "Darwin":  # macOS
            subprocess.Popen(["open", filepath])
        else:  # Linux
            subprocess.Popen(["xdg-open", filepath])
        logging.info(f"Arquivo aberto: {filepath}")
    except Exception as e:
        messagebox.showerror("Erro ao Abrir", f"Não foi possível abrir o arquivo:\n{e}")
        logging.error(f"Falha ao abrir o arquivo {filepath}: {e}")

class ToolTip:
    """Cria uma tooltip para um widget."""
    def __init__(self, widget, text):
        self.widget, self.text, self.tooltip_window = widget, text, None
        self.widget.bind("<Enter>", self.show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)
    def show_tooltip(self, event=None):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 20
        self.tooltip_window = Toplevel(self.widget)
        self.tooltip_window.wm_overrideredirect(True)
        self.tooltip_window.wm_geometry(f"+{x}+{y}")
        label = Label(self.tooltip_window, text=self.text, justify='left', background="#ffffe0", relief='solid', borderwidth=1, font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)
    def hide_tooltip(self, event=None):
        if self.tooltip_window:
            self.tooltip_window.destroy()
        self.tooltip_window = None

# --- Classe Principal da Aplicação ---
class FileManagerApp(Tk):
    def __init__(self):
        super().__init__()
        self.title("Sistema de Gerenciamento de Arquivos v5.2")
        self.geometry("1280x800")
        self.minsize(1024, 768)
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        style = ttk.Style(self)
        style.theme_use('clam')

        self.current_user = None
        self.user_role = None
        self.user_permissions = {}
        
        self.container = ttk.Frame(self)
        self.container.pack(expand=True, fill='both')

        self.show_login_frame()

    def show_login_frame(self):
        for widget in self.container.winfo_children():
            widget.destroy()
        self.title("Sistema de Gerenciamento de Arquivos v5.2 - Login")
        self.login_frame = LoginFrame(self.container, self)
        self.login_frame.pack(expand=True)
        
    def attempt_login(self, username, password):
        users = read_users()
        user_data = users.get(username)
        if user_data and verify_password(user_data.get("password"), password):
            self.current_user = username
            self.user_role = user_data.get("role", "user")
            if self.user_role == 'admin':
                self.user_permissions = {tab: 'edit' for tab in MANAGEABLE_TABS}
            else:
                self.user_permissions = user_data.get("permissions", {})

            logging.info(f"Login bem-sucedido para o usuário '{username}' com função '{self.user_role}'.")
            log_user_action(self.current_user, "LOGIN SUCESSO", f"Usuário '{username}' logou no sistema.") # <-- MODIFICADO
            self.show_main_app_frame()
        else:
            messagebox.showerror("Falha no Login", "Nome de usuário ou senha incorretos.")
            logging.warning(f"Tentativa de login falhou para o usuário '{username}'.")
            log_user_action(username, "LOGIN FALHA", f"Tentativa de login com usuário '{username}'.") # <-- MODIFICADO


    def show_main_app_frame(self):
        for widget in self.container.winfo_children():
            widget.destroy()
        self.title(f"Sistema de Gerenciamento de Arquivos v5.2 - Logado como: {self.current_user} ({self.user_role})")
        
        self.notebook = ttk.Notebook(self.container)
        self.notebook.pack(expand=True, fill='both', padx=5, pady=5)

        self.tabs = {}
        self.create_tabs()

        self.trash_cleanup_thread = threading.Thread(target=self.periodic_trash_cleanup, daemon=True)
        self.trash_cleanup_thread.start()

    def create_tabs(self):
        lixeira_perm = self.user_permissions.get("Lixeira", "none")
        if lixeira_perm != "none":
            trash_frame = Frame(self.notebook, bg="#f0f0f0")
            self.notebook.add(trash_frame, text="🗑️ Lixeira")
            self.tabs["Lixeira"] = TrashManagerTab(trash_frame, self, self.user_role, lixeira_perm)

        planilhas_perm = self.user_permissions.get("Planilhas", "none")
        if planilhas_perm != "none":
            spreadsheets_frame = Frame(self.notebook, bg="#f0f0f0")
            self.notebook.add(spreadsheets_frame, text="📊 Planilhas")
            self.tabs["Planilhas"] = SpreadsheetManagerTab(spreadsheets_frame, self, self.user_role, planilhas_perm)
        
        for dir_name in COMPANY_DIRS:
            perm = self.user_permissions.get(dir_name, "none")
            if perm == "none":
                continue
            
            path = os.path.join(ROOT_DIR, dir_name)
            if os.path.isdir(path):
                tab_frame = Frame(self.notebook, bg="#f0f0f0")
                self.notebook.add(tab_frame, text=f"📂 {dir_name}")
                self.tabs[dir_name] = FileBrowserTab(tab_frame, self, path, self.user_role, perm)
        
        if self.user_role == 'admin':
            user_mgmt_frame = Frame(self.notebook, bg="#f0f0f0")
            self.notebook.add(user_mgmt_frame, text="👤 Gerenciar Usuários")
            self.tabs["UserManagement"] = UserManagementTab(user_mgmt_frame, self)

    def refresh_all_tabs(self, refresh_companies=False): # <-- MODIFICADO
        for tab in self.tabs.values():
            if hasattr(tab, 'populate_file_tree') and callable(tab.populate_file_tree):
                if refresh_companies and hasattr(tab, 'populate_company_tree'):
                    tab.populate_company_tree()
                tab.populate_file_tree(tab.current_path)

            elif hasattr(tab, 'populate_list') and callable(tab.populate_list):
                 tab.populate_list()


    def on_closing(self):
        if messagebox.askokcancel("Sair", "Deseja realmente sair da aplicação?"):
            logging.info("Aplicação encerrada pelo usuário.")
            if self.current_user:
                log_user_action(self.current_user, "LOGOUT", "Usuário fechou a aplicação.")
            self.destroy()

    def periodic_trash_cleanup(self):
        while True:
            time.sleep(3600)
            if self.user_role != 'admin': continue
            
            logging.info("Verificando a lixeira para limpeza automática...")
            metadata = read_metadata()
            thirty_days_ago = datetime.now() - timedelta(days=30)
            items_to_remove = [name for name, info in metadata.get("trash", {}).items()
                               if datetime.fromisoformat(info["deleted_at"]) < thirty_days_ago]
            
            if not items_to_remove: continue
            
            log_user_action("Sistema", "LIMPEZA AUTOMÁTICA LIXEIRA", f"Itens com mais de 30 dias excluídos: {items_to_remove}") # <-- NOVO
            for item_name in items_to_remove:
                TrashManagerTab.delete_item_permanently(item_name) # <-- MODIFICADO (sem log individual aqui)
            
            trash_tab = self.tabs.get("Lixeira")
            if trash_tab and trash_tab.parent_frame.winfo_exists():
                trash_tab.populate_list()

# --- Classe da Tela de Login ---
class LoginFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        frame = ttk.Frame(self, padding="20 40")
        frame.grid(row=0, column=0)
        ttk.Label(frame, text="Login do Sistema", font=("Helvetica", 16, "bold")).grid(row=0, column=0, columnspan=2, pady=10, sticky="ew")
        ttk.Label(frame, text="Usuário:", font=("Helvetica", 11)).grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.username_entry = ttk.Entry(frame, width=30, font=("Helvetica", 11))
        self.username_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=5)
        self.username_entry.focus()
        ttk.Label(frame, text="Senha:", font=("Helvetica", 11)).grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.password_entry = ttk.Entry(frame, width=30, show="*", font=("Helvetica", 11))
        self.password_entry.grid(row=2, column=1, sticky="ew", padx=5, pady=5)
        self.password_entry.bind("<Return>", lambda e: self.login_button.invoke())
        self.login_button = ttk.Button(frame, text="Entrar", command=self.on_login_click)
        self.login_button.grid(row=3, column=0, columnspan=2, pady=20, sticky="ew")

    def on_login_click(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if not username or not password:
            messagebox.showwarning("Campos Vazios", "Por favor, preencha o usuário e a senha.")
            return
        self.controller.attempt_login(username, password)

# --- Classe para Abas de Navegação de Arquivos ---
class FileBrowserTab:
    def __init__(self, parent_frame, main_app, base_path, user_role, permission):
        self.parent_frame = parent_frame
        self.main_app = main_app
        self.base_path = base_path
        self.user_role = user_role
        self.permission = permission
        self.history = [self.base_path]
        self.current_path = self.base_path
        self.preview_widget = None
        self._all_file_tree_items = []
        self.load_icons()
        self.paned_window = ttk.PanedWindow(parent_frame, orient='horizontal')
        self.paned_window.pack(expand=True, fill='both')
        self.left_frame = ttk.Frame(self.paned_window, width=350)
        self.paned_window.add(self.left_frame, weight=1)
        self.company_tree_frame = ttk.Frame(self.left_frame)
        self.company_tree_frame.pack(expand=True, fill='both')
        ttk.Label(self.company_tree_frame, text="Empresas", font=("Helvetica", 10, "bold")).pack(pady=5)
        self.company_tree = self.create_treeview(self.company_tree_frame, columns=("ID", "Nome"))
        self.company_tree.heading("ID", text="ID"); self.company_tree.heading("Nome", text="Nome")
        self.company_tree.column("#0", width=0, stretch=False)
        self.company_tree.column("ID", width=60, anchor='center')
        self.company_tree.bind('<<TreeviewSelect>>', self.on_company_select)
        self.preview_frame = ttk.Frame(self.left_frame)
        self.right_frame = ttk.Frame(self.paned_window)
        self.paned_window.add(self.right_frame, weight=3)
        self.action_frame = self.create_action_buttons(self.right_frame)
        self.action_frame.pack(fill='x', pady=5)
        self.nav_frame = ttk.Frame(self.right_frame)
        self.nav_frame.pack(fill='x', pady=(0, 5))
        self.back_button = self.create_button(self.nav_frame, '◀ Voltar', self.go_back, "Voltar")
        self.up_button = self.create_button(self.nav_frame, '▲ Acima', self.go_up, "Pasta pai")
        self.current_path_label = ttk.Label(self.nav_frame, text="", relief="sunken", anchor="w", padding=5)
        self.current_path_label.pack(side='left', fill='x', expand=True, padx=5)
        search_frame = ttk.Frame(self.right_frame)
        search_frame.pack(fill='x', padx=5, pady=(5,0))
        ttk.Label(search_frame, text="🔎 Pesquisar:").pack(side='left', padx=(0,5))
        self.search_var = StringVar()
        self.search_var.trace_add("write", self.filter_files)
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        self.search_entry.pack(side='left', fill='x', expand=True)
        self.file_tree_frame = ttk.Frame(self.right_frame)
        self.file_tree_frame.pack(expand=True, fill='both')
        self.file_tree = self.create_treeview(self.file_tree_frame, columns=("Tipo", "Modificado em"))
        self.file_tree.heading("#0", text="Nome")
        self.file_tree.heading("Tipo", text="Tipo"); self.file_tree.heading("Modificado em", text="Modificado em")
        self.file_tree.column("Tipo", width=100, anchor='center')
        self.file_tree.column("Modificado em", width=150, anchor='center')
        self.file_tree.bind('<Double-1>', self.on_item_double_click)
        self.file_tree.bind('<<TreeviewSelect>>', self.on_file_select)
        self.file_tree.bind('<Button-3>', self.show_context_menu)
        self.populate_company_tree()
        self.populate_file_tree(self.base_path)

    def create_action_buttons(self, parent): # <-- MODIFICADO
        frame = ttk.Frame(parent)
        is_admin = self.user_role == 'admin'
        can_edit = self.permission == 'edit'
        
        self.create_button(frame, "Nova Empresa", self.create_new_company, "Cria estrutura de pastas para uma empresa.", state='normal' if is_admin else 'disabled')
        # Apenas a aba "Desenhos" terá o botão de excluir, para evitar repetição
        if self.base_path.endswith("Desenhos"):
            self.create_button(frame, "Excluir Empresa", self.delete_company, "Exclui PERMANENTEMENTE uma empresa e todos os seus arquivos.", state='normal' if is_admin else 'disabled')
        
        self.create_button(frame, "Nova Subpasta", self.create_new_subfolder, "Cria uma subpasta no local atual.", state='normal' if can_edit else 'disabled')
        self.create_button(frame, "Carregar Arquivo(s)", self.upload_files, "Carrega arquivos para a pasta atual.", state='normal' if can_edit else 'disabled')
        self.create_button(frame, "Carregar Pasta", self.upload_folder, "Carrega uma pasta e seu conteúdo.", state='normal' if can_edit else 'disabled')
        self.create_button(frame, "Excluir Item", self.delete_item, "Move o item para a lixeira.", state='normal' if can_edit else 'disabled')
        return frame
    
    def show_context_menu(self, event):
        item_id = self.file_tree.identify_row(event.y)
        if not item_id: return
        self.file_tree.selection_set(item_id)
        can_edit = self.permission == 'edit'
        menu = Menu(self.file_tree, tearoff=0)
        menu.add_command(label="Abrir", command=self.on_item_double_click)
        if can_edit:
            menu.add_command(label="Renomear", command=self.rename_item)
            menu.add_separator()
            menu.add_command(label="Excluir para Lixeira", command=self.delete_item)
        menu.tk_popup(event.x_root, event.y_root)
    
    def load_icons(self):
        try:
            self.icon_folder = ImageTk.PhotoImage(Image.new('RGBA', (16, 16), (255, 193, 7, 255)))
            self.icon_file = ImageTk.PhotoImage(Image.new('RGBA', (16, 16), (33, 150, 243, 255)))
            self.icon_pdf = ImageTk.PhotoImage(Image.new('RGBA', (16, 16), (244, 67, 54, 255)))
            self.icon_img = ImageTk.PhotoImage(Image.new('RGBA', (16, 16), (76, 175, 80, 255)))
            self.icon_dxf = ImageTk.PhotoImage(Image.new('RGBA', (16, 16), (156, 39, 176, 255)))
        except Exception:
            self.icon_folder = self.icon_file = self.icon_pdf = self.icon_img = self.icon_dxf = None

    def get_icon(self, filename):
        if self.icon_folder is None: return None
        ext = os.path.splitext(filename)[1].lower()
        if ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp']: return self.icon_img
        if ext == '.pdf': return self.icon_pdf
        if ext == '.dxf': return self.icon_dxf
        return self.icon_file
    
    def create_treeview(self, parent, columns):
        frame = ttk.Frame(parent)
        frame.pack(expand=True, fill='both')
        tree = ttk.Treeview(frame, columns=columns)
        tree.pack(side='left', expand=True, fill='both')
        scrollbar_y = ttk.Scrollbar(frame, orient='vertical', command=tree.yview)
        scrollbar_y.pack(side='right', fill='y')
        tree.configure(yscrollcommand=scrollbar_y.set)
        tree['show'] = 'tree headings'
        return tree
    
    def create_button(self, parent, text, command, tooltip_text, state='normal'):
        button = ttk.Button(parent, text=text, command=command, state=state)
        button.pack(side='left', padx=2)
        ToolTip(button, tooltip_text)
        return button

    def populate_company_tree(self):
        self.clear_tree(self.company_tree)
        try:
            # A lista de empresas é a mesma em todas as abas, então pegamos de um diretório base
            company_base_dir = os.path.join(ROOT_DIR, COMPANY_DIRS[0])
            for item in os.listdir(company_base_dir):
                if os.path.isdir(os.path.join(company_base_dir, item)):
                    parts = item.split("_", 1)
                    if len(parts) == 2:
                        self.company_tree.insert("", "end", values=parts, tags=('company',), iid=item)
        except Exception as e:
            logging.error(f"Erro ao listar empresas em {self.base_path}: {e}")

    def populate_file_tree(self, path):
        self.current_path = path
        if not self.history or self.history[-1] != path:
            self.history.append(path)
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
                if os.path.isdir(full_path):
                    item_id = self.file_tree.insert("", "end", text=name, values=("[Pasta]", ""), tags=('folder',), image=self.icon_folder)
                else:
                    mod_time = datetime.fromtimestamp(os.path.getmtime(full_path)).strftime('%d/%m/%Y %H:%M')
                    file_ext = os.path.splitext(name)[1].upper() or "Arquivo"
                    icon = self.get_icon(name)
                    item_id = self.file_tree.insert("", "end", text=name, values=(file_ext, mod_time), tags=('file',), image=icon)
                self._all_file_tree_items.append(item_id)
        except Exception as e:
            messagebox.showerror("Erro de Acesso", f"Não foi possível acessar:\n{e}")
            self.go_back()

    def update_nav_state(self):
        self.back_button.config(state='normal' if len(self.history) > 1 else 'disabled')
        is_root_of_tab = os.path.normpath(self.current_path) == os.path.normpath(self.base_path)
        self.up_button.config(state='disabled' if is_root_of_tab else 'normal')

    def clear_tree(self, tree):
        tree.delete(*tree.get_children())
    
    def filter_files(self, *args):
        search_term = self.search_var.get().lower()
        for item_id in self.file_tree.get_children(): # Re-attach all first
            if item_id not in self._all_file_tree_items:
                 self.file_tree.move(item_id, '', 'end')

        if not search_term: return

        for item_id in self._all_file_tree_items:
            if self.file_tree.exists(item_id):
                if search_term not in self.file_tree.item(item_id, 'text').lower():
                    self.file_tree.detach(item_id)
                    
    def create_new_company(self):
        company_name = simpledialog.askstring("Nova Empresa", "Digite o nome da empresa:")
        if not company_name or not company_name.strip(): return
        metadata = read_metadata()
        company_id = metadata.get("next_company_id", 1)
        folder_name = f"{company_id:06d}_{company_name.strip()}"
        try:
            for dir_name in COMPANY_DIRS:
                os.makedirs(os.path.join(ROOT_DIR, dir_name, folder_name), exist_ok=True)
            metadata["next_company_id"] = company_id + 1
            write_metadata(metadata)
            log_user_action(self.main_app.current_user, "CRIAÇÃO DE EMPRESA", f"Empresa: '{folder_name}'") # <-- NOVO
            messagebox.showinfo("Sucesso", f"Empresa '{company_name}' criada.")
            self.main_app.refresh_all_tabs(refresh_companies=True) # <-- MODIFICADO
        except Exception as e:
            messagebox.showerror("Erro", f"Não foi possível criar a empresa:\n{e}")

    def delete_company(self): # <-- NOVO
        selected_item = self.company_tree.focus()
        if not selected_item:
            messagebox.showwarning("Nenhuma Seleção", "Selecione uma empresa na lista à esquerda para excluir.")
            return

        company_folder_name = selected_item
        _, company_name = company_folder_name.split("_", 1)
        
        # Confirmação 1
        if not messagebox.askyesno("Confirmar Exclusão", 
            f"Você está prestes a excluir PERMANENTEMENTE a empresa '{company_name}' e TODOS os seus arquivos em todas as seções (Desenhos, Orçamentos, etc.).\n\nESTA AÇÃO NÃO PODE SER DESFEITA.\n\nDeseja continuar?"):
            return

        # Confirmação 2 (digitar nome)
        prompt = f"Para confirmar a exclusão permanente, digite o nome da empresa exatamente como mostrado abaixo:\n\n{company_name}"
        confirmed_name = simpledialog.askstring("Confirmação Final de Exclusão", prompt)

        if confirmed_name != company_name:
            messagebox.showerror("Exclusão Cancelada", "O nome digitado não confere. A empresa não foi excluída.")
            return

        try:
            deleted_paths = []
            for dir_name in COMPANY_DIRS:
                path_to_delete = os.path.join(ROOT_DIR, dir_name, company_folder_name)
                if os.path.exists(path_to_delete):
                    shutil.rmtree(path_to_delete)
                    deleted_paths.append(path_to_delete)
            
            log_user_action(self.main_app.current_user, "EXCLUSÃO PERMANENTE DE EMPRESA", f"Empresa: '{company_folder_name}'. Caminhos removidos: {deleted_paths}")
            messagebox.showinfo("Sucesso", f"A empresa '{company_name}' foi excluída permanentemente.")
            self.main_app.refresh_all_tabs(refresh_companies=True)

        except Exception as e:
            error_msg = f"Falha ao excluir a empresa '{company_name}':\n{e}"
            log_user_action(self.main_app.current_user, "FALHA EXCLUSÃO EMPRESA", error_msg)
            messagebox.showerror("Erro de Exclusão", error_msg)


    def create_new_subfolder(self):
        folder_name = simpledialog.askstring("Nova Subpasta", "Digite o nome da pasta:")
        if not folder_name or not folder_name.strip(): return
        new_path = os.path.join(self.current_path, folder_name)
        try:
            os.makedirs(new_path)
            log_user_action(self.main_app.current_user, "CRIAÇÃO DE SUBPASTA", f"Pasta: '{new_path}'") # <-- NOVO
            self.populate_file_tree(self.current_path)
        except FileExistsError:
            messagebox.showwarning("Pasta Existente", "Uma pasta com este nome já existe.")
        except Exception as e:
            messagebox.showerror("Erro", f"Não foi possível criar a pasta:\n{e}")

    def upload_files(self):
        files = filedialog.askopenfilenames(title="Selecione os arquivos")
        if not files: return
        for file_path in files:
            try:
                shutil.copy(file_path, self.current_path)
                log_user_action(self.main_app.current_user, "UPLOAD DE ARQUIVO", f"De: '{file_path}' Para: '{self.current_path}'") # <-- NOVO
            except Exception as e:
                messagebox.showerror("Erro no Upload", f"Falha ao carregar:\n{os.path.basename(file_path)}")
        self.populate_file_tree(self.current_path)
        
    def upload_folder(self):
        source_path = filedialog.askdirectory(title="Selecione a pasta para carregar")
        if not source_path: return
        folder_name = os.path.basename(source_path)
        destination_path = os.path.join(self.current_path, folder_name)
        if os.path.exists(destination_path):
            messagebox.showwarning("Pasta Existente", f"A pasta '{folder_name}' já existe neste local.")
            return
        try:
            shutil.copytree(source_path, destination_path)
            log_user_action(self.main_app.current_user, "UPLOAD DE PASTA", f"De: '{source_path}' Para: '{destination_path}'") # <-- NOVO
            self.populate_file_tree(self.current_path)
        except Exception as e:
            messagebox.showerror("Erro ao Copiar Pasta", f"Não foi possível carregar a pasta:\n{e}")

    def delete_item(self):
        selected_item = self.file_tree.focus()
        if not selected_item:
            messagebox.showwarning("Nenhum Item", "Selecione um item para excluir.")
            return
        item_name = self.file_tree.item(selected_item, 'text')
        item_path = os.path.join(self.current_path, item_name)
        if not messagebox.askyesno("Confirmar", f"Tem certeza que deseja mover '{item_name}' para a lixeira?"):
            return
        try:
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            trash_item_name = f"{timestamp}_{item_name}"
            trash_path = os.path.join(TRASH_DIR, trash_item_name)
            shutil.move(item_path, trash_path)
            metadata = read_metadata()
            metadata.setdefault("trash", {})[trash_item_name] = {"original_path": item_path, "deleted_at": datetime.now().isoformat()}
            write_metadata(metadata)
            log_user_action(self.main_app.current_user, "EXCLUSÃO PARA LIXEIRA", f"Item: '{item_path}'") # <-- MODIFICADO
            self.populate_file_tree(self.current_path)
            # Safe way to get and refresh trash tab
            trash_tab = self.main_app.tabs.get("Lixeira")
            if trash_tab:
                trash_tab.populate_list()
        except Exception as e:
            messagebox.showerror("Erro ao Excluir", f"Não foi possível mover o item:\n{e}")

    def rename_item(self):
        selected_item = self.file_tree.focus()
        if not selected_item: return
        old_name = self.file_tree.item(selected_item, 'text')
        old_path = os.path.join(self.current_path, old_name)
        new_name = simpledialog.askstring("Renomear", f"Digite o novo nome para '{old_name}':", initialvalue=old_name)
        if not new_name or new_name == old_name: return
        new_path = os.path.join(self.current_path, new_name)
        if os.path.exists(new_path):
            messagebox.showwarning("Erro", "Um item com este nome já existe.")
            return
        try:
            os.rename(old_path, new_path)
            log_user_action(self.main_app.current_user, "RENOMEAÇÃO", f"De: '{old_path}' Para: '{new_path}'") # <-- MODIFICADO
            self.populate_file_tree(self.current_path)
        except Exception as e:
            messagebox.showerror("Erro ao Renomear", f"Não foi possível renomear o item:\n{e}")
            
    def go_back(self):
        if len(self.history) > 1:
            self.history.pop()
            self.populate_file_tree(self.history[-1])

    def go_up(self):
        parent_path = os.path.dirname(self.current_path)
        if os.path.normpath(parent_path) != os.path.normpath(self.current_path) and os.path.normpath(parent_path).startswith(os.path.normpath(ROOT_DIR)):
            self.populate_file_tree(parent_path)

    def on_company_select(self, event):
        selected_item = self.company_tree.focus()
        if not selected_item: return
        company_path = os.path.join(self.base_path, selected_item)
        if os.path.isdir(company_path):
            self.history = [self.base_path] # Reset history to tab root
            self.populate_file_tree(company_path)

    def on_item_double_click(self, event=None):
        item_id = self.file_tree.focus()
        if not item_id: return
        item_name = self.file_tree.item(item_id, 'text')
        item_path = os.path.join(self.current_path, item_name)
        if os.path.isdir(item_path): 
            self.populate_file_tree(item_path)
        else: 
            open_file_with_default_app(item_path)
            log_user_action(self.main_app.current_user, "ABERTURA DE ARQUIVO", f"Arquivo: '{item_path}'") # <-- NOVO

    def on_file_select(self, event):
        selected_item = self.file_tree.focus()
        if not selected_item:
            self.hide_preview()
            return
        item_path = os.path.join(self.current_path, self.file_tree.item(selected_item, 'text'))
        if os.path.isdir(item_path):
            self.hide_preview()
            return
        ext = os.path.splitext(item_path)[1].lower()
        if ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp']: self.show_image_preview(item_path)
        elif ext == '.pdf' and fitz: self.show_pdf_preview(item_path)
        elif ext == '.dxf' and ezdxf and plt: self.show_dxf_preview(item_path)
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
            img = Image.open(path)
            img.thumbnail((w if w > 1 else 300, h if h > 1 else 300), Image.Resampling.LANCZOS)
            photo = ImageTk.PhotoImage(img)
            frame = ttk.Frame(self.preview_frame); frame.pack(expand=True, fill='both')
            label = ttk.Label(frame, image=photo); label.pack(pady=10); label.image = photo
            self.preview_widget = frame
        except Exception as e:
            logging.error(f"Erro no preview da imagem {path}: {e}")
            self.hide_preview()

    def show_pdf_preview(self, path):
        self.show_preview_frame()
        try:
            doc = fitz.open(path)
            if doc.page_count > 0:
                w = self.left_frame.winfo_width() - 10
                pix = doc.load_page(0).get_pixmap(dpi=150)
                img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
                img.thumbnail((w if w > 1 else 400, 600), Image.Resampling.LANCZOS)
                photo = ImageTk.PhotoImage(img)
                
                frame = ttk.Frame(self.preview_frame)
                frame.pack(expand=True, fill='both')
                label = ttk.Label(frame, image=photo)
                label.pack(pady=10)
                label.image = photo
                self.preview_widget = frame
            doc.close()
        except Exception as e:
            logging.error(f"Erro no preview do PDF {path}: {e}")
            self.hide_preview()

    def show_dxf_preview(self, path):
        self.show_preview_frame()
        try:
            doc = ezdxf.readfile(path)
            msp = doc.modelspace()
            
            fig, ax = plt.subplots()
            
            ctx = RenderContext(doc)
            out = MatplotlibBackend(ax)
            Frontend(ctx, out).draw_layout(msp, finalize=True)
            
            if not ax.has_data():
                raise ValueError("Nenhum dado para plotar no DXF.")

            ax.set_aspect('equal', 'box')
            ax.autoscale_view()
            fig.tight_layout()

            canvas = FigureCanvasTkAgg(fig, master=self.preview_frame)
            canvas_widget = canvas.get_tk_widget()
            canvas_widget.pack(expand=True, fill='both', pady=10)
            self.preview_widget = canvas_widget
            
            plt.close(fig)

        except Exception as e:
            messagebox.showerror("Erro no Preview do DXF", f"Não foi possível renderizar o arquivo '{os.path.basename(path)}'.\n\nDetalhe: {e}")
            logging.error(f"Erro ao criar preview do DXF {path}: {e}")
            self.hide_preview()

# --- Classe para Gerenciar a Lixeira ---
class TrashManagerTab:
    def __init__(self, parent_frame, main_app, user_role, permission):
        self.parent_frame = parent_frame
        self.main_app = main_app
        self.user_role = user_role
        self.permission = permission
        main_frame = ttk.Frame(parent_frame); main_frame.pack(expand=True, fill='both', padx=10, pady=10)
        action_frame = ttk.Frame(main_frame); action_frame.pack(fill='x', pady=5)
        can_edit = self.permission == 'edit'
        self.create_button(action_frame, "Restaurar Selecionado", self.restore_selected_item, "Devolve o item ao seu local original.", state='normal' if can_edit else 'disabled')
        self.create_button(action_frame, "Excluir Permanentemente", self.delete_selected_item, "Apaga o item selecionado para sempre.", state='normal' if can_edit else 'disabled')
        self.create_button(action_frame, "Esvaziar Lixeira", self.empty_trash, "Apaga TODOS os itens da lixeira permanentemente.", state='normal' if can_edit else 'disabled')
        self.tree = self.create_treeview(main_frame, columns=("Local Original", "Data de Exclusão"))
        self.tree.heading("#0", text="Nome na Lixeira"); self.tree.heading("Local Original", text="Local Original"); self.tree.heading("Data de Exclusão", text="Data de Exclusão")
        self.tree.column("#0", width=300); self.tree.column("Local Original", width=450); self.tree.column("Data de Exclusão", width=150, anchor='center')
        self.populate_list()

    def create_button(self, parent, text, command, tooltip_text, state='normal'):
        button = ttk.Button(parent, text=text, command=command, state=state); button.pack(side='left', padx=5, pady=5)
        ToolTip(button, tooltip_text)

    def create_treeview(self, parent, columns):
        frame = ttk.Frame(parent); frame.pack(expand=True, fill='both')
        tree = ttk.Treeview(frame, columns=columns); tree['show'] = 'tree headings'
        tree.pack(side='left', expand=True, fill='both')
        scrollbar_y = ttk.Scrollbar(frame, orient='vertical', command=tree.yview); scrollbar_y.pack(side='right', fill='y')
        tree.configure(yscrollcommand=scrollbar_y.set)
        return tree

    def populate_list(self):
        self.tree.delete(*self.tree.get_children())
        sorted_items = sorted(read_metadata().get("trash", {}).items(), key=lambda i: i[1]['deleted_at'], reverse=True)
        for name, info in sorted_items:
            deleted_at = datetime.fromisoformat(info['deleted_at']).strftime('%d/%m/%Y %H:%M')
            self.tree.insert("", "end", text=f" {name}", values=(info.get('original_path', 'N/A'), deleted_at), iid=name)

    def restore_selected_item(self):
        selected_item = self.tree.focus()
        if not selected_item: return messagebox.showwarning("Nenhuma Seleção", "Selecione um item para restaurar.")
        metadata = read_metadata()
        item_info = metadata["trash"].get(selected_item)
        if not item_info: return
        original_path = item_info["original_path"]
        os.makedirs(os.path.dirname(original_path), exist_ok=True)
        if os.path.exists(original_path): return messagebox.showerror("Erro", f"O caminho original '{original_path}' já está ocupado.")
        try:
            shutil.move(os.path.join(TRASH_DIR, selected_item), original_path)
            del metadata["trash"][selected_item]
            write_metadata(metadata)
            log_user_action(self.main_app.current_user, "RESTAURAÇÃO DE ITEM", f"Item '{selected_item}' restaurado para '{original_path}'") # <-- NOVO
            self.populate_list()
            self.main_app.refresh_all_tabs()
        except Exception as e:
            messagebox.showerror("Erro ao Restaurar", f"Não foi possível restaurar o item:\n{e}")

    def delete_selected_item(self):
        selected_item = self.tree.focus()
        if not selected_item: return messagebox.showwarning("Nenhuma Seleção", "Selecione um item para excluir.")
        if not messagebox.askyesno("Confirmar Exclusão", f"Excluir '{selected_item}' permanentemente? Esta ação não pode ser desfeita."): return
        
        log_user_action(self.main_app.current_user, "EXCLUSÃO PERMANENTE DA LIXEIRA", f"Item: '{selected_item}'") # <-- NOVO
        if self.delete_item_permanently(selected_item):
            self.populate_list()

    def empty_trash(self):
        if not read_metadata().get("trash"): return messagebox.showinfo("Lixeira", "A lixeira já está vazia.")
        if not messagebox.askyesno("Confirmar Esvaziar", "Excluir TODOS os itens da lixeira permanentemente?"): return
        
        log_user_action(self.main_app.current_user, "ESVAZIAMENTO DA LIXEIRA", "Todos os itens foram excluídos permanentemente.") # <-- NOVO
        for item_name in list(read_metadata().get("trash", {}).keys()):
            self.delete_item_permanently(item_name) # <-- MODIFICADO (log agora é feito uma vez)
        self.populate_list()
        messagebox.showinfo("Sucesso", "A lixeira foi esvaziada.")

    @staticmethod
    def delete_item_permanently(trash_item_name):
        try:
            trash_path = os.path.join(TRASH_DIR, trash_item_name)
            if os.path.isdir(trash_path): shutil.rmtree(trash_path)
            elif os.path.isfile(trash_path): os.remove(trash_path)
            metadata = read_metadata()
            if "trash" in metadata and trash_item_name in metadata["trash"]:
                del metadata["trash"][trash_item_name]
                write_metadata(metadata)
            logging.info(f"Item excluído permanentemente: {trash_item_name}")
            return True
        except Exception as e:
            logging.error(f"Falha ao excluir permanentemente '{trash_item_name}': {e}")
            messagebox.showerror("Erro", f"Não foi possível excluir permanentemente o item '{trash_item_name}'.\nVerifique o log para detalhes.")
            return False

# --- Classe para a Aba de Planilhas ---
class SpreadsheetManagerTab:
    def __init__(self, parent_frame, main_app, user_role, permission):
        self.parent_frame = parent_frame
        self.main_app = main_app
        self.user_role = user_role
        self.permission = permission
        main_frame = ttk.Frame(parent_frame); main_frame.pack(expand=True, fill='both', padx=10, pady=10)
        action_frame = ttk.Frame(main_frame); action_frame.pack(fill='x', pady=5)
        can_edit = self.permission == 'edit'
        self.create_button(action_frame, "Nova Planilha (.xlsx)", self.create_new_spreadsheet, "Cria um novo arquivo Excel.", state='normal' if can_edit else 'disabled')
        self.create_button(action_frame, "Abrir Planilha", self.open_spreadsheet, "Abre a planilha selecionada.")
        self.create_button(action_frame, "Excluir Planilha", self.delete_spreadsheet, "Move a planilha para a lixeira.", state='normal' if can_edit else 'disabled')
        self.tree = self.create_treeview(main_frame, columns=("Tamanho", "Modificado em"))
        self.tree.heading("#0", text="Nome do Arquivo")
        self.tree.heading("Tamanho", text="Tamanho (KB)"); self.tree.heading("Modificado em", text="Modificado em")
        self.tree.column("#0", width=350)
        self.tree.column("Tamanho", width=120, anchor='e'); self.tree.column("Modificado em", width=150, anchor='center')
        self.tree.bind('<Double-1>', lambda e: self.open_spreadsheet())
        self.populate_list()

    def create_button(self, parent, text, command, tooltip_text, state='normal'):
        button = ttk.Button(parent, text=text, command=command, state=state); button.pack(side='left', padx=5, pady=5)
        ToolTip(button, tooltip_text)

    def create_treeview(self, parent, columns):
        frame = ttk.Frame(parent); frame.pack(expand=True, fill='both')
        tree = ttk.Treeview(frame, columns=columns); tree['show'] = 'tree headings'
        tree.pack(side='left', expand=True, fill='both')
        scrollbar_y = ttk.Scrollbar(frame, orient='vertical', command=tree.yview); scrollbar_y.pack(side='right', fill='y')
        tree.configure(yscrollcommand=scrollbar_y.set)
        return tree

    def populate_list(self):
        self.tree.delete(*self.tree.get_children())
        try:
            for filename in sorted(os.listdir(SPREADSHEETS_DIR)):
                if filename.lower().endswith(('.xlsx', '.csv')):
                    path = os.path.join(SPREADSHEETS_DIR, filename)
                    stat = os.stat(path)
                    self.tree.insert("", "end", text=f" {filename}", values=(f"{stat.st_size/1024:.2f}", datetime.fromtimestamp(stat.st_mtime).strftime('%d/%m/%Y %H:%M')))
        except Exception as e:
            logging.error(f"Erro ao listar planilhas: {e}")

    def create_new_spreadsheet(self):
        if not openpyxl: return messagebox.showerror("Dependência Faltando", "'openpyxl' é necessária para criar planilhas.")
        filename = simpledialog.askstring("Nova Planilha", "Nome do arquivo (sem extensão):")
        if not filename or not filename.strip(): return
        path = os.path.join(SPREADSHEETS_DIR, f"{filename}.xlsx")
        if os.path.exists(path): return messagebox.showwarning("Arquivo Existente", "Um arquivo com este nome já existe.")
        try:
            openpyxl.Workbook().save(path)
            log_user_action(self.main_app.current_user, "CRIAÇÃO DE PLANILHA", f"Planilha: '{path}'") # <-- NOVO
            self.populate_list()
            if messagebox.askyesno("Abrir", f"Deseja abri-la agora?"): open_file_with_default_app(path)
        except Exception as e: messagebox.showerror("Erro", f"Não foi possível criar a planilha:\n{e}")

    def open_spreadsheet(self):
        selected_item = self.tree.focus()
        if not selected_item: return
        filepath = os.path.join(SPREADSHEETS_DIR, self.tree.item(selected_item, 'text').strip())
        open_file_with_default_app(filepath)
        log_user_action(self.main_app.current_user, "ABERTURA DE PLANILHA", f"Planilha: '{filepath}'") # <-- NOVO

    def delete_spreadsheet(self):
        selected_item = self.tree.focus()
        if not selected_item: return
        filename = self.tree.item(selected_item, 'text').strip()
        if not messagebox.askyesno("Confirmar", f"Mover '{filename}' para a lixeira?"): return
        try:
            item_path = os.path.join(SPREADSHEETS_DIR, filename)
            trash_item_name = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
            trash_path = os.path.join(TRASH_DIR, trash_item_name)
            shutil.move(item_path, trash_path)
            metadata = read_metadata()
            metadata.setdefault("trash", {})[trash_item_name] = {"original_path": item_path, "deleted_at": datetime.now().isoformat()}
            write_metadata(metadata)
            log_user_action(self.main_app.current_user, "EXCLUSÃO DE PLANILHA", f"Planilha movida para lixeira: '{item_path}'") # <-- NOVO
            self.populate_list()
            trash_tab = self.main_app.tabs.get("Lixeira")
            if trash_tab:
                trash_tab.populate_list()
        except Exception as e:
            messagebox.showerror("Erro ao Excluir", f"Não foi possível mover a planilha:\n{e}")

# --- Classe Janela de Permissões ---
class PermissionsEditorWindow(Toplevel): # <-- MODIFICADO
    def __init__(self, parent, user_management_tab, username=None):
        super().__init__(parent)
        self.user_management_tab = user_management_tab
        self.username = username
        self.is_new_user = username is None
        self.title("Editar Permissões" if not self.is_new_user else "Adicionar Novo Usuário")
        self.transient(parent)
        self.grab_set()
        
        self.permission_vars = {}
        self.role_var = StringVar(value='user') # <-- NOVO
        self.users_data = read_users()
        current_permissions = self.users_data.get(self.username, {}).get("permissions", {})

        details_frame = ttk.LabelFrame(self, text="Detalhes do Usuário", padding=10)
        details_frame.pack(padx=10, pady=10, fill="x")
        
        ttk.Label(details_frame, text="Nome de Usuário:").grid(row=0, column=0, sticky='w', pady=5)
        self.username_entry = ttk.Entry(details_frame, width=40)
        self.username_entry.grid(row=0, column=1, pady=5)
        if not self.is_new_user:
            self.username_entry.insert(0, self.username)
            self.username_entry.config(state='readonly')

        ttk.Label(details_frame, text="Senha:").grid(row=1, column=0, sticky='w', pady=5)
        self.password_entry = ttk.Entry(details_frame, width=40, show="*")
        self.password_entry.grid(row=1, column=1, pady=5)
        if not self.is_new_user:
            self.password_entry.insert(0, "(não alterada)")
            # self.password_entry.config(state='readonly') # Permitir alteração de senha
            
        # --- Campo de Função (Role) --- NOVO
        ttk.Label(details_frame, text="Função:").grid(row=2, column=0, sticky='w', pady=5)
        self.role_combobox = ttk.Combobox(details_frame, textvariable=self.role_var, values=['user', 'admin'], state='readonly')
        self.role_combobox.grid(row=2, column=1, sticky='ew', pady=5)
        if not self.is_new_user:
            self.role_combobox.set(self.users_data.get(self.username, {}).get("role", "user"))
            self.role_combobox.config(state='disabled') # Não permite alterar a função de um usuário existente por aqui
        # --- Fim do Campo de Função ---

        self.permissions_frame = ttk.LabelFrame(self, text="Permissões de Acesso às Abas", padding=10)
        self.permissions_frame.pack(padx=10, pady=10, fill="x")

        permission_map = {"edit": "Acesso e Edição", "view": "Apenas Acesso", "none": "Nenhum Acesso"}
        reverse_permission_map = {v: k for k, v in permission_map.items()}
        
        for i, tab_name in enumerate(MANAGEABLE_TABS):
            ttk.Label(self.permissions_frame, text=f"{tab_name}:").grid(row=i, column=0, sticky='w', padx=5, pady=5)
            perm_var = StringVar()
            combobox = ttk.Combobox(self.permissions_frame, textvariable=perm_var, values=list(permission_map.values()), state='readonly')
            current_perm_key = current_permissions.get(tab_name, 'none')
            combobox.set(permission_map[current_perm_key])
            combobox.grid(row=i, column=1, sticky='ew', padx=5, pady=5)
            self.permission_vars[tab_name] = (perm_var, reverse_permission_map)

        action_frame = ttk.Frame(self)
        action_frame.pack(pady=10)
        save_btn = ttk.Button(action_frame, text="Salvar", command=self.save_permissions)
        save_btn.pack(side='left', padx=10)
        cancel_btn = ttk.Button(action_frame, text="Cancelar", command=self.destroy)
        cancel_btn.pack(side='left', padx=10)
        
        self.role_var.trace_add('write', self.toggle_permissions_frame) # <-- NOVO
        self.toggle_permissions_frame() # <-- NOVO

    def toggle_permissions_frame(self, *args): # <-- NOVO
        """Desabilita o frame de permissões se a função for 'admin'."""
        if self.role_var.get() == 'admin':
            for child in self.permissions_frame.winfo_children():
                child.config(state='disabled')
        else:
            for child in self.permissions_frame.winfo_children():
                child.config(state='normal')


    def save_permissions(self): # <-- MODIFICADO
        if self.is_new_user:
            new_username = self.username_entry.get().strip()
            new_password = self.password_entry.get()
            new_role = self.role_var.get()

            if not new_username or not new_password:
                messagebox.showerror("Erro", "Nome de usuário e senha são obrigatórios para novos usuários.", parent=self)
                return
            if new_username in self.users_data:
                messagebox.showerror("Erro", "Este nome de usuário já existe.", parent=self)
                return
            
            self.username = new_username
            self.users_data[self.username] = {
                "password": hash_password(new_password),
                "role": new_role,
                "permissions": {}
            }
            log_user_action(self.user_management_tab.main_app.current_user, "CRIAÇÃO DE USUÁRIO", f"Usuário: '{new_username}', Função: '{new_role}'")
        else: # Editando usuário existente (apenas permissões)
            # Poderia adicionar lógica para mudança de senha aqui se desejado
            pass

        # Salva as permissões apenas se não for admin
        if self.users_data[self.username]['role'] != 'admin':
            new_permissions = {}
            for tab_name, (perm_var, reverse_map) in self.permission_vars.items():
                user_choice = perm_var.get()
                new_permissions[tab_name] = reverse_map[user_choice]
            self.users_data[self.username]["permissions"] = new_permissions
        else:
             self.users_data[self.username]["permissions"] = {} # Garante que admin não tenha permissões explícitas

        write_users(self.users_data)
        
        log_user_action(self.user_management_tab.main_app.current_user, "ATUALIZAÇÃO DE PERMISSÕES", f"Permissões atualizadas para o usuário '{self.username}'")
        messagebox.showinfo("Sucesso", f"Dados para '{self.username}' salvos com sucesso.")
        
        self.user_management_tab.populate_user_list()
        self.destroy()

# --- Classe para Gerenciar Usuários (Admin) ---
class UserManagementTab:
    def __init__(self, parent_frame, main_app):
        self.parent_frame = parent_frame
        self.main_app = main_app
        main_frame = ttk.Frame(parent_frame); main_frame.pack(expand=True, fill='both', padx=10, pady=10)
        action_frame = ttk.Frame(main_frame); action_frame.pack(fill='x', pady=5)
        self.create_button(action_frame, "Adicionar Usuário", self.add_user, "Adiciona um novo usuário ao sistema.")
        self.edit_perms_button = self.create_button(action_frame, "Editar Permissões", self.edit_user_permissions, "Edita as permissões do usuário selecionado.", state='disabled')
        self.create_button(action_frame, "Remover Usuário", self.remove_user, "Remove o usuário selecionado.")
        self.tree = self.create_treeview(main_frame, columns=("Função",))
        self.tree.heading("#0", text="Nome de Usuário"); self.tree.heading("Função", text="Função")
        self.tree.column("#0", width=300); self.tree.column("Função", width=150, anchor='center')
        self.tree.bind('<<TreeviewSelect>>', self.on_user_select)
        self.populate_user_list()

    def on_user_select(self, event):
        selected_item = self.tree.focus()
        if not selected_item:
            self.edit_perms_button.config(state='disabled')
            return
        user_data = read_users().get(selected_item, {})
        if user_data.get("role") == "admin":
            self.edit_perms_button.config(state='disabled')
        else:
            self.edit_perms_button.config(state='normal')
            
    def add_user(self):
        PermissionsEditorWindow(self.parent_frame, self)

    def edit_user_permissions(self):
        selected_item = self.tree.focus()
        if not selected_item: return
        PermissionsEditorWindow(self.parent_frame, self, username=selected_item)

    def create_button(self, parent, text, command, tooltip_text, state='normal'):
        button = ttk.Button(parent, text=text, command=command, state=state); button.pack(side='left', padx=5, pady=5)
        ToolTip(button, tooltip_text)
        return button

    def create_treeview(self, parent, columns):
        frame = ttk.Frame(parent); frame.pack(expand=True, fill='both')
        tree = ttk.Treeview(frame, columns=columns); tree['show'] = 'tree headings'
        tree.pack(side='left', expand=True, fill='both')
        scrollbar = ttk.Scrollbar(frame, orient='vertical', command=tree.yview); scrollbar.pack(side='right', fill='y')
        tree.configure(yscrollcommand=scrollbar.set)
        return tree

    def populate_user_list(self):
        self.tree.delete(*self.tree.get_children())
        users = read_users()
        for username, data in users.items():
            self.tree.insert("", "end", text=username, values=(data.get('role', 'N/A'),), iid=username)
        self.edit_perms_button.config(state='disabled')

    def remove_user(self):
        selected_item = self.tree.focus()
        if not selected_item:
            return messagebox.showwarning("Nenhuma Seleção", "Selecione um usuário para remover.")
        if selected_item == self.main_app.current_user:
            return messagebox.showerror("Erro", "Não é possível remover o usuário logado no momento.")
        users = read_users()
        if users.get(selected_item, {}).get("role") == "admin":
             return messagebox.showerror("Erro", "Contas de administrador não podem ser removidas por este painel.")
        if not messagebox.askyesno("Confirmar Remoção", f"Tem certeza que deseja remover o usuário '{selected_item}'?"):
            return
        if selected_item in users:
            del users[selected_item]
            write_users(users)
            log_user_action(self.main_app.current_user, "REMOÇÃO DE USUÁRIO", f"Usuário '{selected_item}' foi removido.") # <-- NOVO
            self.populate_user_list()
            messagebox.showinfo("Sucesso", f"Usuário '{selected_item}' removido.")

# --- Ponto de Entrada da Aplicação ---
if __name__ == "__main__":
    missing_deps = []
    if not fitz: missing_deps.append("PyMuPDF (para preview de PDF)")
    if not ezdxf or not plt: missing_deps.append("ezdxf e matplotlib (para preview de DXF)")
    if not openpyxl: missing_deps.append("openpyxl (para criar .xlsx)")
    if missing_deps:
        msg = "Atenção: Algumas dependências opcionais não foram encontradas:\n\n" + "\n".join(f"- {dep}" for dep in missing_deps)
        root = Tk()
        root.withdraw()
        messagebox.showwarning("Dependências Opcionais Faltando", msg)
        root.destroy()

    setup_environment()
    app = FileManagerApp()
    app.mainloop()