from main import *
import customtkinter as ctk
import pyperclip

class ASKMasterPasswordWindow(ctk.CTkToplevel):

    def __init__(self, parent):

        super().__init__(parent)
        self.title("Master Password")
        self.geometry(self.Center(300, 150))
        self.resizable(False, False)
        self.grab_set()
        self.focus_set()
        self.transient(parent)
        self.parent_app = parent

        self.label = ctk.CTkLabel(self, text="Enter Master Password:")
        self.label.pack(pady=10)
        
        self.entry_password = ctk.CTkEntry(self, show="*")
        self.entry_password.pack(pady=10)
        self.entry_password.bind("<Return>", lambda event: self.accept())
        
        self.accept_button = ctk.CTkButton(self, text="Accept", command=self.accept)
        self.accept_button.focus()
        self.accept_button.pack(pady=10)
    
    def accept(self):

        self.master_password = self.entry_password.get()
        self.parent_app.set_master_password(self.master_password)
        self.destroy()

    def Center(self, width=300, height=150):
        self.update_idletasks()
        w = width
        h = height
        ws = self.winfo_screenwidth()
        hs = self.winfo_screenheight()
        x = (ws // 2) - (w // 2)
        y = (hs // 2) - (h // 2)
        self.geometry(f'{w}x{h}+{x}+{y}')

class PasswordManagerApp(ctk.CTk):

    def __init__(self):

        super().__init__()
        self.title("Safe Credential - Password Manager")
        self.iconbitmap(default="app/icon.ico")
        self.geometry(ASKMasterPasswordWindow.Center(self, 300, 280))
        self.resizable(False, False)
        self.data = load_data()
        self.key = None
        self.master_password = None

        self.create_widgets()
    
    def create_widgets(self):

        self.label = ctk.CTkLabel(self, text="Enter Master Password:")
        self.label.pack(pady=10)
        
        self.password_entry = ctk.CTkEntry(self, show="*")
        self.password_entry.pack(pady=10)
        
        self.login_button = ctk.CTkButton(self, text="Login")
        self.login_button.focus()
        self.login_button.pack(pady=10)
        
        self.new_entry_button = ctk.CTkButton(self, text="New Entry", command=self.new_entry)
        self.new_entry_button.pack(pady=10)
        self.new_entry_button.configure(state="disabled")
        
        self.view_entries_button = ctk.CTkButton(self, text="View Entries", command=self.view_entries)
        self.view_entries_button.pack(pady=10)
        self.view_entries_button.configure(state="disabled")
    
    def set_master_password(self, master_password):

        self.master_password = master_password
        self.key = get_key(master_password)

        self.password_entry.delete(0, "end")
        self.password_entry.insert(0, len(master_password) * "a")
        self.password_entry.configure(state="disabled")
        
        self.label.configure(text="Logged in successfully!")
        self.login_button.configure(state="disabled")
        
        self.new_entry_button.configure(state="normal")
        self.view_entries_button.configure(state="normal")

    def new_entry(self):

        self.new_entry_input_window = ctk.CTkToplevel(self)
        self.new_entry_input_window.title("New Entry")
        self.new_entry_input_window.geometry(ASKMasterPasswordWindow.Center(self.new_entry_input_window, 300, 280))
        self.new_entry_input_window.resizable(False, False)
        self.new_entry_input_window.grab_set()
        self.new_entry_input_window.focus_set()
        self.new_entry_input_window.transient(self)

        self.website_label = ctk.CTkLabel(self.new_entry_input_window, text="Website:")
        self.website_label.pack(pady=5)

        self.website_entry = ctk.CTkEntry(self.new_entry_input_window)
        self.website_entry.pack(pady=5)

        self.username_label = ctk.CTkLabel(self.new_entry_input_window, text="Username:")
        self.username_label.pack(pady=5)

        self.username_entry = ctk.CTkEntry(self.new_entry_input_window)
        self.username_entry.pack(pady=5)

        self.password_label = ctk.CTkLabel(self.new_entry_input_window, text="Password:")
        self.password_label.pack(pady=5)

        self.password_entry = ctk.CTkEntry(self.new_entry_input_window, show="*")
        self.password_entry.pack(pady=5)

        self.accept_button = ctk.CTkButton(self.new_entry_input_window, text="Add Entry", command=self.add_entry)
        self.accept_button.pack(pady=10)
    
    def add_entry(self, website=None, username=None, password=None):

        if website is None:
            website = self.website_entry.get()
        
        if username is None:
            username = self.username_entry.get()
        
        if password is None:
            password = self.password_entry.get()
        
        encrypted_password = encrypt(password, self.key).decode()
        
        self.data[website] = {
            'username': username,
            'password': encrypted_password
        }

        save_data(self.data)
        print(f"Entry for {website} added.")
        self.new_entry_input_window.destroy()

    def view_entries(self):

        self.view_entries_window = ctk.CTkToplevel(self)
        self.view_entries_window.title("View Entries")
        self.view_entries_window.geometry(ASKMasterPasswordWindow.Center(self.view_entries_window, 700, 400))
        self.view_entries_window.resizable(False, True)
        self.view_entries_window.grab_set()
        self.view_entries_window.focus_set()
        
        header_frame = ctk.CTkFrame(self.view_entries_window)
        header_frame.pack(fill="x", padx=10, pady=10)
        
        website_header = ctk.CTkLabel(header_frame, text="Website", font=("Arial", 12, "bold"), width=150, anchor="center")
        website_header.pack(side="left", padx=10)
        
        username_header = ctk.CTkLabel(header_frame, text="Username", font=("Arial", 12, "bold"), width=150, anchor="center")
        username_header.pack(side="left", padx=10)
        
        password_header = ctk.CTkLabel(header_frame, text="Password", font=("Arial", 12, "bold"), width=150, anchor="center")
        password_header.pack(side="left", padx=10)
        
        scrollable_frame = ctk.CTkScrollableFrame(self.view_entries_window, width=700, height=320)
        scrollable_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        for website, entry in self.data.items():
            encrypted_password = entry['password']

            entry_frame = ctk.CTkFrame(scrollable_frame, fg_color=("gray90", "gray20"))
            entry_frame.pack(fill="x", pady=5)

            website_label = ctk.CTkLabel(entry_frame, text=website, width=150, anchor="center")
            website_label.pack(side="left", padx=5, pady=5)

            username_label = ctk.CTkLabel(entry_frame, text=entry['username'], width=150, anchor="center")
            username_label.pack(side="left", padx=10, pady=5)

            masked = "•" * 8
            password_label = ctk.CTkLabel(entry_frame, text=masked, width=150, anchor="center")
            password_label.pack(side="left", padx=10, pady=5)

            copy_button = ctk.CTkButton(entry_frame, text="📑", width=40)
            copy_button.pack(side="left", padx=5, pady=5)

            show_button = ctk.CTkButton(entry_frame, text="👁", width=40)
            show_button.pack(side="left", padx=5, pady=5)

            def toggle(lbl=password_label, enc=encrypted_password, btn=show_button):

                if btn.cget("text") == "👁":
                    try:
                        pwd = decrypt(enc.encode(), self.key)
                    except Exception:
                        pwd = "<decryption error>"
                    lbl.configure(text=pwd)
                    btn.configure(text="🕶")
                else:
                    lbl.configure(text="•" * 8)
                    btn.configure(text="👁")

            def copy_to_clipboard(enc=encrypted_password, web=website, btn=show_button):
                try:
                    if btn.cget("text") == "👁":
                        print("Password is hidden. Please show it before copying.")
                        return
                    pwd = decrypt(enc.encode(), self.key)
                except Exception:
                    print(f"Unable to decrypt password for {web}")
                    return
                pyperclip.copy(pwd)
                print(f"Password for {web} copied to clipboard.")

            copy_button.configure(command=copy_to_clipboard)
            show_button.configure(command=toggle)
        


if __name__ == "__main__":

    app = PasswordManagerApp()
    password_window = ASKMasterPasswordWindow(app)
    app.mainloop()
