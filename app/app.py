from main import *
import customtkinter as ctk

class PasswordManagerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Safe Credential - Password Manager")
        self.geometry("400x300")
        self.minsize(400, 300)
        
        self.data = load_data()
        self.key = None
        
        self.create_widgets()
    
    def create_widgets(self):
        self.label = ctk.CTkLabel(self, text="Enter Master Password:")
        self.label.pack(pady=10)
        
        self.password_entry = ctk.CTkEntry(self, show="*")
        self.password_entry.pack(pady=10)
        
        self.login_button = ctk.CTkButton(self, text="Login", command=self.login)
        self.login_button.focus()
        self.login_button.pack(pady=10)
        
        self.new_entry_button = ctk.CTkButton(self, text="New Entry", command=self.new_entry)
        self.new_entry_button.pack(pady=10)
        self.new_entry_button.configure(state="disabled")
        
        self.view_entries_button = ctk.CTkButton(self, text="View Entries", command=self.view_entries)
        self.view_entries_button.pack(pady=10)
        self.view_entries_button.configure(state="disabled")
    
    def login(self):

        master_password = self.password_entry.get()

        self.key = get_key(master_password)

        self.new_entry_button.configure(state="normal")
        self.view_entries_button.configure(state="normal")

        self.label.configure(text="Logged in successfully!")

        self.login_button.configure(state="disabled")

        self.password_entry.configure(state="disabled")
    
    def new_entry(self):

        self.new_entry_input_window = ctk.CTkToplevel(self)
        self.new_entry_input_window.title("New Entry")
        self.new_entry_input_window.geometry("300x280")
        self.minsize(300, 280)
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
        view_entries(self.data, self.key)

if __name__ == "__main__":
    app = PasswordManagerApp()
    app.mainloop()