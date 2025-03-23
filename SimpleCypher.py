import sys
import os
import hashlib
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QFileDialog, QLineEdit, QLabel, QComboBox, QHBoxLayout
from cryptography.fernet import Fernet

class EncryptorApp(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("SimpleCypher")
        self.setGeometry(200, 200, 500, 400)
        
        layout = QVBoxLayout()
        
        self.label = QLabel("Enter a key (leave empty for auto AES):")
        layout.addWidget(self.label)
        
        self.key_input = QLineEdit()
        layout.addWidget(self.key_input)
        
        self.method_label = QLabel("Choose an encryption method:")
        layout.addWidget(self.method_label)
        
        self.method_combo = QComboBox()
        self.method_combo.addItems(["AES", "SHA-256", "SHA-512", "MD5"])
        layout.addWidget(self.method_combo)
        
        self.generate_key_button = QPushButton("Generate Key (AES)")
        self.generate_key_button.clicked.connect(self.generate_key)
        layout.addWidget(self.generate_key_button)
        
        file_layout = QHBoxLayout()
        
        self.select_button = QPushButton("Select a File")
        self.select_button.clicked.connect(self.select_file)
        file_layout.addWidget(self.select_button)
        
        self.file_label = QLabel("No file selected")
        file_layout.addWidget(self.file_label)
        
        layout.addLayout(file_layout)
        
        self.encrypt_button = QPushButton("Encrypt")
        self.encrypt_button.clicked.connect(self.encrypt_file)
        layout.addWidget(self.encrypt_button)
        
        self.decrypt_button = QPushButton("Decrypt (AES only)")
        self.decrypt_button.clicked.connect(self.decrypt_file)
        layout.addWidget(self.decrypt_button)
        
        self.sign_button = QPushButton("Sign File")
        self.sign_button.clicked.connect(self.sign_file)
        layout.addWidget(self.sign_button)
        
        self.verify_button = QPushButton("Verify Signature")
        self.verify_button.clicked.connect(self.verify_signature)
        layout.addWidget(self.verify_button)
        
        self.status_label = QLabel("")
        layout.addWidget(self.status_label)
        
        self.setLayout(layout)
        self.file_path = ""

        footer = QLabel("v1.1")
        footer.setStyleSheet("background-color: #383838; padding: 5px; text-align: center;")

        layout.addWidget(footer)
        layout.setStretch(0, 1) 
        layout.setStretch(1, 0)  

    def generate_key(self):
        key = Fernet.generate_key()
        self.key_input.setText(key.decode())
        
    def select_file(self):
        file_dialog = QFileDialog()
        self.file_path, _ = file_dialog.getOpenFileName(self, "Select a File")
        if self.file_path:
            self.file_label.setText(os.path.basename(self.file_path))
            
    def get_hash_function(self, method):
        if method == "SHA-256":
            return hashlib.sha256()
        elif method == "SHA-512":
            return hashlib.sha512()
        elif method == "MD5":
            return hashlib.md5()
        else:
            self.status_label.setText("Invalid hashing method.")
            return None
    
    def encrypt_file(self):
        if not self.file_path:
            self.status_label.setText("Please select a file.")
            return
        
        method = self.method_combo.currentText()
        
        if method == "AES":
            if not self.key_input.text():
                self.status_label.setText("Please enter a key for AES.")
                return
            
            key = self.key_input.text().encode()
            cipher = Fernet(key)
            
            with open(self.file_path, "rb") as file:
                data = file.read()
                encrypted_data = cipher.encrypt(data)
            
            with open(self.file_path + ".enc", "wb") as file:
                file.write(encrypted_data)
            
            self.status_label.setText("File successfully encrypted (AES).")
        else:
            hash_func = self.get_hash_function(method)
            if not hash_func:
                return
            
            with open(self.file_path, "rb") as file:
                while chunk := file.read(4096):
                    hash_func.update(chunk)
            
            hash_value = hash_func.hexdigest()
            
            with open(self.file_path + f".{method.lower()}_hash", "w") as file:
                file.write(hash_value)
            
            self.status_label.setText(f"{method} hash generated successfully.")
    
    def decrypt_file(self):
        if not self.file_path or not self.key_input.text():
            self.status_label.setText("Please select a file and enter a key.")
            return
        
        if self.method_combo.currentText() != "AES":
            self.status_label.setText("Decryption is only possible with AES.")
            return
        
        key = self.key_input.text().encode()
        cipher = Fernet(key)
        
        with open(self.file_path, "rb") as file:
            encrypted_data = file.read()
            try:
                decrypted_data = cipher.decrypt(encrypted_data)
            except:
                self.status_label.setText("Invalid key or corrupted file.")
                return
        
        with open(self.file_path.replace(".enc", ""), "wb") as file:
            file.write(decrypted_data)
        
        self.status_label.setText("File successfully decrypted (AES).")
    
    def sign_file(self):
        if not self.file_path:
            self.status_label.setText("Please select a file.")
            return
        
        method = self.method_combo.currentText()
        if method == "AES":
            self.status_label.setText("Signing is not possible with AES.")
            return
        
        hash_func = self.get_hash_function(method)
        if not hash_func:
            return
        
        with open(self.file_path, "rb") as file:
            while chunk := file.read(4096):
                hash_func.update(chunk)
        
        signature = hash_func.hexdigest()
        
        with open(self.file_path + f".{method.lower()}_sig", "w") as file:
            file.write(signature)
        
        self.status_label.setText(f"File signed with {method}.")
    
    def verify_signature(self):
        if not self.file_path:
            self.status_label.setText("Please select a file.")
            return
        
        signature_path, _ = QFileDialog.getOpenFileName(self, "Select the signature file")
        if not signature_path:
            self.status_label.setText("Please select a signature file.")
            return
        
        method = self.method_combo.currentText()
        hash_func = self.get_hash_function(method)
        if not hash_func:
            return
        
        with open(self.file_path, "rb") as file:
            while chunk := file.read(4096):
                hash_func.update(chunk)
        
        computed_signature = hash_func.hexdigest()
        
        with open(signature_path, "r") as file:
            stored_signature = file.read().strip()
        
        if computed_signature == stored_signature:
            self.status_label.setText("Signature is valid!")
        else:
            self.status_label.setText("Signature is invalid!")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = EncryptorApp()
    window.show()
    sys.exit(app.exec())
