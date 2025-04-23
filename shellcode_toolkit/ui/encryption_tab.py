from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,                                     
                            QLabel, QTextEdit, QPushButton, QComboBox,                                         
                            QFileDialog, QMessageBox)                                                          
from PyQt6.QtGui import QFont                                                                                  
from core.encryption import EncryptionHandler                                                                  
from core.utils import format_hex, validate_hex_input                                                          
                                                                                                               
class EncryptionTab(QWidget):                                                                                  
    def __init__(self):                                                                                        
        super().__init__()                                                                                     
        self.encryptor = EncryptionHandler()                                                                   
        self.setup_ui()                                                                                        
        self.connect_events()                                                                                  
                                                                                                               
    def setup_ui(self):                                                                                        
        # 主布局                                                                                               
        layout = QVBoxLayout()                                                                                 
        layout.setContentsMargins(5, 5, 5, 5)                                                                  
        layout.setSpacing(10)                                                                                  
                                                                                                               
        # 按钮工具栏                                                                                           
        button_bar = QHBoxLayout()                                                                             
        button_bar.setSpacing(5)                                                                               
                                                                                                               
        self.generate_btn = QPushButton("生成密钥")                                                            
        self.generate_btn.setFixedHeight(30)                                                                   
                                                                                                               
        self.encrypt_btn = QPushButton("加密")                                                                 
        self.encrypt_btn.setFixedHeight(30)                                                                    
                                                                                                               
        self.decrypt_btn = QPushButton("解密")                                                                 
        self.decrypt_btn.setFixedHeight(30)                                                                    
                                                                                                               
        self.load_btn = QPushButton("加载文件")                                                                
        self.load_btn.setFixedHeight(30)                                                                       
                                                                                                               
        self.save_btn = QPushButton("保存文件")                                                                
        self.save_btn.setFixedHeight(30)                                                                       
                                                                                                               
        button_bar.addWidget(self.generate_btn)                                                                
        button_bar.addWidget(self.encrypt_btn)                                                                 
        button_bar.addWidget(self.decrypt_btn)                                                                 
        button_bar.addWidget(self.load_btn)                                                                    
        button_bar.addWidget(self.save_btn)                                                                    
        layout.addLayout(button_bar)                                                                           
                                                                                                               
        # 算法选择                                                                                             
        algo_group = QGroupBox("加密设置")                                                                     
        algo_layout = QHBoxLayout()                                                                            
        self.algo_combo = QComboBox()                                                                          
        self.algo_combo.addItems(["XOR", "AES-256", "RC4", "Huffman"])                                         
        algo_layout.addWidget(QLabel("加密算法:"))                                                             
        algo_layout.addWidget(self.algo_combo)                                                                 
        algo_group.setLayout(algo_layout)                                                                      
        layout.addWidget(algo_group)                                                                           
                                                                                                               
        # Shellcode输入                                                                                        
        input_group = QGroupBox("Shellcode输入")                                                               
        self.shellcode_input = QTextEdit()                                                                     
        self.shellcode_input.setPlaceholderText("输入十六进制格式的shellcode (如: 90 90 CC C3)")               
        self.shellcode_input.setFont(QFont("Consolas", 10))                                                    
        input_group.setLayout(QVBoxLayout())                                                                   
        input_group.layout().addWidget(self.shellcode_input)                                                   
        layout.addWidget(input_group)                                                                          
                                                                                                               
        # 密钥显示                                                                                             
        key_group = QGroupBox("加密密钥")                                                                      
        self.key_display = QTextEdit()                                                                         
        self.key_display.setMaximumHeight(70)                                                                  
        self.key_display.setReadOnly(True)                                                                     
        self.key_display.setPlaceholderText("生成的密钥将显示在这里")                                          
        self.key_display.setFont(QFont("Consolas", 10))                                                        
        key_group.setLayout(QVBoxLayout())                                                                     
        key_group.layout().addWidget(self.key_display)                                                         
        layout.addWidget(key_group)                                                                            
                                                                                                               
        self.setLayout(layout)                                                                                 
                                                                                                               
    def connect_events(self):                                                                                  
        """连接所有按钮事件"""                                                                                 
        self.generate_btn.clicked.connect(self.on_generate_key)                                                
        self.encrypt_btn.clicked.connect(self.on_encrypt)                                                      
        self.decrypt_btn.clicked.connect(self.on_decrypt)                                                      
        self.load_btn.clicked.connect(self.on_load_file)                                                       
        self.save_btn.clicked.connect(self.on_save_file)                                                       
                                                                                                               
    def on_generate_key(self):                                                                                 
        """生成密钥按钮点击事件"""                                                                             
        algo = self.algo_combo.currentText()                                                                   
        try:                                                                                                   
            key = self.encryptor.generate_key(algo)                                                            
            if key is not None:                                                                                
                self.key_display.setPlainText(format_hex(key))                                                 
                QMessageBox.information(self, "成功", "密钥生成成功")                                          
            else:                                                                                              
                QMessageBox.information(self, "提示", "Huffman编码不需要密钥")                                 
        except Exception as e:                                                                                 
            QMessageBox.critical(self, "错误", f"生成密钥失败: {str(e)}")                                      
                                                                                                               
    def on_encrypt(self):                                                                                      
        """加密按钮点击事件"""                                                                                 
        try:                                                                                                   
            hex_str = self.shellcode_input.toPlainText()                                                       
            data = validate_hex_input(hex_str)                                                                 
                                                                                                               
            algo = self.algo_combo.currentText()                                                               
            encrypted = self.encryptor.process_data(data, algo, encrypt=True)                                  
                                                                                                               
            self.shellcode_input.setPlainText(format_hex(encrypted))                                           
            QMessageBox.information(self, "成功", "加密成功")                                                  
        except Exception as e:                                                                                 
            QMessageBox.critical(self, "错误", f"加密失败: {str(e)}")                                          
                                                                                                               
    def on_decrypt(self):                                                                                      
        """解密按钮点击事件"""                                                                                 
        try:                                                                                                   
            hex_str = self.shellcode_input.toPlainText()                                                       
            data = validate_hex_input(hex_str)                                                                 
                                                                                                               
            algo = self.algo_combo.currentText()                                                               
            decrypted = self.encryptor.process_data(data, algo, encrypt=False)                                 
                                                                                                               
            self.shellcode_input.setPlainText(format_hex(decrypted))                                           
            QMessageBox.information(self, "成功", "解密成功")                                                  
        except Exception as e:                                                                                 
            QMessageBox.critical(self, "错误", f"解密失败: {str(e)}")                                          
                                                                                                               
    def on_load_file(self):                                                                                    
        """加载文件按钮点击事件"""                                                                             
        path, _ = QFileDialog.getOpenFileName(self, "打开文件")                                                
        if path:                                                                                               
            try:                                                                                               
                with open(path, 'rb') as f:                                                                    
                    data = f.read()                                                                            
                    self.shellcode_input.setPlainText(format_hex(data))                                        
            except Exception as e:                                                                             
                QMessageBox.critical(self, "错误", f"加载文件失败: {str(e)}")                                  
                                                                                                               
    def on_save_file(self):                                                                                    
        """保存文件按钮点击事件"""                                                                             
        path, _ = QFileDialog.getSaveFileName(self, "保存文件")                                                
        if path:                                                                                               
            try:                                                                                               
                hex_str = self.shellcode_input.toPlainText()                                                   
                data = validate_hex_input(hex_str)                                                             
                                                                                                               
                with open(path, 'wb') as f:                                                                    
                    f.write(data)                                                                              
                QMessageBox.information(self, "成功", "保存成功")                                              
            except Exception as e:                                                                             
                QMessageBox.critical(self, "错误", f"保存文件失败: {str(e)}")                                  
                                                                                                               