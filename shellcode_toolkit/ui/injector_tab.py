                                                                                                              
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,                                   
                           QLabel, QLineEdit, QPushButton, QComboBox,                                        
                           QCheckBox, QMessageBox)                                                           
from PyQt6.QtCore import Qt                                                                                  
from core.pe_injector import PEInjector                                                                      
from core.utils import select_file_dialog                                                                    
                                                                                                             
class PEInjectorTab(QWidget):                                                                                
    def __init__(self, parent=None):                                                                         
        super().__init__(parent)                                                                             
        self.injector = PEInjector()                                                                         
        self.main_window = parent  # 保存主窗口引用                                                          
        self.setup_ui()                                                                                      
                                                                                                             
    def setup_ui(self):                                                                                      
        # 主布局                                                                                             
        layout = QVBoxLayout()                                                                               
        layout.setContentsMargins(5, 5, 5, 5)                                                                
        layout.setSpacing(10)                                                                                
                                                                                                             
        # 按钮工具栏                                                                                         
        button_bar = QHBoxLayout()                                                                           
        button_bar.setSpacing(5)                                                                             
                                                                                                             
        self.execute_btn = QPushButton("执行注入")                                                           
        self.execute_btn.setFixedHeight(30)                                                                  
        self.execute_btn.clicked.connect(self.on_execute_injection)                                          
                                                                                                             
        button_bar.addWidget(self.execute_btn)                                                               
        button_bar.addStretch()                                                                              
        layout.addLayout(button_bar)                                                                         
                                                                                                             
        # 模式选择                                                                                           
        mode_group = QGroupBox("注入设置")                                                                   
        mode_layout = QVBoxLayout()                                                                          
        mode_layout.setContentsMargins(10, 15, 10, 10)                                                       
                                                                                                             
        # 注入类型选择                                                                                       
        type_layout = QHBoxLayout()                                                                          
        self.mode_combo = QComboBox()                                                                        
        self.mode_combo.addItems(["函数注入", "入口点注入", "TLS注入", "导出表注入"])                        
        self.mode_combo.setFixedHeight(30)                                                                   
                                                                                                             
        type_layout.addWidget(QLabel("注入类型:"))                                                           
        type_layout.addWidget(self.mode_combo)                                                               
        type_layout.addStretch()                                                                             
        mode_layout.addLayout(type_layout)                                                                   
                                                                                                             
        # 签名选项                                                                                           
        self.sign_check = QCheckBox("保留数字签名")                                                          
        mode_layout.addWidget(self.sign_check)                                                               
                                                                                                             
        # 函数名输入(仅导出表模式)                                                                           
        self.func_name = QLineEdit()                                                                         
        self.func_name.setPlaceholderText("输入要注入的导出函数名")                                          
        self.func_name.setVisible(False)                                                                     
        self.func_name.setFixedHeight(30)                                                                    
        mode_layout.addWidget(self.func_name)                                                                
                                                                                                             
        # 注入类型变化时显示/隐藏函数名输入                                                                  
        self.mode_combo.currentTextChanged.connect(                                                          
            lambda t: self.func_name.setVisible(t == "导出表注入")                                           
        )                                                                                                    
                                                                                                             
        mode_group.setLayout(mode_layout)                                                                    
        layout.addWidget(mode_group)                                                                         
                                                                                                             
        # 文件选择                                                                                           
        file_group = QGroupBox("文件选择")                                                                   
        file_layout = QVBoxLayout()                                                                          
        file_layout.setContentsMargins(10, 15, 10, 10)                                                       
                                                                                                             
        # PE文件选择                                                                                         
        pe_layout = QHBoxLayout()                                                                            
        self.pe_path = QLineEdit()                                                                           
        self.pe_path.setPlaceholderText("选择要修改的PE文件")                                                
        self.pe_path.setFixedHeight(30)                                                                      
                                                                                                             
        pe_btn = QPushButton("浏览...")                                                                      
        pe_btn.setFixedHeight(30)                                                                            
        pe_btn.clicked.connect(                                                                              
            lambda: self._select_file(self.pe_path, "选择PE文件", "可执行文件 (*.exe *.dll)")                
        )                                                                                                    
                                                                                                             
        pe_layout.addWidget(self.pe_path)                                                                    
        pe_layout.addWidget(pe_btn)                                                                          
        file_layout.addLayout(pe_layout)                                                                     
                                                                                                             
        # Shellcode文件选择                                                                                  
        sc_layout = QHBoxLayout()                                                                            
        self.sc_path = QLineEdit()                                                                           
        self.sc_path.setPlaceholderText("选择shellcode文件")                                                 
        self.sc_path.setFixedHeight(30)                                                                      
                                                                                                             
        sc_btn = QPushButton("浏览...")                                                                      
        sc_btn.setFixedHeight(30)                                                                            
        sc_btn.clicked.connect(                                                                              
            lambda: self._select_file(self.sc_path, "选择shellcode文件", "所有文件 (*)")                     
        )                                                                                                    
                                                                                                             
        sc_layout.addWidget(self.sc_path)                                                                    
        sc_layout.addWidget(sc_btn)                                                                          
        file_layout.addLayout(sc_layout)                                                                     
                                                                                                             
        file_group.setLayout(file_layout)                                                                    
        layout.addWidget(file_group)                                                                         
                                                                                                             
        layout.addStretch()                                                                                  
        self.setLayout(layout)                                                                               
                                                                                                             
    def _select_file(self, line_edit, title, filter):                                                        
        """显示文件选择对话框并更新输入框"""                                                                 
        path = select_file_dialog(self, title, filter)                                                       
        if path:                                                                                             
            line_edit.setText(path)                                                                          
                                                                                                             
    def on_execute_injection(self):                                                                          
        """执行注入按钮点击事件"""                                                                           
        pe_path = self.pe_path.text()                                                                        
        sc_path = self.sc_path.text()                                                                        
        mode = self.mode_combo.currentText()                                                                 
        keep_sign = self.sign_check.isChecked()                                                              
                                                                                                             
        if not pe_path or not sc_path:                                                                       
            QMessageBox.warning(self, "警告", "请选择PE文件和shellcode文件")                                 
            return                                                                                           
                                                                                                             
        try:                                                                                                 
            # 备份文件                                                                                       
            self.injector.backup_file(pe_path)                                                               
                                                                                                             
            # 处理签名                                                                                       
            cert = None                                                                                      
            if keep_sign:                                                                                    
                cert = self.injector.copy_cert(pe_path)                                                      
                                                                                                             
            # 执行注入                                                                                       
            if mode == "函数注入":                                                                           
                self.injector.function_inject(pe_path, sc_path)                                              
            elif mode == "入口点注入":                                                                       
                self.injector.entrypoint_inject(pe_path, sc_path)                                            
            elif mode == "TLS注入":                                                                          
                self.injector.tls_inject(pe_path, sc_path)                                                   
            elif mode == "导出表注入":                                                                       
                func_name = self.func_name.text()                                                            
                if not func_name:                                                                            
                    raise ValueError("导出表注入需要指定函数名")                                             
                self.injector.eat_inject(pe_path, sc_path, func_name)                                        
                                                                                                             
            # 恢复签名                                                                                       
            if keep_sign and cert:                                                                           
                self.injector.write_cert(cert, pe_path)                                                      
                                                                                                             
            # 使用主窗口的状态栏                                                                             
            if hasattr(self.main_window, 'statusBar'):                                                       
                self.main_window.statusBar().showMessage("注入成功", 3000)                                   
            QMessageBox.information(self, "成功", "PE注入完成")                                              
        except Exception as e:                                                                               
            # 使用主窗口的状态栏                                                                             
            if hasattr(self.main_window, 'statusBar'):                                                       
                self.main_window.statusBar().showMessage(f"注入失败: {str(e)}", 3000)                        
            QMessageBox.critical(self, "错误", f"注入失败: {str(e)}")                                        
                                                                                                             