                                                                                                              
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,                                   
                           QLabel, QLineEdit, QPushButton, QProgressBar,                                     
                           QTextEdit, QMessageBox, QFileDialog)                                              
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont                                                                                  
from core.pe_extractor import PEExtractor                                                                    
                                                                                                             
class PEExtractorTab(QWidget):                                                                               
    def __init__(self, parent=None):                                                                         
        super().__init__(parent)                                                                             
        self.extractor = PEExtractor()                                                                       
        self.main_window = parent                                                                            
        self.setup_ui()                                                                                      
                                                                                                             
    def setup_ui(self):                                                                                      
        # 主布局                                                                                             
        layout = QVBoxLayout()                                                                               
        layout.setContentsMargins(5, 5, 5, 5)                                                                
        layout.setSpacing(10)                                                                                
                                                                                                             
        # 按钮工具栏                                                                                         
        button_bar = QHBoxLayout()                                                                           
        button_bar.setSpacing(5)                                                                             
                                                                                                             
        self.extract_btn = QPushButton("提取Shellcode")                                                      
        self.extract_btn.setFixedHeight(30)                                                                  
        self.extract_btn.clicked.connect(self.on_extract)                                                    
                                                                                                             
        button_bar.addWidget(self.extract_btn)                                                               
        button_bar.addStretch()                                                                              
        layout.addLayout(button_bar)                                                                         
                                                                                                             
        # 输入文件部分                                                                                       
        input_group = QGroupBox("选择PE文件")                                                                
        input_group.setStyleSheet("QGroupBox { margin-top: 5px; }")                                          
        input_layout = QVBoxLayout()                                                                         
        input_layout.setContentsMargins(10, 15, 10, 10)                                                      
                                                                                                             
        pe_layout = QHBoxLayout()                                                                            
        self.pe_path = QLineEdit()                                                                           
        self.pe_path.setPlaceholderText("选择PE文件")                                                        
        self.pe_path.setFixedHeight(30)                                                                      
                                                                                                             
        pe_btn = QPushButton("浏览...")                                                                      
        pe_btn.setFixedHeight(30)                                                                            
        pe_btn.clicked.connect(                                                                              
            lambda: self._select_file(self.pe_path, "选择PE文件", "可执行文件 (*.exe *.dll)")                
        )                                                                                                    
                                                                                                             
        pe_layout.addWidget(self.pe_path)                                                                    
        pe_layout.addWidget(pe_btn)                                                                          
        input_layout.addLayout(pe_layout)                                                                    
        input_group.setLayout(input_layout)                                                                  
        layout.addWidget(input_group)                                                                        
                                                                                                             
        # 输出文件部分                                                                                       
        output_group = QGroupBox("输出文件路径")                                                             
        output_group.setStyleSheet("QGroupBox { margin-top: 5px; }")                                         
        output_layout = QVBoxLayout()                                                                        
        output_layout.setContentsMargins(10, 15, 10, 10)                                                     
                                                                                                             
        out_layout = QHBoxLayout()                                                                           
        self.output_path = QLineEdit()                                                                       
        self.output_path.setPlaceholderText("选择输出文件")                                                  
        self.output_path.setFixedHeight(30)                                                                  
                                                                                                             
        out_btn = QPushButton("浏览...")                                                                     
        out_btn.setFixedHeight(30)                                                                           
        out_btn.clicked.connect(                                                                             
            lambda: self._select_output_file()                                                               
        )                                                                                                    
                                                                                                             
        out_layout.addWidget(self.output_path)                                                               
        out_layout.addWidget(out_btn)                                                                        
        output_layout.addLayout(out_layout)                                                                  
        output_group.setLayout(output_layout)                                                                
        layout.addWidget(output_group)                                                                       
                                                                                                             
        # 进度条                                                                                             
        self.progress = QProgressBar()                                                                       
        self.progress.setRange(0, 100)                                                                       
        self.progress.setFixedHeight(20)                                                                     
        layout.addWidget(self.progress)                                                                      
                                                                                                             
        # 日志输出                                                                                           
        log_group = QGroupBox("操作日志")                                                                    
        log_group.setStyleSheet("QGroupBox { margin-top: 5px; }")                                            
        log_layout = QVBoxLayout()                                                                           
        log_layout.setContentsMargins(10, 15, 10, 10)                                                        
                                                                                                             
        self.log_text = QTextEdit()                                                                          
        self.log_text.setReadOnly(True)                                                                      
        self.log_text.setFont(QFont("Consolas", 10))                                                         
        self.log_text.setMinimumHeight(150)                                                                  
                                                                                                             
        log_layout.addWidget(self.log_text)                                                                  
        log_group.setLayout(log_layout)                                                                      
        layout.addWidget(log_group)                                                                          
                                                                                                             
        layout.addStretch()                                                                                  
        self.setLayout(layout)                                                                               
                                                                                                             
    def _select_file(self, line_edit, title, filter):                                                        
        """显示文件选择对话框并更新输入框"""                                                                 
        path, _ = QFileDialog.getOpenFileName(self, title, "", filter)                                       
        if path:                                                                                             
            line_edit.setText(path)                                                                          
            self.log_message(f"已选择输入文件: {path}")                                                      
                                                                                                             
    def _select_output_file(self):                                                                           
        """选择输出文件"""                                                                                   
        path, _ = QFileDialog.getSaveFileName(                                                               
            self,                                                                                            
            "保存Shellcode",                                                                                 
            "",                                                                                              
            "二进制文件 (*.bin);;所有文件 (*)"                                                               
        )                                                                                                    
        if path:                                                                                             
            if not path.endswith('.bin'):                                                                    
                path += '.bin'                                                                               
            self.output_path.setText(path)                                                                   
            self.log_message(f"设置输出路径: {path}")                                                        
                                                                                                             
    def on_extract(self):                                                                                    
        """执行提取操作"""                                                                                   
        pe_path = self.pe_path.text()                                                                        
        output_path = self.output_path.text()                                                                
                                                                                                             
        if not pe_path:                                                                                      
            QMessageBox.warning(self, "警告", "请选择PE文件")                                                
            return                                                                                           
                                                                                                             
        if not output_path:                                                                                  
            QMessageBox.warning(self, "警告", "请设置输出路径")                                              
            return                                                                                           
                                                                                                             
        if not os.path.exists(pe_path):                                                                      
            QMessageBox.warning(self, "警告", "输入文件不存在")                                              
            return                                                                                           
                                                                                                             
        self.progress.setValue(10)                                                                           
        self.log_message(f"开始处理文件: {os.path.basename(pe_path)}")                                       
                                                                                                             
        try:                                                                                                 
            success, message = self.extractor.extract_text_section(pe_path, output_path)                     
                                                                                                             
            if success:                                                                                      
                self.progress.setValue(100)                                                                  
                self.log_message(message)                                                                    
                self.log_message(f"Shellcode已保存到: {output_path}")                                        
                QMessageBox.information(                                                                     
                    self,                                                                                    
                    "完成",                                                                                  
                    f"{message}\n保存到: {output_path}"                                                      
                )                                                                                            
            else:                                                                                            
                self.progress.setValue(0)                                                                    
                self.log_message(f"错误: {message}")                                                         
                QMessageBox.critical(self, "错误", message)                                                  
        except Exception as e:                                                                               
            self.progress.setValue(0)                                                                        
            self.log_message(f"处理错误: {str(e)}")                                                          
            QMessageBox.critical(self, "错误", f"处理错误: {str(e)}")                                        
                                                                                                             
    def log_message(self, message):                                                                          
        """记录日志信息"""                                                                                   
        self.log_text.append(message)                                                                        
        self.log_text.ensureCursorVisible()                                                                  
                                                                                                             