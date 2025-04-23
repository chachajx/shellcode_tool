                                                                                                                
from PyQt6.QtWidgets import QMainWindow, QTabWidget,QWidget,QVBoxLayout                                              
from ui.encryption_tab import EncryptionTab                                                                    
from ui.injector_tab import PEInjectorTab                                                                      
from ui.extractor_tab import PEExtractorTab  # 新增导入                                                        
                                                                                                               
class ShellcodeToolkit(QMainWindow):                                                                           
    def __init__(self):                                                                                        
        super().__init__()                                                                                     
        self.setWindowTitle("Shellcode Toolkit v3.1")  # 更新版本号                                            
        self.setGeometry(200, 200, 1000, 700)                                                                  
        self.setup_ui()                                                                                        
                                                                                                               
    def setup_ui(self):                                                                                        
        # 主选项卡                                                                                             
        self.tabs = QTabWidget()                                                                               
        self.tabs.setDocumentMode(True)                                                                        
                                                                                                               
        # 添加加密工具标签页                                                                                   
        self.encryption_tab = EncryptionTab()                                                                  
        self.tabs.addTab(self.encryption_tab, "🔒 shellcode加密")                                                   
                                                                                                               
        # 添加PE注入工具标签页                                                                                 
        self.injector_tab = PEInjectorTab(self)                                                                
        self.tabs.addTab(self.injector_tab, "💉 PE注入")                                                       
                                                                                                               
        # 添加PE提取工具标签页                                                                                 
        self.extractor_tab = PEExtractorTab(self)                                                              
        self.tabs.addTab(self.extractor_tab, "📦 PE提取")                                                      
                                                                                                               
        # 主布局                                                                                               
        main_widget = QWidget()                                                                                
        main_layout = QVBoxLayout()                                                                            
        main_layout.addWidget(self.tabs)                                                                       
        main_layout.setContentsMargins(10, 10, 10, 10)                                                         
        main_layout.setSpacing(10)                                                                             
                                                                                                               
        main_widget.setLayout(main_layout)                                                                     
        self.setCentralWidget(main_widget)                                                                     
                                                                                                               