import sys                                                                                                     
from PyQt6.QtWidgets import QApplication                                                                       
from ui.main_window import ShellcodeToolkit                                                                    
                                                                                                               
if __name__ == "__main__":                                                                                     
    app = QApplication(sys.argv)                                                                               
                                                                                                               
    # 在实际环境中替换为您的运行时检查逻辑                                                                     
    try:                                                                                                       
        window = ShellcodeToolkit()                                                                            
        window.show()                                                                                          
        sys.exit(app.exec())                                                                                   
    except ImportError as e:                                                                                   
        print(f"缺少依赖: {str(e)}", file=sys.stderr)                                                          
        print("请运行: pip install -r requirements.txt")                                                    