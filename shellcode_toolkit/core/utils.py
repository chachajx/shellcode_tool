import os                                                                                                      
import binascii                                                                                                
                                                                                                               
def format_hex(data):                                                                                          
    """格式化十六进制显示"""                                                                                   
    if not isinstance(data, bytes):                                                                            
        raise ValueError("输入必须是bytes类型")                                                                
    hex_str = binascii.hexlify(data).decode()                                                                  
    return ' '.join([hex_str[i:i+2] for i in range(0, len(hex_str), 2)])                                       
                                                                                                               
def validate_hex_input(hex_str):                                                                               
    """验证十六进制输入"""                                                                                     
    if not isinstance(hex_str, str):                                                                           
        raise ValueError("输入必须是字符串")                                                                   
                                                                                                               
    hex_str = hex_str.replace(" ", "")                                                                         
    if not hex_str:                                                                                            
        raise ValueError("输入不能为空")                                                                       
    if len(hex_str) % 2 != 0:                                                                                  
        raise ValueError("十六进制长度应为偶数")                                                               
    try:                                                                                                       
        return binascii.unhexlify(hex_str)                                                                     
    except Exception as e:                                                                                     
        raise ValueError(f"无效的十六进制数据: {str(e)}")                                                      
                                                                                                               
def select_file_dialog(parent, title, filter):                                                                 
    """显示文件选择对话框"""                                                                                   
    from PyQt6.QtWidgets import QFileDialog                                                                    
    path, _ = QFileDialog.getOpenFileName(parent, title, "", filter)                                           
    return path                                                        