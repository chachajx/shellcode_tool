                                                                                                                
import pefile                                                                                                  
import os                                                                                                      
                                                                                                               
class PEExtractor:                                                                                             
    def __init__(self):                                                                                        
        pass                                                                                                   
                                                                                                               
    def extract_text_section(self, pe_path, output_path):                                                      
        """                                                                                                    
        从PE文件中提取.text段                                                                                  
        :param pe_path: PE文件路径                                                                             
        :param output_path: 输出文件路径                                                                       
        :return: (success, message)                                                                            
        """                                                                                                    
        try:                                                                                                   
            pe = pefile.PE(pe_path)                                                                            
                                                                                                               
            for section in pe.sections:                                                                        
                try:                                                                                           
                    section_name = section.Name.replace(b'\x00', b'').decode('utf-8')                          
                    if section_name == ".text":                                                                
                        data = section.get_data()                                                              
                        size = len(data)                                                                       
                                                                                                               
                        with open(output_path, 'wb') as f:                                                     
                            f.write(data)                                                                      
                                                                                                               
                        return True, f"成功提取 {size} 字节"                                                   
                except Exception as e:                                                                         
                    continue                                                                                   
                                                                                                               
            return False, "未找到.text段"                                                                      
        except pefile.PEFormatError as e:                                                                      
            return False, "无效的PE文件格式"                                                                   
        except Exception as e:                                                                                 
            return False, f"处理错误: {str(e)}"                                                                
                                                                                                               