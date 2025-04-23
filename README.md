 # Shellcode Toolkit (Shellcode处理工具)                                                                 
                                                                                                                                                                                                                                                                      
一款基于PyQt5的Shellcode生成与测试工具，支持多种编码方式和注入技术。                                  
                                                                                                            
## 主要功能                                                                                                 
                                                                                                            
### 核心功能                                                                                                
  Shellcode加密处理支持（Base64、XOR、AES等）                                                                   
  PE注入，支持函数注入、入口点注入、TLS注入、导出表注入                                                                                                                                                                                                                                                                                                                                                                         
                                                                                                           
### 基础环境                                                                                                
```bash                                                                                                     
# 克隆仓库                                                                                                  
git clone https://github.com/chachajx/shellcode_toolkit.git                                                 
cd shellcode_toolkit                                                                                        
                                                                                                            
# 安装依赖                                                                                                  
pip install -r requirements.txt                                                                             
```                                                                                                         
                                                                                                                                                                                                 
## 使用说明                                                                                                 
                                                                                                            
### 图形界面                                                                                                
```bash                                                                                                     
python main.py                                                                                              
```                                                                                                         
                                                                   
## 免责声明                                                                                                 
                                                                                                            
⚠️ 本工具仅限授权安全测试使用，禁止用于非法用途。使用者需遵守当地法律法规，开发者不对滥用行为负责。          
                                                                                             
## 致谢
本项目参考https://github.com/timwhitez/BinHol的注入方法进行改写
                                                                            
