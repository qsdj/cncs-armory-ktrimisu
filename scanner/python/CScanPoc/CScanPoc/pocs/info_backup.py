# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Info_Backup'  # 平台漏洞编号，留空
    name = '网站备份文件泄露'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        网站运维管理人员有时候操作不当会将一些敏感文件甚至是网站备份文件放在网站的目录下,攻击者可以直接下载到这些数据,直接造成了网站的重要数据信息泄露.
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Info_Backup(网站备份文件泄露)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '14642a57-847b-4d22-b70e-99f561114f27'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-28'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # 讲常见的后台地址组成list,循环去请求是否存在默认后台地址
            filename_list = ['www', 'back', 'backup', 'web', 'temp', 'data']
            filetypt_list = ['.rar', '.zip', '.7z',
                             '.tar.gz', '.bak', '.swp', '.txt']
            for filename in filename_list:
                for filetype in filetypt_list:
                    payload = filename+filetype
                    request = requests.get(
                        '{target}/{payload}'.format(target=self.target, payload=payload))
                    # print request.url
                    if request.status_code == 200 and filename+filetype in request.text:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞;存在文件{fname}'.format(
                            target=self.target, name=self.vuln.name, fname=filename+filetype))
                        continue

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        # 这里直接将后台地址输出来
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            filename_list = ['www', 'back', 'backup', 'web', 'temp', 'data']
            filetypt_list = ['.rar', '.zip', '.7z',
                             '.tar.gz', '.bak', '.swp', '.txt']
            for filename in filename_list:
                for filetype in filetypt_list:
                    payload = filename+filetype
                    request = requests.get(
                        '{target}/{payload}'.format(target=self.target, payload=payload))
                    # print request.url
                    if request.status_code == 200 and filename+filetype in request.text:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞;存在文件{fname}'.format(
                            target=self.target, name=self.vuln.name, fname=filename+filetype))
                        continue

        except Exception, e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
