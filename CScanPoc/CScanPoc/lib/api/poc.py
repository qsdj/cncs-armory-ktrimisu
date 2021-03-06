# coding: utf-8
"""POC"""

from abc import abstractmethod, abstractproperty, ABCMeta
from CScanPoc.lib.core.log import get_scan_outputer
from .vuln import ABVuln
from .common import RuntimeOptionSupport
from urllib.parse import urlparse


class PocException(Exception):
    """POC 相关异常"""

    pass


class PocDefinitionException(PocException):
    """POC 定义错误"""

    pass


class PocStaticDefinition(metaclass=ABCMeta):
    """POC 静态信息定义"""

    def __init__(self, vuln):
        # 当前 poc 扫描的漏洞
        self._vuln = None
        self.vuln = vuln

        # 默认 poc_id 和 poc_name
        self._poc_id = vuln.vuln_id
        self._poc_name = vuln.name

    @property
    def poc_id(self) -> str:
        """CScanPoc 内部 POC ID"""
        return self._poc_id

    @poc_id.setter
    def poc_id(self, val) -> str:
        self._poc_id = val

    @property
    def poc_name(self):
        """POC 名字"""
        return self._poc_name

    @poc_name.setter
    def poc_name(self, val):
        self._poc_name = val

    @property
    def vuln(self) -> ABVuln:
        """当前 POC 绑定的漏洞"""
        return self._vuln

    @vuln.setter
    def vuln(self, val):
        if val is None or not isinstance(val, ABVuln):
            raise PocDefinitionException("POC 关联漏洞设定错误，无效漏洞值：{}".format(val))
        self._vuln = val

    @abstractproperty
    def author(self):
        """poc 作者"""
        pass

    @abstractproperty
    def create_date(self):
        """poc 创建时间
        返回类似 datetime(2017, 12, 30) 的对象
        """
        pass


class ABPoc(PocStaticDefinition, RuntimeOptionSupport):
    """Abstract Base of specific CScan poc

    漏洞的 POC。子类中必须覆写方法 verify 和 exploit
    """

    def __init__(self, vuln, reporter=None):
        """ABPoc.__init__

        :param vuln: 可选，当前扫描器关联的漏洞
        :type vuln: CScanPoc.lib.api.vuln.Vuln
        :param reporter: 漏洞报告函数
        :type reporter: (vuln) -> void
        """
        PocStaticDefinition.__init__(self, vuln)
        RuntimeOptionSupport.__init__(self)

        # 漏洞扫描输出
        self.output = get_scan_outputer(poc=self, reporter=reporter)

        # 扫描目标
        self.target = None

    @property
    def target_url(self):
        """目标 URL 地址，如果给定 target 是 IP，将根据组件 http/https 属性创建实际 URL"""
        if urlparse(self.target).scheme:
            return self.target
        elif "http" in self.components_properties:
            port = self.components_properties["http"].get("port", 80)
            if port == 80:
                return "http://{}".format(self.target)
            else:
                return "http://{}:{}".format(self.target, port)
        elif "https" in self.components_properties:
            port = self.components_properties["https"].get("port", 443)
            if port == 443:
                return "https://{}".format(self.target)
            else:
                return "https://{}:{}".format(self.target, port)
        else:
            return "http://{}".format(self.target)

    @property
    def target_host(self):
        """目标主机地址，如果 target 是 URL，将解析获取其 hostname 部分"""
        parsed = urlparse(self.target)
        if parsed.scheme:
            return parsed.hostname
        return self.target

    @property
    def default_component(self):
        return self.vuln.product

    def run(
        self,
        target=None,
        mode="verify",
        args=None,
        exec_option={},
        components_properties={},
    ):
        """执行扫描操作

        当 target=None 时，忽略函数参数，解析命令行参数获取执行参数

        :param target: 扫描目标
        :param mode: 扫描模式
        :type target: str, None 默认为 None
        :type mode: 'verify' | 'exploit'
        """

        if target is None:
            args = super().parse_args(args)
            self.target = args.url
            mode = args.mode
        else:
            self.target = target
            self.exec_option = exec_option
            self.components_properties = components_properties

        if not self.target:
            return

        if mode == "verify":
            self.output.info('开始使用 %s 验证 %s' % (self, self.vuln))
            self.verify()
        else:
            self.exploit()

    @abstractmethod
    def verify(self):
        """漏洞验证"""
        pass

    def exploit(self):
        """漏洞利用"""
        self.verify()

    def __str__(self):
        return "[Poc {}]".format(self.poc_name)
