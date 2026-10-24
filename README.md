# ota-manifest

离线生成和验证软件更新清单的最小实现。清单包含版本、目标 ECU、镜像 SHA-256、大小和回滚策略，签名使用标准库 HMAC-SHA256，便于在没有第三方依赖和网络的环境中做 CI 练习。

使用示例：python otamanifest.py sign examples/payload.bin examples/manifest.json --version 1.0.0 --key demo-secret；验证使用 python otamanifest.py verify examples/manifest.json --key demo-secret。

演示版使用共享密钥，量产应替换为硬件保护的非对称签名和密钥轮换机制。

UN R156/ISO 24089 让软件更新的版本、目标、完整性和可追溯证据成为持续运营的一部分。这个仓库提供可读、可审计的最小数据模型，帮助团队先把流程固化。

## 许可证

MIT
