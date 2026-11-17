# pairwise-cert-chain

内部 CA 一轮换，服务端证书链就验不过：链构建只按 issuer 字符串找父证书，交叉签名的两条链随机选；name constraints 只检查叶子，中间 CA 的 DNS 约束被忽略；EKU 没有区分 serverAuth 和 clientAuth，客户端证书能当服务端用；OCSP 响应没有校验 thisUpdate/nextUpdate，过期响应仍被接受；证书透明度只检查 SCT 数量，签名者不在白名单；pinning 只 pin 叶子证书，轮换后无法灰度。security/cert_chain.py 是核心，tests/test_cert_chain.py 15个红。要修的是：按签名构建链；逐级 name constraints；EKU 用途；OCSP 时效；SCT 签名者；pin 公钥/SPKI。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：其他；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
