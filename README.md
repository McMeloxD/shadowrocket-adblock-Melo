# shadowrocket-adblock-Melo

将多个去广告模块每日自动合并为一个 Shadowrocket 模块，合并前进行安全校验。
由 [McMeloxD](https://github.com/McMeloxD) 维护。

## 用法

Shadowrocket → 配置 → 模块 → 添加远程模块：

```text
https://raw.githubusercontent.com/McMeloxD/shadowrocket-adblock-Melo/main/dist/merged.sgmodule
```

模块已合并 MITM 域名。使用 HTTPS 重写和脚本功能时，需启用 MITM，并安装、信任自己的证书。

## 覆盖

QQ 音乐、高德地图、淘宝、京东、中国联通、美团、哔哩哔哩、滴滴、闲鱼的去广告模块，
以及秋风 AWAvenue 的第三方广告域名规则。

具体效果取决于上游规则、App 版本及客户端设置。

## 自动更新

每天北京时间 03:17 自动拉取上游、校验并合并，也支持手动运行 GitHub Actions。
检查脚本来源与哈希、MITM 敏感域及通配符、下载完整性和规则数量异常；校验失败时停止更新，保留上一版。

## 来源

- [秋风 AWAvenue](https://github.com/TG-Twilight/AWAvenue-Ads-Rule)
- [fmz200/wool_scripts](https://github.com/fmz200/wool_scripts)

感谢原始仓库及各规则、脚本作者的维护。
