# Taker Bot

一个 Taker 平台自动化工具，支持答题、挖矿、播种等功能。

## 功能

- 🔐 生成以太坊钱包
- 📝 自动答题
- 🎯 领取积分
- 🌱 播种任务
- ⛏️ 挖矿任务

## 快速开始


### 1. 配置
复制 `config_demo.yaml` 为 `config.yaml` 并修改配置(打码平台：`https://yescaptcha.com/i/HiIywr`)：
```yaml
settings:
  pause_between_accounts: [10, 20]

yescaptcha: 
  clientKey: "你的打码平台Key"

invite:
  invite_codes: ["邀请码1", "邀请码2"]
```

### 2. 准备私钥
在 `data/private_keys.txt` 中添加私钥，每行一个：
```
0x你的私钥1
0x你的私钥2
```

### 3. 运行
```bash
python main.py
```

或直接运行打包好的 exe 文件：
```bash
./main.exe
```

## 任务说明

运行后选择任务：
- `[0]` 生成助记词 - 生成新钱包
- `[1]` taker答题 - 自动完成答题
- `[2]` 领取答题积分 - 领取奖励
- `[3]` 播种任务 - 执行播种
- `[4]` 挖矿任务 - 执行挖矿

## 打包exe

```bash
pip install pyinstaller
pyinstaller --onefile --console --collect-all pyfiglet --collect-all bip_utils --name taker_main main.py
```

## 注意事项

- 保护好私钥文件安全
- 确保网络连接稳定
- 首次使用建议用测试账户

## 联系

- 开发者: WU KONG
- Telegram: [@wukong_web3](https://t.me/wukong_web3)
- 版本: 2.0