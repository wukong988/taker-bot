
from typing import Optional
from termcolor import cprint
from pyfiglet import figlet_format
from colorama import init
import sys
import os
import json
import yaml
from loguru import logger
from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes




def show_logo():
    os.system("cls")
    init(strip=not sys.stdout.isatty())
    print("\n")
    logo = figlet_format("WU KONG", font="banner3")
    cprint(logo, 'light_cyan')
    print("")


def show_dev_info():
    print("\033[36m" + "VERSION: " + "\033[92m" + "2.0" + "\033[92m")
    print("\033[36m"+"DEV: " + "\033[92m" + "https://t.me/wukong_web3" + "\033[92m")
    # print("\033[36m"+"GitHub: " + "\033[92m" + "https://github.com/wukong988" + "\033[92m")
    print("\033[36m" + "DONATION EVM ADDRESS: " + "\033[92m" + "0x4c7973492b57d4a3d5370ea6d16ab052f9d61dfc" + "\033[0m")
    print()


def show_menu(menu_items: list):
    os.system("")
    print()
    counter = 0
    for item in menu_items:
        counter += 1

        if counter == len(menu_items):
            print('' + '[' + '\033[34m' + f'{counter}' + '\033[0m' + ']' + f' {item}\n')
        else:
            print('' + '[' + '\033[34m' + f'{counter}' + '\033[0m' + ']' + f' {item}')

def read_txt_file(file_name: str, file_path: str) -> list:
    with open(file_path, "r") as file:
        items = [line.strip() for line in file]

    logger.success(f"Successfully loaded {len(items)} {file_name}.")
    return items


def read_config() -> dict:
    with open('config.yaml', 'r', encoding='utf-8') as file:
        config = yaml.safe_load(file)

    return config

def write_config(config: dict):
    with open('config.yaml', 'w', encoding='utf-8') as file:
        yaml.dump(config, file, allow_unicode=True, default_flow_style=False)

def update_config(key: str, value) -> dict:
    config = read_config()
    config[key] = value
    write_config(config)
    return config

def read_abi(path) -> dict:
    with open(path, "r") as f:
        return json.load(f)

        
def generate_eth_wallet() -> Optional[dict]:
    try:
        
        # 生成一个12个单词的助记词（你也可以选择24个）
        mnemonic = Bip39MnemonicGenerator().FromWordsNumber(12)
        print("Mnemonic:", mnemonic)

        # 从助记词生成种子
        seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

        # 使用以太坊标准路径 m/44'/60'/0'/0/0
        bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
        account = bip44_mst_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)

        # 输出地址、私钥、公钥
        print("Address:   ", account.PublicKey().ToAddress())
        print("Private Key:", account.PrivateKey().Raw().ToHex())
        print("Public Key: ", account.PublicKey().RawCompressed().ToHex())
        
        return {
            "mnemonic": mnemonic.ToStr(),
            "private_key": "0x" + account.PrivateKey().Raw().ToHex(),
            "address": account.PublicKey().ToAddress()
        }
    except Exception as error:
        print(f"生成钱包时出错: {error}")
        return None
