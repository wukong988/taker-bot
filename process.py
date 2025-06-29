import queue
import random
import time
from concurrent.futures import ThreadPoolExecutor

import requests
from loguru import logger
import threading

import taker
from utils import show_logo, show_dev_info, read_config, read_txt_file, generate_eth_wallet


def start():
    show_logo()
    show_dev_info()

    task = int(
        input(
            "请选择要执行的任务: \n\n"
            "[0] 生成助记词\n"
            "[1] taker答题\n"
            "[2] taker领取答题积分\n"
            "[3] taker领取及sowing\n"
            "[4] taker-Miner挖矿\n"
            "[9] 占位.....\n\n>> "
        ).strip()
    )


    # task = 6

    def launch_wrapper(index, private_key):
        if index <= threads:
            delay = random.uniform(1, threads)
            logger.info(f"线程 {index} 启动，延迟 {delay:.1f}秒")
            time.sleep(delay)

        account_flow(lock, index, private_key, config, task)

    if task == 0:
        threads = int(input("\n请输入需要生成的数量: ").strip())
        for i in range(threads):
            wallet = generate_eth_wallet()
            with open("./data/wallets.txt", "a") as f:
                row_text = f"{wallet.get('mnemonic')}:{wallet.get('private_key')}:{wallet.get('address')}\n"
                f.write(row_text)
        logger.success("所有账户执行完毕，已将账户和私钥保存到文件..................")
        return 

    threads = 1
    # 连接邮箱需要验证码，需要手动输入，不能多线程
    if task != 0: 
        threads = int(input("\n请输入需要的线程数: ").strip())

    config = read_config()

    private_keys = read_txt_file("private keys", "data/private_keys.txt")
    indexes = [i + 1 for i in range(len(private_keys))]

    lock = threading.Lock()

    if task in [3, 4]:
        cycle_interval = config["cycle"]["cycle_interval"]
        cycle_count = config["cycle"]["cycle_count"]
        for i in range(cycle_count):
            logger.info(f"开始执行第 {i+1} 次...")
            with ThreadPoolExecutor(max_workers=threads) as executor:
                executor.map(launch_wrapper, indexes, private_keys)
        
            wait_time = random.randint(cycle_interval[0], cycle_interval[1])
            logger.info(f"第 {i+1} 次执行完毕，等待 {wait_time} 秒后继续执行")
            time.sleep(wait_time)
        return
    else:
        logger.info("开始执行...")
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(launch_wrapper, indexes, private_keys)
        logger.success("所有账户执行完毕....")

def account_flow(
    lock: threading.Lock,
    account_index: int,
    private_key: str,
    config: dict,
    task: int
):
    try:
        logger.info(f"当前账号: {account_index}")
        taker_instance = taker.Taker(private_key, config)

        address = ""
        token = ""
        if task in [1, 2, 3]:
            ok, address, token = wrapper(taker_instance.init_instance, 1)
            logger.info(f"{account_index} | 初始化 taker 实例成功: {address}")
            if not ok:
                raise Exception("无法初始化 taker 实例")
        elif task == 4:
            ok, address, token = wrapper(taker_instance.init_lightmining_instance, 1)
            logger.info(f"{account_index} | 初始化 taker 实例成功: {address}")
            if not ok:
                raise Exception("无法初始化 taker 实例")

        if task == 1:
            ok = wrapper(taker_instance.start, 1)
            if not ok:
                raise Exception("无法完成所有任务")

        if task == 2:
            ok = wrapper(taker_instance.claim_answer_score, 1)
            if not ok:
                raise Exception("无法领取答题积分")

        if task == 3:
            ok, message, wait_time = wrapper(taker_instance.execute_sowing_task, 1, token)
            with lock:
                with open("data/sowing_data.txt", "a", encoding="utf-8") as f:
                    f.write(f"{address}:{message}:{time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            if not ok:
                raise Exception(f"无法领取及播种: {message}")

        if task == 4:
            ok, message, wait_time = wrapper(taker_instance.execute_lightmining_task, 1, token)
            with lock:
                with open("data/miner_data.txt", "a", encoding="utf-8") as f:
                    f.write(f"{address}:{message}:{time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            if not ok:
                raise Exception(f"无法挖矿: {message}")
                
        

        # if task == 0:
        #     with lock:
        #         with open("data/address_data.txt", "a") as f:
        #             f.write(f"{private_key}:{address}\n")

        time.sleep(
            random.randint(
                config["settings"]["pause_between_accounts"][0],
                config["settings"]["pause_between_accounts"][1],
            )
        )
        logger.success(f"{account_index} | 账户流程执行成功")

    except Exception as err:
        logger.error(f"{account_index} | 账户流程失败: {err}")


def wrapper(function, attempts: int, *args, **kwargs):
    for _ in range(attempts):
        result = function(*args, **kwargs)
        if isinstance(result, tuple) and result and isinstance(result[0], bool):
            if result[0]:
                return result
        elif isinstance(result, bool):
            if result:
                return True

    return result


def report_failed_key(private_key: str, invite_code: str):
    try:
        with open("./data/failed_keys.txt", "a") as file:
            file.write(private_key + ":" + invite_code + "\n")

    except Exception as err:
        logger.error(f"报告失败账户时出错: {err}")
