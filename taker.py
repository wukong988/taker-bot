import asyncio
import json
import random
import time
from traceback import format_exc
from typing import Dict, Optional
from eth_account import Account
from loguru import logger
from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
from eth_account.messages import encode_defunct


import requests
from web3 import Web3

url = "https://sowing-api.taker.xyz"
lightmining_url = "https://lightmining-api.taker.xyz"
invitation_code = ""

class Taker:        
    def __init__(self, mnemonic_str: str, config: dict):
        self.mnemonic_str = mnemonic_str
        self.private_key = ""
        self.invitation_code = ""
        self.address = ""
        self.token = ""
        self.config = config
        self.lightmining_token = ""

    def sign_message(self, message: str) -> str:
        try:
            account = Account.from_key(self.private_key)
            # 正确构建 SignableMessage 对象
            message_encoded = encode_defunct(text=message)
            signed_message = account.sign_message(message_encoded)
            return signed_message.signature.hex()
        except Exception as error:
            logger.error(f"签名消息时出错: {error}")
            return None

    def get_nonce(self, wallet_address: str, retries: int = 3) -> Optional[str]:
        try:
            response = requests.post(
                url=f"{url}/wallet/generateNonce",
                json={"walletAddress": wallet_address}
            )
            response.raise_for_status()  # 检查响应状态
            return response.json()
        except Exception as error:
            if retries > 0:
                logger.error(f"获取 nonce 失败: {str(error)}")
                logger.warning(f"正在重试... (剩余 {retries - 1} 次尝试)")
                time.sleep(3)  # 暂停3秒
                return self.get_nonce(wallet_address, retries - 1)
            else:
                logger.error(f"多次重试后仍无法获取 nonce: {str(error)}")
                return None

    def login(self, address: str, message: str, signature: str, retries: int = 3) -> Optional[Dict]:
        try:
            data = {
                "address": address,
                "message": message,
                "signature": signature
            }
            if self.config["invite"]["invite_codes"]:
                ref_code = random.choice(self.config["invite"]["invite_codes"])
                if ref_code:
                    data["refCode"] = ref_code
            response = requests.post(
                url=f"{url}/wallet/login",
                json=data
            )
            response.raise_for_status()  # 检查响应状态
            return response.json()
        except Exception as error:
            if retries > 0:
                logger.error(f"登录失败: {str(error)}")
                logger.warning(f"正在重试... (剩余 {retries - 1} 次尝试)")
                time.sleep(3)  # 暂停3秒
                return self.login(address, message, signature, retries - 1)
            else:
                logger.error(f"多次重试后仍无法登录: {str(error)}")
                return None
    
    def get_user_info(self, token: str):
        response = requests.get(
            url=f"{url}/user/info",
            headers={"Authorization": f"Bearer {token}"}
        )
        return response.json()

    """获取答题任务明细"""
    def get_answer_task_detail(self, token: str, address: str):
        response = requests.get(
            url=f"{url}/task/detail?walletAddress={address}&taskId=6",
            headers={"Authorization": f"Bearer {token}"}
        )
        return response.json()

    """获取平台任务列表"""
    def get_task_list(self, token: str):
        response = requests.get(
            url=f"{url}/task/list?walletAddress={self.address}",
            headers={"Authorization": f"Bearer {token}"}
        )
        return response.json()

    """校验答题"""
    def check_answer(self, token: str, taskId: str = "6", taskEventId: str = "", answer: list = []):
        data = {
            "answerList": answer,
            "taskId": taskId,
            "taskEventId": taskEventId
        }
        response = requests.post(
            url=f"{url}/task/check",
            headers={"Authorization": f"Bearer {token}"},
            json=data
        )
        """
            {"code":200,"message":"SUCCESS","result":true,"total":0}
        """
        return response.json()

    """ 获取答题积分 """
    def get_answer_score(self, token: str):
        response = requests.get(
            url=f"{url}/task/claim-reward?taskId=6",
            headers={"Authorization": f"Bearer {token}"}
        )
        return 

    def claim_answer_score(self):

        # task_list = self.get_task_list(self.token)
        # if task_list.get('code') != 200:
        #     logger.error(f"获取平台任务列表失败: {task_list.get('message')}")
        #     return
        # task_list = task_list.get('result')
        # for task in task_list:
        #     taskId = task.get('id')
        #     if taskId == 6:

        

        answer_task_response = self.get_answer_task_detail(self.token, self.address)
        if answer_task_response.get('code') != 200:
            logger.error(f"获取答题任务明细失败: {answer_task_response.get('message')}")
            return
        task_result = answer_task_response.get('result')
        taskEvents = task_result.get('taskEvents')
        over_task = True
        for taskEvent in taskEvents:
            taskEventId = taskEvent.get('id')
            title = taskEvent.get('title')
            completed = taskEvent.get('completeStatus')
            if completed != 1:
                logger.info(f"任务未完成: {title} {taskEventId} ")
                over_task = False
                break

        if not over_task:
            logger.error(f"不可领取积分，答题任务未完成...")
            return False
        answer_score_response = self.get_answer_score(self.token)
        logger.info(f"领取积分结束...")
        
        return True
            
        

    def init_instance(self):
        try:
            for i in range(3):

                # mnemonic_str = "forget length upper chief rebel vast parade faculty bomb hurdle matrix large"
                # 从助记词生成种子
                seed_bytes = Bip39SeedGenerator(self.mnemonic_str).Generate()

                # 使用以太坊标准路径 m/44'/60'/0'/0/0
                bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
                account = bip44_mst_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)

                self.private_key = "0x" + account.PrivateKey().Raw().ToHex()
                
                address = Account.from_key(self.private_key).address
                self.address = address
                message_response = self.get_nonce(address)
                if message_response.get('code') != 200:
                    logger.error(f"获取nonce失败: {message_response.get('message')}")
                    continue
                nonce = message_response.get('result').get('nonce')
                signature = self.sign_message(nonce)
                if signature is None:
                    logger.error("签名失败")
                    continue
                login_response = self.login(address, nonce, "0x" + signature)
                if login_response.get('code') != 200:
                    logger.error(f"登录失败: {login_response.get('message')}")
                    continue
                token = login_response.get('result').get('token')
                self.token = token
                return True, address, token
            return False, "", ""
        except Exception as error:
            logger.error(f"初始化实例时出错: {error}")
            return False, "", ""

    """ 开始答题 """
    def start(self):

        answer_task_response = self.get_answer_task_detail(self.token, self.address)
        if answer_task_response.get('code') != 200:
            logger.error(f"获取答题任务明细失败: {answer_task_response.get('message')}")
            return
        task_result = answer_task_response.get('result')
        taskEvents = task_result.get('taskEvents')
        for taskEvent in taskEvents:
            taskEventId = taskEvent.get('id')
            description = taskEvent.get('description')
            options = taskEvent.get('options')
            title = taskEvent.get('title')
            completed = taskEvent.get('completeStatus')
            if completed == 1:
                logger.info(f"任务已完成: {title} {taskEventId} ")
                continue
            
            answer = []
            for option in options:
                optionContent = option.get("optionContent")
                optionName = option.get("optionName")
                if title == "What is the total amount of BTC？" and optionContent == "2100w":
                    answer.append(optionName)
                if title == "Who created BTC?" and optionContent == "Satoshi Nakamoto":
                    answer.append(optionName)
                if title == "What does Taker bring to BTC?" and optionContent == "All of the above":
                    answer.append(optionName)
                
            check_response = self.check_answer(self.token, "6", taskEventId, answer)
            if check_response.get('code') == 200 and check_response.get('result'):
                logger.success(f"答题成功: {title} {taskEventId} {answer}")
                continue
            else:
                logger.error(f"答题失败: {title} {taskEventId} {answer}")
                continue
        return True

    
    """ yes 打码 """
    # 创建过验证码任务
    def create_sowing_faucet_cf(self, clientKey: str) -> str:
        url = "https://api.yescaptcha.com/createTask"
        body = {
            "clientKey": clientKey,
            "task": {
                "type": "TurnstileTaskProxylessM1",
                "websiteURL": "https://sowing.taker.xyz/",
                "websiteKey": "0x4AAAAAABNqF8H4KF9TDs2O",
            },
            "softID": "54751",
        }

        response = requests.post(url, json=body)
        # logger.info(f"create cf task::{response.text}")

        result = json.loads(response.text)
        # logger.info(f"create cf task result::{result}")

        return result["taskId"]

    # 检查验证码是否通过
    def check_cf(self, taskId: str, clientKey: str):
        body = {"clientKey": clientKey, "taskId": taskId, "softID": "54751"}
        url = "https://api.yescaptcha.com/getTaskResult"
        response = requests.post(url, json=body)
        # logger.info(f"check cf task::{response.text}")

        result = json.loads(response.text)
        """ 响应参数
            {
                "errorId": 0,  // errorId>0 表示失败
                "errorCode": null,
                "errorDescription": null,
                "solution": {
                    "token": "0.ufq5RgSVZd11DPSX1brdrxnEs28KcVlKj2ORchqxSy2q9yAW6ciq3hriXDF4x……",
                    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36", 
                },
                "status": "ready"  // processing：正在识别中，请3秒后重试    ready：识别完成，在solution参数中找到结果

            }
        """

        return result


    """
        --------------------------------------------------------------
        播种合约：0xF929AB815E8BfB84Cdab8d1bb53F22eB1e455378  是https://sowing.taker.xyz/detail/6?start=YVWF4PVY
        先交互合约，然后执行开始播种，进入倒计时
    """
    """ 开始播种 """
    def start_sowing(self, token: str, sowing_captcha_result: str, status: str):
        headers = {
            "Authorization": f"Bearer {token}",
            "cf-turnstile-token": sowing_captcha_result['token'],
            "user-agent": sowing_captcha_result['userAgent'],
            "origin": "https://sowing.taker.xyz",
            "Host": "sowing-api.taker.xyz",
            "referer": "https://sowing.taker.xyz/",
            "accept": "application/json, text/plain, */*"
        }
        response = requests.get(
            url=f"{url}/task/signIn?status={status}",
            headers=headers
        )
        logger.info(f"播种请求返回：{response.text}")
        # logger.info(f"header: {headers}, url: {url}/task/signIn?status={status}, 播种请求返回：{response.text}, response: {response.status_code}")
        """
            {"code":200,"message":"SUCCESS","result":true,"total":0}
        """
        return response.json()

    """ 查询播种信息 """
    def get_sowing_info(self, token: str):
        response = requests.get(
            url=f"{url}/user/info",
            headers={"Authorization": f"Bearer {token}"}
        )
        """
            {
                "code": 200,
                "message": "SUCCESS",
                "result": {
                    "id": 1911567,
                    "walletAddress": "0xb7dd3c44e6c937191f5a11ab7ec20a44b55aa909",
                    "invitationCode": "7T8VXVEG",
                    "takerPoints": 300.000000000000000000,
                    "consecutiveSignInCount": 1,
                    "nextTimestamp": 1745166858036,
                    "rewardCount": 3,
                    "discordBindStatus": false,
                    "tgBindStatus": false,
                    "firstSign": false,
                    "bindingBtcWallet": false,
                    "xbindStatus": false
                },
                "total": 0
            }
        
        """
        return response.json()

    def interact_sowing_contract(self):
        # 连接到 Taker RPC
        w3 = Web3(Web3.HTTPProvider('https://rpc-mainnet.taker.xyz/'))
        
        # 确保连接成功
        if not w3.is_connected():
            logger.error("无法连接到 Taker RPC")
            return None
        
        # 合约信息
        contract_address = '0xF929AB815E8BfB84Cdab8d1bb53F22eB1e455378'
        contract_abi = [
            {
                "inputs": [],
                "name": "active",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            }
        ]
        
        try:
            # 确保私钥格式正确
            if not self.private_key.startswith('0x'):
                self.private_key = '0x' + self.private_key
                
            # 创建账户
            account = Account.from_key(self.private_key)
            logger.info(f"使用地址: {account.address}")
            
            # 创建合约实例
            contract = w3.eth.contract(address=contract_address, abi=contract_abi)
            
            # 获取当前 gas 价格
            gas_price = w3.eth.gas_price
            
            # 估算 gas
            gas_estimate = contract.functions.active().estimate_gas({'from': account.address})
            
            # 获取 nonce
            nonce = w3.eth.get_transaction_count(account.address)
            
            # 构建交易
            tx = contract.functions.active().build_transaction({
                'from': account.address,
                'nonce': nonce,
                'gas': gas_estimate,
                'gasPrice': gas_price,
            })
            
            # 签名交易
            signed_tx = w3.eth.account.sign_transaction(tx, self.private_key)
            # logger.info(f"signed_tx:{signed_tx}")
            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            logger.info(f"交易已发送，等待确认... Hash: {tx_hash.hex()}")
            
            # 等待交易确认
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt['status'] == 1:
                logger.info(f"交易成功确认！Gas 使用: {receipt['gasUsed']}")
                return tx_hash.hex()
            else:
                logger.error("交易失败！")
                return None
                
        except Exception as e:
            logger.error(f"交互播种合约失败: {str(e)}::{format_exc()}")
            return None
        

    """ 播种打码 """
    def sowing_captcha(self):
        clientKey = self.config["yescaptcha"]["clientKey"]
        if not clientKey:
            logger.error("yes打码平台clientKey未配置")
            return None
        for i in range(5):
            try:
                taskId = self.create_sowing_faucet_cf(clientKey)
                logger.info(f"第{i}次创建播种打码任务: {taskId}")
                index = 0
                while True:
                    if index > 50:
                        logger.error(f"超出重试次数")
                        break
                    cf_result = self.check_cf(taskId, clientKey)
                    if cf_result["errorId"] > 0:
                        logger.error(f"过cf盾异常...")
                        break
                    if cf_result["status"] == "ready":
                        logger.info(f"过盾成功...")
                        return cf_result['solution']
                    index = index + 1
                    logger.info(f"第{index}次检查过盾结束，重新检查...")
                    time.sleep(3)
                logger.error(f"第{i}次播种打码失败...")
                time.sleep(5)
            except Exception as error:
                logger.error(f"播种打码失败: {error}")
                time.sleep(5)
                continue
        return None       

    """ 执行播种任务 """
    def execute_sowing_task(self, token: str):
        get_sowing_info_response = self.get_sowing_info(token)
        logger.info(get_sowing_info_response)
        if get_sowing_info_response.get('code') != 200:
            logger.error(f"获取播种信息失败: {get_sowing_info_response.get('message')}")
            return False, "获取播种信息失败", -1
        sowing_info = get_sowing_info_response.get('result')
        logger.info(sowing_info)
        # 睡眠3s, taker的时间戳比我的快几十ms。先睡眠一下保证当前时间比他的最新时间大
        time.sleep(3)
        # 获取当前时间戳 毫秒
        current_timestamp = int(time.time() * 1000)
        logger.info(f"当前时间戳: {current_timestamp}，播种时间戳: {sowing_info.get('nextTimestamp')}")

        # 是否是第一次签名
        is_first_sign = sowing_info.get('firstSign')
        logger.info(f"是否是第一次播种: {is_first_sign}")
        status = 'true'
        if not is_first_sign:
            # 判断是否可以播种
            if current_timestamp < sowing_info.get('nextTimestamp'):
                logger.info(f"当前正在进行播种，等待：{int((sowing_info.get('nextTimestamp') - current_timestamp)/1000)} s")
                return False, "当前正在进行播种，等待:" + str(int((sowing_info.get('nextTimestamp') - current_timestamp)/1000)) + " s", int((sowing_info.get('nextTimestamp') - current_timestamp)/1000)
            # 先进行合约交互：
            logger.info("可以领取播种奖励，开始进行合约交互...")
            tx_hash = self.interact_sowing_contract()
            logger.info(f"交易哈希: {tx_hash}")
            if tx_hash is None:
                logger.error(f"领取播种奖励失败...")
                return False, "领取播种奖励失败", -1

            # TODO 随机睡眠时间
            time.sleep(random.randint(1, 3))

        try:
            if not is_first_sign:
                status = 'false'
            for i in range(5):
                # 先打码
                sowing_captcha_result = self.sowing_captcha()
                logger.debug(f"播种打码结果: {sowing_captcha_result}")
                if sowing_captcha_result is None:
                    logger.info(f"播种打码失败...")
                    time.sleep(5)
                    continue
                # 播种
                start_sowing_response = self.start_sowing(token, sowing_captcha_result, status)
                if start_sowing_response.get('code') != 200:
                    logger.error(f"播种失败: {start_sowing_response.get('message')}")
                    time.sleep(5)
                    continue
                logger.success(f"播种成功")
                return True, "播种成功", -1
        except Exception as error:
            logger.error(f"播种失败: {format_exc()}")
            return False, "播种失败", -1
        return False, "播种失败，超过重试次数", -1
    """ -------------------------------------------------------------- """


    
    def get_lightmining_nonce(self, wallet_address: str, retries: int = 3):
        try:
            headers = {
                "accept": "application/json, text/plain, */*"
            }
            response = requests.post(
                url=f"{lightmining_url}/wallet/generateNonce",
                json={"walletAddress": wallet_address},
                headers=headers
            )
            return json.loads(response.text)
        except Exception as error:
            if retries > 0:
                logger.error(f"获取 nonce 失败: {str(error)}")
                logger.warning(f"正在重试... (剩余 {retries - 1} 次尝试)")
                time.sleep(3)  # 暂停3秒
                return self.get_lightmining_nonce(wallet_address, retries - 1)
            else:
                logger.error(f"多次重试后仍无法获取 nonce: {str(error)}")
                return None
    
    def login_lightmining(self, address: str, message: str, signature: str, retries: int = 3) -> Optional[Dict]:
        try:

            data = {
                "address": address,
                "message": message,
                "signature": signature
            }
            if self.config["invite"]["miner_invite_codes"]:
                ref_code = random.choice(self.config["invite"]["miner_invite_codes"])
                if ref_code:
                    data["refCode"] = ref_code
            response = requests.post(
                url=f"{lightmining_url}/wallet/login",
                json=data
            )
            return response.json()
        except Exception as error:
            if retries > 0:
                logger.error(f"登录失败: {str(error)}")
                logger.warning(f"正在重试... (剩余 {retries - 1} 次尝试)")
                time.sleep(3)  # 暂停3秒
                return self.login_lightmining(address, message, signature, retries - 1)
            else:
                logger.error(f"多次重试后仍无法登录: {str(error)}")
                return None

    def get_lightmining_user_info(self, token: str):
        response = requests.get(
            url=f"{lightmining_url}/user/getUserInfo",
            headers={"Authorization": f"Bearer {token}"}
        )
        """
            {
                "code": 200,
                "msg": "SUCCESS",
                "data": {
                    "userId": 171664706,
                    "walletAddress": "0xb7dd3c44e6c937191f5a11ab7ec20a44b55aa909",
                    "invitationCode": "AYARWW16",
                    "rewardAmount": "48000.000000000000000000",
                    "inviteCount": 0,
                    "invitationReward": "0.000000000000000000",
                    "totalReward": "48000.000000000000000000",
                    "tgId": null,
                    "dcId": null,
                    "twId": "1803750620408770560",
                    "twName": "ssssy83717"
                }
            }
        """
        return response.json()

    """ 获取挖矿时间 """
    def total_mining_time(self, token: str):
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Authorization": f"Bearer {token}",
            "Connection": "keep-alive",
            "Host": "lightmining-api.taker.xyz",
            "Origin": "https://earn.taker.xyz",
            "Referer": "https://earn.taker.xyz/",
            "Sec-Ch-Ua": "\"Chromium\";v=\"128\", \"Not:A=Brand\";v=\"24\", \"Google Chrome\";v=\"128\"",
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": "\"Windows\"",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
        }
        response = requests.get(
            url=f"{lightmining_url}/assignment/totalMiningTime",
            headers=headers
        )
        """
            {
                "code": 200,
                "msg": "SUCCESS",
                "data": {
                    "lastMiningTime": 1745145588,
                    "totalMiningTime": 172800000
                }
            }
        """
        return response.json()

    def start_mining(self, token: str, status: str):
        response = requests.post(
            url=f"{lightmining_url}/assignment/startMining",
            headers={"Authorization": f"Bearer {token}"},
            json={"status": status}
        )
        """
            {"code":200,"msg":"SUCCESS","data":"ok"}
        """
        return response.json()

    """ 交互挖矿合约 """
    def interact_lightmining_contract(self):
        # 连接到 Taker RPC
        w3 = Web3(Web3.HTTPProvider('https://rpc-mainnet.taker.xyz/'))
        
        # 确保连接成功
        if not w3.is_connected():
            logger.error("无法连接到 Taker RPC")
            return None
        
        # 合约信息
        contract_address = '0xB3eFE5105b835E5Dd9D206445Dbd66DF24b912AB'
        contract_abi = [
            {
                "inputs": [],
                "name": "active",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            }
        ]
        
        try:
            # 确保私钥格式正确
            if not self.private_key.startswith('0x'):
                self.private_key = '0x' + self.private_key
                
            # 创建账户
            account = Account.from_key(self.private_key)
            logger.info(f"使用地址: {account.address}")
            
            # 创建合约实例
            contract = w3.eth.contract(address=contract_address, abi=contract_abi)
            
            # 获取当前 gas 价格
            gas_price = w3.eth.gas_price
            
            # 估算 gas
            gas_estimate = contract.functions.active().estimate_gas({'from': account.address})
            
            # 获取 nonce
            nonce = w3.eth.get_transaction_count(account.address)
            
            # 构建交易
            tx = contract.functions.active().build_transaction({
                'from': account.address,
                'nonce': nonce,
                'gas': gas_estimate,
                'gasPrice': gas_price,
            })
            
            # 签名交易
            signed_tx = w3.eth.account.sign_transaction(tx, self.private_key)
            logger.info(f"signed_tx:{signed_tx}")
            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            logger.info(f"交易已发送，等待确认... Hash: {tx_hash.hex()}")
            
            # 等待交易确认
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt['status'] == 1:
                logger.info(f"交易成功确认！Gas 使用: {receipt['gasUsed']}")
                return tx_hash.hex()
            else:
                logger.error("交易失败！")
                return None
                
        except Exception as e:
            logger.error(f"交互播种合约失败: {str(e)}::{format_exc()}")
            return None
      

    """ 执行挖矿任务 """
    def execute_lightmining_task(self, token: str):
        user_info = self.get_lightmining_user_info(token)
        logger.info(user_info)
        total_mining_time = self.total_mining_time(token)
        logger.info(total_mining_time)

        # 获取当前时间戳 秒
        current_timestamp = int(time.time())
        logger.info(f"当前时间戳: {current_timestamp}，挖矿时间戳: {total_mining_time.get('data').get('lastMiningTime')}")

        # 如果上次挖矿时间和totalMiningTime = 0，可以直接挖矿
        last_mining_time = total_mining_time.get('data').get('lastMiningTime')
        total_mining_time = total_mining_time.get('data').get('totalMiningTime')
        # if last_mining_time == 0 and total_mining_time == 0:

        
        is_first_sign = False
        if last_mining_time == 0 and total_mining_time == 0:
            is_first_sign = True
        status = 'true'
        if not is_first_sign:
            # 判断是否可以挖矿 上次挖矿时间+ 24h
            if current_timestamp < last_mining_time + 24 * 60 * 60:
                logger.info(f"当前正在进行挖矿，等待：{int((last_mining_time + 24 * 60 * 60 - current_timestamp))} s")
                return False, "当前正在进行挖矿，等待:" + str(int((last_mining_time + 24 * 60 * 60 - current_timestamp))) + " s", int((last_mining_time + 24 * 60 * 60 - current_timestamp))
            # TODO 先进行合约交互：
            tx_hash = self.interact_lightmining_contract()
            logger.info(f"交易哈希: {tx_hash}")
            if tx_hash is None:
                logger.error(f"领取挖矿奖励失败...")
                return False, "领取挖矿奖励失败", -1
            # TODO 随机睡眠时间
            time.sleep(random.randint(1, 3))


        # 挖矿
        for i in range(3):
            if not is_first_sign:
                status = 'false'
            try:
                mining_response = self.start_mining(token, status)
                logger.info(mining_response)
                if mining_response.get('code') != 200:
                    if mining_response.get('msg') == "You have not bind x account":
                        return False, "未绑定X账号", -1
                    logger.error(f"挖矿失败: {mining_response.get('msg')}")
                    time.sleep(5)
                    continue
                logger.success(f"挖矿成功")
                return True, "挖矿成功", -1
            except Exception as error:
                logger.error(f"挖矿失败: {error}")
                time.sleep(5)
                continue
        return False, "挖矿失败，超过重试次数", -1

    
    def init_lightmining_instance(self):
        try:
            for i in range(3):
                # mnemonic_str = "forget length upper chief rebel vast parade faculty bomb hurdle matrix large"
                # 从助记词生成种子
                seed_bytes = Bip39SeedGenerator(self.mnemonic_str).Generate()

                # 使用以太坊标准路径 m/44'/60'/0'/0/0
                bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
                account = bip44_mst_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)

                self.private_key = "0x" + account.PrivateKey().Raw().ToHex()
                
                address = Account.from_key(self.private_key).address
                self.address = address
                message_response = self.get_lightmining_nonce(address)
                if message_response.get('code') != 200:
                    logger.error(f"获取nonce失败: {message_response.get('message')}")
                    continue
                nonce = message_response.get('data').get('nonce')
                signature = self.sign_message(nonce)
                if signature is None:
                    logger.error("签名失败")
                    continue
                login_response = self.login_lightmining(address, nonce, "0x" + signature)
                if login_response.get('code') != 200:
                    logger.error(f"登录失败: {login_response.get('message')}")
                    continue
                token = login_response.get('data').get('token')
                self.lightmining_token = token
                return True, address, token
            return False, "", ""
        except Exception as error:
            logger.error(f"初始化实例时出错: {error}")
            return False, "", ""
