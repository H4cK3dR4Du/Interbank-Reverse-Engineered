import json
import os
from ecdsa import SECP256k1, SigningKey, VerifyingKey
from hashlib import sha512, sha256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hmac
import json
import capsolver
import requests
import re
from base64 import b64encode
from json import dumps

capsolver.api_key = 'CAP-6D5AD2BEBA677987B9B17CACB8522C58'

class KeyboardLayout:
    def __init__(self):
        self.uuid_to_key = {}
        self.fetch_keyboard_layout()

    def fetch_keyboard_layout(self):
        """Fetches the keyboard layout from the API and processes the SVG data."""
        headers = {
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Origin': 'https://bancaporinternet.interbank.pe',
            'Referer': 'https://bancaporinternet.interbank.pe/login',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
            'content-type': 'application/json',
            'sec-ch-ua': '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'x-requested-with': 'XMLHttpRequest',
        }

        json_data = {'type': 'all'}

        response = requests.post(
            'https://bancaporinternet.interbank.pe/bpi/api/excluded/keyBoardRestService/keys',
            headers=headers,
            json=json_data,
        )
        self.trackingId = response.json()['trackingId']
        self.keyboard_key = response.json()['data']['keyboard']

        print(f'Keyboard Value : {self.keyboard_key[:80]}**************')

        data_keyboard = response.json()['data']['keyboardData']
        self.process_keyboard_data(data_keyboard['digits'])
        self.process_keyboard_data(data_keyboard['uppercaseLetters'])
        self.process_keyboard_data(data_keyboard['lowercaseLetters'])

    def process_keyboard_data(self, keyboard_section):
        """Processes a section of the keyboard (digits, uppercase, lowercase) and stores the mapping."""
        for uuid, svg_data in keyboard_section.items():
            match = re.search(r'id=\"([^\"]+)\"', svg_data)
            if match:
                key_value = match.group(1)
                self.uuid_to_key[key_value] = uuid

    def get_uuids_for_input(self, input_string):
        """Generates a list of UUIDs corresponding to the input string."""
        uuid_list = []
        for char in str(input_string):
            if char in self.uuid_to_key:
                uuid_list.append(self.uuid_to_key[char])
            else:
                raise ValueError(f"Character '{char}' not found in the keyboard layout.")
        return uuid_list , self.keyboard_key

class CypherText:
    def __init__(self, dni, password):
        self.password , self.keyboard_key = KeyboardLayout().get_uuids_for_input(password)
        self.dni = dni

    def get_monitor(self) -> dict:
        data_sheet = {"Browser": {
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
            "browserName": "Chrome", "browserVersion": "128.0.0.0", "browserMajor": "128", "browserEngineName": "Blink",
            "browserEngineVersion": "128.0.0.0", "osName": "Windows", "osVersion": "10", "deviceVendor": "",
            "deviceModel": "", "deviceType": "", "cpuArchitecture": "amd64", "isPrivateMode": "0"},
         "General": {"fingerprintVersion": "3.1.1", "language": "es-ES", "colorDepth": "24", "deviceMemory": "1",
                     "hardwareConcurrency": "8", "resolution": "694x931", "availableResolution": "694x931",
                     "timezoneOffset": "-180", "sessionStorage": "0", "cookieEnabled": "1", "localStorage": "1",
                     "indexedDb": "0", "cpuClass": "", "openDatabase": "0", "navigatorPlatform": "Win32",
                     "vendorWebGL": "1",
                     "rendererVideo": "ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 SUPER (0x00002783) Direct3D11 vs_5_0 ps_5_0, D3D11)",
                     "timeZone": "GMT+0300 (GMT+03:00)", "zone": "Europe/Istanbul", "UTC": 3, "ram": "1",
                     "processorCount": "8", "videoInput": "1", "audio": "80.46535951293117", "canvas": 60687535},
         "Personalization": {"numberPlugins": "4", "numberFonts": "29"},
         "Alterations": {"adblock": "0", "hasLiedLanguages": "0", "hasLiedResolution": "0", "hasLiedOs": "0",
                         "hasLiedBrowser": "0", "touchSupport": "0"}, "Network": {"publicIp": "", "localIp": ""},
         "Site": {"host": "bancaporinternet.interbank.pe", "hostName": "bancaporinternet.interbank.pe",
                  "href": "https://bancaporinternet.interbank.pe/login", "origin": "", "pathname": "/login", "port": "",
                  "protocol": "https:"}, "Identifiers": {"cookie": "d2c1298be3bd2bebbb7d10fb037e4f67",
                                                         "localStorageValue": "560601a1399158eec14cfb2965f184b1",
                                                         "unanimity1": "6e3cbcbe15f72300232402107460d88d4d845a0ebd6f5e78f0416c68327a3a7f",
                                                         "unanimity2": "a6f06a7728a3197c3588c9175dc63d57d4884b02e2f5cabe4347af402c1b6623",
                                                         "unanimity3": "62a6f237d0ac3b2bf273835a3f271b1dfc1918753e2f88c2ae97ff4c12f922ad",
                                                         "unanimity4": "0939e66ed9d8136474ce3d4e4a09bbe973b9335e8441eb761454d2a93ef0190e",
                                                         "unanimity5": "a6df83bb087f1d0059e3bf267bf4523e016404da040cc5de663f02fcc9495d5a",
                                                         "hash": "8D1EDE4F889E0ED6.781E4F0B0E947040.53"},
         "Geoip": {"as": "AS47331 TTNet A.S.", "asname": "TTNET", "callingCode": "90", "city": "Madrid",
                   "continent": "Asia", "continentCode": "AS", "country": "Spain", "countryCode": "ES",
                   "countryCode3": "ESP", "currency": "TRY", "currentTime": "2024-09-10T17:21:02+03:00", "district": "",
                   "hosting": False, "isp": "MadridTelecom", "lat": 39.9282, "lon": 32.8564, "mobile": False,
                   "offset": 10800, "org": "Madrid Telekomunikasyon A.S", "proxy": False, "query": "78.167.114.53",
                   "region": "06", "regionName": "Madrid", "reverse": "78.167.114.53.dynamic.ttnet.com.es",
                   "status": "success", "timezone": "Europe/Istanbul", "zip": "06420"}}

        return b64encode(dumps(data_sheet).encode()).decode()

    def raw_cypher(self)-> dict:
        solution = capsolver.solve({
            "type":"ReCaptchaV3TaskProxyLess",
            "websiteKey":"6LeLlFspAAAAAPoVc--15o6jwcoqdEtKq5aYd-X8",
            "websiteURL":"https://bancaporinternet.interbank.pe/login",
        })

        data_load = json.dumps({
            "credentials": {
                "identityNumber": self.dni,
                "password": self.password,
                "keyboard": self.keyboard_key,
                "identityType": 1,
                "monitor": self.get_monitor(),
                "recaptcha": solution['gRecaptchaResponse'],
                "rememberIdentity": False,
                "type": "otp"
            },
            "principal": self.dni
        })
        return data_load

def generate_ephemeral_key():
    private_key_bytes = os.urandom(32)
    private_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    return private_key, public_key

def derive_shared_secret(private_key, peer_public_key_hex):
    peer_public_key_bytes = bytes.fromhex(peer_public_key_hex)
    peer_public_key = VerifyingKey.from_string(peer_public_key_bytes, curve=SECP256k1)
    shared_secret = private_key.privkey.secret_multiplier * peer_public_key.pubkey.point
    shared_secret_bytes = shared_secret.x().to_bytes(32, 'big')
    return sha512(shared_secret_bytes).digest()

def aes_cbc_encrypt(iv, key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padding_length = 16 - len(plaintext) % 16
    padded_plaintext = plaintext + bytes([padding_length] * padding_length)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

def hmac_sha256_sign(key, data):
    return hmac.new(key, data, sha256).digest()

def encrypt_and_sign(response_publicKey, plaintext):
    plaintext = plaintext.encode()
    private_key, public_key = generate_ephemeral_key()
    ephemeral_pub_key = public_key.to_string().hex()

    shared_secret = derive_shared_secret(private_key, response_publicKey)
    encryption_key = shared_secret[:32]
    mac_key = shared_secret[32:]

    iv = get_random_bytes(16)
    ciphertext = aes_cbc_encrypt(iv, encryption_key, plaintext)

    message = iv + bytes.fromhex(ephemeral_pub_key) + ciphertext
    mac = hmac_sha256_sign(mac_key, message)

    result = {
        "iv": iv.hex(),
        "publicKey": ephemeral_pub_key,
        "cipherMessage": ciphertext.hex(),
        "mac": mac.hex()
    }

    return result

response_publicKey = "04746916ecfde8d0dfdc1cd13d2ef64cfa6eaf16300c94cd99baeb1fd6bc37e4277ae185eb6a3e83c5323556d0d9ac72e1af5d4ad1a501928f96db2a14dd120636"
e = CypherText('123123123','testpassword').raw_cypher()

result = encrypt_and_sign(response_publicKey, e)

payload = {
    'iv': result['iv'],
    'publicKey': result['publicKey'],
    'cipherMessage': result['cipherMessage'],
    'mac': result['mac'],
}

print(payload)

# discord.gg/raducord
