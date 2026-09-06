import requests

# 获取flag的服务器地址，根据实际填写
FLAG_SERVER = "172.17.0.13"
FLAG_PORT = 12593


def get_flag(token):
    query = f"token={token}"
    url = f"http://{FLAG_SERVER}:{FLAG_PORT}/flag?{query}"

    response = requests.get(url, timeout=10)
    flag = response.text.strip()

    return flag

if __name__ == "__main__":
    token = input("Enter token: ").strip()
    flag = get_flag(token)
    print(f"Flag: {flag}")