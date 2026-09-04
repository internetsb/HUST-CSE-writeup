import requests

# 基本信息
BASE_URL = "http://172.17.0.13:15281"

client_id = "app_74457116de74"
client_secret = "c57b4ac002f3e003b5da91e99f730858"
redirect_uri = "/oauth/cb/app_74457116de74"

def get_access_token(client_id, client_secret, redirect_uri, code):
    url = BASE_URL + "/oauth/token"
    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "code": code,
        "grant_type": "authorization_code"
    }
    response = requests.post(url, data=payload)
    return response.json()

def get_user_info(access_token):
    url = BASE_URL + "/api/me"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = requests.get(url, headers=headers)
    return response.json()

# http://172.17.0.13:15281/oauth/authorize?client_id=app_74457116de74&redirect_uri=/oauth/cb/app_74457116de74&scope=private
# 发送以上网址至私信获取授权码code
# code = "-YFVMgVkN3I2S_lR_ucD4g"  

# access_token = get_access_token(client_id, client_secret, redirect_uri, code)
# print("Access Token:", access_token)

# Access Token: {'access_token': 'CBvwx7jMzNJATFhOE92RmzMsp9dRkwuO', 'scope': 'private', 'token_type': 'Bearer'}

# access_token = "CBvwx7jMzNJATFhOE92RmzMsp9dRkwuO"  

# user_info = get_user_info(access_token)
# print("User Info:", user_info)

if __name__ == "__main__":
    # Example usage
    url_send = f"{BASE_URL}/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&scope=private"
    code = input(f"发送以下链接至私信获取授权码:\n{url_send}\n请输入授权码: ")
    access_token = get_access_token(client_id, client_secret, redirect_uri, code)
    print("Access Token:", access_token)
    userinfo = get_user_info(access_token['access_token'])
    print("User Info:", userinfo)