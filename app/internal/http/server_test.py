import requests

proxies = {
    "http": "http://127.0.0.1:18080",
    "https": "http://127.0.0.1:18080",
}


def test_http(it):
    for i in range(it):
        r = requests.get("http://127.0.0.1:18081", proxies=proxies)
        assert r.status_code == 200 and r.text == "control is an illusion"


def test_https(it):
    for i in range(it):
        r = requests.get("https://127.0.0.1:18082", proxies=proxies, verify=False)
        assert r.status_code == 200 and r.text == "control is an illusion"


if __name__ == "__main__":
    test_http(10)
    test_https(10)
    print("OK")
