import requests

url = 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts'

response = requests.get(url)

with open('blocklist.txt', 'w') as f:
    for line in response.text.splitlines():
        if not line.startswith("#") and not line.strip() == "":
            domain = line.split()[1]
            f.write(f"{domain}\n")
