import requests

url = "https://raw.githubusercontent.com/anudeepND/blacklist/master/facebook.txt"
response = requests.get(url)
print("da")
# Asigură-te că cererea a reușit
assert response.status_code == 200
print("nu")
# Scrie conținutul într-un fișier local
with open("bl2.txt", "w") as f:
    f.write(response.text)
