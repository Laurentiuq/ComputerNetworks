from flask import Flask, render_template
from collections import Counter

app = Flask(__name__)

@app.route('/')
def blocked_domains():
    with open('blocked_requests.txt', 'r') as file:
        blocked_domains = [line.strip() for line in file.readlines()]

    google_domains = [domain for domain in blocked_domains if 'google' in domain]
    facebook_domains = [domain for domain in blocked_domains if 'facebook' in domain]

    num_google = len(google_domains)
    num_facebook = len(facebook_domains)

    company_names = [domain for domain in blocked_domains]
    most_common_companies = Counter(company_names).most_common(5)
    
    return render_template('blocked_domains.html', 
                           domains=blocked_domains, 
                           num_google=num_google, 
                           num_facebook=num_facebook,
                           most_common_companies=most_common_companies)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
