from flask import Flask, render_template, request, make_response
import json
from datetime import datetime

IPLIST_PATH = "/opt/localnet/portal/known_ips.json" # change this

app = Flask(__name__)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    if path == "hotspot-detect.html":
        # We can assume it's an Apple client
        with open(IPLIST_PATH, "r") as f:
            ip_list = json.load(f)
        if request.remote_addr in ip_list:
            return render_template("ios_success.html")
        else:
            return render_template('information.html')
    elif path == "registered.html":
        with open(IPLIST_PATH, "r") as f:
            ip_list = json.load(f)
        ip_list[request.remote_addr] = datetime.now().isoformat()
        with open(IPLIST_PATH, "w") as f:
            json.dump(ip_list, f)
        return render_template("registered.html")
    return "blocked."

if __name__ == '__main__':
    app.run(debug=True)