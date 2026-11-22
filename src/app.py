from flask import Flask, request, render_template, jsonify
import socket
import re
import ipaddress
import requests

app = Flask(__name__)

def is_valid_target(target):
    return re.match(r'^[a-zA-Z0-9.-]+$', target) is not None

def get_client_ip():
    forwarded_for = request.headers.get('X-Forwarded-For', '')
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()
    return request.headers.get('X-Real-IP', request.remote_addr)

@app.route('/')
def home():
    return render_template('index.html')

# Fetch True Public IP and Location 
@app.route('/myip', methods=['GET'])
def get_my_ip():
    try:
        true_ip = get_client_ip()
        geo = requests.get(f"http://ip-api.com/json/{true_ip}?fields=status,country,city,isp,as,query,lat,lon", timeout=3).json()
        
        if geo.get("status") == "success":
            return jsonify({
                "status": "success",
                "ip": geo.get("query", true_ip),
                "country": geo.get("country", "Unknown"),
                "city": geo.get("city", "Unknown"),
                "isp": geo.get("isp", "Unknown"),
                "asn": geo.get("as", "Unknown").split(' ')[0],
                "lat": geo.get("lat", "N/A"),
                "lon": geo.get("lon", "N/A")
            })
    except:
        pass
        
    return jsonify({"status": "error", "ip": "N/A", "isp": "N/A"})

# Public IP Lookup Search
@app.route('/iplookup', methods=['POST'])
def do_iplookup():
    target = request.form.get('target', '').strip()
    if not target:
        return jsonify({"status": "error", "message": "Target IP is required"})
    
    try:
        geo = requests.get(f"http://ip-api.com/json/{target}?fields=status,message,country,city,regionName,isp,org,as,query,lat,lon,timezone", timeout=5).json()
        if geo.get("status") == "success":
            return jsonify({
                "status": "success",
                "ip": geo.get("query", target),
                "country": geo.get("country", "Unknown"),
                "city": geo.get("city", "Unknown"),
                "region": geo.get("regionName", "Unknown"),
                "isp": geo.get("isp", "Unknown"),
                "org": geo.get("org", "Unknown"),
                "asn": geo.get("as", "Unknown").split(' ')[0],
                "lat": geo.get("lat", "N/A"),
                "lon": geo.get("lon", "N/A"),
                "timezone": geo.get("timezone", "N/A")
            })
        else:
            return jsonify({"status": "error", "message": geo.get("message", "Lookup failed - Invalid IP")})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/check', methods=['POST'])
def check_port():
    ip = request.form.get('ip')
    port = request.form.get('port')
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        result = sock.connect_ex((ip, int(port)))
        sock.close()
        return jsonify({"status": "open" if result == 0 else "closed"})
    except Exception:
        return jsonify({"status": "error"})

@app.route('/subnet', methods=['POST'])
def do_subnet():
    ip_val = request.form.get('ip')
    cidr_val = request.form.get('cidr')
    try:
        net = ipaddress.IPv4Network(f"{ip_val}/{cidr_val}", strict=False)
        usable_hosts = net.num_addresses - 2 if net.num_addresses > 2 else 0
        first_host = str(net.network_address + 1) if usable_hosts > 0 else "N/A"
        last_host = str(net.broadcast_address - 1) if usable_hosts > 0 else "N/A"
        host_range = f"{first_host} - {last_host}" if usable_hosts > 0 else "N/A"
        
        return jsonify({
            "status": "success",
            "ip": ip_val,
            "network": str(net.network_address),
            "broadcast": str(net.broadcast_address),
            "netmask": str(net.netmask),
            "wildcard": str(net.hostmask),
            "total_ips": f"{net.num_addresses:,}",
            "usable_hosts": f"{usable_hosts:,}",
            "host_range": host_range,
            "cidr": f"/{cidr_val}"
        })
    except Exception:
        return jsonify({"status": "error", "message": "Invalid IPv4 Address or CIDR"})

@app.route('/vlsm', methods=['POST'])
def do_vlsm():
    ip_val = request.form.get('ip')
    major_cidr = int(request.form.get('major_cidr'))
    target_cidr = int(request.form.get('target_cidr'))
    
    if target_cidr <= major_cidr:
        return jsonify({"status": "error", "message": "Target CIDR must be larger than Major CIDR."})
    if (target_cidr - major_cidr) > 12:
        return jsonify({"status": "error", "message": "Operation too large (Max 4096 subnets)."})
        
    try:
        net = ipaddress.IPv4Network(f"{ip_val}/{major_cidr}", strict=False)
        subnets = list(net.subnets(new_prefix=target_cidr))
        
        results = []
        for i, sub in enumerate(subnets):
            usable_hosts = sub.num_addresses - 2 if sub.num_addresses > 2 else 0
            first_host = str(sub.network_address + 1) if usable_hosts > 0 else "N/A"
            last_host = str(sub.broadcast_address - 1) if usable_hosts > 0 else "N/A"
            results.append({
                "index": i + 1,
                "network": f"{sub.network_address}/{target_cidr}",
                "range": f"{first_host} - {last_host}" if usable_hosts > 0 else "N/A",
                "broadcast": str(sub.broadcast_address)
            })
            
        return jsonify({
            "status": "success",
            "original_network": str(net),
            "total_subnets": f"{len(subnets):,}",
            "usable_per_subnet": f"{usable_hosts:,}",
            "subnets": results
        })
    except Exception:
        return jsonify({"status": "error", "message": "Invalid IPv4 Address or CIDR parameters."})

def fetch_raw_whois(query):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect(('whois.iana.org', 43))
        s.send(f"{query}\r\n".encode())
        resp = b""
        while True:
            d = s.recv(4096)
            if not d: break
            resp += d
        resp_str = resp.decode(errors='replace')
        
        refer = None
        for line in resp_str.splitlines():
            if line.lower().startswith('refer:'):
                refer = line.split(':', 1)[1].strip()
                break
                
        if refer:
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2.settimeout(5.0)
            s2.connect((refer, 43))
            s2.send(f"{query}\r\n".encode())
            resp2 = b""
            while True:
                d = s2.recv(4096)
                if not d: break
                resp2 += d
            s2.close()
            return resp2.decode(errors='replace')
        return resp_str
    except Exception as e:
        return f"Whois lookup failed: {str(e)}\n\n(Verify Port 43 is not blocked by your firewall)"

@app.route('/bgp', methods=['POST'])
def do_bgp():
    target = request.form.get('target', '').strip().upper()
    if not target:
        return jsonify({"status": "error", "message": "Target AS or IP is required"})
    
    asn = target
    if '.' in target or ':' in target:
        try:
            res = requests.get(f"https://stat.ripe.net/data/network-info/data.json?resource={target}", timeout=5).json()
            if res.get('data', {}).get('asns'):
                asn = res['data']['asns'][0]
            else:
                return jsonify({"status": "error", "message": f"No ASN found originating {target}"})
        except Exception:
            return jsonify({"status": "error", "message": "Could not resolve IP to ASN."})
    
    if not str(asn).startswith('AS'):
        asn = f"AS{asn}"
        
    try:
        overview = requests.get(f"https://stat.ripe.net/data/as-overview/data.json?resource={asn}", timeout=5).json().get('data', {})
        prefixes_data = requests.get(f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}", timeout=5).json().get('data', {}).get('prefixes', [])
        peers_data = requests.get(f"https://stat.ripe.net/data/asn-neighbours/data.json?resource={asn}", timeout=5).json().get('data', {}).get('neighbours', [])
        
        v4_prefixes = [p['prefix'] for p in prefixes_data if '.' in p['prefix']]
        
        peers_data = peers_data[:150] 
        peer_asns_str = ",".join(str(p['asn']) for p in peers_data)
        names_dict = {}
        if peer_asns_str:
            names_req = requests.get(f"https://stat.ripe.net/data/as-names/data.json?resource={peer_asns_str}", timeout=5).json()
            names_dict = names_req.get('data', {}).get('names', {})
            
        peers = [{"asn": p['asn'], "type": p['type'], "desc": names_dict.get(str(p['asn']), "Unknown AS")} for p in peers_data]
        whois_text = fetch_raw_whois(asn)

        org_name = "Organization Not Found"
        for line in whois_text.splitlines():
            lower_line = line.lower()
            if lower_line.startswith(('orgname:', 'org-name:', 'organization:', 'descr:')):
                org_name = line.split(':', 1)[1].strip()
                break

        return jsonify({
            "status": "success",
            "asn": asn,
            "holder": overview.get('holder', 'Unknown Entity'),
            "org_name": org_name,
            "v4_prefixes": v4_prefixes,
            "peers": peers,
            "whois": whois_text.strip()
        })
    except Exception as e:
        return jsonify({"status": "error", "message": f"BGP API Error: {str(e)}"})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)