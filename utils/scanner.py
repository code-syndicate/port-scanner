import socket
import sys
import http.client
import ssl

def scan_ports(ip, ports):
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)  # Timeout of 1 second
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
    return open_ports

def grab_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((ip, port))
            s.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = s.recv(1024).decode().strip()
            return banner
    except Exception as e:
        return f"Error grabbing banner: {e}"

def check_http_vulnerability(ip, ports):
    vulnerabilities = []
    
    # Unique default credentials dictionary
    default_creds = {
        'admin': 'admin', 
        'root': 'toor', 
        'admin': 'password', 
        'user': 'user',
        'admin': '1234'
    }

    # Common HTTP/HTTPS ports and known login paths
    login_paths = [
        '/admin/login', 
        '/login', 
        '/admin', 
        '/user/login'
    ]
    
    for port in ports:
        if port == 80 or port == 443:  # Check HTTP/HTTPS ports
            for path in login_paths:
                url = f'http://{ip}:{port}{path}' if port == 80 else f'https://{ip}:{port}{path}'

                conn = None
                
                try:
                    if port == 443:
                        conn = http.client.HTTPSConnection(ip, port, timeout=2)
                    else:
                        conn = http.client.HTTPConnection(ip, port, timeout=2)

                    # Check default credentials
                    for username, password in default_creds.items():
                        conn.request('POST', path, headers={
                            'Authorization': f'Basic {username}:{password}'
                        })
                        response = conn.getresponse()
                        if response.status == 200:
                            vulnerabilities.append(f"Port {port} at {path} might be vulnerable to default credentials ({username}:{password})")

                    # Check for directory listing
                    conn.request('GET', path)
                    response = conn.getresponse()
                    body = response.read().decode()
                    if 'Index of' in body:
                        vulnerabilities.append(f"Port {port} at {path} might have directory listing enabled")

                except Exception as e:
                    vulnerabilities.append(f"Error checking vulnerability on port {port} at {path}: {e}")
                finally:
                    if conn:
                        conn.close()

    return vulnerabilities

def check_ssl_tls(ip, port):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cipher = ssock.cipher()
                ssl_info = f"SSL/TLS version: {cipher[1]}, Cipher: {cipher[0]}"
                return ssl_info
    except Exception as e:
        return f"Error checking SSL/TLS: {e}"

def main(ip, scan_type):
    if scan_type == 'ports':
        ports = list(range(1, 1025))  # Example: scan ports 1 to 1024
        open_ports = scan_ports(ip, ports)
        results = [f"Port {port} is open" for port in open_ports]
        
        # Banner grabbing for open ports
        for port in open_ports:
            banner = grab_banner(ip, port)
            results.append(f"Port {port} banner: {banner}")

    elif scan_type == 'vulnerabilities':
        ports = [80, 443]  # Common HTTP/HTTPS ports
        vulnerabilities = check_http_vulnerability(ip, ports)
        
        # SSL/TLS configuration check
        for port in ports:
            if port == 443:
                ssl_info = check_ssl_tls(ip, port)
                vulnerabilities.append(f"Port {port} SSL/TLS info: {ssl_info}")
        
        results = vulnerabilities

    else:
        results = ['Invalid scan type. Use "ports" or "vulnerabilities".']

    return "\n\n".join(results)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python scanner.py <IP> <scan_type>")
        print("<scan_type> can be 'ports' or 'vulnerabilities'")
        sys.exit(1)

    ip = sys.argv[1]
    scan_type = sys.argv[2]
    print(main(ip, scan_type))
