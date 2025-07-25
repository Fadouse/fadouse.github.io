---
title: Advanced Techniques for Cobalt Strike Evasion and Detection Bypass
date: 2025-07-25
categories: [redteam, evasion]
tags: [evasion, bypass, redteam]
---

# Advanced Techniques for Cobalt Strike Evasion and Detection Bypass
> *Note: This is my first blog post in English, so I welcome any feedback on clarity or style.*

In this article I describe how we successfully bypassed **Kaspersky Endpoint Security**, established a stable C2 channel, and conducted post‑exploitation tasks between **Cobalt Strike Beacons** and the team server.

### Lab topology

Our test environment is hosted on an **Azure Japan B1S** VPS. To shield the team server from port‑scanning and casual probing, all traffic is funneled through an Nginx reverse proxy and the Cloudflare CDN. Only clients that present the correct **User‑Agent** string and **SNI** value are allowed to reach the team server.

<img src="images/2025-7-25_mermaidchart.svg" width="800" alt="流程图">
<!-- ![SVG](images/2025-7-25_mermaidchart.svg) -->

### Nginx filtering strategy

The reverse‑proxy layer enforces:

1. *SNI whitelisting* – only requests bearing the expected TLS server name pass through.
2. *User‑Agent whitelisting* – a narrow set of UA strings mimicking legitimate browser traffic.

Example Nginx configuration:

```conf
load_module modules/ngx_stream_module.so;

user www-data;
worker_processes auto;
pid /run/nginx.pid;
events {
    worker_connections 1024;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    log_format detailed '$remote_addr - $remote_user [$time_local] '
                       '"$request" $status $body_bytes_sent '
                       '"$http_referer" "$http_user_agent" '
                       '"$http_x_forwarded_for" "$http_host" '
                       'rt=$request_time uct="$upstream_connect_time" '
                       'uht="$upstream_header_time" urt="$upstream_response_time" '
                       'request_id=$request_id '
                       'scheme=$scheme ssl_protocol=$ssl_protocol '
                       'ssl_cipher=$ssl_cipher';
    
    log_format c2_detailed '$remote_addr - $remote_user [$time_local] '
                          '"$request_method $request_uri $server_protocol" '
                          '$status $body_bytes_sent $request_length '
                          '"$http_user_agent" "$http_referer" '
                          '"$http_accept" "$http_accept_encoding" '
                          '"$http_accept_language" "$http_connection" '
                          '"$http_cookie" "$http_x_forwarded_for" '
                          'upstream_addr=$upstream_addr '
                          'upstream_status=$upstream_status '
                          'request_time=$request_time '
                          'upstream_response_time=$upstream_response_time '
                          'request_id=$request_id '
                          'args="$args" query_string="$query_string"';
    
    access_log /var/log/nginx/access.log detailed;
    error_log /var/log/nginx/error.log warn;

    server {
        listen 80 default_server;
        server_name _;
        
        access_log /var/log/nginx/default.log detailed;
        
        location / {
            return 200 "nginx is working";
            add_header Content-Type text/plain;
        }
    }
    
    server {
        listen 443 ssl;
        server_name beacon.example.com;
        
        access_log /var/log/nginx/https_beacon.log c2_detailed;
        error_log /var/log/nginx/https_beacon_error.log debug;
        
        ssl_certificate /path_to_ssl/example.com.pem;
        ssl_certificate_key /path_to_ssl/example.com.key;
        
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384;
        ssl_prefer_server_ciphers off;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;

        location ~ ^(/api/v1/updates/core.dat)$ {
            access_log /var/log/nginx/c2_https_get.log c2_detailed;
            
            if ($http_user_agent != "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko") {
                access_log /var/log/nginx/c2_blocked.log c2_detailed;
                return 200 "nginx is working";
                add_header Content-Type text/plain;
            }
            proxy_pass          https://127.0.0.1:8080;

            expires             off;
            proxy_redirect      off;
            proxy_set_header    Host                $host;
            proxy_set_header    X-Forwarded-For     $proxy_add_x_forwarded_for;
            proxy_set_header    X-Real-IP           $remote_addr;
        }
        
        location ~ ^(/static/js/.*|/assets/css/.*|/fonts/woff2/.*|/api/v1/user.*)$ {
            access_log /var/log/nginx/c2_https_get.log c2_detailed;
            
            if ($http_user_agent != "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36") {
                access_log /var/log/nginx/c2_https_blocked.log c2_detailed;
                return 200 "nginx is working";
                add_header Content-Type text/plain;
            }
            
            proxy_pass https://127.0.0.1:8003;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            expires 1d;
            add_header Cache-Control "private, max-age=86400";
        }
        
        location ~ ^(/v2/log/telemetry.*)$ {
            access_log /var/log/nginx/c2_https_post.log c2_detailed;
            
            if ($http_user_agent != "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36") {
                access_log /var/log/nginx/c2_https_blocked.log c2_detailed;
                return 200 "nginx is working";
                add_header Content-Type text/plain;
            }
            
            proxy_pass https://127.0.0.1:8003;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            proxy_read_timeout 60s;
            proxy_send_timeout 60s;
            client_max_body_size 10M;
        }
        
        location / {
            access_log /var/log/nginx/c2_default.log c2_detailed;
            return 200 "nginx is working";
            add_header Content-Type text/plain;
        }
    }
}

stream {
    log_format stream_detailed '$remote_addr [$time_local] '
                              '$protocol $status $bytes_sent $bytes_received '
                              '$session_time upstream_addr=$upstream_addr '
                              'upstream_connect_time=$upstream_connect_time '
                              'ssl_preread_server_name=$ssl_preread_server_name';
    
    access_log /var/log/nginx/stream_access.log stream_detailed;
    error_log /var/log/nginx/stream_error.log debug;
    
    upstream teamserver {
        server 127.0.0.1:50050;
    }
    
    upstream reject {
        server 127.0.0.1:1; 
    }

    map $ssl_preread_server_name $backend {
        TeamServer.example.com     teamserver;
        default                                     reject;    
    }

    server {
        listen 5000 reuseport;
        ssl_preread on;             
        proxy_pass $backend;        
        proxy_timeout 3s;          
        proxy_responses 1;
        proxy_connect_timeout 2s;   
        error_log /var/log/nginx/teamserver_stream.log debug;
        access_log /var/log/nginx/teamserver_access.log stream_detailed;
    }
}
```

