consul {
  auth {
    enabled  = false
  }
  address = "127.0.0.1:8500"

  retry {
    enabled = true
    attempts = 12
    backoff = "250ms"
    max_backoff = "1m"
  }

  ssl {
    enabled = false
  }
}

reload_signal = "SIGHUP"
kill_signal = "SIGINT"
max_stale = "10m"
log_level = "info"
pid_file = "/tmp/venafi-demo-consul-template.pid"

vault {
  address = "http://127.0.0.1:8200"
  grace = "5m"
  unwrap_token = false
  renew_token = false
}

template {
  source = "scripts/config/nginx/cert/fake-nginx.crt.ctmpl"
  destination = "scripts/config/nginx/cert/fake-nginx.crt"
}

template {
  source = "scripts/config/nginx/cert/fake-nginx.key.ctmpl"
  destination = "scripts/config/nginx/cert/fake-nginx.key"
  command = "/bin/sh -c 'scripts/tools/nginx.sh fake 1443'"
}
