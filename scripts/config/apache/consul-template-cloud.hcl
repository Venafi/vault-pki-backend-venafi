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
pid_file = "/tmp/venafi-hck2018-consul-template.pid"

vault {
  address = "http://127.0.0.1:8200"
  grace = "5m"
  unwrap_token = false
  renew_token = false
}

template {
  source = "scripts/config/apache/certs/server.crt.ctmpl"
  destination = "scripts/config/apache/certs/server.crt"
}

template {
  source = "scripts/config/apache/certs/server.key.ctmpl"
  destination = "scripts/config/apache/certs/server.key"
  command = "/bin/sh -c 'scripts/tools/apache.sh 2443'"
}
