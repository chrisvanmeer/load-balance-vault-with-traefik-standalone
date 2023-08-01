# Load balance HashiCorp Vault with Traefik (standalone)

This tutorial shows you how to setup a basic 3 node HashiCorp Vault HA cluster and to load balance this with Traefik. This is all done on virtual machines with both Vault and Traefik running from the binaries. No Docker involved here.

Note that we will **not** use TLS for this setup. Not for Vault and not for Traefik. Needless to say this is **not** suitable for a production environment, but will give you a starting point to use and build your TLS certificates upon this.

## Prep

First of all, you will need 4 VM's or 4 MultiPass instances.  
Mine were named conveniently:

- traefik
- vault01
- vault02
- vault03

## Vault

Install the repository and the binary

```shell
wget -O- https://apt.releawget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor | sudo tee /usr/share/keyrings/hashicorp-archive-keyring.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install -y vault
```

Take note of the IP addresses of the three nodes and replace them accordingly in the configuration files for the `api_addr` and the `cluster_addr` option. Also replace the `node_id` for all three nodes for them to be unique.

Create the Vault configuration files (on all three nodes).

```shell
sudo tee /etc/vault.d/vault.hcl << EOF
api_addr     = "http://192.168.64.44:8200"
cluster_addr = "http://192.168.64.44:8201"

storage "raft" {
  node_id = "vault01"
  path    = "/opt/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}
EOF
```

Start Vault (on all three nodes).

```shell
sudo systemctl enable --now vault
```

Point Vault to the right address (on all three nodes).

```shell
echo 'export VAULT_ADDR=http://127.0.0.1:8200' >> ~/.bashrc
source ~/.bashrc
```

On the first node, initialize, unseal and login to Vault

```shell
vault operator init -key-shares=1 -key-threshold=1 | tee vault.creds >/dev/null
vault operator unseal $(awk '/Unseal/ {print $NF}' vault.creds) >/dev/null
sleep 2
vault login $(awk '/Root/ {print $NF}' vault.creds) >/dev/null
```

If you look now, there will be only one active peer in the cluster (on the first node).

```shell
$ vault operator raft list-peers
Node       Address               State     Voter
----       -------               -----     -----
vault01    192.168.64.44:8201    leader    true
```

Join the other two nodes to the cluster and unseal them using the unseal key from the `vault.creds` file on `vault01`. Replace the IP to your first node's IP.

```shell
$ vault operator raft join http://192.168.64.44:8200
Key       Value
---       -----
Joined    true

$ vault operator unseal
Unseal Key (will be hidden):
Key                Value
---                -----
Seal Type          shamir
Initialized        true
Sealed             true
Total Shares       1
Threshold          1
Unseal Progress    0/1
Unseal Nonce       n/a
Version            1.14.1
Build Date         2023-07-21T10:15:14Z
Storage Type       raft
HA Enabled         true
```

Once done, return to the first node, perform the following and you should see three nodes in your cluster.

```shell
$ vault operator raft list-peers
Node       Address               State       Voter
----       -------               -----       -----
vault01    192.168.64.44:8201    leader      true
vault02    192.168.64.45:8201    follower    false
vault03    192.168.64.46:8201    follower    false
```

## Traefik

For us to correctly load balance the three nodes, we will make use of the built-in [status codes](https://developer.hashicorp.com/vault/api-docs/system/health) from the Vault API. Basically, a `200` means an initialized, unsealed and active node and `429` means an unsealed and standby node.

Traefik can make use of [health checks](https://doc.traefik.io/traefik/routing/services/#health-check) which will consider return codes between `2XX` and `3XX` healthy and deemes the other codes unhealthy. The only thing we need to do is add this custom health check path (`/v1/sys/health`) to our load balance service.

With this information, we can now start the installation and configuration. Grab the latest binary from the [releases](https://github.com/traefik/traefik/releases) page enad extract the downloaded archive. The example below grabs a ARM64 release, be sure to match this with your system architecture.

```shell
sudo apt update && sudo apt install -y jq
wget https://github.com/traefik/traefik/releases/download/v2.10.4/traefik_v2.10.4_linux_arm64.tar.gz
tar -zxvf traefik_*.tar.gz
sudo mv traefik /usr/local/bin
sudo chown root:root /usr/local/bin/traefik
sudo chmod 755 /usr/local/bin/traefik
```

Give the traefik binary the ability to bind to privileged ports (e.g. 80, 443) as a non-root user:

```shell
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/traefik
```

Set up the user, group, and directories that will be needed:

```shell
sudo groupadd -g 1234 traefik
sudo useradd \
  -g traefik --no-user-group \
  --home-dir /var/www --no-create-home \
  --shell /usr/sbin/nologin \
  --system --uid 1234 traefik

sudo mkdir /etc/traefik
sudo mkdir -p /opt/traefik/dynamic
sudo mkdir /var/log/traefik
```

Create basic configuration

```shell
sudo tee /etc/traefik/traefik.toml <<EOF
[api]
  dashboard = true
  insecure = true

[entryPoints]
  [entryPoints.http]
  address = ":80"

[log]
  filePath = "/var/log/traefik/traefik.log"
  level = "DEBUG"

[accessLog]
  filePath = "/var/log/traefik/access.log"

[metrics]
  [metrics.prometheus]

[providers]
  [providers.file]
    directory = "/opt/traefik/dynamic"
    watch = true
EOF
```

Now create the dynamic configuration for the router and the service. Please replace the `rule` to your liking and replace the IP adresses for the load balancer to your IP adresses.

```shell
sudo tee /opt/traefik/dynamic/vault.yml <<EOF
http:
  routers:
    vault:
      rule: "Host(`vault.domain.example`)"
      service: "vault"
  services:
    vault:
      loadBalancer:
        servers:
          - url: "http://192.168.64.44:8200/"
          - url: "http://192.168.64.45:8200/"
          - url: "http://192.168.64.46:8200/"
        healthCheck:
          path: /v1/sys/health
          interval: "10s"
          timeout: "3s"
EOF
```

Set permissions

```shell
sudo chown -R root:root /etc/traefik
sudo chown -R traefik:traefik /opt/traefik/dynamic
sudo chown -R traefik:traefik /var/log/traefik
```

Setup systemd unit file

```shell
sudo tee /usr/lib/systemd/system/traefik.service <<EOF
[Unit]
Description=traefik proxy
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service

[Service]
Restart=on-abnormal
User=traefik
Group=traefik
ExecStart=/usr/local/bin/traefik --configfile=/etc/traefik/traefik.toml
LimitNOFILE=1048576
PrivateTmp=true
PrivateDevices=false
ProtectHome=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now traefik.service
```

You will then (hopefully) see some log entries added to the `/var/log/traefik/traefik.log` file like the ones below (some columns stripped). Here you see that two of the three servers are deemed unhealthy because of the `429` return code. Just like we planned.

```text
msg="Creating load-balancer" entryPointName=http routerName=vault@file serviceName=vault
msg="Creating server 0 http://192.168.64.44:8200/" serviceName=vault serverName=0 entryPointName=http routerName=vault@file
msg="child http://192.168.64.44:8200/ now UP"
msg="Propagating new UP status"
msg="Creating server 1 http://192.168.64.45:8200/" entryPointName=http routerName=vault@file serviceName=vault serverName=1
msg="child http://192.168.64.45:8200/ now UP"
msg="Still UP, no need to propagate"
msg="Creating server 2 http://192.168.64.46:8200/" routerName=vault@file serviceName=vault serverName=2 entryPointName=http
msg="child http://192.168.64.46:8200/ now UP"
msg="Initial health check for backend: \"vault@file\""
level=warning msg="Health check failed, removing from server list. Backend: \"vault@file\" URL: \"http://192.168.64.45:8200/\" Weight: 1 Reason: received error status code: 429"
msg="child http://192.168.64.45:8200/ now DOWN"
msg="Still UP, no need to propagate"
level=warning msg="Health check failed, removing from server list. Backend: \"vault@file\" URL: \"http://192.168.64.46:8200/\" Weight: 1 Reason: received error status code: 429"
msg="child http://192.168.64.46:8200/ now DOWN"
msg="Still UP, no need to propagate"
```

Checking this through API can be done like this

```shell
$ $ curl -s localhost:8080/api/http/services/vault@file | jq
{
  "loadBalancer": {
    "servers": [
      {
        "url": "http://192.168.64.44:8200/"
      },
      {
        "url": "http://192.168.64.45:8200/"
      },
      {
        "url": "http://192.168.64.46:8200/"
      }
    ],
    "healthCheck": {
      "path": "/v1/sys/health",
      "interval": "10s",
      "timeout": "3s",
      "followRedirects": true
    },
    "passHostHeader": true
  },
  "status": "enabled",
  "usedBy": [
    "vault@file"
  ],
  "serverStatus": {
    "http://192.168.64.44:8200/": "UP",
    "http://192.168.64.45:8200/": "DOWN",
    "http://192.168.64.46:8200/": "DOWN"
  },
  "name": "vault@file",
  "provider": "file",
  "type": "loadbalancer"
}
```

There you go!