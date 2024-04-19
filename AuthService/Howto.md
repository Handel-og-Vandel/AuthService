# Howto devleop autservice

## ENV setup

```bash
export VaultURL=https://localhost:8201/
export VaultPath=authorization
export VaultMountPoint=secret
```

## Build Docker image for development

docker build -f Dockerfile -t hnrkjnsn/haav-auth-service:latest-dev .
