# Docker Build Troubleshooting for NetBox Plugin Development

## Standard Build Command

```bash
cd /srv/netbox-docker
docker compose build --no-cache netbox
```

## When Standard Build Fails

If you get errors like:
- `runc run failed: unable to start container process: can't get final child's PID from pipe: EOF`
- `process did not complete successfully: exit code: 1`

Use this command instead:

```bash
docker compose build --no-cache --progress=plain netbox
```

## Why `--progress=plain` Helps

1. **More verbose output**: Shows detailed progress for each build step
2. **BuildKit compatibility**: Can resolve some Docker BuildKit issues
3. **Better error visibility**: Makes it easier to identify which step failed
4. **Consistent behavior**: Sometimes works when the default build mode fails

## Complete Rebuild Workflow

```bash
# 1. Navigate to netbox-docker directory
cd /srv/netbox-docker

# 2. Try standard build first
docker compose build --no-cache netbox

# 3. If that fails, use progress=plain
docker compose build --no-cache --progress=plain netbox

# 4. If still failing, clean up first
docker system prune -f
docker volume prune -f
docker compose build --no-cache --progress=plain netbox

# 5. Restart containers
docker compose down
docker compose up -d

# 6. Verify NetBox started
docker compose ps
docker compose logs netbox | tail -50
```

## Quick Update After Code Push

After pushing code to GitHub:

```bash
cd /srv/netbox-docker
docker compose build --no-cache --progress=plain netbox
docker compose restart netbox
```

## Port Conflict Issues

If you see `Bind for 0.0.0.0:8000 failed: port is already allocated`:

```bash
# 1. Check what's using port 8000
sudo lsof -i :8000
# OR
sudo netstat -tulpn | grep :8000

# 2. Stop the conflicting service or container
# If it's another NetBox instance:
docker ps | grep netbox
docker stop <container-id>

# 3. Or change the port in docker-compose.yml
# Edit the ports section to use a different port like 8001:8001

# 4. Then start again
docker compose up -d
```

## Verify Plugin Version

**Method 1: Check build output (most reliable)**
The commit hash is shown during the Docker build process. Look for lines like:
```
Built netbox-automation-plugin @ git+https://github.com/irfanzq/netbox-automation-plugin.git@c19b13c9636fe996ee4d0d730d5e914656b6e1da
```

**Method 2: Check installation timestamp**
```bash
docker compose exec netbox stat -c "%y" /opt/netbox/venv/lib/python3.12/site-packages/netbox_automation_plugin
```
Compare this timestamp with when you last rebuilt the image.

**Method 3: Check version in code (package version, not git commit)**
```bash
docker compose exec netbox grep "__version__" /opt/netbox/venv/lib/python3.12/site-packages/netbox_automation_plugin/__init__.py
```
Note: This shows the package version (e.g., `1.0.0`), not the git commit hash.

**Method 4: Compare with local git**
On your local machine:
```bash
git log --oneline -1
git rev-parse HEAD
```
If the commit matches what you see in the build output, you have the latest code.

