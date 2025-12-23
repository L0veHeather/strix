# Strix Development Guide: Hot Updates

This guide explains how to set up Strix for local development so that your code changes take effect immediately without needing to reinstall.

## 1. Local Development (Pip Editable Mode)

If you are working in a local virtual environment (recommended), you can install Strix in "editable" mode.

```bash
# Clone the repository
git clone https://github.com/L0veHeather/strix.git
cd strix

# Create and activate a virtual environment (optional but recommended)
python -m venv .venv
source .venv/bin/activate

# Install in editable mode
pip install -e .
# OR use the Makefile helper
make dev-link
```

Now, any changes you make to the code in the `strix/` directory will be reflected immediately when you run the `strix` command.

## 2. Global Development (Pipx Editable Mode)

If you prefer using `pipx` for global access but still want to develop locally:

```bash
# If already installed, uninstall first (optional)
pipx uninstall strix

# Install from the local source in editable mode
pipx install --editable .
```

This gives you a global `strix` command that points directly to your local source code. No more `pipx uninstall`/`pipx install` cycles!

## 3. Docker Development

The project includes a dedicated Docker Compose setup for development that supports hot reloading via volume mounts.

```bash
### Running in Docker
For the best development experience with hot reloading:
```bash
docker compose -f docker-compose.dev.yml up --build
```

> [!TIP]
> **Docker Permissions**: If Strix needs to interact with other containers (e.g., in Omniscient mode), it uses the mounted `/var/run/docker.sock`. If you encounter permission errors, you may need to grant access on your host:
> `sudo chmod 666 /var/run/docker.sock`
# Run commands inside the container
docker compose -f docker-compose.dev.yml run --rm strix-dev strix --version
```

The `docker-compose.dev.yml` file mounts your local `./strix` directory into the container at `/app/strix`, so changes on your host machine are immediately visible inside the container.

## 4. Vibe Coding Checklist (Verification)

To verify your hot update setup is working:

1. **Verify Version Change**:
   - Open `strix/__init__.py`.
   - Change `__version__ = "0.3.6"` to `__version__ = "0.3.6-dev"`.
   - Run `strix --version`.
   - If it shows `0.3.6-dev`, your hot update setup is working!

2. **Verify CLI Change**:
   - Open `strix/interface/main.py`.
   - Modify a help message or a print statement.
   - Run the command and verify the change appears.

---

> [!TIP]
> Always ensure you are in the correct virtual environment if you have multiple versions of Strix installed.
