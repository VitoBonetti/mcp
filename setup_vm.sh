#!/usr/bin/env bash
set -euo pipefail

# --- System deps, Docker, Nginx, Certbot ---
sudo apt update

# Docker + Compose plugin
sudo apt install -y apt-transport-https ca-certificates curl gnupg lsb-release
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER

# Nginx & Certbot
sudo apt install -y nginx certbot python3-certbot-nginx

# Create the application directory
sudo mkdir -p /opt/vulnai
sudo chown $USER:$USER /opt/vulnai

echo "Bootstrap complete. Re-login for Docker group to take effect."
echo "Next steps:"
echo "1. Copy your entire application (mcp/, docker-compose.yml) to /opt/vulnai/"
echo "2. Place your service_account.json in /opt/vulnai/mcp/service_account.json"
echo "3. Run 'sudo certbot --nginx -d vulnai.vitobonetti.nl' to get SSL certs."
echo "4. Copy mcp/nginx/vulnai to /etc/nginx/sites-available/vulnai"
echo "5. Run 'sudo ln -s /etc/nginx/sites-available/vulnai /etc/nginx/sites-enabled/'"
echo "6. Run 'sudo systemctl restart nginx'"
echo "7. Copy the new systemd service to /etc/systemd/system/vulnai.service and run 'sudo systemctl enable --now vulnai'"