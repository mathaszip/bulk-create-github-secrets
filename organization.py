import requests
import csv
import base64
from nacl import encoding, public
import sys
import os
from typing import Dict, Tuple

class GitHubSecretsManager:
    def __init__(self, token: str, org: str, repo: str):
        """
        Initialize the GitHub Secrets Manager.
        
        Args:
            token: GitHub Personal Access Token (Classic)
            org: Organization name
            repo: Repository name
        """
        self.token = token
        self.org = org
        self.repo = repo
        self.base_url = f"https://api.github.com/repos/{org}/{repo}"
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": f"Bearer {token}",
        }

    def get_public_key(self) -> Tuple[str, str]:
        """Get the repository's public key for secret encryption."""
        response = requests.get(
            f"{self.base_url}/actions/secrets/public-key",
            headers=self.headers
        )
        response.raise_for_status()
        data = response.json()
        return data["key_id"], data["key"]

    def encrypt_secret(self, public_key: str, secret_value: str) -> str:
        """
        Encrypt a secret using the repository's public key.
        
        Args:
            public_key: Repository's public key
            secret_value: Secret value to encrypt
        
        Returns:
            Encrypted secret value in base64
        """
        public_key_bytes = base64.b64decode(public_key)
        public_key_obj = public.PublicKey(public_key_bytes)
        sealed_box = public.SealedBox(public_key_obj)
        encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
        return base64.b64encode(encrypted).decode("utf-8")

    def set_secret(self, name: str, encrypted_value: str, key_id: str) -> None:
        """
        Set a secret in the repository.
        
        Args:
            name: Secret name
            encrypted_value: Encrypted secret value
            key_id: Public key ID
        """
        data = {
            "encrypted_value": encrypted_value,
            "key_id": key_id
        }
        response = requests.put(
            f"{self.base_url}/actions/secrets/{name}",
            headers=self.headers,
            json=data
        )
        response.raise_for_status()

def load_secrets_from_csv(file_path: str) -> Dict[str, str]:
    """
    Load secrets from a CSV file.
    
    Args:
        file_path: Path to the CSV file
    
    Returns:
        Dictionary of secret names and values
    """
    secrets = {}
    with open(file_path, 'r') as f:
        reader = csv.reader(f)
        next(reader, None)  # Skip header row
        for row in reader:
            if len(row) == 2:
                secrets[row[0]] = row[1]
    return secrets

def main():
    # Check command line arguments
    if len(sys.argv) != 5:
        print("Usage: python script.py <token> <org> <repo> <secrets_file>")
        sys.exit(1)

    token = sys.argv[1]
    org = sys.argv[2]
    repo = sys.argv[3]
    secrets_file = sys.argv[4]

    # Validate that the secrets file exists
    if not os.path.exists(secrets_file):
        print(f"Error: Secrets file '{secrets_file}' not found")
        sys.exit(1)

    try:
        # Initialize the secrets manager
        manager = GitHubSecretsManager(token, org, repo)
        
        # Get the repository's public key
        key_id, public_key = manager.get_public_key()
        
        # Load secrets from CSV
        secrets = load_secrets_from_csv(secrets_file)
        
        # Set each secret
        for name, value in secrets.items():
            try:
                print(f"Setting secret: {name}")
                encrypted_value = manager.encrypt_secret(public_key, value)
                manager.set_secret(name, encrypted_value, key_id)
                print(f"Successfully set secret: {name}")
            except Exception as e:
                print(f"Error setting secret {name}: {str(e)}")

    except requests.exceptions.RequestException as e:
        print(f"GitHub API Error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()