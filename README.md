# Bulk GitHub Secrets Manager

This tool allows you to bulk create GitHub Actions secrets for both personal and organization repositories using Python. It supports creating multiple secrets at once using a CSV file as input.

## Prerequisites

- Python 3.6 or higher
- GitHub Personal Access Token with appropriate permissions
- Required Python packages: `requests`, `PyNaCl`

## Installation

1. Clone this repository:

```bash
git clone https://github.com/mathaszip/bulk-create-github-secrets.git
cd bulk-create-github-secrets
```

2. Install required packages:

```bash
pip install -r requirements.txt
```

## Setting up a GitHub Personal Access Token

1. Go to GitHub Settings → Developer Settings → [Personal Access Tokens](https://github.com/settings/tokens)
2. Click "Generate new token (classic)"
3. Select the following scopes:
   - For personal repositories: `repo` and `workflow`
   - For organization repositories: `repo`, `workflow`, and `admin:org`
4. Copy the generated token and store it securely

## Preparing Your Secrets

Create a CSV file with your secrets in the following format:

```csv
name,secret
API_KEY,your-api-key-here
DATABASE_URL,your-database-url
```

The first row must be the header row.

## Usage

### For Personal Repositories

```bash
python personal.py <github_token> <username/repository> <secrets_file.csv>
```

Example:

```bash
python personal.py ghp_xxxxxxxxxxxx username/my-repo secrets.csv
```

### For Organization Repositories

```bash
python organization.py <github_token> <organization> <repository> <secrets_file.csv>
```

Example:

```bash
python organization.py ghp_xxxxxxxxxxxx my-org my-repo secrets.csv
```

## Error Handling

The script will:

- Validate the existence of your secrets file
- Check for proper CSV formatting
- Report any errors during secret creation
- Continue processing remaining secrets if one fails

## Security Notes

- Never commit your GitHub token or secrets file to version control
- Use environment variables or secure secret management for the GitHub token
- Delete your token immediately if accidentally exposed

## Contributing

Feel free to open issues or submit pull requests for improvements.

## License

MIT License - Feel free to use and modify as needed.
