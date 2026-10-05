# Claude Provider Status Plugin

Real-time cloud and VCS infrastructure status awareness for Claude Code.

Monitors upstream operational status across major cloud compute platforms (**AWS**, **Google Cloud**, **Microsoft Azure**) and version control providers (**GitHub**, **GitLab**, **Bitbucket**). Automatically injects non-intrusive markdown advisories during Claude Code sessions and correlates bash tool execution failures with ongoing provider disruptions.

---

## Features

- **Multi-Format Ingestion**: Native parsing for RSS 2.0 (GitHub, GitLab, Bitbucket, Azure), Atom 1.0 (Google Cloud), and JSON APIs (AWS Health Dashboard).
- **Zero Third-Party Dependencies**: Pure Python 3 standard library implementation.
- **Fail-Fast Sub-60ms Cache**: Local cache (`status_cache.json`) with configurable TTL (default: 300s) and 2.5s network timeouts ensures zero prompt latency overhead.
- **Incident Correlating**: Maps failed CLI and SDK commands (`git`, `gh`, `aws`, `gcloud`, `az`, `terraform`, `tofu`, `kubectl`, `helm`, `docker`) to active upstream incidents.
- **Zero-Token Idle Footprint**: When all services are operational, output remains completely silent.
- **Decoupled Feed Registry**: Add, disable, or modify status feeds in `config/status_feeds.json` without code modifications.

---

## Installation

### Method 1: Claude Code Plugin (Marketplace)

Register this repository as a marketplace and install the plugin:

```bash
# Register marketplace catalog
claude plugin marketplace add awill1988/claude-provider-status

# Install plugin
claude plugin install provider-status@awill1988
```

Alternatively, from within an interactive Claude Code session:
```text
/plugin install provider-status@awill1988
```

### Method 2: Standalone Hook

1. Clone this repository:
   ```bash
   git clone https://github.com/awill1988/claude-provider-status.git ~/.claude/plugins/claude-provider-status
   ```

2. Register the hook in `~/.claude/settings.json`:
   ```json
   {
     "hooks": {
       "SessionStart": [
         {
           "matcher": "",
           "hooks": [
             {
               "type": "command",
               "command": "python3 ~/.claude/plugins/claude-provider-status/scripts/provider_status.py --event SessionStart"
             }
           ]
         }
       ],
       "UserPromptSubmit": [
         {
           "matcher": "",
           "hooks": [
             {
               "type": "command",
               "command": "python3 ~/.claude/plugins/claude-provider-status/scripts/provider_status.py --event UserPromptSubmit"
             }
           ]
         }
       ],
       "PostToolUseFailure": [
         {
           "matcher": "Bash",
           "hooks": [
             {
               "type": "command",
               "command": "python3 ~/.claude/plugins/claude-provider-status/scripts/provider_status.py --event PostToolUseFailure"
             }
           ]
         }
       ]
     }
   }
   ```

### Method 3: Nix Flakes & Home Manager

Add as a non-flake input in your `flake.nix`:

```nix
inputs = {
  claude-provider-status = {
    url = "github:awill1988/claude-provider-status";
    flake = false;
  };
};
```

Link the engine and configuration into your Home Manager configuration:

```nix
home.file.".claude/hooks/provider_status.py" = {
  source = "${inputs.claude-provider-status}/scripts/provider_status.py";
  executable = true;
};

home.file.".claude/hooks/status_feeds.json" = {
  source = "${inputs.claude-provider-status}/config/status_feeds.json";
};
```

---

## Configuration (`status_feeds.json`)

Feed definitions reside in `config/status_feeds.json`. Custom configurations can also be placed in project roots at `.claude/status_feeds.json` or globally at `~/.claude/hooks/status_feeds.json`.

```json
{
  "version": 1,
  "cache_ttl_seconds": 300,
  "timeout_seconds": 2.5,
  "max_incident_age_hours": 72,
  "feeds": [
    {
      "name": "AWS",
      "category": "cloud",
      "url": "https://health.aws.amazon.com/public/currentevents",
      "format": "aws-json",
      "enabled": true,
      "tool_matchers": ["aws", "terraform", "tofu", "cdk", "serverless", "sam", "pulumi"],
      "keywords": ["ec2", "s3", "lambda", "ecs", "eks", "rds", "dynamodb", "iam", "cloudformation", "route53", "vpc"]
    },
    {
      "name": "Google Cloud",
      "category": "cloud",
      "url": "https://status.cloud.google.com/feed.atom",
      "format": "atom",
      "enabled": true,
      "tool_matchers": ["gcloud", "gsutil", "bq", "terraform", "tofu", "kubectl", "helm"],
      "keywords": ["compute engine", "gke", "cloud storage", "cloud run", "networking", "iam", "bigquery"]
    },
    {
      "name": "GitHub",
      "category": "vcs",
      "url": "https://www.githubstatus.com/history.rss",
      "format": "rss",
      "enabled": true,
      "tool_matchers": ["git", "gh"],
      "keywords": ["actions", "git operations", "api requests", "webhooks", "codespaces", "pull requests"]
    }
  ]
}
```

### Adding a Custom Statuspage Feed

Most developer services (Datadog, Cloudflare, Atlassian, HashiCorp, Vercel) provide RSS or Atom history feeds. To add one:

```json
{
  "name": "Cloudflare",
  "category": "network",
  "url": "https://www.cloudflarestatus.com/history.rss",
  "format": "rss",
  "enabled": true,
  "tool_matchers": ["wrangler", "cloudflared", "curl"],
  "keywords": ["workers", "dns", "cdn", "pages", "r2"]
}
```

---

## CLI Utilities

Inspect configured feeds, test feeds individually, and verify cache status using the CLI:

```bash
# List all configured feeds
python3 scripts/provider_status.py --list-feeds

# Test fetching and parsing a specific feed
python3 scripts/provider_status.py --test-feed "AWS"
python3 scripts/provider_status.py --test-feed "Google Cloud"
python3 scripts/provider_status.py --test-feed "GitHub"

# Print active incident summary from cache
python3 scripts/provider_status.py --status

# Force cache refresh
python3 scripts/provider_status.py --refresh
```

---

## Testing

Run unit tests locally against offline fixtures:

```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
