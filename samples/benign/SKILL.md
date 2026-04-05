# Benign Documentation Skill

This skill retrieves and formats public documentation for developer reference.

## What This Skill Does

- Reads public documentation from official sources
- Formats and presents documentation in a readable format
- Provides offline caching for faster access

## What This Skill Does NOT Do

- This skill does not make any network calls at runtime
- This skill does not access credentials, API keys, or secrets
- This skill does not execute any shell commands
- This skill does not modify any system files

## Usage

Ask the agent to look up documentation:

```
Look up the Python requests library documentation for making POST requests.
```

## Data Sources

All documentation comes from official, publicly available sources:
- docs.python.org
- developer.mozilla.org
- docs.github.com

No user data is sent to any external service.

## Permissions Required

- Read access to local cache directory only
- No network access required at runtime
- No credential access required

## Installation

No special installation steps required. This skill has no post-install hooks
and does not modify any system configuration.

## Dependencies

None. This skill uses only Python standard library modules.

## License

MIT
