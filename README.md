# Cased Shell OAuth Handlers

A SSH server that authenticates against Cased Shell and starts Sessions with an web-based OAuth token exchange. The resulting token is placed in the environment, allowing the user to perform actions against an upstream service using the token obtained during the process.

Supported providers:

- Heroku
- Google Cloud Shell

# Usage

```
./ssh-oauth-handlers <provider> <shell_url> <default command to run for new sessions>
```

## Provider: Heroku

See https://github.com/cased/shell-heroku, which contains a working Heroku configuration that deploys Cased Shell and this utility.


## Provider: Google Cloud Shell

See https://github.com/cased/shell-cloud-run, which contains a working Cloud Run configuration that deploys Cased Shell and this utility.
