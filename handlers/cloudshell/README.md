# CloudShell

Accepts a SSH connection from Cased Shell and exchanges it for a Google CloudShell session with a single click.

## Setup

### Create an OAuth Application

```shell
gcloud alpha iap oauth-brands create --application_title="Cased Shell" --support_email="internal-support@example.com"
gcloud alpha iap oauth-clients create brands/cased-shell --display_name="Cased Shell"
```

Note the `client_id` and `secret` in the output of the last command for the next step.
