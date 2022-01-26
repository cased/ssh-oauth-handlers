# CloudShell

Accepts a SSH connection from Cased Shell and exchanges it for a Google CloudShell session with a single click.

## Setup

### Create an OAuth Application

```shell
gcloud alpha iap oauth-brands create --application_title=APPLICATION_TITLE --support_email=SUPPORT_EMAIL
gcloud alpha iap oauth-clients create projects/PROJECT_ID/brands/BRAND-ID --display_name=NAME
```

Note the `client_id` and `secret` in the output of the last command for the next step.
