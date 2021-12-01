# Cased Shell OAuth Handlers

An SSH server that authenticates against Cased Shell and starts Sessions with an web-based OAuth token exchange. The resulting token is placed in the environment, allowing the user to perform actions against an upstream service using the token obtained during the process.

Supported providers:

- Heroku
- ???

# Usage

```
./ssh-oauth-handlers <provider> <shell_url> <default command to run for new sessions>
```

## Provider: Heroku

```
export COOKIE_SECRET=`openssl rand -hex 32`
export COOKIE_ENCRYPT=`openssl rand -hex 16`
HEROKU_OAUTH_SECRET=<secret>  HEROKU_OAUTH_SECRET=<secret> ./ssh-oauth-handlers heroku http://localhost:8888 bash -i
```

1. Create a Heroku app. Its name will be referenced as `<app_name>` throughout this tutorial.
2. Create a Cased Shell instance named `<app_name>.herokuapp.com`. On the Settings tab, enable Certificate Authentication. Configure a host to allow access by connections signed by your certificate, then add the host to Cased Shell.
3. Add a `CASED_SHELL_SECRET` Config Var to your Heroku app using the value from the Cased Shell Settings tab.
4. Clone this repo.
5. Run the following commands to deploy Cased Shell to Heroku:

```
heroku git:remote -a <app_name>
heroku stack:set container
heroku labs:enable runtime-dyno-metadata
heroku plugins:install heroku-cli-oauth
heroku clients:create "<app_name>.herokuapp.com" https://<app_name>.herokuapp.com/oauth/auth/callback
heroku config:add HEROKU_OAUTH_ID=     # set to `id` from command output above
heroku config:add HEROKU_OAUTH_SECRET= # set to `secret` from command output above
heroku config:add COOKIE_SECRET=`openssl rand -hex 32`
heroku config:add COOKIE_ENCRYPT=`openssl rand -hex 16`
git push heroku main
```

Open https://<app_name>.herokuapp.com in your browser and login.
