Sample Code For Azure AD and CRP
================================

Sample CLI Python code to talk to the Azure AD and CRP APIs. This code is
written for Python 3, but it should be possible to support Python 2 rather
trivially.

Dependencies are in `requirements.txt`.


Authenticate
------------

After you have created an app in Azure, you can the app access over a
Subscription using:

     python authenticate.py "<App Client ID>" "<App Client Secret>" "<Subscription ID>"

Optional parameters:

  + `--live`: if your account is a live account, use this.
  + `--directory`:  if your account is a live account, or if you want to
    use a non-default directory (tenant), use this.
