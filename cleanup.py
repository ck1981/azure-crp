#coding:utf-8

from azure.auth import AzureApp
from azure.api import SERVICE_MANAGEMENT_RESOURCE, AzureSubscriptionClient, AzureObject


def main(app_client_id, app_client_secret, tenant_id, subscription_id):
    app = AzureApp(app_client_id, app_client_secret)

    sub = AzureObject({"subscriptionId": subscription_id})
    creds = app.get_app_token(tenant_id, SERVICE_MANAGEMENT_RESOURCE)

    client = AzureSubscriptionClient(sub, creds)

    for rg in client.list_resource_groups():
        if rg.name.endswith('-rg'):
            client.delete_generic(rg)


if __name__ == "__main__":
    from azure.cli import crp_cli_entrypoint
    crp_cli_entrypoint("azure-cleanup", main)
