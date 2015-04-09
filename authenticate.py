# coding:utf-8
import argparse
import logging

from azure.auth import AzureApp
from azure.api import SERVICE_MANAGEMENT_RESOURCE, AD_RESOURCE, AzureCrpClient, AzureGraphClient, \
    AzureSubscriptionClient, AzureObject


logger = logging.getLogger(__name__)



class CandidateSubscription(object):
    """
    A subscription we want to prompt the user to grant access to.
    """
    def __init__(self, tenant, subscription):
        self.tenant = tenant
        self.subscription = subscription


def prompt_for_access_on_subscriptions(app, extra, candidates):
    for candidate in candidates:
        logger.info("Trying subscription: %s (%s)", candidate.subscription.subscriptionId,
                    candidate.subscription.displayName)

        if candidate.subscription.state == "Disabled":
            logger.warning("Skipping %s: subscription is disabled", candidate.subscription.subscriptionId)
            continue

        # This is meant to run in Python 3.
        register = None
        while register is None:
            r = input(" Do you want to add '{0} ({1})'? [y/n]".format(candidate.subscription.subscriptionId,
                                                                      candidate.subscription.displayName))
            register = {"y": True, "n": False}.get(r.lower())

        if not register:
            logger.debug("Skipping subscription: %s", candidate.subscription.subscriptionId)
            continue

        logger.info("Registering app for access to subscription: %s", candidate.subscription.subscriptionId)
        add_access_on_subscription(app, extra, candidate)

        # A Subscription was registered
        return True

    # No Subscriptions were registered
    return False


def add_access_on_subscription(app, extra, candidate):
    # Get admin credentials
    sm_credentials, ad_credentials = get_admin_credentials(app, candidate.tenant, extra)

    sm_client = AzureSubscriptionClient(candidate.subscription, sm_credentials)
    ad_client = AzureGraphClient(candidate.tenant, ad_credentials)

    # The service principal API should let me get the ID of the app's Service Principal in that directory.
    # It should exist assuming directory access has been granted.
    service_principal = ad_client.list_service_principals(filter="appId eq '{0}'".format(app.app_client_id))[0]

    # Grant access!
    for role in sm_client.list_role_definitions():
        if role.properties.roleName == "Contributor":
            sm_client.grant_role_to_service_principal(
                role.id,
                service_principal.objectId
            )
            break
    else:
        raise Exception("Panic! Did not find Contributor Role")


def get_admin_credentials(app, tenant, extra):
    # Do I need to ask twice? Does it not use what is requested when the app is created?
    sm_credentials = app.get_credentials_for_resource(tenant.tenantId, SERVICE_MANAGEMENT_RESOURCE,
                                                             prompt="admin_consent", **extra)
    ad_credentials = app.get_credentials_for_resource(tenant.tenantId, AD_RESOURCE, prompt="admin_consent",
                                                      **extra)
    return sm_credentials, ad_credentials




def main(app_client_id, app_client_secret, live):
    """
    Add the app as a Service Principal in Azure.
    """
    app = AzureApp(app_client_id, app_client_secret)

    # If the user is a live.com user (i.e. a Microsoft account, not an organization account), then we need to pass
    # a "domain_hint" as an additional query argument in our OAuth token request. Otherwise, Azure will get confused
    # and tell the user their credentials are wrong / they can't login (wtf wtf wtf).
    # NOTE: THis is what Azure tells me, but in practice it seems to sometimes work without the hint...!
    extra = {"domain_hint": "live.com"} if live else {}

    # Step 1: Get Service Management credentials for the User's default Tenant ("common").
    default_tenant = AzureObject({"tenantId": "common"})
    sm_generic_credentials = app.get_credentials_for_resource(default_tenant.tenantId, SERVICE_MANAGEMENT_RESOURCE,
                                                              **extra)

    # Step 1.a: OPTIONAL - Try the subscriptions on that tenant.
    prompt_for_access_on_subscriptions(app, extra, [
        CandidateSubscription(default_tenant, subscription)
        for subscription in AzureCrpClient(sm_generic_credentials).list_subscriptions()
    ])

    # Step 2: List the Tenants this user has access to
    tenants = AzureCrpClient(sm_generic_credentials).list_tenants()

    # Step 3: For each Tenant, obtain an Azure Service Management token for the tenant, and use it to list
    # subscriptions.
    # Here, we assemble those in a list that lets us keep a mapping of Subscription -> Tenant to not have to prompt
    # for the tenant credentials *once again*.
    all_subscription_candidates = []

    for tenant in tenants :
        logger.info("Listing subscriptions in Tenant: %s", tenant.tenantId)

        # Step 3.a: Get an access token for the Tenant so we can list subscriptions in it.
        sm_tenant_credentials = app.get_credentials_for_resource(tenant.tenantId, SERVICE_MANAGEMENT_RESOURCE,
                                                                 **extra)

        # Step 3.b: Use this access token to list the Subscriptions that exist within the Tenant.
        subscriptions = AzureCrpClient(sm_tenant_credentials).list_subscriptions() # TODO - Rename this object.
        all_subscription_candidates.extend([CandidateSubscription(tenant, subscription)
                                         for subscription in subscriptions])


    # Step 4: Go through the Subscriptions and identify the one the user wants to use.
    prompt_for_access_on_subscriptions(app, extra, all_subscription_candidates)

    # !!! THIS ONLY WORKS FOR ADMINISTRATORS !!! #
    #print(ad_client.get_tenant_name())

    # "Grant contributor Role on the subscription"
    # getRoleId ("ID of the 'contributor' Role")... and then:
    # grantRoleToServicePrincipalOnSubscription
    # -> graph call

    # Graph call will also
    # I can make a request *without* a resource parameter (and get an authorization code).
    # Then, I can use the refresh token to get an access token to another resource.


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.DEBUG)

    for name in ["requests", "werkzeug", "oauth2client"]:
        logging.getLogger(name).setLevel(logging.WARNING)

    parser = argparse.ArgumentParser("azure-authenticate")
    parser.add_argument("app_client_id")
    parser.add_argument("app_client_secret")
    parser.add_argument("--live", action="store_true", help="Whether this user is a live.com user or organization")

    ns = parser.parse_args()
    main(ns.app_client_id, ns.app_client_secret, ns.live)
