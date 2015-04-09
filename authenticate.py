# coding:utf-8
import argparse
import logging

from azure.auth import AzureApp
from azure.api import SERVICE_MANAGEMENT_RESOURCE, AD_RESOURCE, AzureCrpClient, AzureGraphClient, \
    AzureSubscriptionClient, AzureObject


logger = logging.getLogger("azure-authenticate")



class CandidateSubscription(object):
    """
    A subscription we want to prompt the user to grant access to.
    """
    def __init__(self, tenant, subscription, creds):
        self.tenant = tenant
        self.subscription = subscription
        self.creds = creds


def maybe_add_access(app, subscription_id, candidates):
    for candidate in candidates:
        if candidate.subscription.state == "Disabled":
            logger.debug("Skipping %s (%s): subscription is disabled", candidate.subscription.displayName,
                         candidate.subscription.subscriptionId)
            continue

        if candidate.subscription.subscriptionId != subscription_id:
            logger.debug("Skipping %s (%s): does not match query (%s)", candidate.subscription.displayName,
                         candidate.subscription.subscriptionId, subscription_id)
            continue

        logger.info("Registering app for access to subscription: %s (%s)", candidate.subscription.displayName,
                    candidate.subscription.subscriptionId)
        add_access_on_subscription(app, candidate)

        # A Subscription was registered
        return True

    # No Subscriptions were registered
    return False


def add_access_on_subscription(app, candidate):
    # Client to access the Service Management API
    sm_client = AzureSubscriptionClient(candidate.subscription, candidate.creds)

    # Client to access the AD API. It's important to note that WE USE THE APP'S CREDENTIALS. NOT THE USER's.
    # This lets us get away with one less permission (read directory data is no longer needed), and means we don't
    # have to ask for admin_consent (which read directory data requires).
    ad_creds = app.get_app_token(candidate.tenant.tenantId, AD_RESOURCE)
    ad_client = AzureGraphClient(candidate.tenant, ad_creds)

    service_principal = ad_client.list_service_principals(filter="appId eq '{0}'".format(app.app_client_id))[0]

    # Grant access!
    for role in sm_client.list_role_definitions():
        if role.properties.roleName == "Contributor":
            sm_client.grant_role_to_service_principal(
                role.id,
                service_principal.objectId,
                suppress_errors=[409],  # 409 conflict means the role was already added
            )
            break
    else:
        raise Exception("Panic! Did not find Contributor Role")


def main(app_client_id, app_client_secret, subscription_id, live, directory):
    """
    Add the app as a Service Principal in Azure.
    """

    # App needs permissions:
    # - AD: Enable sign-on and read users' profiles
    # - Service Management: Access Azure Service Management (Preview)
    app = AzureApp(app_client_id, app_client_secret)

    # If the user is a live.com user (i.e. a Microsoft account, not an organization account), then we need to pass
    # a "domain_hint" as an additional query argument in our OAuth token request. Otherwise, Azure will get confused
    # and tell the user their credentials are wrong / they can't login.
    extra = {"domain_hint": "live.com"} if live else {}

    # Furthermore, if the user is a live.com user, we cannot use the "common" endpoint (i.e. the "default directory"),
    # and we MUST provide the tenant name / ID. The only way to do that is to ask the user for it.
    if directory is None:
        if live:
            raise Exception("Cannot use --live without --directory!")
        directory = "common"

    # Step 1: Get Service Management credentials for the User's default Tenant ("common").
    default_tenant = AzureObject({"tenantId": directory})
    default_tenant_creds = app.get_credentials_for_resource(default_tenant.tenantId, SERVICE_MANAGEMENT_RESOURCE,
                                                              **extra)

    # Step 1.a: OPTIONAL - Try the subscriptions on that tenant.
    access_added = maybe_add_access(app, subscription_id, [
        CandidateSubscription(default_tenant, subscription, default_tenant_creds)
        for subscription in AzureCrpClient(default_tenant_creds).list_subscriptions()
    ])

    print([dict(s) for s in AzureCrpClient(default_tenant_creds).list_subscriptions()])

    if access_added:
        return

    # Step 2: List the Tenants this user has access to
    tenants = AzureCrpClient(default_tenant_creds).list_tenants()

    # Step 3: For each Tenant, obtain an Azure Service Management token for the tenant, and use it to list
    # subscriptions.
    # Here, we assemble those in a list that lets us keep a mapping of Subscription -> Tenant to not have to prompt
    # for the tenant credentials *once again*.
    all_subscription_candidates = []

    # In interactive mode, consider asking the tenant for their name and hitting that tenant directly
    for tenant in tenants :
        logger.info("Listing subscriptions in Tenant: %s", tenant.tenantId)

        # Step 3.a: Get an access token for the Tenant so we can list subscriptions in it.
        tenant_credentials = app.get_credentials_for_resource(tenant.tenantId, SERVICE_MANAGEMENT_RESOURCE,
                                                              **extra)

        # Step 3.b: Use this access token to list the Subscriptions that exist within the Tenant.
        subscriptions = AzureCrpClient(tenant_credentials).list_subscriptions() # TODO - Rename this object.
        all_subscription_candidates.extend([CandidateSubscription(tenant, subscription, tenant_credentials)
                                         for subscription in subscriptions])


    # Step 4: Go through the Subscriptions and identify the one the user wants to use.
    maybe_add_access(app, subscription_id, all_subscription_candidates)


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.DEBUG)

    for name in ["requests", "werkzeug", "oauth2client"]:
        logging.getLogger(name).setLevel(logging.WARNING)
    logging.getLogger("azure.auth").setLevel(logging.INFO)

    parser = argparse.ArgumentParser("azure-authenticate")

    parser.add_argument("app_client_id")
    parser.add_argument("app_client_secret")
    parser.add_argument("subscription_id", help="Id of the subscription you'd like to register")

    parser.add_argument("--live", action="store_true", help="Whether this user is a live.com user or organization")
    parser.add_argument("--directory", help="Provide a directory name to use")

    ns = parser.parse_args()
    main(ns.app_client_id, ns.app_client_secret, ns.subscription_id, ns.live, ns.directory)
