import uuid
import httplib2
import logging
import time

import requests
import requests.exceptions
import attrdict


logger = logging.getLogger(__name__)


SERVICE_MANAGEMENT_RESOURCE = "https://management.core.windows.net/" # (???)
AD_RESOURCE = "https://graph.windows.net/"

DEFAULT_RETRY_COUNT = 16
DEFAULT_RETRY_DELAY = 1
RETRY_BACKOFF_FACTOR = 1.5



class AzureObject(attrdict.AttrDict):
    @property
    def uri(self):
        return self["id"]



def make_serializable_dict(d):
    if not isinstance(d, (dict, attrdict.AttrDict)):
        return d

    new = {}
    for k, v in list(d.items()):
        if isinstance(v, (dict, attrdict.AttrDict)):
            new[k] = make_serializable_dict(v)
        elif isinstance(v, list):
            new[k] = [make_serializable_dict(e) for e in v]
        else:
            new[k] = v
    return new


class BaseAzureClient(requests.Session):
    base_url = None

    def __init__(self, credentials):
        super().__init__()
        self.credentials = credentials

    def _get_api_version(self, request):
        raise NotImplementedError

    def prepare_request(self, request):
        """
        Helper to inject common parameters in all requests (overrides method from requests.Session).
        """
        #  API version GET parameter
        request.params["api-version"] = self._get_api_version(request)

        # Authentication
        self.credentials.apply(request.headers)

        # https://msdn.microsoft.com/en-us/library/azure/8d088ecc-26eb-42e9-8acc-fe929ed33563#bk_common
        request.url = "".join([self.base_url, request.url])

        if request.json:
            request.headers["Content-Type"] = "application/json"
            request.json = make_serializable_dict(request.json)


        return super().prepare_request(request)

    def request(self, *args, **kwargs):
        retry_count = kwargs.pop('retry_count', DEFAULT_RETRY_COUNT)
        retry_delay = kwargs.pop('retry_delay', DEFAULT_RETRY_DELAY)

        res = super().request(*args, **kwargs)
        logger.debug("%s: %s",  " ".join(args), res.status_code)

        # Now, check for errors. We do this before raising to be able to log errors.
        try:
            err = res.json().get("error")
            if err is not None:
                logger.warning("Error (%s): %s\n%s", err["code"], err["message"], err.get("details", "(No details)"))
        except ValueError:
            # Probably just an empty response
            pass

        # Check if an error happened and retry if appropriate.
        try:
            res.raise_for_status()
        except requests.exceptions.HTTPError:
            logger.warning("Received error (status: %s)", res.status_code)

            if retry_count <= 0:
                raise

            if res.status_code == 401:
                logger.info("Refreshing credentials")
                self.credentials.refresh(httplib2.Http())

            retry_count -=1
            retry_delay *= RETRY_BACKOFF_FACTOR
            kwargs.update(retry_count=retry_count, retry_delay=retry_delay)

            logger.debug("Retrying in %ss, retries left: %s", retry_delay, retry_count)
            time.sleep(retry_delay)

            return self.request(*args, **kwargs)

        try:
            out = AzureObject(res.json())
        except ValueError:
            out = res.text

        return out

    def list(self, url, **kwargs):
        out = []
        while url is not None:
            res = self.get(url, **kwargs)
            out.extend([AzureObject(o) for o in res["value"]])
            url = res.get("nextLink")
        return out


class AzureGraphClient(BaseAzureClient):
    base_url = "https://graph.windows.net"

    def __init__(self, tenant, credentials):
        super().__init__(credentials)
        self.tenant = tenant

    def _get_api_version(self, request):
        return "1.5"

    def get_tenant_name(self):
        return self.get("/{tenant.tenantId}/tenantDetails".format(tenant=self.tenant))

    def list_service_principals(self, filter=None):
        params = {}
        if filter is not None:
            params.update({"$filter": filter})
        return self.list("/{tenant.tenantId}/servicePrincipals/".format(tenant=self.tenant), params=params)


class AzureCrpClient(BaseAzureClient):
    base_url = "https://management.azure.com"

    def _get_api_version(self, request):
        for ns in ["Compute", "Network", "Storage"]:
            if "/Microsoft.{0}/".format(ns) in request.url:
                return "2014-12-01-preview"
        for ns in ["Authorization"]:
            if "/Microsoft.{0}/".format(ns) in request.url:
                return "2014-10-01-preview"
        else:
            return "2015-01-01"

    # Providers #

    def list_providers(self):
        return self.list("/providers")

    # Tenants #

    def list_tenants(self):
        return self.list("/tenants")

    # Subscriptions #
    def list_subscriptions(self):
        return self.list("/subscriptions")


class AzureSubscriptionClient(AzureCrpClient):

    def __init__(self, subscription, credentials):
        super().__init__(credentials)
        self.subscription = subscription

    def _subscription(self):
        # TODO - Remove and just access subscription directly.
        return AzureObject({"id": "/subscriptions/{subscription_id}".format(subscription_id=self.subscription.subscriptionId)})

    # Resource Groups #

    def create_resource_group(self, name, body):
        return self.put("{subscription.uri}/resourceGroups/{name}".format(subscription=self._subscription(), name=name), json=body)

    def get_resource_group(self, name):
        return self.get("{subscription.uri}/resourceGroups/{name}".format(subscription=self._subscription(), name=name))

    def list_resource_groups(self):
        return self.list("{subscription.uri}/resourceGroups".format(subscription=self._subscription()))

    def delete_resource_group(self, rg):
        self.delete(rg.uri)


    # Storage Account #

    def create_storage_account(self, rg, name, body):
        self.put("{rg.uri}/providers/Microsoft.Storage/storageAccounts/{name}".format(rg=rg, name=name), json=body)
        # The API returns an incomplete object when making the call to create a storage account, so we hit it again.
        return self.get_storage_account(rg, name)

    def get_storage_account(self, rg, name):
        return self.get("{rg.uri}/providers/Microsoft.Storage/storageAccounts/{name}".format(rg=rg, name=name))

    def delete_storage_account(self, sa):
        self.delete(sa.uri)

    # Virtual Networks #

    def create_virtual_network(self, rg, name, body):
        return self.put("{rg.uri}/providers/Microsoft.Network/virtualNetworks/{name}".format(rg=rg, name=name),
                        json=body)

    def get_virtual_network(self, rg, name):
        return self.get("{rg.uri}/providers/Microsoft.Network/virtualNetworks/{name}".format(rg=rg, name=name))

    def delete_virtual_network(self, net):
        self.delete(net.uri)

    def get_subnet(self, network, name):
        return self.get("{network.uri}/subnets/{name}".format(network=network, name=name))

    # Public IP Address

    def create_public_address(self, rg, name, body):
        return self.put("{rg.uri}/providers/Microsoft.Network/publicIPAddresses/{name}".format(rg=rg, name=name), json=body)

    def get_public_address(self, rg, name):
        return self.get("{rg.uri}/providers/Microsoft.Network/publicIPAddresses/{name}".format(rg=rg, name=name))

    # Network Interfaces

    def create_network_interface(self, rg, name, body):
        return  self.put("{rg.uri}/providers/Microsoft.Network/networkInterfaces/{name}".format(rg=rg, name=name), json=body)

    def get_network_interface(self, rg, name):
        return self.get("{rg.uri}/providers/Microsoft.Network/networkInterfaces/{name}".format(rg=rg, name=name))

    # VMs #

    def create_virtual_machine(self, rg, name, body):
        return self.put("{rg.uri}/providers/Microsoft.Compute/virtualMachines/{name}".format(rg=rg, name=name), json=body)

    def delete_virtual_machine(self, rg, name):
        return self.delete("{rg.uri}/providers/Microsoft.Compute/virtualMachines/{name}".format(rg=rg, name=name))

    def list_virtual_machines(self, rg):
        return self.list("{rg.uri}/providers/Microsoft.Compute/virtualMachines/".format(rg=rg))

    def get_virtual_machine(self, rg, name, model=False):
        url = "{rg.uri}/providers/Microsoft.Compute/virtualMachines/{name}".format(rg=rg, name=name)
        if not model:
            url += "/instanceView"
        return self.get(url)


    # Service Principal Assignment #

    def list_role_definitions(self):
        return self.list("{subscription.uri}/providers/Microsoft.Authorization/roleDefinitions/".format(subscription=self._subscription()))

    def grant_role_to_service_principal(self, roleDefinitionId, servicePrincipalId):
        return self.put(
            "{subscription.uri}/providers/Microsoft.Authorization/roleAssignments/{roleAssignmentId}".format(subscription=self._subscription(), roleAssignmentId=uuid.uuid4()),
            json={
            "properties": {
                "roleDefinitionId": roleDefinitionId,
                "principalId": servicePrincipalId

            }
        })

    # Generic methods
    def delete_generic(self, obj):
        return self.delete(obj.uri)

    def get_generic(self, obj):
        return self.get(obj.uri)
