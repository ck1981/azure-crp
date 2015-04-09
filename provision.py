# coding:utf-8
import sys
import time
import logging
import random
import string
import functools
import base64
import json

from azure.auth import AzureApp
from azure.api import SERVICE_MANAGEMENT_RESOURCE, AzureSubscriptionClient, AzureObject, make_serializable_dict


logger = logging.getLogger("azure-provision")


def run_test(client, vm):
    json.dump(make_serializable_dict(vm), sys.stdout, indent=2)
    ip = vm.properties.networkProfile.networkInterfaces[0].properties.ipConfigurations[0].properties.publicIPAddress

    while 1:
        ip = client.get_generic(ip)
        # NOTE! Looking at the status actually isn't enough to tell whether the IP Address will be there.
        # One should look at the ipAddress property instead...!
        json.dump(make_serializable_dict(ip), sys.stdout, indent=2)
        if ip.properties.get("ipAddress"):
            break
        time.sleep(5)

    input("Press enter to cleanup")


def main(app_client_id, app_client_secret, tenant_id, subscription_id):
    app = AzureApp(app_client_id, app_client_secret)

    sub = AzureObject({"subscriptionId": subscription_id})
    creds = app.get_app_token(tenant_id, SERVICE_MANAGEMENT_RESOURCE)

    # IMPORTANT NOTE: The credentials you obtain for the app CANNOT BE REFRESHED. You should obtan brand new
    # credentials instead (but it's just one API Call anyway).
    client = AzureSubscriptionClient(sub, creds)

    # Used to randomize names a bit and avoid conflicts
    prefix = ''.join(random.choice(string.ascii_lowercase) for _ in range(4))
    def make_name(s, separator=True):
        l = [prefix]
        if separator:
            l.append("-")
        l.append(s)
        return "".join(l)


    cleanup_steps = []
    def schedule_for_deletion(obj):
        cleanup_steps.append(functools.partial(client.delete_generic, obj))


    # noinspection PyBroadException
    try:
        logger.info("Creating Resource Group")
        rg = client.create_resource_group(make_name("rg"), {"location": "West US"})
        schedule_for_deletion(rg)

        logger.info("Creating Storage Account")
        sa = client.create_storage_account(rg, make_name("sa", False), {
            "location": "West US",
            "properties": {
                "accountType": "Standard_GRS"
            }
        })
        schedule_for_deletion(sa)


        logger.info("Creating Virtual Network")
        net = client.create_virtual_network(rg, make_name("net"), {
            "location": "West US",
            "properties": {
                "addressSpace": {
                    "addressPrefixes": [
                        "10.0.0.0/16"
                    ]
                },
                "subnets": [
                    {
                        "name": "frontend-subnet",
                        "properties": {
                            "addressPrefix": "10.0.1.0/24"
                        }
                    },
                    {
                        "name": "backend-subnet",
                        "properties": {
                            "addressPrefix": "10.0.2.0/24"
                        }
                    }
                ]
            }
        })
        schedule_for_deletion(net)

        frontent_subnet = client.get_subnet(net, "frontend-subnet")

        logger.info("Creating IP Address")
        ip = client.create_public_address(rg, make_name("public-ip"), {
            "location": "West US",
            "properties": {
                "publicIPAllocationMethod": "Dynamic"
            }
        })
        schedule_for_deletion(ip)


        logger.info("Creating NIC")
        nic = client.create_network_interface(rg, make_name("nic"), {
            "location": "West US",
            "properties": {
                "ipConfigurations": [
                    {
                        "name": make_name("private-ip"),  # This MUST be set.
                        "properties": {
                            "subnet": frontent_subnet,
                            "publicIPAddress": ip,
                            "privateIPAllocationMethod": "Dynamic",
                        }
                    }
                ]
            }
        })
        schedule_for_deletion(nic)


        logger.info("Creating VM")

        vm_name = make_name("vm")
        custom_data = "#cloud-config\nssh_import_id: [torozco]\npackages:\n  - apache2"
        image = AzureObject({"id": "/99def150-d64f-4525-82ac-c55f8800e56b/services/images/b39f27a8b8c64d52b05eac6a62ebad85__Ubuntu-14_04_1-LTS-amd64-server-20141125-en-us-30GB"})

        vhd_container = "".join([sa.properties.primaryEndpoints.blob, "vhds"])

        vm = client.create_virtual_machine(rg, vm_name, {
            "location": "West US",
            "properties": {
                "hardwareProfile": {
                    "vmSize": "Standard_A1"
                },
                "storageProfile": {
                    "sourceImage": image,
                    "destinationVhdsContainer": vhd_container,
                    #"osDisk": {
                    #    "name": "root",
                    #    "vhdUri": "{container}/root.vhd".format(container=vhd_container),
                    #    "caching": "none",
                    #}
                },
                "networkProfile": {
                    "networkInterfaces": [
                        nic,
                    ],
                },
                "osProfile": {
                    "computerName": vm_name,
                    "adminUsername": "thomas",
                    "adminPassword": "qv4AcnkdvksS",
                    #"windowsConfiguration": {
                    #    "provisionVMAgent": False
                    #},
                    "linuxConfiguration": {
                        "disablePasswordAuthentication": False,
                        # TODO - Figure out SSH Profile / ssh
                    },
                    "customData": base64.b64encode(custom_data.encode('utf-8')).decode('utf-8')
                },
            }
        })
        schedule_for_deletion(vm)

        run_test(client, vm)

        logger.info("Completed test sequence.")

    except Exception:
        logger.exception("An error occurred!")

    finally:
        logger.warning("Cleaning up")
        for cleanup_step in reversed(cleanup_steps):
            cleanup_step()

    return


if __name__ == "__main__":
    from azure.cli import crp_cli_entrypoint
    crp_cli_entrypoint("azure-provision", main)
