#coding:utf-8

def crp_cli_entrypoint(name, main):
    import logging
    import argparse

    logging.basicConfig(level=logging.DEBUG)

    for name in ["requests", "werkzeug", "oauth2client", "azure.ad"]:
        logging.getLogger(name).setLevel(logging.WARNING)

    parser = argparse.ArgumentParser(name)
    parser.add_argument("app_client_id")
    parser.add_argument("app_client_secret")
    parser.add_argument("tenant_id")
    parser.add_argument("subscription_id")

    ns = parser.parse_args()
    main(ns.app_client_id, ns.app_client_secret, ns.tenant_id, ns.subscription_id)
