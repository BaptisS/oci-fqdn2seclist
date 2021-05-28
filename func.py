import io
import json
import logging
import dns.resolver
import os
import oci

from fdk import response

sl_id = os.getenv("sl_ocid")
#nsg_id = os.getenv("nsg_ocid")
cidr = "/32"

def update_sl(network_client, security_list_id, ip):
    update_sl_response = network_client.update_security_list(security_list_id=sl_id,
        update_security_list_details=oci.core.models.UpdateSecurityListDetails(
        egress_security_rules=[
            oci.core.models.EgressSecurityRule(
                protocol="6",
                description="BS_ZT-SecurityRule (Automated Creation)",
                destination=(ip + cidr),
                destination_type="CIDR_BLOCK",
                is_stateless=False,
                tcp_options=oci.core.models.TcpOptions(
                    destination_port_range=oci.core.models.PortRange(
                        max=443,
                        min=443
                    )
                )
            )
        ]
        )
    ).data
    return update_sl_response


#def resolvefqdn()

def handler(ctx, data: io.BytesIO = None):

    signer = oci.auth.signers.get_resource_principals_signer()
    network_client = oci.core.VirtualNetworkClient(config={}, signer=signer)

    name = os.getenv("fqdn2resolve")
    security_list_id = os.getenv("sl_ocid")
    result = []
    update_sl_resp = []

    try:
        answers = dns.resolver.query(name, 'A')
        for destip in answers:
             logging.getLogger().info("FQDN2RESOLVER execution" + destip.address)
             #update_sl_resp = update_sl(network_client, security_list_id, destip)
             result.append(destip.address)
             for ip in result:
                 update_sl_resp = update_sl(network_client, security_list_id, ip)
        #return result
        return update_sl_resp

    except (Exception, ValueError) as ex:
        logging.getLogger().info('error resolving name: ' + str(ex))
    

    logging.getLogger().info("FQDN2RESOLVER execution")

    return response.Response(
        ctx, response_data=json.dumps(
            {"message": "Resolved Ip is {0}".format(update_sl_resp)}),
        headers={"Content-Type": "application/json"}
    )
