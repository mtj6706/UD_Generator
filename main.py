import muddy.muddy.mud
import scapy.all as scapy
from muddy.muddy.mud import MUD
from muddy.muddy.models import Direction, IPVersion, Protocol, MatchType
from ipaddress import ip_address, ip_network
import json
from os.path import basename


def _generate_host_map(packets: scapy.PacketList, target_device: str) -> dict:
    """
    Finds the DNS responses made to the target devices requests to acquire the hostnames being requested by the
    target. This will assist in converting the IP addresses the target is interacting with to hostnames for the
    policy. If a particular IP is not in the DNS responses then there will not be a mapping for it. This is likely
    the case for direct IP communications like in the case of controller communication.
    :param packets: The packets containing the device traffic.
    :param target_device: The IP address of the device being examined.
    :return: A dictionary containing the IPs (keys) of the devices interacting with the target and their associated
    host name (value)
    """
    mapping: dict = dict()
    for pkt in packets:
        if pkt.haslayer("DNSRR") and pkt["IP"].dst == target_device \
                and pkt.getlayer('DNSQR').qname.decode('utf-8') not in mapping.values():
            # Check if the packet has a DNS response to the target that we haven't mapped already
            answers = int(pkt.getlayer("DNS").ancount)
            responses = pkt.getlayer("DNSRR")
            for i in range(answers):
                response_name: str = responses[i].rrname.decode('utf-8')
                host_list: [str] = mapping.get(responses[i].rdata, [])
                if response_name not in host_list:
                    host_list.append(response_name)
                    mapping.update({responses[i].rdata: host_list})

    return mapping


def _gather_mud_info() -> (MUD, dict[str, str]):
    """
    Gathers necessary information for filling out the MUD system information, it will also check to see if the user has
    information about the existence of a controller that should be included in the policy.
    :return:
    """
    # TODO: Input validation should really be done here but is not fpr the sake of time. This information should be
    #  available
    version = int(input("Insert MUD version (int): "))
    mud_url = input("Mud URL (Include https): ")
    mfg_name = input("Manufacturer Name: ")
    is_supported = True if input(f"Is this device still supported by {mfg_name}? [y/N]: ") == 'y' else False    # Default No b/c this is intedned to be used by consumers. The default is fail-safe.
    system_info = input("Short description of device (<60 char): ")[:60]
    controller = True if input("Is there a local controller used with this device? [y/N]: ") == 'y' else False

    if controller:
        # If there is a controller we need to determine if it is only used by the target or multiple devices for when
        # the policy is made involving the controller.
        controller_type = MatchType.IS_CONTROLLER if input("Is this controller used only by the target device? [y/N]: ") == 'y' else MatchType.IS_MY_CONTROLLER
        controller = {input("Enter Controller IPv4 address: "): controller_type}
    else:
        controller = None

    # TODO: Additional support for IPv6 should be added
    mud = MUD(mud_version=version, mud_url=mud_url, is_supported=is_supported, mfg_name=mfg_name, system_info=system_info, ip_version=IPVersion.IPV4)

    return mud, controller


def _gather_IP_data(alt_dict, alt_ip, ip_layer) -> None:
    """
    Using a shallow copy of the alt_dict, we can update its value from a remote function
    :param alt_dict: The alternate dictionary tracking either the sources or destinations interacting with the target
    :param alt_ip: The alternate IP that is interacting with the target IP
    :param ip_layer: The IP layer of the packet being inspected
    :return: None
    """
    # Extract information relating to the alt host regarding IP, protocol, and port.
    if ip_layer.proto == "6":
        protocol = Protocol.TCP
        sport = ip_layer.sport
        dport = ip_layer.dport
    elif ip_layer.proto == "17":
        protocol = Protocol.UDP
        sport = ip_layer.sport
        dport = ip_layer.dport
    else:
        protocol = Protocol.ANY
        sport = 1
        dport = 1

    data: dict = {'protocol': protocol, 'sport': sport, 'dport': dport}

    # Check if the alt_ip was already seen
    if alt_ip not in alt_dict.keys():
        # If not, add a new entry
        alt_dict.update({alt_ip: [data]})

    else:
        # If we have an existing alt_ip, add the communication data
        data_list = alt_dict.get(alt_ip)
        if data not in data_list:
            # Verify we don't already have this data combination. If not, add it.
            data_list.append(data)
            alt_dict.update({alt_ip: data_list})


def generate_mud_rules(alt_dict: dict, ip_mapping: dict, controller: dict, mud: muddy.muddy.mud.MUD, direction: Direction) -> dict:
    """
    Generate the rules for the new device policy based on the data captured for each IP, the IP mapping, and the
    direction of the traffic.
    :param alt_dict: The data for each IP that was collected.
    :param ip_mapping: The mapping for IP to hostname.
    :param controller: The information related to the controller submitted by the user.
    :param mud: The MUD object being created.
    :param direction: Which direction the current data set is in relation to relative to the target device.
    :return: A dictionary of errors tied to the processing of each IP, used to ensure that the policy is not ruined
            because of unexpected activity.
    """

    # Catch errors in processing the packets to be displayed to the user without stopping.
    errors: dict = {}

    # Add the destinations to the device policy
    for alt in alt_dict.items():
        # If there is no mapping then this is likely a local IP and does not need a target_url
        targets: [str] = ip_mapping.get(alt[0], "blank")
        # Check if the IP in the alt item is a local address or not
        if ip_address(alt[0]) in ip_network(local_subnet):
            # Check if the local address is the controller or not
            if controller is not None and alt[0] in controller.keys():
                # Get the MatchType for the controller.
                match = controller.get(alt[0])
            else:
                match = MatchType.IS_LOCAL

        else:
            # If its not a local device it is assumed to be a cloud device.
            # TODO: MFG matching is not capable at this time as it would require the comparison of other device MUD
            #  files to determine if the target device is talking with other devices with the same manufacturer.
            match = MatchType.IS_CLOUD

            if targets == "blank":
                # Check if the target is defined, if not we need to skip it and move on to the next destination.
                alt_errors = errors.get(alt[0], None)
                if alt_errors is None:
                    # There are no errors recorded with this IP yet, add a new record for it.
                    alt_errors = ["MappingError: This IP did not have a mapped hostname and did not appear to be a local IP"]

                else:
                    # Append a mapping error to the dictionary of accrued errors for the destination
                    mapping_error = False
                    for error in alt_errors:
                        if "MappingError" in error:
                            # This alt already has a mapping error and does not need another
                            mapping_error = True
                    if not mapping_error:
                        # If mapping_error is False then we need to add a mapping error to this IP.
                        alt_errors.append("MappingError: This IP did not have a mapped hostname and did not appear to be a local IP")

                # Update the errors entry for this IP and stop processing the current destination
                errors.update({alt[0]: alt_errors})
                continue

        # Examine the data associated with the destination.
        for targ in targets:
            for data_dict in alt[1]:
                sport = None
                dport = None
                if direction is Direction.FROM_DEVICE:
                    dport = data_dict.get("dport")
                    # sport is assumed to be dynamic as the target device is the initiator here.
                    mud.add_rule(target_url=targ, match_type=match, direction_initiated=direction, protocol=data_dict.get("protocol"),
                                 remote_port=dport)
                else:
                    # If it's not FROM_DEVICE it must be TO_DEVICE
                    sport = data_dict.get("sport")
                    # dport is assumed to be dynamic as the target device is the receiver here.
                    mud.add_rule(target_url=targ, match_type=match, direction_initiated=direction, protocol=data_dict.get("protocol"), local_port=sport)

    return errors


def generate_mud_policies(packets: scapy.PacketList, target_device: str, local_subnet):
    """
    Generate the mud policies for the target device based on its network activity.
    :param packets: The packets that were captured in relation to the target device
    :param target_device: The IP address that is being examined
    :param local_subnet: The local subnet used to determine if there is local network communication
    :return: (dict) A python dictionary of the to and from device policies
    """
    ip_mapping = _generate_host_map(packets, target_device) # Map the ip addresses in the packets to the DNS responses seen.
    mud, controller = _gather_mud_info()
    if controller is not None:
        ip_mapping.update(controller)
    destinations: dict = {}     # This dictionary will be used to create the to_device policy
    sources: dict = {}  # This dictionary will be used to create the from_device policy
    for packet in packets:
        if packet.getlayer("IP") is None:
            # Verify that this is an IP packet, otherwise skip it
            continue
        # Identify source and destination IP addresses
        src_ip: str = packet.getlayer('IP').src
        dst_ip: str = packet.getlayer('IP').dst
        ip_layer = packet.getlayer('IP')

        # First check if the target device is the source
        # If the packet is not UDP or TCP, we do not check the ports
        if src_ip == target_device and (ip_layer.proto not in [6, 17] or int(ip_layer.dport) in range(0, 49152)):
            # Use a shallow copy of the destinations dictionary to update its entries
            _gather_IP_data(destinations, dst_ip, ip_layer)

        # Check if the target device is the destination
        # If the packet is not UDP or TCP, we do not check the ports
        elif dst_ip == target_device and (ip_layer.proto not in [6, 17] or int(ip_layer.dport) in range(0, 49152)):
            # Use a shallow copy of the sources dictionary to update its entries
            _gather_IP_data(sources, src_ip, ip_layer)


    # Pass the destinations, sources, and auxiliary data to generate the rules.
    print("Destinations Errors:\n" + str(
        generate_mud_rules(destinations, ip_mapping, controller, mud, Direction.FROM_DEVICE)))
    print("Sources Errors:\n" + str(
        generate_mud_rules(sources, ip_mapping, controller, mud, Direction.TO_DEVICE)))

    # Compile the rules.
    return mud.make_mud_5()

if __name__ == "__main__":
    # TODO: Input validation should be performed here as well as adding the capacity to pass in command line arguments
    #   as well as support for IPv6
    file_path: str = input("Enter file path (relative) to packet capture: ")
    target_device: str = input("Enter the IPv4 address for the device you would like to generate a MUD file for: ")
    local_subnet: str = input("Enter the local subnet in CIDR notation: ")
    packets: scapy.PacketList = scapy.rdpcap(file_path)

    mud_policies = generate_mud_policies(packets, target_device, local_subnet)
    policy_name = basename(file_path).split('.')[0] + ".json"
    try:
        with open(policy_name, 'w') as f:
            f.write(json.dumps(mud_policies))
    except:
        print(f"Failed to write policy to file: {policy_name}. Printing policy instead")
        print(mud_policies)
