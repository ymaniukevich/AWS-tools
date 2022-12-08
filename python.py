import boto3
import pandas
import hashlib
from collections import defaultdict
from IPy import IP

aws_profiles = ["staging"]
aws_regions = {
    "staging" : ['us-east-2'],
    "prod" : ['ap-south-1', 'eu-north-1', 'eu-west-3', 'eu-west-2', 'eu-west-1', 'ap-northeast-3', 'ap-northeast-2', 'ap-northeast-1', 'ca-central-1', 'sa-east-1', 'ap-east-1', 'ap-southeast-1', 'ap-southeast-2', 'eu-central-1', 'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2']
}

ignore_ports    = [443]
output_filename = "stg_env_public_sg_rules.xlsx"

def is_public_ip(ip):
    ip = list(map(int, ip.strip().split('.')[:2]))
    if ip[0] == 10: return False
    if ip[0] == 172 and ip[1] in range(16, 32): return False
    if ip[0] == 192 and ip[1] == 168: return False
    return True

def rule_format(ip_rule):
    try:
        if ip_rule.get("CidrIp"):
            return "{0} ({1})".format(ip_rule["CidrIp"], ip_rule["Description"])
        elif ip_rule.get("GroupId"):
            return "{0} ({1})".format(ip_rule["GroupId"], ip_rule["Description"])
    except KeyError:
        if ip_rule.get("CidrIp"):
            return ip_rule["CidrIp"]
        elif ip_rule.get("GroupId"):
            return ip_rule["GroupId"]

def find_unused_security_group(ec2_client, sg_id, unused_count, used_count):
    checking = ec2_client.describe_network_interfaces(
        Filters=[
            {
                'Name': 'group-id',
                'Values': [ sg_id ]
            },
        ],
    )

    if len(checking['NetworkInterfaces']) == 0:
        unused_count.add(sg_id)
        return "UNUSED"
    else:
        used_count.add(sg_id)
        return "USED"


sg_statistics = {
    "Total sg" : set(),
    "Unused sg" : set(),
    "Used sg": set(),
    "Used sg with public ips": set()
}

with pandas.ExcelWriter(output_filename) as writer:
    for aws_profile in aws_profiles:
        ip_rules = []
        for aws_region in aws_regions[aws_profile]:
            session = boto3.Session(profile_name=aws_profile)
            aws_account_id = session.client("sts").get_caller_identity()["Account"]
            ec2 = session.client('ec2',region_name=aws_region)

            security_groups = ec2.describe_security_groups()['SecurityGroups']
            for security_group in security_groups:
                sg_name = security_group["GroupName"]
                sg_id = security_group["GroupId"]
                sg_rules = security_group["IpPermissions"]

                state = find_unused_security_group(ec2, sg_id, sg_statistics["Unused sg"], sg_statistics["Used sg"])

                sg_statistics["Total sg"].add(sg_id)

                for rule in sg_rules:
                    if rule["IpProtocol"] == "-1":
                        from_port = "all"
                        to_port   = "all"
                        protocol  = ""

                        ip_ranges = [ rule_format(ip_range) for ip_range in rule['IpRanges']  if is_public_ip(ip_range["CidrIp"]) ]
                        source_sg_id = [ rule_format(ip_range) for ip_range in rule['UserIdGroupPairs'] if ip_range["GroupId"]]
                        if len(ip_ranges) > 0:
                            ip_rules.append([aws_account_id, aws_region, sg_id, sg_name, state, ip_ranges, from_port, to_port, protocol])
                    else:
                        from_port = rule["FromPort"]
                        to_port   = rule["ToPort"]
                        protocol  = rule["IpProtocol"]
                        ip_ranges = [ rule_format(ip_range) for ip_range in rule['IpRanges']  if is_public_ip(ip_range["CidrIp"]) ]
                        source_sg_id = [ rule_format(ip_range) for ip_range in rule['UserIdGroupPairs'] ]
                        if len(ip_ranges) > 0 and from_port not in ignore_ports:
                            ip_rules.append([aws_account_id, aws_region, sg_id, sg_name, state, ip_ranges, from_port, to_port, protocol])

    csv_columns = ["AWS Account ID", "AWS region", "Security Group ID", "Security Group Name", "State", "IP rule", "From port", "To port", "Protocol"]
    csv_file = pandas.DataFrame(ip_rules, columns=csv_columns).to_excel(writer, sheet_name=aws_profile, index=False)

print("Total security group: {0}".format(len(sg_statistics["Total sg"])))
print("Unused security group: {0}".format(len(sg_statistics["Unused sg"])))
print("Used security group: {0}".format(len(sg_statistics["Used sg"])))