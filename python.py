import boto3
import pandas
import hashlib
from collections import defaultdict
import ipaddress

aws_profiles = ["staging"]

aws_regions = {
    "staging" : ["us-east-1", "us-east-2"],
    "prod" : ["us-west-1", "us-west-2"]
}

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
            if "dev" not in sg_name:
#           if sg_id == "sg-0655c7f88b1da6fcd":
#               print(sg_rules)
                for rule in sg_rules:
                    if rule["IpProtocol"] == "-1":
                        from_port = "all"
                        to_port   = "all"
                        protocol  = ""
                        ip_ranges = [ ip_range["CidrIp"] for ip_range in rule['IpRanges']  if not (ip_range["CidrIp"].startswith("10") or ip_range["CidrIp"].startswith("192.168") or ip_range["CidrIp"].startswith("172"))]
                        source_sg_id = [ ip_range["GroupId"] for ip_range in rule['UserIdGroupPairs'] if ip_range["GroupId"]]
                        print(ip_ranges)
                        if len(ip_ranges) > 0:
                            ip_rules.append([aws_account_id, aws_region, sg_id, sg_name, ip_ranges, source_sg_id, from_port, protocol])
                    else:
                        from_port = rule["FromPort"]
                        to_port   = rule["ToPort"]
                        protocol  = rule["IpProtocol"]
                        ip_ranges = [ip_range["CidrIp"] for ip_range in rule['IpRanges'] if not (ip_range["CidrIp"].startswith("10") or ip_range["CidrIp"].startswith("192.168") or ip_range["CidrIp"].startswith("172"))]
                        source_sg_id = [ ip_range["GroupId"] for ip_range in rule['UserIdGroupPairs'] ]

                        if len(ip_ranges) > 0 and from_port not in [443]:
                            ip_rules.append([aws_account_id, aws_region, sg_id, sg_name, ip_ranges, source_sg_id, from_port, protocol])



#csv_columns = ["AWS Account ID", "AWS region", "Security Group ID", "Security Group Name", "IP rule","SG rule", "Port", "Protocol"]
#csv_file = pandas.DataFrame(ip_rules, columns=csv_columns).to_csv("all_sg_rules.csv", index=False, sep=';')
