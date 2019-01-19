import boto3
import argparse
import os
import subprocess
import configparser
import assume_role


class ec2_instance:
    def __init__(self, id, name, ip):
        self.id = id
        self.name = name
        self.ip = ip

    def __str__(self):
          return '%s [%s]' % (self.name, self.ip)

    def connect(self):
        subprocess.run(['aws', 'ssm', 'start-session', '--target', self.id])


def parse_arguments():
    description = "A CLI tool making that allows SSH access to EC2 instances through assumed roles."
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('account',
                        help='The AWS account id or shortened account alias defined in the ~/.aws/accounts file.',
                        default='security')
    parser.add_argument('role',
                        help='(Optional) The IAM role to assume on the trusting account. Will look in %s/.aws/config to find default or prompt if not passed.' % os.environ["HOME"],
                        nargs='?')
    parser.add_argument('instance',
                        help='(Optional) The instance name, id or private IP address. Will prompt if not passed.',
                        nargs='?')
    args = parser.parse_args()
    return args


def authenticate(account, role):

    _ar = assume_role.AssumeRole(account=account, role=role)

    try:
        _ar.run()
    except:
        print('\nPlease make sure you have correct account, role and token specified!\n')
        return False

    os.environ["AWS_REGION"] = _ar.region
    os.environ["AWS_PROFILE"] = _ar.profile
    os.environ["AWS_ACCOUNT_ROLE"] = _ar.role
    os.environ["AWS_ACCOUNT_ID"] = _ar.account_id
    os.environ["LOCAL_AWS_ACCOUNT_ALIAS"] = _ar.local_account_alias
    os.environ["AWS_IDENTITY_ACCOUNT_ACCESS_KEY_ID"] = _ar.aws_identity_account_session_access_key_id
    os.environ["AWS_IDENTITY_ACCOUNT_SECRET_ACCESS_KEY"] = _ar.aws_identity_account_session_secret_access_key
    os.environ["AWS_IDENTITY_ACCOUNT_SESSION_TOKEN"] = _ar.aws_identity_account_session_token
    os.environ["AWS_IDENTITY_ACCOUNT_SESSION_EXPIRATION"] = str(_ar.aws_identity_account_session_expiration)
    os.environ["AWS_ACCESS_KEY_ID"] = _ar.aws_trusting_account_session_access_key_id
    os.environ["AWS_SECRET_ACCESS_KEY"] = _ar.aws_trusting_account_session_secret_access_key
    os.environ["AWS_SESSION_TOKEN"] = _ar.aws_trusting_account_session_token
    os.environ["AWS_SESSION_EXPIRATION"] = str(_ar.aws_trusting_account_session_expiration)

    return True


def get_menu_options():
    ssm = boto3.client('ssm')

    managed_instances = ssm.describe_instance_information()

    if (not managed_instances['InstanceInformationList']):
        print("\nNo managed instances in %s to connect to!\n" % os.environ["LOCAL_AWS_ACCOUNT_ALIAS"])
        return {}, 0

    instance_options = {}
    option_number = 0

    for instance in managed_instances['InstanceInformationList']:
        option_number += 1
        instance_name = 'undefined'
        ec2 = boto3.resource('ec2')
        ec2instance = ec2.Instance(instance['InstanceId'])
        for tag in ec2instance.tags:
            if tag["Key"] == 'Name':
                instance_name = tag['Value']

        instance_options['%s' % option_number] = ec2_instance(instance['InstanceId'], instance_name,
                                                              instance['IPAddress'])

    exit_option = option_number + 1
    instance_options['%s' % exit_option] = 'Exit'
    return instance_options, exit_option


def find_instance(lookup):
    lookup = lookup.upper()

    ssm = boto3.client('ssm')

    managed_instances = ssm.describe_instance_information()

    if (not managed_instances['InstanceInformationList']):
        return None, False

    for instance in managed_instances['InstanceInformationList']:

        instance_name = 'undefined'
        ec2 = boto3.resource('ec2')
        ec2instance = ec2.Instance(instance['InstanceId'])
        for tag in ec2instance.tags:
            if tag["Key"] == 'Name':
                instance_name = tag['Value']

        if (lookup in instance_name.upper()) or (lookup in instance['InstanceId'].upper()) or (lookup in instance['IPAddress'].upper()):
            return ec2_instance(instance['InstanceId'], instance_name, instance['IPAddress']), True


def main(args=None):

    args = parse_arguments()
    role = args.role

    if role is None:
        try:
            config = configparser.ConfigParser()
            config.read('%s/.aws/config' % os.environ["HOME"])
            role = config['default']['role']
        except:
            print('Add a role to %s/.aws/config to use as default.' % os.environ["HOME"])
            role = input('Enter role: ')

    if not authenticate(args.account, role):
        exit()

    if args.instance is None:

        instance_options, exit_option = get_menu_options()
        if exit_option == 0:
            exit()

        exit_menu = False

        while not exit_menu:

            print('\nSelect instance in %s to connect to:' % os.environ["LOCAL_AWS_ACCOUNT_ALIAS"])

            for option, instance in instance_options.items():
                print('\t%s. %s' % (option, instance))

            selected_option = input('Option: ')

            if selected_option not in instance_options:
                print('\nInvalid option! Please select a number from the list.')
                continue

            if int(selected_option) < exit_option:
                instance_options[selected_option].connect()
            else:
                exit_menu = True

    else:
        ec2_instance, found = find_instance(args.instance)
        if found:
            ec2_instance.connect()
        else:
            print('\nCould not find instance %s in account %s.' % (args.instance, os.environ["LOCAL_AWS_ACCOUNT_ALIAS"]))

    exit()


if __name__ == '__main__':
    main()



