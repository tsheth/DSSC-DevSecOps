import deepsecurity as api
from deepsecurity.rest import ApiException as api_exception
import sys
import getopt

app_control_status = ''
check_status = ''
search_name = ''
ds_api_key = ''
ds_url = ''
output = ''

def init(argv):
    try:
        opts, args = getopt.getopt(argv, "h:v", ["app_control_status=", "search_name=", "ds_api_key=", "ds_url=", "output="])

    except getopt.GetoptError as error:
        print('Error Not enough Arguments')
        print(str(error))
        sys.exit()

    for opt, arg in opts:
        if opt == '-h':
            print('scans.py -i <inputfile> -o <outputfile>')
        elif opt in ("--app_control_status"):
            global app_control_status
            app_control_status = arg

        elif opt in ("--search_name"):
            global search_name
            search_name = arg

        elif opt in ("--ds_api_key"):
            global ds_api_key
            ds_api_key = arg

        elif opt in ("--ds_url"):
            global ds_url
            ds_url = arg

        elif opt in ("--output"):
            global output
            output = arg

def tune_app_control(api, configuration, api_version, api_exception):

    try:
        # Create a PoliciesApi object
        policies_api = api.PoliciesApi(api.ApiClient(configuration))

        # List policies using version v1 of the API
        policies_list = policies_api.list_policies(api_version)

        # View the list of policies
        # return policies_list

    except api_exception as e:
        return "Exception: " + str(e)

    # Search computer in deep security dashboard
    search_criteria = api.SearchCriteria()
    search_criteria.field_name = "displayName"
    search_criteria.string_value = '%' + search_name + '%'
    search_criteria.string_test = "equal"
    search_criteria.string_wildcards = True

    # Create search filter to find computer
    search_filter = api.SearchFilter(None, [search_criteria])

    # Create a ComputerApi object
    computer_api = api.ComputersApi(api.ApiClient(configuration))

    try:
        # Perform the search
        computer_details = computer_api.search_computers(api_version, search_filter=search_filter)
        ec2_instance_id = []
        ds_ids = []
        for ec2_details in computer_details.computers:
            ec2_instance_id.append(ec2_details.ec2_virtual_machine_summary.instance_id)
            ds_ids.append(ec2_details.id)

        # Set the Reconnaissance Scan value
        setting_value = api.SettingValue()
        setting_value.value = "true"

        # Add the SettingValue to a ComputerSettings object
        computer_settings = api.ComputerSettings()
        computer_settings.firewall_setting_reconnaissance_enabled = setting_value

        app_controll_settings = api.ApplicationControlComputerExtension()
        app_controll_settings.state = app_control_status

        # Add the ComputerSettings object to a Computer object
        computer = api.Computer()
        computer.computer_settings = computer_settings
        computer.application_control = app_controll_settings

        for ds_id in ds_ids:
            computer_api.modify_computer(ds_id, computer, api_version, overrides=True)

        return ec2_instance_id

    except api_exception as e:
        return "Exception: " + str(e)


if __name__ == '__main__':
    # Add Deep Security Manager host information to the api client configuration
    init(sys.argv[1:])
    configuration = api.Configuration()
    configuration.host = "https://" + ds_url + "/api"

    print(configuration.host)
    configuration.verify_ssl = True

    # Authentication
    configuration.api_key['api-secret-key'] = ds_api_key

    # Version
    api_version = 'v1'
    tune_app_control(api, configuration, api_version, api_exception)