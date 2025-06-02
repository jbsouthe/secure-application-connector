#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Phantom App imports
import phantom.app as phantom
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

# Usage of the consts file is recommended
# from secureapplication_consts import *
import requests
import json
from bs4 import BeautifulSoup


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class SecureApplicationConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(SecureApplicationConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

        # Policy type to policyTypeId
        self._policy_type_map = {
            "Command execution": 1,
            "Filesystem access": 2,
            "Network or socket access": 3,
            "Database queries": 4,
            "Libraries loaded at runtime": 5,
            "Unhandled exceptions": 6,
            "Headers in http transactions": 7,
            "Cookies in outgoing http response": 8,
            "Class deserialization at runtime": 9
        }

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ), None
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace(u'{', '{{').replace(u'}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                url,
                # auth=(username, password),  # basic authentication
                verify=config.get('verify_server_cert', False),
                **kwargs
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))
                ), resp_json
            )

        # Handle 204 No Content
        if r.status_code == 204:
            return RetVal(action_result.set_status(phantom.APP_SUCCESS), {})

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = "/v1/libraries"
        headers = self._get_rest_api_headers(token=self._token, debug=self._debug)

        # make REST call - list all libaries
        ret_val, response = self._make_rest_call(
            endpoint,
            action_result,
            headers=headers,
            method="get"
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, "Test connectiviy successful")

    def _handle_create_new_policy(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        policy_type = param["type"]
        application_id = param["application_id"]
        tier_id = param["tier_id"]

        if application_id.lower() == "all":
            application_id = None

        if tier_id.lower() == "all":
            tier_id = None

        default_action = param["default_action"]
        if default_action.lower() == "ignore":
            default_action = "NONE"

        enable_policy = param["enable_policy"]

        policy_type_id = self._policy_type_map.get(policy_type)
        if not policy_type_id:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Unsupported policy type: {policy_type}"
            )

        status = "ON" if enable_policy.upper() == "YES" else "OFF"

        payload = {
            "action": default_action,
            "applicationId": application_id,
            "tierId": tier_id,
            "status": status,
            "policyTypeId": policy_type_id,
            "operativePolicyTypeId": policy_type_id
        }

        self.debug_print("Payload being sent:\n{}".format(json.dumps(payload, indent=2)))

        headers = self._get_rest_api_headers(token=self._token, debug=self._debug)

        # make rest call
        endpoint = "/v1/policyConfigs"

        ret_val, response = self._make_rest_call(
            endpoint,
            action_result,
            json=payload,
            headers=headers,
            method="post"
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_policy(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        policy_id = param['policy_id']

        # make rest call
        endpoint = f"/v1/policyConfigs/{policy_id}"

        headers = self._get_rest_api_headers(token=self._token, debug=self._debug)

        # REST CALL - delete
        ret_val, response = self._make_rest_call(
            endpoint,
            action_result,
            headers=headers,
            method="delete"
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data({"message": "Policy deleted successfully", "policy_id": policy_id})
        return action_result.set_status(phantom.APP_SUCCESS, "Policy deleted successfully.")

    def _handle_get_policy_by_id(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        policy_id = param['policy_id']
        if not policy_id:
            return action_result.set_status(phantom.APP_ERROR, "Missing policy_id")

        ret_val, response = self._get_policy_by_id(policy_id, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved policy")

    def _handle_list_policies(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = "/v1/policyConfigs"
        headers = self._get_rest_api_headers(token=self._token, debug=self._debug)

        limit = 10  # Adjust based on API default or max
        offset = 0
        all_policies = []
        total = None

        while True:
            self.debug_print("Starting the collection")
            url = f"{endpoint}?limit={limit}&offset={offset}"
            ret_val, response = self._make_rest_call(
                url,
                action_result,
                headers=headers,
                method="get"
            )

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            # Response will have total and items
            if isinstance(response, dict):
                items = response.get("items", [])
                total = response.get("total", total)

            all_policies.extend(items)

            if total is None or len(all_policies) >= total:
                break

            offset += limit

        for policy in all_policies:
            action_result.add_data(policy)

        action_result.set_summary({"total_policies": len(all_policies)})
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved policies")

    def _handle_update_policy(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        policy_id = param.get("policy_id")
        if not policy_id:
            return action_result.set_status(phantom.APP_ERROR, "Missing 'policy_id' parameter")

        enable_policy = param.get("enable_policy")
        if enable_policy:
            policy_status = "ON" if enable_policy.upper() == "YES" else "OFF"

        # Get existing policy
        status, existing_policy = self._get_policy_by_id(policy_id, action_result)
        if phantom.is_fail(status):
            return action_result.get_status()

        if not existing_policy:
            return action_result.set_status(phantom.APP_ERROR, "Failed to retrieve existing policy")

        updated_policy = existing_policy.copy()

        # Apply updates
        if "enable_policy" in param:
            updated_policy["status"] = policy_status

        if "default_action" in param:
            if param["default_action"].lower() == "ignore":
                updated_policy["action"] = "NONE"
            else:
                updated_policy["action"] = param["default_action"]

        if "tier_id" in param:
            updated_policy["tierId"] = param["tier_id"]
            if updated_policy["tierId"].lower() == 'all':
                updated_policy["tierId"] = None

        if "application_id" in param:
            updated_policy["applicationId"] = param["application_id"]
            if updated_policy["applicationId"].lower() == 'all':
                updated_policy["applicationId"] = None

        # rest call - update policy
        endpoint = f"/v1/policyConfigs/{policy_id}"

        headers = self._get_rest_api_headers(token=self._token, debug=self._debug)

        self.debug_print("Sending payload: {}".format(json.dumps(updated_policy, indent=2)))
        self.debug_print("Params received:\n{}".format(json.dumps(param, indent=2)))

        ret_val, response = self._make_rest_call(
            endpoint,
            action_result,
            json=updated_policy,
            headers=headers,
            method="patch"
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, "Policy updated successfully")

    def _handle_add_a_rule_to_command_execution_policy(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        policyType = self._policy_type_map.get("Command execution")
        status = self._send_updated_policy_with_rule_change(param, action_result, True, False, policyType)
        if phantom.is_success(status):
            return action_result.set_status(status, "Rule added to Command execution policy successfully")
        return status

    def _handle_add_a_rule_to_filesystem_access_policy(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        policyType = self._policy_type_map.get("Filesystem access")
        status = self._send_updated_policy_with_rule_change(param, action_result, True, False, policyType)
        if phantom.is_success(status):
            return action_result.set_status(status, "Rule added to filesystem access policy successfully")
        return status

    def _handle_add_a_rule_to_network_or_socket_access_policy(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        policyType = self._policy_type_map.get("Network or socket access")
        status = self._send_updated_policy_with_rule_change(param, action_result, True, False, policyType)
        if phantom.is_success(status):
            return action_result.set_status(status, "Rule added to Network or socket access policy successfully")
        return status

    def _handle_delete_a_rule_from_command_execution_policy(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        status = self._send_updated_policy_with_rule_change(param, action_result, False, True,
                                                            self._policy_type_map.get("Command execution"))
        if phantom.is_success(status):
            return action_result.set_status(status, "Rule deleted from Command execution policy successfully")
        return status

    def _handle_delete_a_rule_from_filesystem_access_policy(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        status = self._send_updated_policy_with_rule_change(param, action_result, False, True,
                                                            self._policy_type_map.get("Filesystem access"))
        if phantom.is_success(status):
            return action_result.set_status(status, "Rule deleted from filesystem access policy successfully")
        return status

    def _handle_delete_a_rule_from_network_or_socket_access_policy(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        status = self._send_updated_policy_with_rule_change(param, action_result, False, True,
                                                            self._policy_type_map.get("Network or socket access"))
        if phantom.is_success(status):
            return action_result.set_status(status, "Rule deleted from Network or socket access policy successfully")
        return status

    def _handle_list_all_rules(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        policy_id = param.get("policy_id")

        if not policy_id:
            return action_result.set_status(phantom.APP_ERROR, "Missing policy ID")

        # Get existing policy
        status, existing_policy = self._get_policy_by_id(policy_id, action_result)
        if phantom.is_fail(status):
            return action_result.get_status()

        if not existing_policy:
            return action_result.set_status(phantom.APP_ERROR, "Failed to retrieve existing policy")

        # Get policy type
        policy_type = existing_policy.get("policyTypeId")
        # Parse config details
        # Parse configDetails
        config_details = self._decode_config_details(existing_policy.get("configDetails"))
        self.debug_print("Decoded config_details:\n{}".format(json.dumps(config_details, indent=2)))

        rules = config_details.get("permission", {}).get("filter", [])

        if not rules:
            return action_result.set_status(phantom.APP_SUCCESS, "No rules found in policy")

        # Reverse mapping from matchType to operation string
        reverse_operation_map = {
            "EQUALS": "equals",
            "STARTSWITH": "starts with",
            "SUBSTRING": "contains",
            "REGEX": "matches regex"
        }

        for rule in rules:
            if not ("stackMatch" in rule or "targetMatch" in rule):
                continue
            entry = {}

            action = rule.get("action", "").upper()
            entry["action"] = "ignore" if action == "NONE" else action.lower()

            match = None
            if "stackMatch" in rule:
                entry["type"] = "stack trace"
                match = rule["stackMatch"]
            elif "targetMatch" in rule:
                if self._policy_type_map.get("Command execution") == policy_type:
                    entry["type"] = "process"
                elif self._policy_type_map.get("Filesystem access") == policy_type:
                    entry["type"] = "filename"
                elif self._policy_type_map.get("Network or socket access") == policy_type:
                    entry["type"] = "hostname"
                match = rule["targetMatch"]

            if match:
                entry["operation"] = reverse_operation_map.get(match.get("matchType"), "unknown")
                entry["value"] = match.get("value")

            entry["name"] = rule.get("name", "")
            action_result.add_data(entry)

        summary = {"total_rules": len(rules)}
        action_result.update_summary(summary)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved rules from policy")

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'create_new_policy':
            ret_val = self._handle_create_new_policy(param)

        if action_id == 'delete_policy':
            ret_val = self._handle_delete_policy(param)

        if action_id == 'get_policy_by_id':
            ret_val = self._handle_get_policy_by_id(param)

        if action_id == 'list_policies':
            ret_val = self._handle_list_policies(param)

        if action_id == 'update_policy':
            ret_val = self._handle_update_policy(param)

        if action_id == 'add_a_rule_to_command_execution_policy':
            ret_val = self._handle_add_a_rule_to_command_execution_policy(param)

        if action_id == 'add_a_rule_to_filesystem_access_policy':
            ret_val = self._handle_add_a_rule_to_filesystem_access_policy(param)

        if action_id == 'add_a_rule_to_network_or_socket_access_policy':
            ret_val = self._handle_add_a_rule_to_network_or_socket_access_policy(param)

        if action_id == 'delete_a_rule_from_command_execution_policy':
            ret_val = self._handle_delete_a_rule_from_command_execution_policy(param)

        if action_id == 'delete_a_rule_from_filesystem_access_policy':
            ret_val = self._handle_delete_a_rule_from_filesystem_access_policy(param)

        if action_id == 'delete_a_rule_from_network_or_socket_access_policy':
            ret_val = self._handle_delete_a_rule_from_network_or_socket_access_policy(param)

        if action_id == 'list_all_rules':
            ret_val = self._handle_list_all_rules(param)

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()
        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = config.get('base_url')
        self._account_id = config.get('account_id')
        self._api_key = config.get('api_key')
        self._api_key_secret = config.get('api_key_secret')
        self._token = None

        # debug turned on to connect to CI environment
        self._debug = False

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    # Helper function to get policy by ID
    # Disabling it till this api is available in fusion
    '''
    def _get_policy_by_id(self, policy_id, action_result):

        endpoint = f"/v1/policyConfigs/{policy_id}"

        headers = self._get_rest_api_headers(token=self._token, debug=self._debug)

        ret_val, response = self._make_rest_call(
            endpoint,
            action_result,
            headers=headers,
            method="get"
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, response
    '''

    def _get_policy_by_id(self, policy_id, action_result):
        return self._get_policy_by_id_from_list(policy_id, action_result)

    def _get_policy_by_id_from_list(self, policy_id, action_result):
        endpoint = f"/v1/policyConfigs"

        headers = self._get_rest_api_headers(token=self._token, debug=self._debug)

        ret_val, response = self._make_rest_call(
            endpoint,
            action_result,
            headers=headers,
            method="get"
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        policies = response.get("items")

        if not isinstance(policies, list):
            return action_result.set_status(
                phantom.APP_ERROR, "Unexpected response format while retrieving policies"
            ), None

        for policy in policies:
            if policy.get("id") == policy_id:
                return phantom.APP_SUCCESS, policy

        return action_result.set_status(phantom.APP_ERROR,
                                        f"Policy with ID {policy_id} not found"), None

    # Helper function to decode configDetails from policy into a dict
    def _decode_config_details(self, config_details_str):
        if config_details_str:
            return json.loads(config_details_str)
        return {"permission": {"filter": []}}

    # Helper functiom to add a rule to configDetails
    def _append_rule_to_config(self, config_dict, rule):
        config_dict.setdefault("permission", {}).setdefault("filter", []).append(rule)
        return config_dict

    # Helper function to delete a rule from configDetails
    # {\"permission\":{\"filter\":[{\"action\":\"DETECT\",\"targetMatch\":      {\"matchType\":\"EQUALS\",\"value\":\"aaaaaaa.exe\"},\"name\":\"detect aaaaaaa.exe\"}]}}
    def _delete_rule_from_config(self, config_dict, rule_to_delete):

        self.debug_print("[_delete_rule_from_config] called")
        self.debug_print("rules:\n{}".format(json.dumps(config_dict, indent=2)))

        filters = config_dict.get("permission", {}).get("filter", [])
        self.debug_print("filters:\n{}".format(json.dumps(filters, indent=2)))
        updated_filters = []
        rule_found = False

        if "targetMatch" in rule_to_delete:
            match_field = "targetMatch"
        else:
            match_field = "stackMatch"

        # Build a new list excluding the rule(s) to be deleted
        for rule in filters:
            self.debug_print("Comparing rule:", rule)
            self.debug_print("With rule_to_delete:", rule_to_delete)

            if match_field not in rule:
                updated_filters.append(rule)
                continue

            rule_filter = rule.get(match_field, {})
            delete_rule_filter = rule_to_delete.get(match_field, {})

            if (
                    rule.get("action") == rule_to_delete.get("action") and
                    rule_filter.get("matchType") == delete_rule_filter.get("matchType") and
                    rule_filter.get("value") == delete_rule_filter.get("value")
            ):
                rule_found = True
                self.debug_print("Rule matched and will be deleted.")
                continue

            updated_filters.append(rule)

        config_dict.setdefault("permission", {})["filter"] = updated_filters
        return config_dict, rule_found

    # Helper function to encode the configDetails dict to json
    def _encode_config_details(self, config_dict):
        return json.dumps(config_dict)

    # Helper function to  add/delete rule
    def _send_updated_policy_with_rule_change(self, param, action_result, add, delete, policyType):

        policy_id = param.get("policy_id")
        rule_action = param.get("action")
        rule_value = param.get("value")
        rule_operation = param.get("operation")
        rule_type = param.get("type")

        if not all([policy_id, rule_action, rule_value, rule_operation, rule_type]):
            return action_result.set_status(phantom.APP_ERROR, "Missing one or more required parameters")

        # Get existing policy
        status, existing_policy = self._get_policy_by_id(policy_id, action_result)
        if phantom.is_fail(status):
            return action_result.get_status()

        if not existing_policy:
            return action_result.set_status(phantom.APP_ERROR, "Failed to retrieve existing policy")

        if existing_policy["policyTypeId"] != policyType:
            return action_result.set_status(phantom.APP_ERROR, "Incorrect action chosen for the policy type")

        # Parse configDetails
        config_details = self._decode_config_details(existing_policy.get("configDetails"))

        # Build the new rule
        operation_map = {
            "equals": "EQUALS",
            "contains": "SUBSTRING",
            "matches regex": "REGEX",
            "starts with": "STARTSWITH"
        }

        match_type = operation_map.get(rule_operation.lower())
        if match_type is None:
            raise ValueError(f"Unsupported match operation: {rule_operation}")

        match_field = None
        if rule_type == "stack trace":
            match_field = "stackMatch"
        elif rule_type == "filename":
            match_field = "targetMatch"
        elif rule_type == "hostname":
            match_field = "targetMatch"
        elif rule_type == "process":
            match_field = "targetMatch"
        else:
            return action_result.set_status(phantom.APP_ERROR, f"Unsupported rule type: {rule_type}")

        if rule_action.lower() == "ignore":
            action = "NONE"
        else:
            action = rule_action.upper()

        rule = {
            "action": action,
            match_field: {
                "matchType": match_type,
                "value": rule_value
            },
            "name": f"{rule_action.lower()} {rule_value}"
        }

        if add:
            # Add rule to the json dict retrieved for configDetails
            updated_config = self._append_rule_to_config(config_details, rule)

        if delete:
            # Delete a rule from the json dict retrieved for configDetails
            updated_config, rule_found = self._delete_rule_from_config(config_details, rule)
            if not rule_found:
                action_result.set_status(phantom.APP_ERROR, "Specified rule not found in config")
                return action_result.get_status()

        # Encode configDetails dict into json
        existing_policy["configDetails"] = self._encode_config_details(updated_config)

        # Patch the updated policy
        endpoint = f"/v1/policyConfigs/{policy_id}"
        headers = self._get_rest_api_headers(token=self._token, debug=self._debug)

        self.debug_print("Sending updated policy:\n{}".format(json.dumps(existing_policy, indent=2)))

        ret_val, response = self._make_rest_call(
            endpoint,
            action_result,
            json=existing_policy,
            headers=headers,
            method="patch"
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        return phantom.APP_SUCCESS

    # Helper function to populate headers for debug in internal CI environment
    def _get_authentication_token(self, url, account, api_key, api_secret):
        if self._token is None:
            response = requests.post(f"{url}/controller/api/oauth/access_token",
                                     headers={
                                         'Content-Type': 'application/x-www-form-urlencoded'
                                     },
                                     data={
                                         "grant_type": "client_credentials",
                                         "client_id": f"{api_key}@{account}",
                                         "client_secret": api_secret
                                     },
                                     auth=(api_key, api_secret),
                                     verify=False,
                                     timeout=15)
            if response.status_code >= 300:
                raise Exception(f"Authentication token failed, check permissions for this api key {api_key}")
            r_json = self._handle_response(response)

            # Get token and calculate its expiration time
            self._token = r_json['access_token']
        return self._token

    def _get_rest_api_headers(self, token=None, debug=False):
        if token is None:
            token = self._get_authentication_token(self._base_url, self._account_id, self._api_key, self._api_secret)

        if debug:
            return {
                "X-Argento-User": "Argento-UI",
                "X-Argento-Roles": "superuser",
                "X-Argento-Tenant": token,
                "X-Appd-Permissions": "CONFIG_ARGENTO",
                "Content-Type": "application/json"
            }
        else:
            return {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = SecureApplicationConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SecureApplicationConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
