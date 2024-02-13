#!/usr/bin/env python3
"""OneTrust Cumulus operations

List defined domains and manage assigning OT Organization domains and
cookies to a group domain for the org.

Requires the following 3rd-party libraries
using pip3:
    * dotenv
    * requests
"""
# Check for and import libraries
try:
    import textwrap
    from copy import deepcopy
    import argparse
    import re
    import sys
    import os
    import csv
    import json
    from time import time
    from time import sleep
    from datetime import datetime
    import locale
    from datetime import timedelta
    import logging
    from typing import List, Dict, Callable

    import dotenv
    import requests
except ImportError as i:
    print(
        f"python library {i.name} is required, please install the necessary"
        "package."
    )
    sys.exit(1)

# Defaults
API_KEY = None
API_DOMAIN = "app.onetrust.com"

# Use the system's default locale
locale.setlocale(locale.LC_TIME, '')

# Initialize logger. Errors are sent to stderr, all others to stdout
LOG = logging.getLogger()
LOG.setLevel(logging.WARNING)
formatter = logging.Formatter(
    "%(levelname)s: %(message)s",
)
class levelFilter:
    """Filter log messages by level"""
    def __init__(self, min_level=0, max_level=99):
        self.min_level = min_level
        self.max_level = max_level
    def filter(self, record):
        return self.min_level <= record.levelno <= self.max_level
stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.DEBUG)
stdout_handler.addFilter(levelFilter(
    min_level=0,
    max_level=logging.WARNING
))
stdout_handler.setFormatter(formatter)
stderr_handler = logging.StreamHandler(sys.stderr)
stderr_handler.setLevel(logging.ERROR)
stderr_handler.addFilter(levelFilter(
    min_level=logging.ERROR,
    max_level=99
))
stderr_handler.setFormatter(formatter)
LOG.addHandler(stdout_handler)
LOG.addHandler(stderr_handler)

#
# Data wrappers
#

class CommandWrapper:
    """Definition for API commands"""

    commit_notice = textwrap.dedent(
        """\
        This command updates domain configurations. The domain's script must
        be MANUALLY republished from the OneTrust GUI before changes will
        become active. When updating a group, you must republish the group
        domain's script.\
        """
    ).replace("\n", " ")

    commit_help = textwrap.dedent(
        """\
        NOTE: This command requires a --commit flag in order to make changes
        in the OneTrust system.\
        """
    ).replace("\n", " ")

    supported_keys = {
        "name": (str, None),
        "help": (str, None),
        "epilog": (str, None),
        "subparser": (Callable, None),
        "commits": (bool, False),
        "run": (Callable, None),
    }

    def __init__(self, **kwargs):
        for key, (expected_type, default_value) in \
            CommandWrapper.supported_keys.items():
            value = kwargs.get(key)
            if value is not None and isinstance(value, expected_type):
                setattr(self, "_" + key, value)
            else:
                setattr(self, "_" + key, default_value)

    def __getattr__(self, name):
        internal_name = "_" + name
        if name in CommandWrapper.supported_keys:
            if not object.__getattribute__(self, internal_name):
                return CommandWrapper.supported_keys[name][1]
            if isinstance(CommandWrapper.supported_keys[name], str):
                return getattr(self, internal_name) % self.get_string_properties()
            else:
                return getattr(self, internal_name)
        # if name in CommandWrapper.supported_keys \
        #     and object.__getattribute__(self, internal_name):
        #     if isinstance(CommandWrapper.supported_keys[name], str):
        #         return getattr(self, internal_name) % self.get_string_properties()
        #     else:
        #         return getattr(self, internal_name)
        return object.__getattribute__(self, name)

    def add_parser(
        self,
        subparser: argparse._SubParsersAction,
        parents=[],
        arguments=[],
        **kwargs
    ) -> argparse.ArgumentParser:
        defaults = {
            "help": self.help,
            "epilog": self.epilog or (self.commit_help if self.commits else ""),
            "description": self.help,
            "add_help": False,
            "parents": parents,
            "formatter_class": ArgparseSmartHelpFormatter,
        }
        merged_options = defaults.copy()
        merged_options.update(kwargs)
        self.subparser_instance: argparse.ArgumentParser = \
            subparser.add_parser(
                self.name,
                **merged_options
            )
        if len(arguments) > 0:
            self.process_arguments(self.subparser_instance, arguments)
        return self.subparser_instance

    def process_arguments(self, parser, arguments):
        for a in arguments:
            if a.get("group"):
                self.add_argument_group(parser, a)
            else:
                self.add_argument(parser, **a)

    def add_argument(
            self,
            parser: argparse.ArgumentParser | argparse._ArgumentGroup,
            **kwargs
        ):
        arg = kwargs.get("arg")
        if not arg:
            raise ValueError(
                "add_argument requires an 'arg' argument"
            )
        del kwargs["arg"]
        parser.add_argument(*arg, **kwargs)

    def add_argument_group(
            self,
            parser: argparse.ArgumentParser,
            group: dict
        ):
        type = group.get("group", "argument_group")
        method_name = "add_" + type
        args = group.get("args", None)
        if not args:
            raise ValueError("Argument groups must have an args key")

        if hasattr(parser, method_name):
            method = getattr(parser, method_name)
            method_args = group.get("group_args", []).copy()

            if type == "mutually_exclusive_group":
                """Create a parent group for mutually exclusive groups
                so they may have a title and description"""
                parent_group_args = {}
                if "title" in method_args:
                    parent_group_args["title"] = method_args["title"]
                    del method_args["title"]
                if "description" in method_args:
                    parent_group_args["description"] = \
                        method_args["description"]
                    del method_args["description"]
                parent_group = parser.add_argument_group(**parent_group_args)
                method = getattr(parent_group, method_name)

            arg_group = method(**method_args)

            for a in args:
                self.add_argument(arg_group, **a)

    def get_string_properties(self):
        command_strings = {}
        for k, (ktype, default_value) in CommandWrapper.supported_keys:
            if isinstance(ktype, str):
                internal_name = "_" + k
                command_strings[internal_name] = \
                    getattr(self, internal_name)
        return command_strings

class DomainData:
    """Data container for domains

    Parameters
    -------------
        name: str
            The domain name.
        uuid: str
            The OneTrust UUID for the domain.
        orgUUID: str
            The OneTrust org UUID the domain resides within.
    """
    def __init__(self, name: str = None, uuid: str = None, orgUUID: str = None):
        if uuid != None and not Helper.is_valid_uuid(uuid):
            raise Exception("Invalid domain UUID provided.")
        if orgUUID != None and not Helper.is_valid_uuid(orgUUID):
            raise Exception("Invalid org UUID provided.")
        self.name = name
        self.uuid = uuid
        self.orgUUID = orgUUID

    def __json__(self):
        return {key: value for key, value in vars(self).items()}


class DomainCookieData:
    """Data container for a single domain cookie.

    Be aware that OneTrust cookies have two separate UUIDs, see
    the cookieUUID and domainCookieUUID instance attributes.

    Args
    --------------
        cookieName: str
            Required. The name of the cookie.
        cookieUUID: str
            Required. OneTrust's "cookieId". Refers to the cookie's entire
            configuration. OneTrust possibly uses this for deduplication.
        thirdParty: bool
            If the cookie is third-party, set to True. For first-party
            cookies, set to False. Defaults is False.
        cookieCategoryID:
            Required. The OneTrust category ID of the cookie's DOMAIN
            instance, e.g. "C0001".
        domainCookieUUID:
            Required. The cookie's DOMAIN instance UUID ("domainCookieId")
        domainName:
            Required. The domain name of the cookie's DOMAIN instance.
    """
    def __init__(
            self,
            cookieName: str = None,
            cookieUUID: str = None,
            thirdParty: bool = False,
            cookieCategoryID: str = None,
            domainCookieUUID: str = None,
            domainName: str = None,
        ):
        if any(v is None for v in (
                cookieName,
                cookieUUID,
                cookieCategoryID,
                domainCookieUUID,
                domainName,
            )):
            raise Exception(
                "Required DomainCookie Data parameter not set."
            )
        self.cookieName = cookieName
        self.cookieUUID = cookieUUID
        self.thirdParty = thirdParty
        self.cookieCategoryID = cookieCategoryID
        self.domainCookieUUID = domainCookieUUID
        self.domainName = domainName

    def __json__(self):
        return {key: value for key, value in vars(self).items()}

#
# Custom exceptions
#

class GroupNotFoundException(Exception):
    """Raised by commands when a group UUID is specified, but that group
    does not exist"""

    def __init__(self, message="Group UUID not found."):
        self.message = message
        super().__init__(message)

class BadRequestError(Exception):
    """Raised by commands that make a bad request to the OT API"""

    def __init__(self, message="Invalid API request, check your inputs."):
        self.message = message
        super().__init__(message)

class JsonTruncatedEncoder(json.JSONEncoder):
    """Returns truncated JSON for debug output"""
    def default(self, obj):
        if isinstance(obj, list) and len(obj) > 50:
            trunc = obj[:10]
            trunc += "..."
            return trunc
        return json.JSONEncoder.default(self, obj)

#
# Helper functions
#
class Helper:
    """Helper functions"""

    def wraptext(txt, width=79, subsequent_indent=''):
        """Helper to wrap and dedent text"""
        return textwrap.fill(
            textwrap.dedent(re.sub(r'\s+', ' ', txt)),
            width=width,
            subsequent_indent=subsequent_indent
        )

    def is_domain_name(domain):
        """Check if a string is a valid domain name"""
        domainPattern = re.compile(
            r'^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|'
            r'([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|'
            r'([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\.'
            r'([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$'
        )
        return bool(domainPattern.match(domain))

    def is_valid_uuid(s):
        """Check if a given value is a valid UUID"""
        uuid_pattern = re.compile(
            r'^[0-9a-fA-F]{8}-'
            r'[0-9a-fA-F]{4}-'
            r'[1-5][0-9a-fA-F]{3}-'
            r'[89abAB][0-9a-fA-F]{3}-'
            r'[0-9a-fA-F]{12}$'
        )
        return bool(uuid_pattern.match(s))

    def convert_to_array(value) -> list:
        """Converts a given value to an array"""
        return value.split() if isinstance(value, str) \
            else (value if isinstance(value, list) else [value])

    def chunk_array(arr: list, size: int):
        """Split a list into [size] chunks"""
        return [arr[i:i + size] for i in range(0, len(arr), size)]

    def generate_headers(headers: dict = {}, authorized=True):
        """Generate required header for API call"""
        global API_KEY
        if headers is None:
            headers = {}
        if not "content-type" in headers:
            headers["content-type"] = "application/json"
        if authorized is True and not "Authorization" in headers:
            headers["Authorization"] = f"Bearer {API_KEY}"
        return headers


    def make_ratelimited_request(
            method="post",
            url: str = '',
            params: dict = None,
            data: dict = None,
            headers: dict = None,
            tries: int = 1,
        ) -> requests.Response:
        """Make an API request with handling for 429 rate-limited responses"""

        if tries > 10:
            raise ConnectionError("Could not complete request in %d tries" % tries)

        debug_headers = headers.copy()
        if "Authorization" in debug_headers:
            debug_headers["Authorization"] = "Bearer *MASKED*"

        LOG.debug(
            "%(method)s %(url)s\n"
            "Headers: %(debug_headers)r\n"
            "Params: %(params)r\n"
            "Tries: %(tries)d\n"
            "Data: %(data)r" % {
                "method": str(method).upper(),
                "url": url,
                "debug_headers": debug_headers,
                "params": params,
                "tries": tries,
                "data": data
            }
        )

        response = getattr(requests, method)(
            url=url,
            params=params,
            json=data,
            headers=headers
        )
        if response.status_code == 401:
            raise PermissionError(
                "OneTrust API returned error 401: Unauthorized. "
                "Check that your API key is valid."
            )

        if response.status_code in [429, 502]:
            retry_after = int(response.headers.get('Retry-After', 5)) + 1
            if not retry_after:
                retry_after = 5

            if response.status_code == 429:
                LOG.warning(
                    "Request has been rate limited, retrying in %f seconds..." %
                    retry_after
                )
            else:
                LOG.warning(
                    "Possible network instability detected, retrying in %f seconds..." %
                    retry_after
                )

            sleep(retry_after)

            return Helper.make_ratelimited_request(
                method=method,
                url=url,
                params=params,
                data=data,
                headers=headers,
                tries=tries + 1
            )
        else:
            return response

    def fetch_all_pages(
            url: str = '',
            method: str = 'get',
            headers: dict | None = None,
            params: dict | None = None,
            data: dict | None = None
        ) -> list:
        """Fetch all pages from a paginated OT API query"""
        headers = Helper.generate_headers(headers)

        if params is None:
            params = {}
        if not "size" in params:
            params["size"] = 200

        def fetchPage(page: int = 0, content: list = []):
            params["page"] = page
            LOG.debug(f"Fetching page %d..." % page)
            response = Helper.make_ratelimited_request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=data
            )
            response.raise_for_status()

            response_data = response.json()
            LOG.debug(
                "Received response:\n%s" % json.dumps(response_data, indent=2)
            )

            if ("numberOfElements" not in response_data
                or response_data["numberOfElements"] < 1):
                return content

            content += response_data["content"]

            if ("totalPages" not in response_data
                or response_data["totalPages"] <= page - 1):
                return content

            # Don't slam OT API
            sleep(0.5)
            return fetchPage(page + 1, content)

        content = fetchPage(0, [])

        LOG.debug("All pages received.")
        LOG.debug("Received:\n%s" % json.dumps(content, indent=2))

        return content

    def read_domains_from_csv(path: str = None):
        LOG.debug("Checking CSV file %s" % path)
        domains = []
        if not os.path.isfile(path):
            raise FileNotFoundError("CSV file not found.")
        with open(path, 'r') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if Helper.is_domain_name(row[0]):
                    domains.append(row[0])
        csvfile.close()
        return domains

#
# Argparser types
#
def ArgDomainsCsv(path):
    if not os.path.isfile(path):
        raise FileNotFoundError("Could not find provided CSV file.")
    domains = []
    with open(path, 'r') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if Helper.is_domain_name(row[0]):
                domains.append(row[0])
        csvfile.close()
    return domains

def ArgDomain(dstr):
    if not Helper.is_domain_name(dstr):
        raise ValueError("Provided domain is not valid.")
    return dstr

def ArgUUID(ustr):
    if not Helper.is_valid_uuid(ustr):
        raise ValueError("Provided UUID is not valid.")
    return ustr

def ArgTruthiness(val):
    false_vals = ["no", "n", "false"]
    lower_val = val.lower()
    if not lower_val or lower_val in false_vals:
        return False
    return True

def ArgCaseInsensitiveChoice(choices):
    def parse(val):
        if val.lower() in (choice.lower() for choice in choices):
            return val.lower()
        raise argparse.ArgumentTypeError(f'Invalid choice: {val}')
    return parse


# Smarter argparse formatter to preserve newlines
# https://gist.github.com/panzi/b4a51b3968f67b9ff4c99459fb9c5b3d
class ArgparseSmartHelpFormatter(argparse.HelpFormatter):
    def _split_lines(self, text, width):
        lines: List[str] = []
        for line_str in text.split('\n'):
            line: List[str] = []
            line_len = 0
            for word in line_str.split():
                word_len = len(word)
                next_len = line_len + word_len
                if line: next_len += 1
                if next_len > width:
                    lines.append(' '.join(line))
                    line.clear()
                    line_len = 0
                elif line:
                    line_len += 1

                line.append(word)
                line_len += word_len

            lines.append(' '.join(line))
        return lines

    def _fill_text(self, text: str, width: int, indent: str) -> str:
        return '\n'.join(indent + line for line in self._split_lines(text, width - len(indent)))

    def _format_action(self, action):
        """Add "(required)" to parameter help when required."""
        if action.required and not "(required)" in action.help:
            action.help = "(required) " + action.help
        return super()._format_action(action)

    def _format_usage(self, usage, actions, groups, prefix):
        # Replace "[options]" with a custom string
        if usage:
            return super()._format_usage(usage.replace(
                    "[options]",
                    "[common_options]"
                ), actions, groups, prefix)
        else:
            return super()._format_usage(usage, actions, groups, prefix)


# Domain argparse config allowing individual -d/--domain flags
# or a -c/--csv file path containing domains in first column.
argument_domains = {
    "group": "mutually_exclusive_group",
    "group_args": { "required": True, "title": "Supply domains using one of the following options" },
    "args": [
        {
            "arg": ["-c", "--csv"],
            "type": ArgDomainsCsv,
            "dest": "domains",
            "metavar": "FILE_PATH",
            "default": [],
            "help": "Supply domain names as a CSV file "
                    "with domains in column 1."
        },
        {
            "arg": ["-d", "--domain"],
            "type": ArgDomain,
            "dest": "domains",
            "metavar": "DOMAIN",
            "default": [],
            "action": "append",
            "help": "Domain names. Specify multiple "
                    "domains by repeating this option."
        }
    ]
}

COMMANDS: Dict[str, CommandWrapper] = {}

def fetch_domains(**kwargs) -> List[DomainData]:
    """Retrieve domains from OneTrust, optionally filtered by
    org_uuid, or excluding a group_uuid
    """

    org_uuid = kwargs.get("org_uuid", None)
    group_uuid = kwargs.get("group_uuid", None)
    internal = kwargs.get("internal", False)

    if org_uuid != None and not Helper.is_valid_uuid(org_uuid):
        raise ValueError("Invalid org UUID provided.")

    if group_uuid != None and not Helper.is_valid_uuid(group_uuid):
        raise ValueError("Invalid group UUID provided.")

    LOG.info(
        "Fetching domains from OneTrust"
        + (f" within org {org_uuid}" if org_uuid is not None else "")
        + (f" excluding group {group_uuid}" if group_uuid is not None else "")
        + " (this may take a while)."
    )

    try:
        data = Helper.fetch_all_pages(
            url=f"https://{API_DOMAIN}/api/cookiemanager/v1/websitescans",
            params={
                "searchStr": "",
                "sort": "Url,ASC"
            }
        )
        domains = []
        for row in data:
            domain = DomainData(
                name=row["domain"],
                uuid=row["domainId"],
                orgUUID=row["organizationUUID"]
            )

            # Exclude group domain if set
            if group_uuid is not None and domain.uuid == group_uuid:
                continue

            # Exclude domains not in org if set
            if org_uuid is not None and domain.orgUUID != org_uuid:
                continue

            domains.append(domain)

        if not internal:
            LOG.info("Found %d domains" % len(domains))
            LOG.info([d.__json__() for d in domains])
        else:
            LOG.info("Found %d domains. Enable debug output for list." % len(domains))
            LOG.debug([d.__json__() for d in domains])
        return domains
    except:
        raise
COMMANDS["fetchDomains"] = CommandWrapper(
    name="fetchDomains",
    help="Fetch all domains scanned by OneTrust.",
    subparser=lambda instance, subparser, parents=[]: (
        instance.add_parser(
            subparser,
            parents,
            arguments=[
                {
                    "arg": ["-o", "--org-uuid"],
                    "type": ArgUUID,
                    "help": "Limit results to a OneTrust Org UUID."
                },
                {
                    "arg": ["-g", "--group-uuid"],
                    "type": ArgUUID,
                    "help": "Group domain UUID. If specified, the group "
                            "domain will be excluded from results."
                }
            ]
        )
    ),
    run=fetch_domains
)

def fetch_group_domains(**kwargs) -> List[str]:
    """Fetch domain names from OneTrust assigned to a group UUID"""

    group_uuid = kwargs.get("group_uuid", None)

    if not group_uuid or not Helper.is_valid_uuid(group_uuid):
        raise ValueError("Invalid group UUID provided.")

    try:
        LOG.info(
            "Fetching domains assigned to group %s." % group_uuid
        )
        response = requests.get(
            f"https://cdn.cookielaw.org/consent/{group_uuid}/domain-list.json",
            headers={ "content-type": "application/json" }
        )
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        if err.response.status_code == 404:
            raise GroupNotFoundException(
                f"Group {group_uuid} not found. Has it been published?"
            )
        else:
            raise

    domains = response.json()
    LOG.info("Found %d domains. Enable debug output for list." % len(domains))
    LOG.debug(domains)
    return domains
COMMANDS["fetchGroupDomains"] = CommandWrapper(
    name="fetchGroupDomains",
    help="Fetch domain names assigned to a group UUID.",
    subparser=lambda instance, subparser, parents=[]: (
        instance.add_parser(
            subparser,
            parents,
            arguments=[
                {
                    "arg": ["-g", "--group-uuid"],
                    "type": ArgUUID,
                    "required": True,
                    "help": "Group domain UUID."
                }
            ]
        )
    ),
    run=fetch_group_domains
)

def assign_domains_to_group(**kwargs):
    """Add a collection of domains to a group UUID"""

    group_uuid = kwargs.get("group_uuid")
    org_uuid = kwargs.get("org_uuid")
    domains = Helper.convert_to_array(kwargs.get("domains"))
    all_domains = kwargs.get("all_domains")
    skip_domain_check = kwargs.get("skip_domain_check", False)
    remove_existing = kwargs.get("remove_existing", False)

    if not group_uuid or not Helper.is_valid_uuid(group_uuid):
        raise ValueError("Invalid group UUID provided.")

    if not domains or len(domains) == 0:
        raise ValueError("No domains provided.")

    if not skip_domain_check:
        if not all_domains:
            all_domains = fetch_domains(org_uuid=org_uuid, internal=True)

        all_uuids, all_names = zip(
            *[(d.uuid, d.name) for d in all_domains]
        )
        valid_domains = []

        if not group_uuid in all_uuids:
            raise GroupNotFoundException(
                f"Group {group_uuid} not found."
            )

        for d in domains:
            if not d in all_names:
                raise ValueError(
                    "Domain %s was not found in OneTrust, has it been scanned?" % d
                )
            if Helper.is_domain_name(d):
                valid_domains.append(d)

        valid_domains = sorted(set(valid_domains))
    else:
        valid_domains = sorted(set(domains))

    if len(valid_domains) == 0:
        raise ValueError("No valid domains provided.")

    # If remove_existing is not True, adding an existing domain
    # will throw an error. We must check the existing domains
    # on the group, but that data is not available if the group
    # domain is not published...
    if not remove_existing:
        try:
            existing_group = fetch_group_domains(group_uuid=group_uuid)
        except GroupNotFoundException as err:
            raise RuntimeError(
                "Could not check existing group for domains. "
                "Existing domains must be checked when --remove-existing "
                "is not set."
            )
        if isinstance(existing_group, list) and len(existing_group) > 0:
            valid_domains = [
                d for d in valid_domains if d not in existing_group
            ]
            if len(valid_domains) == 0:
                LOG.info(
                    "All provided domains already exist within group."
                )
                return True

    LOG.info(
        "Assigning %(count)d domains to group %(group)s." % {
            "count": len(valid_domains),
            "group": group_uuid
        }
    )

    if remove_existing:
        LOG.info("Existing domains will be removed.")

    api_url = f"https://{API_DOMAIN}/api/cookiemanager/v1/domains/{group_uuid}/domaingroup"
    payload = {
        "urls": valid_domains,
        "removeExisting": remove_existing
    }

    if not kwargs.get("commit"):
        LOG.info(
            "Dry-run enabled, request would contain:\n"
            "POST %(url)s\n %(payload)s" % {
                "url": api_url,
                "payload": json.dumps(payload, indent=2)
            }
        )
        return True

    LOG.info("Sending update request...")

    response = Helper.make_ratelimited_request(
        method="post",
        url=api_url,
        data=payload,
        headers=Helper.generate_headers()
    )

    if response.status_code == 200:
        LOG.info("Domain group updated successfully.")
        #LOG.warning(CommandWrapper.commit_notice)
        return True

    if response.status_code == 500:
        raise BadRequestError(
            "Error updating domain group (%(code)d). "
            "This error may occur when attempting to add a domain which "
            "already exists in the group. Please check your list and "
            "try again.\nResponse content:%(content)s" % {
                "code": response.status_code,
                "content": response.content
            }
        )

    raise BadRequestError(
        "Unhandled error updating domain group (%(code)d).\n"
        "Response content:\n"
        "%(content)s" % {
            "code": response.status_code,
            "content": response.content
        }
    )
COMMANDS["assignDomainsToGroup"] = CommandWrapper(
    name="assignDomainsToGroup",
    help="Add domain names to a group domain UUID. If --remove-existing "
         "is not provided, group must be previously published.",
    subparser=lambda instance, subparser, parents=[]: (
        instance.add_parser(
            subparser,
            parents,
            arguments=[
                argument_domains,
                {
                    "arg": ["-g", "--group-uuid"],
                    "type": ArgUUID,
                    "required": True,
                    "help": "Group domain UUID."
                },
                {
                    "arg": ["--remove-existing"],
                    "action": "store_true",
                    "default": False,
                    "help": "Remove existing domains from the group "
                            "before adding new domains."
                },
                {
                    "arg": ["-o", "--org-uuid"],
                    "type": ArgUUID,
                    "required": False,
                    "help": textwrap.dedent("""\
                            Specifying an org UUID will limit the initial
                            domain check to that org. The group and all supplied
                            domains must exist within the org.""").replace(
                                "\n", " "
                            )
                }
            ]
        )
    ),
    run=assign_domains_to_group,
    commits=True
)

def remove_domains_from_group(**kwargs):
    """Remove domains from a group UUID. Only works for
    domains under PUBLISHED group domains.
    """

    group_uuid = kwargs.get("group_uuid")
    org_uuid = kwargs.get("org_uuid")
    domains = Helper.convert_to_array(kwargs.get("domains"))
    all_domains = kwargs.get("all_domains")

    if not group_uuid or not Helper.is_valid_uuid(group_uuid):
        raise ValueError("Invalid group UUID provided.")

    existing_domains = fetch_group_domains(**kwargs)

    if len(existing_domains) == 0:
        LOG.info("Group contains no domains, nothing to remove.")
        return False

    resolved_domains = [d for d in existing_domains if d not in domains]

    if len(resolved_domains) == 0:
        LOG.info("None of the provided domains exist in group, nothing to remove.")
        return False

    LOG.info(
        "%d domains will remain in group. Enable debug output to view list."
        % len(resolved_domains)
    )
    LOG.debug(resolved_domains)

    new_args = dict(kwargs)
    new_args["remove_existing"] = True
    new_args["domains"] = resolved_domains
    new_args["skip_domain_check"] = True

    LOG.info("Passing request to assignDomainsToGroup...")
    return assign_domains_to_group(**new_args)
COMMANDS["removeDomainsFromGroup"] = CommandWrapper(
    name="removeDomainsFromGroup",
    help="Remove domain names from a group UUID. Group must be "
         "previously published.",
    subparser=lambda instance, subparser, parents=[]: (
        instance.add_parser(
            subparser,
            parents,
            arguments=[
                argument_domains,
                {
                    "arg": ["-g", "--group-uuid"],
                    "type": ArgUUID,
                    "required": True,
                    "help": "Group domain UUID."
                },
                {
                    "arg": ["-o", "--org-uuid"],
                    "type": ArgUUID,
                    "required": False,
                    "help": textwrap.dedent("""\
                            Specifying an org UUID will limit the initial
                            domain check to that org. The group and all supplied
                            domains must exist within the org.""").replace(
                                "\n", " "
                            )
                }
            ]
        )
    ),
    run=remove_domains_from_group,
    commits=True
)

def assign_org_domains_to_group(**kwargs):
    """Assigns all domains within an org UUID to a group domain

    All domains within the org REPLACE ALL EXISTING domains
    under the group domain.

    The group UUID *must* exist within the specified org.
    """

    group_uuid = kwargs.get("group_uuid")
    org_uuid = kwargs.get("org_uuid")
    org_domains = kwargs.get("org_domains")

    if not group_uuid or not Helper.is_valid_uuid(group_uuid):
        raise ValueError("Invalid group UUID provided.")
    if not org_uuid or not Helper.is_valid_uuid(org_uuid):
        raise ValueError("Invalid org UUID provided.")

    if not org_domains:
        org_domains = fetch_domains(org_uuid=org_uuid, internal=True)

    group_info = next((d for d in org_domains if d.uuid == group_uuid), False)

    if not group_info:
        raise ValueError("Group UUID does not exist within org.")

    domains = [d.name for d in org_domains if d.uuid != group_info.uuid]

    if len(domains) == 0:
        raise ValueError("No domains found in org.")

    new_args = dict(kwargs)
    new_args["group_uuid"] = group_info.uuid
    new_args["domains"] = domains
    new_args["remove_existing"] = True
    new_args["skip_domain_check"] = True
    new_args["internal"] = True

    LOG.info("Passing request to assignDomainsToGroup...")
    return assign_domains_to_group(**new_args)
COMMANDS["assignOrgDomainsToGroup"] = CommandWrapper(
    name="assignOrgDomainsToGroup",
    help="Assign all domains within an org UUID to a group UUID. All "
         "existing domains in the group will be replaced.",
    subparser=lambda instance, subparser, parents=[]: (
        instance.add_parser(
            subparser,
            parents,
            arguments=[
                {
                    "arg": ["-o", "--org-uuid"],
                    "type": ArgUUID,
                    "required": True,
                    "help": "Org UUID."
                },
                {
                    "arg": ["-g", "--group-uuid"],
                    "type": ArgUUID,
                    "required": True,
                    "help": "Group domain UUID."
                }
            ]
        )
    ),
    run=assign_org_domains_to_group,
    commits=True
)

def fetch_domain_cookies_raw(**kwargs) -> List[Dict]:
    """Retrieve all raw cookies for a given list of domains"""

    internal = kwargs.get("internal", False)
    domains = Helper.convert_to_array(kwargs.get("domains"))

    valid_domains = [d for d in domains if Helper.is_domain_name(d)]

    if not valid_domains or len(valid_domains) == 0:
        raise ValueError("No domains provided.")

    LOG.info(
        "Fetching cookies for %d domains%s." % (
            len(valid_domains),
            " (this may take a while)" if len(valid_domains) > 50 else ""
        )
    )
    if not internal:
        LOG.debug("Domains: %r" % valid_domains)

    try:
        data = Helper.fetch_all_pages(
            url=f"https://{API_DOMAIN}/api/cookiemanager/v2/cookie-reports/search",
            method="post",
            params={ "language": "en" },
            data={ "domains": valid_domains }
        )
    except requests.exceptions.HTTPError as http_error:
        if http_error.response.status_code == 400:
            raise BadRequestError(
                "Error 400 Bad Request. Please check that the requested "
                "domains are valid and exist *exactly* as entered in the "
                "OneTrust account, including 'www.' if used."
            )
        else:
            raise

    LOG.info("Retrieved %d cookies for %d domains." % (
        len(data),
        len(valid_domains)
    ))
    if not internal:
        LOG.debug("Cookie data: %s" % data)

    return data
COMMANDS["fetchRawDomainCookies"] = CommandWrapper(
    name="fetchRawDomainCookies",
    help="Retrieve raw cookie data from OneTrust for given domains.",
    subparser=lambda instance, subparser, parents=[]: (
        instance.add_parser(
            subparser,
            parents,
            arguments=[
                argument_domains,
            ]
        )
    ),
    run=fetch_domain_cookies_raw,
)

def fetch_domain_cookies(**kwargs) -> List[DomainCookieData]:
    """Retrieves a list of DomainCookieData objects for a
    given list of domains"""

    new_args = dict(kwargs)
    new_args["internal"] = True
    raw_cookie_data = fetch_domain_cookies_raw(**new_args)
    deduplicated_cookie_data = generate_domaincookiedata_from_raw(
        cookies=raw_cookie_data,
        skip_domain=kwargs.get("skip_domain")
    )

    if len(deduplicated_cookie_data) == 0 and not kwargs.get("internal"):
        LOG.info("No cookies found.")

    return deduplicated_cookie_data
COMMANDS["fetchDomainCookies"] = CommandWrapper(
    name="fetchDomainCookies",
    help="Retrieve a limited set of %s-relevant cookie data for a given "
         "list of domain names. Note: This does not return raw cookie data "
         "from the API. For the raw data, use fetchRawDomainCookies" %
         os.path.basename(sys.argv[0]),
    subparser=lambda instance, subparser, parents=[]: (
        instance.add_parser(
            subparser,
            parents,
            arguments=[
                argument_domains,
            ]
        )
    ),
    run=fetch_domain_cookies,
)

def generate_domaincookiedata_from_raw(
        cookies: list,
        skip_domain: DomainData | None = None,
    ) -> List[DomainCookieData]:
    """Generates a list of DomainCookieData objects
    from a raw list of OneTrust cookie data. Returned
    list is deduplicated by cookieId"""

    if len(cookies) == 0:
        raise SyntaxError("cookies list is required.")

    unique_cookie_ids = set()
    deduplicated_cookies = []

    for cookie in cookies:
        if not "domainCookieInfoDtoList" in cookie:
            continue
        for dc in cookie["domainCookieInfoDtoList"]:
            if not "cookieId" in dc:
                continue
            if dc["cookieId"] in unique_cookie_ids:
                continue
            # skip cookies from the group domain
            if skip_domain and skip_domain.name == dc["domainName"]:
                continue

            deduplicated_cookies.append(
                DomainCookieData(
                    cookieName=cookie["cookieName"],
                    cookieUUID=dc["cookieId"],
                    thirdParty=dc["thirdParty"],
                    cookieCategoryID=dc["cookieCategoryID"],
                    domainCookieUUID=dc["domainCookieId"],
                    domainName=dc["domainName"]
                )
            )
            unique_cookie_ids.add(dc["cookieId"])

    return deduplicated_cookies

def assign_domain_to_cookie(
        cookie: DomainCookieData | None = None,
        domain: DomainData | None = None,
        remove_domain: bool = False,
        commit: bool = False,
    ):
    """Add or remove a domain from a cookie."""

    if not cookie:
        raise SyntaxError("cookie is required.")

    if not isinstance(cookie, DomainCookieData):
        raise SyntaxError("cookie must be an instance of DomainCookieData.")

    payload = {
        "cookieId": cookie.cookieUUID
    }
    log_operation = "Adding"
    if remove_domain is True:
        log_operation = "Removing"
        payload["domainToDeleteIds"] = [domain.uuid]
    else:
        payload["domainCookieCategoryList"] = [
            {
                "domainId": domain.uuid,
                "thirdParty": cookie.thirdParty
            }
        ]

    LOG.info(
        '%(op)s domain "%(domain)s" (UUID: %(domainUUID)s) '
        'to %(thirdParty)s cookie "%(cookieName)s" (UUID: %(cookieUUID)s), '
        'originally found on %(cookieDomain)s' % {
            "op": log_operation,
            "domain": domain.name,
            "domainUUID": domain.uuid,
            "thirdParty": "third-party" if cookie.thirdParty else "first-party",
            "cookieName": cookie.cookieName,
            "cookieUUID": cookie.cookieUUID,
            "domainCookieUUID": cookie.domainCookieUUID,
            "cookieDomain": cookie.domainName,
        }
    )
    api_url = f"https://{API_DOMAIN}/api/cookiemanager/v1/cookies"

    if not commit:
        LOG.info(
            "Dry-run enabled, request would contain:\n"
            "PUT %(url)s\n"
            "%(payload)s" % {
                "url": api_url,
                "payload": json.dumps(payload, indent=2)
            }
        )
        return True

    try:
        response = Helper.make_ratelimited_request(
            method="put",
            url=api_url,
            headers=Helper.generate_headers(),
            data=payload
        )
        response.raise_for_status()
    except:
        raise

    return True

def assign_domain_cookies_to_group(**kwargs):
    """Assign or remove a group domain UUID to all cookies
    from a list of domains"""

    group_uuid = kwargs.get("group_uuid")
    org_uuid = kwargs.get("org_uuid")
    domains = kwargs.get("domains")
    skip_existing = kwargs.get("skip_existing", False)
    remove_group = kwargs.get("remove_group", False)
    all_domains = kwargs.get("all_domains")
    commit = kwargs.get("commit")
    internal = kwargs.get("internal")

    if not group_uuid or not Helper.is_valid_uuid(group_uuid):
        raise ValueError("Invalid group UUID provided.")

    if not domains or len(domains) == 0:
        raise ValueError("No domains provided.")

    if not all_domains:
        all_domains = fetch_domains(org_uuid=org_uuid, internal=True)

    valid_group = next((d for d in all_domains if d.uuid == group_uuid), False)
    if not valid_group:
        raise ValueError("Group not found within queried domains.")

    existing_domain_names = [d.name for d in all_domains]
    valid_domain_names = []
    for d in domains:
        if not Helper.is_domain_name(d):
            LOG.warning("Ignoring invalid domain: %s" % d)
            continue
        if d not in existing_domain_names:
            LOG.warning(
                "Ignoring domain not found in queried domains: %s" % d
            )
            continue
        valid_domain_names.append(d)
    # remove duplicates
    valid_domain_names = sorted(set(valid_domain_names))

    if len(valid_domain_names) == 0:
        raise ValueError("No valid domains provided.")

    LOG.debug("Valid domains: %r" % valid_domain_names)

    domain_cookies = fetch_domain_cookies(
        domains=valid_domain_names,
        skip_domain=valid_group,
        internal=True
    )

    if len(domain_cookies) == 0:
        LOG.info("No cookies found for requested domains.")
        return None

    if not remove_group and skip_existing:
        sleep(1)
        LOG.info("Fetching cookies already assigned to group domain.")
        group_cookies = fetch_domain_cookies(
            domains=[valid_group.name],
            internal=True
        )
        group_cookie_uuids = [c.cookieUUID for c in group_cookies]

        unassigned_cookies = [
            c for c in domain_cookies \
                if c.cookieUUID not in group_cookie_uuids
        ]
    else:
        unassigned_cookies = domain_cookies

    if len(unassigned_cookies) == 0:
        LOG.info("No cookies to assign.")
        return True

    sorted_cookies = sorted(unassigned_cookies, key=lambda x: x.domainName)

    LOG.info("Found %d unique cookies." % len(sorted_cookies))
    LOG.debug(
        "Cookies: %r" % json.dumps(
            [dc.__dict__ for dc in sorted_cookies],
            indent=2
        )
    )

    LOG.info(
        "Assigning domain to cookies.%s" %
        " In dry run, network request delays are simulated." \
            if not commit else ""
    )
    for cookie in sorted_cookies:
        assign_domain_to_cookie(
            cookie=cookie,
            domain=valid_group,
            remove_domain=remove_group,
            commit=commit
        )
        if commit:
            # Try not to hammer the API...
            sleep(0.2)
        else:
            # Simulate extra network response time
            sleep(0.5)

    LOG.info(
        "Assignment of %(cookie_count)d cookies to "
        "%(domain_name)s complete." %
        {
            "cookie_count": len(sorted_cookies),
            "domain_name": valid_group.name
        }
    )
    pass
COMMANDS["assignDomainCookiesToGroup"] = CommandWrapper(
    name="assignDomainCookiesToGroup",
    help="Add a group domain (by UUID) to all cookies from given domain names.",
    subparser=lambda instance, subparser, parents=[]: (
        instance.add_parser(
            subparser,
            parents,
            arguments=[
                argument_domains,
                {
                    "arg": ["-g", "--group-uuid"],
                    "type": ArgUUID,
                    "required": True,
                    "help": "Group domain UUID."
                },
                {
                    "arg": ["-o", "--org-uuid"],
                    "type": ArgUUID,
                    "required": False,
                    "help": "Restrict valid domains and group to an org UUID."
                },
                {
                    "arg": ["--skip-existing"],
                    "default": False,
                    "action": "store_true",
                    "help": "By default, no checking is done for cookies "
                            "already assigned to the group. Providing this "
                            "flag skips cookies already assigned to the "
                            "group. Has no effect if --remove-group is given."
                },
                {
                    "arg": ["--remove-group"],
                    "default": False,
                    "action": "store_true",
                    "help": "Remove group from cookies instead of assigning."
                }
            ]
        )
    ),
    run=assign_domain_cookies_to_group,
    commits=True
)

def assign_org_domain_cookies_to_group(**kwargs):
    """Assign all domains within an org to a group domain."""
    group_uuid = kwargs.get("group_uuid")
    org_uuid = kwargs.get("org_uuid")
    remove_group = kwargs.get("remove_group")
    org_domains = kwargs.get("org_domains")

    if not group_uuid or not Helper.is_valid_uuid(group_uuid):
        raise ValueError("Invalid group UUID provided.")

    if not org_uuid or not Helper.is_valid_uuid(org_uuid):
        raise ValueError("Invalid org UUID provided.")

    if not org_domains:
        org_domains = fetch_domains(org_uuid=org_uuid, internal=True)

    if len(org_domains) == 0:
        raise ValueError("No domains found in org!")

    valid_group = next(
        (d for d in org_domains if d.uuid == group_uuid), False
    )
    if not valid_group:
        raise GroupNotFoundException(
            "Invalid group UUID provided. Group must exist within org."
        )

    valid_domains = [d for d in org_domains if d.uuid != valid_group.uuid]

    if len(valid_domains) == 0:
        raise ValueError("No domains found in org!")

    valid_domain_names = [d.name for d in valid_domains]

    new_args = dict(kwargs)
    new_args["group_uuid"] = valid_group.uuid
    new_args["domains"] = valid_domain_names
    new_args["all_domains"] = org_domains
    return assign_domain_cookies_to_group(**new_args)
COMMANDS["assignOrgDomainCookiesToGroup"] = CommandWrapper(
    name="assignOrgDomainCookiesToGroup",
    help="Assign a group domain (by UUID) to all cookies from all domains "
         "within an org UUID. Group must exist in org.",
    subparser=lambda instance, subparser, parents=[]: (
        instance.add_parser(
            subparser,
            parents,
            arguments=[
                {
                    "arg": ["-g", "--group-uuid"],
                    "type": ArgUUID,
                    "required": True,
                    "help": "Group domain UUID."
                },
                {
                    "arg": ["-o", "--org-uuid"],
                    "type": ArgUUID,
                    "required": True,
                    "help": "Org UUID."
                },
                {
                    "arg": ["--skip-existing"],
                    "default": False,
                    "action": "store_true",
                    "help": "By default, no checking is done for cookies "
                            "already assigned to the group. Providing this "
                            "flag skips cookies already assigned to the "
                            "group. Has no effect if --remove-group is given."
                },
                {
                    "arg": ["--remove-group"],
                    "default": False,
                    "action": "store_true",
                    "help": "Remove group from cookies instead of assigning."
                }
            ]
        )
    ),
    run=assign_org_domain_cookies_to_group,
    commits=True
)

def complete_org_assign_to_group(**kwargs):
    """Both assigns domains to a group, and assigns
    that group to all domains within the org."""

    org_uuid = kwargs.get("org_uuid")
    if not org_uuid or not Helper.is_valid_uuid(org_uuid):
        raise ValueError("Invalid org UUID provided.")

    org_domains = fetch_domains(
        org_uuid=org_uuid, internal=True
    )

    new_args = dict(kwargs)
    new_args["org_domains"] = org_domains

    assign_org_domains_to_group(**new_args)

    assign_org_domain_cookies_to_group(**new_args)
COMMANDS["completeOrgAssignToGroup"] = CommandWrapper(
    name="completeOrgAssignToGroup",
    help="Runs both assignOrgDomainsToGroup and "
         "assignOrgDomainCookiesToGroup. Assigns all domains in a given "
         "org UUID to a group domain UUID, replacing all existing domains "
         "and the group domain to all org domain cookies.",
    subparser=lambda instance, subparser, parents=[]: (
        instance.add_parser(
            subparser,
            parents,
            arguments=[
                {
                    "arg": ["-g", "--group-uuid"],
                    "type": ArgUUID,
                    "required": True,
                    "help": "Group domain UUID."
                },
                {
                    "arg": ["-o", "--org-uuid"],
                    "type": ArgUUID,
                    "required": True,
                    "help": "Org UUID."
                },
                {
                    "arg": ["--skip-existing"],
                    "default": False,
                    "action": "store_true",
                    "help": "By default, no checking is done for cookies "
                            "already assigned to the group. Providing this "
                            "flag skips cookies already assigned to the "
                            "group. Has no effect if --remove-group is given."
                },
                {
                    "arg": ["--remove-group"],
                    "default": False,
                    "action": "store_true",
                    "help": "Remove group from cookies instead of assigning."
                }
            ]
        )
    ),
    run=complete_org_assign_to_group,
    commits=True
)

def fetch_domain_script(**kwargs):
    """Fetch published scripts for a domain"""

    domain = kwargs.get("domain")

    if not Helper.is_domain_name(domain) and not Helper.is_valid_uuid(domain):
        raise ValueError("domain must be a domain name or UUID.")

    script_type = kwargs.get("script_type")

    api_url = f"https://{API_DOMAIN}/api/cookiemanager/v2/websites/scripts?website={domain}"
    if script_type:
        api_url += f"&scriptType={script_type}"

    LOG.info("Fetching scripts for domain %s" % domain)
    response = Helper.make_ratelimited_request(
        method="get",
        url=api_url,
        headers=Helper.generate_headers()
    )

    if response.status_code == 200:
        if "Unable to find" in response.text:
            LOG.warning("Could not find domain!")
            return False
        LOG.info("Domain scripts received successfully.")
        return response.text

    response.raise_for_status()
COMMANDS["fetchDomainScript"] = CommandWrapper(
    name="fetchDomainScript",
    help="Fetch the latest published script for a given domain.",
    subparser=lambda instance, subparser, parents=[]: (
        instance.add_parser(
            subparser,
            parents,
            arguments=[
                {
                    "arg": ["-d", "--domain", "-g", "--group-uuid"],
                    "dest": "domain",
                    "required": True,
                    "help": "Domain to publish. May be a domain name or UUID."
                },
                {
                    "arg": ["--script-type"],
                    "default": 'prod',
                    "help": "Type of the script. It can be 'test' or 'prod'. "
                            "Default 'prod'."
                },
            ]
        )
    ),
    run=fetch_domain_script,
)

def publish_domain_script(**kwargs):
    """Attempts to publish the scripts for domain"""

    domain = kwargs.get("domain")

    if not Helper.is_domain_name(domain) and not Helper.is_valid_uuid(domain):
        raise ValueError("domain must be a domain name or UUID.")

    is_uuid = True if Helper.is_valid_uuid(domain) else False

    org_uuid = kwargs.get("org_uuid")
    all_domains = kwargs.get("all_domains")
    skip_domain_check = kwargs.get("skip_domain_check", False)

    script_type = kwargs.get("script_type")
    autoblock_enabled = kwargs.get("autoblock_enabled")
    enable_common_trackers = kwargs.get("enable_common_trackers")
    language_detection = kwargs.get("language_detection")
    languages = kwargs.get("languages")
    require_reconsent = kwargs.get("require_reconsent")
    suppress_banner = kwargs.get("suppress_banner")
    suppress_pc_enabled = kwargs.get("suppress_pc_enabled")

    if not skip_domain_check:
        if not all_domains:
            org_domains = fetch_domains(org_uuid=org_uuid, internal=True)

        if is_uuid:
            valid_domain = next(
                (d.uuid for d in org_domains if d.uuid == domain), False
            )
        else:
            valid_domain = next(
                (d.uuid for d in org_domains if d.name == domain), False
            )

        if not valid_domain:
            raise GroupNotFoundException(
                "Invalid domain provided or domain not found."
            )
    else:
        valid_domain = domain

    api_url = f"https://{API_DOMAIN}/api/cookiemanager/v2/websites/publish?website={valid_domain}"
    if script_type:
        api_url += f"&scriptType={script_type}"

    payload = {
        "autoblockEnabled": autoblock_enabled,
        "enableCommonTrackers": enable_common_trackers,
        "languageDetectionEnabled": True if language_detection in \
              ["html", "visitor"] else False,
        "languageDetectionHtml": True if language_detection == "html" \
            else False,
        "languageDetectionVisitor": True if language_detection == "visitor" \
            else False,
        "languages": languages,
        "publishIndividualLanguages": True if languages else False,
        "requireReconsent": require_reconsent,
        "suppressBannerEnabled": suppress_banner,
        "suppressPCEnabled": suppress_pc_enabled,
    }
    payload = {key: value for key, value in payload.items() if value is not None}

    if not kwargs.get("commit"):
        LOG.info(
            "Dry-run enabled, request would contain:\n"
            "PUT %(url)s\n %(payload)s" % {
                "url": api_url,
                "payload": json.dumps(payload, indent=2)
            }
        )
        return True

    response = Helper.make_ratelimited_request(
        method="put",
        url=api_url,
        data=payload,
        headers=Helper.generate_headers()
    )

    if response.status_code == 200:
        LOG.info("Domain script(s) published successfully.")
        return True

    response.raise_for_status()
COMMANDS["publishDomainScript"] = CommandWrapper(
    name="publishDomainScript",
    help="EXPERIMENTAL. Publishes a given domain's scripts. This function is "
         "not done automatically as the API has historically been unstable. "
         "You may still have to publish manually through the OneTrust web "
         "admin.",
    subparser=lambda instance, subparser, parents=[]: (
        instance.add_parser(
            subparser,
            parents,
            arguments=[
                {
                    "arg": ["-d", "--domain", "-g", "--group-uuid"],
                    "dest": "domain",
                    "required": True,
                    "help": "Domain to publish. May be a domain name or UUID."
                },
                {
                    "arg": ["-o", "--org-uuid"],
                    "type": ArgUUID,
                    "required": False,
                    "help": textwrap.dedent("""\
                            Specifying an org UUID will limit the initial
                            domain check to that org. The domain must exist
                            within the org.""").replace("\n", " ")
                },
                {
                    "arg": ["--script-type"],
                    "default": None,
                    "help": "Type of the script. It can be 'test' or 'prod'. "
                    "If nothing is provided by the user, both test and "
                    "prod scripts will be published."
                },
                {
                    "arg": ["--autoblock-enabled"],
                    "type": ArgTruthiness,
                    "default": True,
                    "help": "Auto-blocking leverages an additional script "
                            "that must be added to the website to block "
                            "tracking technologies based on the source "
                            "setting them. Default 'yes'."
                },
                {
                    "arg": ["--enable-common-trackers"],
                    "type": ArgTruthiness,
                    "default": True,
                    "help": "Block known trackers. Default 'yes'. Has no "
                            "effect when autoblock is disabled."
                },
                {
                    "arg": ["--language-detection"],
                    "type": ArgCaseInsensitiveChoice(
                        ["html", "visitor", "no", "false"]
                    ),
                    "default": "html",
                    "choices": ["html", "visitor", "no", "false"],
                    "help": "Automatically detect the language of the website "
                            "visitor. Default 'html'."
                },
                {
                    "arg": ["--languages"],
                    "default": None,
                    "help": "Publish only a specific subset of languages, "
                            "specified as a comma-delimited string "
                            "without spaces, e.g. 'English,Spanish'."
                },
                {
                    "arg": ["--require-reconsent"],
                    "default": False,
                    "action": "store_true",
                    "help": "Providing this flag will force visitors to "
                            "be re-prompted for consent."
                },
                {
                    "arg": ["--suppress-banner"],
                    "default": False,
                    "action": "store_true",
                    "help": "Prevent banner from automatically displaying "
                            "on initial page load. If set, you must manually "
                            "invoke the banner in your own page scripting."
                },
                {
                    "arg": ["--suppress-pc"],
                    "default": False,
                    "action": "store_true",
                    "help": "Do not fetch preference center code until "
                            "visitor interacts with the banner."
                }
            ]
        )
    ),
    run=publish_domain_script,
    commits=True
)

def main():
    global API_KEY

    # Load API key from environment
    dotenv.load_dotenv()
    if os.getenv("OT_API_KEY") is None or len(os.getenv("OT_API_KEY")) < 1:
        LOG.critical("Required environment variable OT_API_KEY was not found.")
        sys.exit(1)
    API_KEY = os.getenv("OT_API_KEY")

    # Main argument parser
    parser = argparse.ArgumentParser(
        description="List, verify, and group domains and their cookies with "
                    "the OneTrust Cookie Consent API.",
        formatter_class=ArgparseSmartHelpFormatter,
        usage="%(prog)s [-h [command | all]] [options]",
        add_help=False,
    )
    help_arg = parser.add_argument(
        '-h', '--help',
        nargs='?',
        metavar="command",
        const=True,
        default=False,
        help="Output usage information. To get help with a specific command, "
             "use -h [command] or -h all to ouput help for all commands."
    )

    common_parser = argparse.ArgumentParser(
        add_help=False,
        parents=[parser],
        formatter_class=ArgparseSmartHelpFormatter,
    )

    # Common arguments
    common_group = common_parser.add_argument_group(
        title="common options",
        description="Options which apply to all commands."
    )
    common_group.add_argument(
        '--commit',
        action="store_true",
        default=False,
        help="By default, commands which may make changes are in 'dry run' "
             "mode and no changes are sent to the OneTrust API. Enable "
             "commit with this flag to send changes."
    )
    common_group.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        help="Enables verbose output.",
        default=False
    )
    common_group.add_argument(
        '--api-domain',
        default=API_DOMAIN,
        help="Manually specify the API domain, default is api.onetrust.com."
    )
    common_group.add_argument(
        '--debug',
        action="store_true",
        default=False,
        help="Enables debug output."
    )
    common_group.add_argument(
        '--include-log-time',
        action="store_true",
        default=False,
        help="Include date and time in log output."
    )
    common_group.add_argument(
        '--indent',
        type=int,
        default=0,
        help="For commands which output data, specify the indent formatting of "
             "the JSON output."
    )

    # Command parser
    command_parsers = parser.add_subparsers(
        help="Purpose",
        title="Commands",
        description="To view usage of a command, use -h <command>",
        dest="cmd",
        metavar="Command",
    )
    for C in COMMANDS:
        if hasattr(COMMANDS[C], "subparser"):
            COMMANDS[C].subparser(
                COMMANDS[C],
                command_parsers,
                [common_parser]
            )

    try:
        args, extra_args = parser.parse_known_args()
        #common_args, common_extra_args = common_parser.parse_known_args()
    except (
        GroupNotFoundException,
        BadRequestError,
        SyntaxError,
        FileNotFoundError,
        ValueError
    ) as err:
        LOG.error(str(err))
        sys.exit(1)

    # Configure log level
    if getattr(args, "verbose", False) is True:
        LOG.setLevel(level=logging.INFO)
        LOG.info("Log level verbose (INFO)")
    if getattr(args, "debug", False) is True:
        LOG.setLevel(level=logging.DEBUG)
        LOG.debug("Log level DEBUG")

    # Configure logging timestamps
    if getattr(args, "include_log_time", False) is True:
        formatter = logging.Formatter(
            "[%(asctime)s] %(levelname)s: %(message)s",
        )
        for handler in LOG.handlers:
            handler.setFormatter(formatter)

    def output_help():
        def print_common_help(group=common_group):
            print(group.title + ':')
            print(textwrap.fill(
                f"  {group.description}",
                width=80,
                subsequent_indent=2
            ))
            print()
            for action in common_parser._actions:
                if not isinstance(action, argparse._HelpAction) \
                    and not "-h" in action.option_strings:
                    option_strings = ', '.join(action.option_strings)
                    help_text = textwrap.fill(
                        f'  {option_strings.ljust(20)}  {action.help}',
                        width=80,
                        subsequent_indent=' ' * 24
                    )
                    print(help_text)

        if args.help in COMMANDS:
            print("Command: %s" % COMMANDS[args.help].name)
            help_arg.help = argparse.SUPPRESS
            COMMANDS[args.help].subparser_instance.print_help()
        elif isinstance(args.help, str) and args.help.lower() == 'all':
            # This one gets a little weird. I want to output the command's
            # arguments, but NOT the parent parser's common options, so
            # I'm recreating the subparsers with a temporary parent.
            parser.print_help()
            print()
            print_common_help()
            print()
            help_arg.help = argparse.SUPPRESS
            tmp_parser = argparse.ArgumentParser(
                description=parser.description,
                formatter_class=parser.formatter_class,
                usage=parser.usage,
                add_help=False,
            )
            tmp_cmd_subparser = tmp_parser.add_subparsers()
            tmp_commands = COMMANDS.copy()
            for C in tmp_commands:
                header = "Command: %s" % C
                print("-" * len(header))
                print(header)
                print()
                if hasattr(tmp_commands[C], "subparser"):
                    tmp_commands[C].subparser(
                        tmp_commands[C],
                        tmp_cmd_subparser
                    )
                    tmp_commands[C].subparser_instance.print_help()
                    print()
        else:
            parser.print_help()
            print()
            print_common_help()
            print()
        sys.exit(0)

    if getattr(args, "help", False):
        output_help()

    # Run a command!
    if getattr(args, "cmd", None) != None and args.cmd in COMMANDS \
        and COMMANDS[args.cmd].run \
            and callable(COMMANDS[args.cmd].run):
        try:
            start_time = time()
            LOG.info("%s begun %s" % (
                COMMANDS[args.cmd].name,
                datetime.fromtimestamp(start_time).strftime('%c')
            ))
            end_time = time()
            LOG.info(
                'Completed. Elapsed time %s' %
                str(timedelta(seconds=end_time - start_time))
            )

            output = COMMANDS[args.cmd].run(**vars(args))
            if output not in (None, True, False):
                if isinstance(output, str):
                    print(output)
                else:
                    print(json.dumps(
                        output,
                        indent=args.indent,
                        default=lambda o: o.__json__() if hasattr(o, '__json__') \
                            else o
                    ))

            if getattr(args, "commit", False) and \
                getattr(COMMANDS[args.cmd], "commits", False):
                LOG.warning(
                    CommandWrapper.commit_notice
                )
        except (
            GroupNotFoundException,
            BadRequestError,
            SyntaxError,
            FileNotFoundError,
            ValueError,
            PermissionError,
            ConnectionError,
        ) as err:
            LOG.error(str(err))
            sys.exit(1)
        except KeyboardInterrupt as err:
            LOG.error("Program interrupted by user.")
            sys.exit(1)
    elif getattr(args, "cmd", None) != None:
        LOG.error("Invalid command: %s" % args.cmd)
        sys.exit(1)
    else:
        parser.print_usage()

if __name__ == "__main__":
    main()
