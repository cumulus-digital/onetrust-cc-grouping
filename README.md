# OneTrust Cookie Consent Domain Group Management

`ot.py` provides an interface for the OneTrust Cookie Consent API to list, verify, and group domains and their cookies under a single domain.

# Setup

A OneTrust API key is required for most operations. Required scope must include cookie management with read and write capability.

Copy the included `example.env` to `.env` and edit it to include your API key, or provide the key in your environment with an `OT_API_KEY` variable. Do not expose or share your key or the `.env` file with anyone.

## Required Python libraries

* dotenv
* requests

`ot.py` will attempt to report missing required libraries at runtime.

## Running

A `COMMAND` is required. Help and usage information is available with the `--help` or `-h` flag.

```
usage: ot.py [-h [command | all]] [common_options]

options:
  -h [command], --help [command]
                        Output usage information. To get help with a specific
                        command, use -h [command] or -h all to ouput help for
                        all commands.

common options:
  Options which apply to all commands.

  --commit              By default, commands which may make changes are in 'dry
                        run' mode and no changes are sent to the OneTrust API.
                        Enable commit with this flag to send changes.
  -v, --verbose         Enables verbose output.
  --api-domain          Manually specify the API domain, default is
                        api.onetrust.com.
  --debug               Enables debug output.
  --include-log-time    Include date and time in log output.
  --indent              For commands which output data, specify the indent
                        formatting of the JSON output.
```

### Important Notes on Default Running State

* **All commands which may make changes in OneTrust run in a dry-run state unless you provide a `--commit` flag.** See command usage below for committing commands.

* Console output is limited to API output (to stdout), warning (to stdout), and error logs (to stderr) unless verbose output is enabled with the `--verbose` or `-v` flags. Verbose output gives some indication of program state as it makes API calls and processes data.

* Debug output may be *extremely* verbose.

* API keys should be masked in all output, but be sure to double-check before sharing logs.


## Commands

Commands have specific options. See their expanded help text further down this page, or access their usage help with `./ot.py -h <COMMAND>`

*Commands are case-sensitive.*

* [`fetchDomains`](#fetchDomains):

  Fetch all domains scanned by OneTrust.

* [`fetchGroupDomains`](#fetchGroupDomains):

  Fetch domain names assigned to a group UUID. Group must be previously published.

* [`assignDomainsToGroup`](#assignDomainsToGroup):

  Add domain names to a group UUID. If --remove-existing is not provided, group must be previously published.

* [`removeDomainsFromGroup`](#removeDomainsFromGroup):

  Remove domain names from a group UUID. Group must be previously published.

* [`assignOrgDomainsToGroup`](#assignOrgDomainsToGroup):

  Assign all domains within an org UUID to a group UUID. All existing domains in the group will be replaced.

* [`fetchRawDomainCookies`](#fetchRawDomainCookies):

  Retrieve raw cookie data from OneTrust for given domains.

* [`fetchDomainCookies`](#fetchDomainCookies):

  Retrieve a limited set of `ot.py`-relevant cookie data for a given list of domain names. Note: This does not return raw cookie data from the API. For the raw data, use [`fetchRawDomainCookies`](#fetchRawDomainCookies).

* [`assignDomainCookiesToGroup`](#assignDomainCookiesToGroup):

  Add a group domain (by UUID) to all cookies from given domain names.

* [`assignOrgDomainCookiesToGroup`](#assignOrgDomainCookiesToGroup):

  Assign a group domain (by UUID) to all cookies from all domains within an org UUID. Group must exist in org.

* [`completeOrgAssignToGroup`](#completeOrgAssignToGroup):

  Runs both [`assignOrgDomainsToGroup`](#assignOrgDomainsToGroup) and [`assignOrgDomainCookiesToGroup`](#assignOrgDomainCookiesToGroup). Assigns all domains in a given org UUID to a group domain UUID, replacing all existing domains, and the group domain to all org domain cookies.

* [`fetchDomainScript`](#fetchDomainScript):

  Fetch the latest published script for a given domain.

* [`publishDomainScript`](#publishDomainScript):

  EXPERIMENTAL. Publishes a given domain's scripts. This function is not done automatically as the API has historically been unstable. You may still have to publish manually through the OneTrust web admin.


### `fetchDomains`
Fetch all domains scanned by OneTrust.

```
usage: ot.py [-h [command | all]] [common_options] fetchDomains
       [-o ORG_UUID] [-g GROUP_UUID]

options:
  -o ORG_UUID, --org-uuid ORG_UUID
                        Limit results to a OneTrust Org UUID.
  -g GROUP_UUID, --group-uuid GROUP_UUID
                        Group domain UUID. If specified, the group domain will
                        be excluded from results.
```

### `fetchGroupDomains`
Fetch domain names assigned to a group UUID.

```
usage: ot.py [-h [command | all]] [common_options] fetchGroupDomains
       -g GROUP_UUID

options:
  -g GROUP_UUID, --group-uuid GROUP_UUID
                        (required) Group domain UUID.
```

### `assignDomainsToGroup`
Add domain names to a group domain UUID. If --remove-existing is not provided,
group must be previously published.

```
usage: ot.py [-h [command | all]] [common_options] assignDomainsToGroup
       (-c FILE_PATH | -d DOMAIN) -g GROUP_UUID [--remove-existing]
       [-o ORG_UUID]

options:
  -g GROUP_UUID, --group-uuid GROUP_UUID
                        (required) Group domain UUID.
  --remove-existing     Remove existing domains from the group before adding
                        new domains.
  -o ORG_UUID, --org-uuid ORG_UUID
                        Specifying an org UUID will limit the initial
                        domain and group check to that org. The group
                        and all supplied domains must exit within
                        the org.

Supply domains using one of the following options:
  -c FILE_PATH, --csv FILE_PATH
                        Supply domain names as a CSV file with domains in
                        column 1.
  -d DOMAIN, --domain DOMAIN
                        Domain names. Specify multiple domains by repeating
                        this option.

NOTE: This command requires a --commit flag in order to make changes in the OneTrust system.
```

### `removeDomainsFromGroup`
Remove domain names from a group UUID. Group must be previously published.

```
usage: ot.py [-h [command | all]] [common_options] removeDomainsFromGroup
       (-c FILE_PATH | -d DOMAIN) -g GROUP_UUID [-o ORG_UUID]

options:
  -g GROUP_UUID, --group-uuid GROUP_UUID
                        (required) Group domain UUID.
  -o ORG_UUID, --org-uuid ORG_UUID
                        Specifying an org UUID will limit the initial
                        domain and group check to that org. The group
                        and all supplied domains must exit within
                        the org.

Supply domains using one of the following options:
  -c FILE_PATH, --csv FILE_PATH
                        Supply domain names as a CSV file with domains in
                        column 1.
  -d DOMAIN, --domain DOMAIN
                        Domain names. Specify multiple domains by repeating
                        this option.

NOTE: This command requires a --commit flag in order to make changes in the OneTrust system.
```

### `assignOrgDomainsToGroup`
Assign all domains within an org UUID to a group UUID. All existing domains in
the group will be replaced.

```
usage: ot.py [-h [command | all]] [common_options] assignOrgDomainsToGroup
       -o ORG_UUID -g GROUP_UUID

options:
  -o ORG_UUID, --org-uuid ORG_UUID
                        (required) Org UUID.
  -g GROUP_UUID, --group-uuid GROUP_UUID
                        (required) Group domain UUID.

NOTE: This command requires a --commit flag in order to make changes in the OneTrust system.
```

### `fetchRawDomainCookies`
Retrieve raw cookie data from OneTrust for given domains.

```
usage: ot.py [-h [command | all]] [common_options] fetchRawDomainCookies
       (-c FILE_PATH | -d DOMAIN)

Supply domains using one of the following options:
  -c FILE_PATH, --csv FILE_PATH
                        Supply domain names as a CSV file with domains in
                        column 1.
  -d DOMAIN, --domain DOMAIN
                        Domain names. Specify multiple domains by repeating
                        this option.
```

### `fetchDomainCookies`
Retrieve a limited set of ot.py-relevant cookie data for a given list of
domain names. Note: This does not return raw cookie data from the API. For the
raw data, use fetchRawDomainCookies

```
usage: ot.py [-h [command | all]] [common_options] fetchDomainCookies
       (-c FILE_PATH | -d DOMAIN)

Supply domains using one of the following options:
  -c FILE_PATH, --csv FILE_PATH
                        Supply domain names as a CSV file with domains in
                        column 1.
  -d DOMAIN, --domain DOMAIN
                        Domain names. Specify multiple domains by repeating
                        this option.
```

### `assignDomainCookiesToGroup`
Add a group domain (by UUID) to all cookies from given domain names.

```
usage: ot.py [-h [command | all]] [common_options] assignDomainCookiesToGroup
       (-c FILE_PATH | -d DOMAIN) -g GROUP_UUID [-o ORG_UUID]
       [--skip-existing] [--remove-group]

options:
  -g GROUP_UUID, --group-uuid GROUP_UUID
                        (required) Group domain UUID.
  -o ORG_UUID, --org-uuid ORG_UUID
                        Restrict valid domains and group to an org UUID.
  --skip-existing       By default, no checking is done for cookies already
                        assigned to the group. Providing this flag skips
                        cookies already assigned to the group. Has no effect
                        if --remove-group is given.
  --remove-group        Remove group from cookies instead of assigning.

Supply domains using one of the following options:
  -c FILE_PATH, --csv FILE_PATH
                        Supply domain names as a CSV file with domains in
                        column 1.
  -d DOMAIN, --domain DOMAIN
                        Domain names. Specify multiple domains by repeating
                        this option.

NOTE: This command requires a --commit flag in order to make changes in the OneTrust system.
```

### `assignOrgDomainCookiesToGroup`
Assign a group domain (by UUID) to all cookies from all domains within an org
UUID. Group must exist in org.

```
usage: ot.py [-h [command | all]] [common_options] assignOrgDomainCookiesToGroup
       -g GROUP_UUID -o ORG_UUID [--skip-existing] [--remove-group]

options:
  -g GROUP_UUID, --group-uuid GROUP_UUID
                        (required) Group domain UUID.
  -o ORG_UUID, --org-uuid ORG_UUID
                        (required) Org UUID.
  --skip-existing       By default, no checking is done for cookies already
                        assigned to the group. Providing this flag skips
                        cookies already assigned to the group. Has no effect
                        if --remove-group is given.
  --remove-group        Remove group from cookies instead of assigning.

NOTE: This command requires a --commit flag in order to make changes in the OneTrust system.
```

### `completeOrgAssignToGroup`
Runs both assignOrgDomainsToGroup and assignOrgDomainCookiesToGroup. Assigns
all domains in a given org UUID to a group domain UUID, and the group domain
to all org domain cookies.

```
usage: ot.py [-h [command | all]] [common_options] completeOrgAssignToGroup
       -g GROUP_UUID -o ORG_UUID [--skip-existing] [--remove-group]

options:
  -g GROUP_UUID, --group-uuid GROUP_UUID
                        (required) Group domain UUID.
  -o ORG_UUID, --org-uuid ORG_UUID
                        (required) Org UUID.
  --skip-existing       By default, no checking is done for cookies already
                        assigned to the group. Providing this flag skips
                        cookies already assigned to the group. Has no effect
                        if --remove-group is given.
  --remove-group        Remove group from cookies instead of assigning.

NOTE: This command requires a --commit flag in order to make changes in the OneTrust system.
```

### `fetchDomainScript`

Fetch the latest published script for a given domain.

```
usage: ot.py [-h [command | all]] [common_options] fetchDomainScript
       [--commit] [-v] [--api-domain API_DOMAIN] [--debug]
       [--include-log-time] [--indent INDENT] -d DOMAIN
       [--script-type SCRIPT_TYPE]

options:
  -d DOMAIN, --domain DOMAIN, -g DOMAIN, --group-uuid DOMAIN
                        (required) Domain to publish. May be a domain name or
                        UUID.
  --script-type SCRIPT_TYPE
                        Type of the script. It can be 'test' or 'prod'.
                        Default 'prod'.
```

### `publishDomainScript`

EXPERIMENTAL. Publishes a given domain's scripts. This function is not done automatically as the API has historically been unstable. You may still have to publish manually through the OneTrust web admin.

```
usage: ot.py [-h [command | all]] [common_options] publishDomainScript
       [--commit] [-v] [--api-domain API_DOMAIN] [--debug]
       [--include-log-time] [--indent INDENT] -d DOMAIN [-o ORG_UUID]
       [--script-type SCRIPT_TYPE] [--autoblock-enabled AUTOBLOCK_ENABLED]
       [--enable-common-trackers ENABLE_COMMON_TRACKERS]
       [--language-detection {html,visitor,no,false}] [--languages LANGUAGES]
       [--require-reconsent] [--suppress-banner] [--suppress-pc]


options:
  -d DOMAIN, --domain DOMAIN, -g DOMAIN, --group-uuid DOMAIN
                        (required) Domain to publish. May be a domain name or
                        UUID.
  -o ORG_UUID, --org-uuid ORG_UUID
                        Specifying an org UUID will limit the initial
                        domain check to that org. The domain must exist
                        within the org.
  --script-type SCRIPT_TYPE
                        Type of the script. It can be 'test' or 'prod'. If
                        nothing is provided by the user, both test and prod
                        scripts will be published.
  --autoblock-enabled AUTOBLOCK_ENABLED
                        Auto-blocking leverages an additional script that must
                        be added to the website to block tracking technologies
                        based on the source setting them. Defaults to 'yes'
  --enable-common-trackers ENABLE_COMMON_TRACKERS
                        Set auto-blocking to block known trackers. Default
                        'yes'. Has no effect when autoblock is disabled.
  --language-detection {html,visitor,no,false}
                        Automatically detect the language of the website
                        visitor. Default 'html'.
  --languages LANGUAGES
                        Publish only a specific subset of languages, specified
                        as a comma-delimited string without spaces, e.g.
                        English,Spanish
  --require-reconsent   Providing this flag will force visitors to be
                        re-prompted for consent.
  --suppress-banner     Prevent banner from automatically displaying on
                        initial page load. If set, you must manually invoke
                        the banner in your own page scripting.
  --suppress-pc         Do not fetch preference center code until visitor
                        interacts with the banner.

NOTE: This command requires a --commit flag in order to make changes in the
OneTrust system.
```