#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace

function usage() {
    if [ -n "${1:-}" ]; then
        echo "$@" > /dev/stderr
        echo "" > /dev/stderr
    fi
    echo "$0

Migration tool for moving from IBM Cloud Pak foundational services Identity and Access Management (IAM) to Red Hat build of Keycloak (RHBK) provided as a service using IBM Cloud Pak foundational services.

Dependencies:
    oc
    jq

Usage:
    $0 <namespace>

Parameters:
    namespace
        The namespace of your CP4I installation.
    -d <directory>
        Directory to store temporary files

Environment Variables:
    IAM_NAMESPACE
        Override the IAM namespace instead of automatically detecting it.
    KEYCLOAK_NAMESPACE
        Override the Keycloak namespace instead of automatically detecting it.
" > /dev/stderr

    exit 1
}

function fatal ()
{
    echo "FATAL: $*" > /dev/stderr
    exit 1
}

function debug ()
{
    if [[ -n "${DEBUG+x}" ]]; then
        echo "$@" > /dev/stderr
    fi
}

# Consts
keycloakRealm="master"
keycloakCloudPakRealm="cloudpak"
checkAgainstKeycloak="true"

csLdapConnections="csLdapConnections.json"
csSamlConnections="csSamlConnections.json"
csOidcConnections="csOidcConnections.json"
keycloakLdapConnections="keycloakLdapConnections.json"
keycloakIdpConnections="keycloakIdpConnections.json"

### Functions
# Get an access token
function getCsAccessToken {
    echo ""
    echo "Generating Common services access token..."
    csAccessToken="$(curl -ks --location "https://$cpConsole/idprovider/v1/auth/identitytoken" \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "username=$cpAdminUserName" \
    --data-urlencode "password=$cpAdminUserPass" \
    --data-urlencode "scope=openid" \
    --data-urlencode "grant_type=password" \
    | jq -r .access_token)"
}

function getKeycloakcsAccessToken {
    echo ""
    echo "Generating Keycloak access token..."
    keycloakAccessToken="$(curl -ks --location "https://$keycloakUrl/realms/$keycloakRealm/protocol/openid-connect/token" \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "password=$keycloakAdminPass" \
    --data-urlencode "username=admin" \
    --data-urlencode "client_id=admin-cli" \
    --data-urlencode "grant_type=password" \
    | jq -r .access_token)"
}

function getCsTeams {
    echo ""
    echo "Getting IAM teams"
    csTeams="$(curl -ks "https://$cpConsole/idmgmt/identity/api/v1/teams" \
    --header "Authorization: Bearer $csAccessToken")"

    # Check we have not got an error
    if [[ $csTeams == Error* ]]
    then
        echo ""
        echo "An error occurred getting IAM teams, Exiting..."
        exit 1
    fi
}

function processTeam() {
    echo ""
    team="$1"
    teamName="$(echo "$team" | jq -r .name)"
    teamType="$(echo "$team" | jq -r .type)"

    # Ignore "System" teams
    if [ "$teamType" == "Custom" ]
    then
        # Do some teamwork
        echo "$teamName team"
        echo "================"

        getTeamUsers "$team" # sets teamAdmins, teamViewers
        getTeamGroups "$team" # sets groupAdmins, groupViewers

        teamAdminsCount="$(echo "$teamAdmins" | jq -r length)"
        teamViewersCount="$(echo "$teamViewers" | jq -r length)"
        groupAdminsCount="$(echo "$groupAdmins" | jq -r length)"
        groupViewersCount="$(echo "$groupViewers" | jq -r length)"

        if [[ "$teamAdminsCount" -eq "0" ]] && [[ "$teamViewersCount" -eq "0" ]] && [[ "$groupAdminsCount" -eq "0" ]] && [[ "$groupViewersCount" -eq "0" ]];
        then
          # Nothing to do for this team
          echo "[x] No users or groups to migrate"
        else
          # Need to tell the user to add a mapper in keycloak to pick up these groups
          processAdmins
          processViewers
        fi
    fi
}

adminsQuery="map(select(.roles[].id == \"crn:v1:icp:private:iam::::role:ClusterAdministrator\" or .roles[].id == \"crn:v1:icp:private:iam::::role:CloudPakAdministrator\" or .roles[].id == \"crn:v1:icp:private:iam::::role:Administrator\""
viewersQuery="map(select(.roles[].id == \"crn:v1:icp:private:iam::::role:Editor\" or .roles[].id == \"crn:v1:icp:private:iam::::role:Operator\" or .roles[].id == \"crn:v1:icp:private:iam::::role:Viewer\" or .roles[].id == \"crn:v1:icp:private:iam::::role:Auditor\""

function getTeamUsers() {
    teamAdmins="$(echo "$1" | jq -r ".users | $adminsQuery)) | map(.userId)")"
    teamViewers="$(echo "$1" | jq -r ".users | $viewersQuery)) | map(.userId)")"
}

function getTeamGroups() {
    groupAdmins="$(echo "$1" | jq -r ".usergroups | $adminsQuery)) | map(.name)")"
    groupViewers="$(echo "$1" | jq -r ".usergroups | $viewersQuery)) | map(.name)")"
}

function processAdmins {
  # process users first
  userCount="$(echo "$teamAdmins" | jq -r length)"
  groupName="$teamName-admins"
  groupRole="admin"
  if [[ "$userCount" -gt "0" ]]; 
  then
    users=$(echo "$teamAdmins" | jq -r '. | join(", ")')
    groupCreated=" "
    usersAdded=" "
    roleAdded=" "
    if [[ "$checkAgainstKeycloak" == "true" ]]
    then
      checkIfGroupRoleAndUsersMigrated "true" "$teamAdmins"
    fi
    echo "[$groupCreated] Create a group in the $keycloakCloudPakRealm realm called $groupName"
    echo "[$usersAdded] Add user/s $users to $groupName group"
    echo "[$roleAdded] Assign $groupRole role mapping (from $cp4iKeycloakClientId) to $groupName group"
  fi

  # process groups
  groupCount="$(echo "$groupAdmins" | jq -r length)"
  if [[ "$groupCount" -gt "0" ]]; 
  then
    # Loop through each group
    echo "$groupAdmins" | jq -r '.[]' | while read -r i; do
        groupName="$i"
        roleAdded=" "
        if [[ "$checkAgainstKeycloak" == "true" ]]
        then
          checkIfGroupRoleAndUsersMigrated "false"
        fi
        echo "[$roleAdded] Assign $groupRole role mapping (from $cp4iKeycloakClientId) to existing LDAP group $i"
    done
  fi
  echo ""
}

function processViewers {
  # process users first
  userCount="$(echo "$teamViewers" | jq -r length)"
  users=$(echo "$teamViewers" | jq -r '. | join(", ")')
  groupName="$teamName-viewers"
  groupRole="viewer"
  if [[ "$userCount" -gt "0" ]]; 
  then
    groupCreated=" "
    usersAdded=" "
    roleAdded=" "
    if [[ "$checkAgainstKeycloak" == "true" ]]
    then
      checkIfGroupRoleAndUsersMigrated "true" "$teamViewers"
    fi
    echo "[$groupCreated] Create a group in the $keycloakCloudPakRealm realm called $groupName"
    echo "[$usersAdded] Add user/s $users to $groupName group"
    echo "[$roleAdded] Assign $groupRole role mapping (from $cp4iKeycloakClientId) to $groupName group"
  fi

  # process groups
  groupCount="$(echo "$groupViewers" | jq -r length)"
  if [[ "$groupCount" -gt "0" ]]; 
  then
    # Loop through each group
    echo "$groupViewers" | jq -r '.[]' | while read -r i; do
        groupName="$i"
        roleAdded=" "
        if [[ "$checkAgainstKeycloak" == "true" ]]
        then
          checkIfGroupRoleAndUsersMigrated "false"
        fi
        echo "[$roleAdded] Assign $groupRole role mapping (from $cp4iKeycloakClientId) to existing LDAP group $i"
    done
  fi
  echo ""
}

function inspectTeams {
  echo "$csTeams" | jq -c '.[]' | while read -r i; do
      processTeam "$i"
  done
}

function checkForLdapConnections {
  # https://www.ibm.com/docs/en/cloud-paks/foundational-services/3.23?topic=apis-directory-management#list
  curl -ks "https://$cpConsole/idmgmt/identity/api/v1/directory/ldap/list" \
       --header "Authorization: Bearer $csAccessToken" > "$datadir/$csLdapConnections"
  # Check we have not got an error
  if grep ^Error "$datadir/$csLdapConnections" > /dev/null 2>&1; then
      echo ""
      echo "An error occurred checking LDAP connections, Exiting..."
      exit 1
  fi
}

function checkForSamlConnections {
  # https://www.ibm.com/docs/en/cloud-paks/foundational-services/3.23?topic=apis-identity-provider#saml-uid-idpv3
  curl -ks "https://$cpConsole/idprovider/v3/auth/idsource?protocol=saml" \
       --header "Authorization: Bearer $csAccessToken" > "$datadir/$csSamlConnections"

  # Check we have not got an error
  if grep ^Error "$datadir/$csSamlConnections" > /dev/null 2>&1; then
      echo ""
      echo "An error occurred checking SAML connections, Exiting..."
      exit 1
  fi
}

function checkForOidcConnections {
  # https://www.ibm.com/docs/en/cloud-paks/foundational-services/3.23?topic=apis-identity-provider#saml-uid-idpv3
  curl -ks "https://$cpConsole/idprovider/v3/auth/idsource?protocol=oidc" \
       --header "Authorization: Bearer $csAccessToken" > "$datadir/$csOidcConnections"

  # Check we have not got an error
  if grep ^Error "$datadir/$csOidcConnections" > /dev/null 2>&1; then
      echo ""
      echo "An error occurred checking OIDC connections, Exiting..."
      exit 1
  fi
}

function getKeycloakLdapConnections {
  curl -ks "https://$keycloakUrl/admin/realms/$keycloakCloudPakRealm/components?type=org.keycloak.storage.UserStorageProvider" \
       --header "Authorization: Bearer $keycloakAccessToken" > "$datadir/$keycloakLdapConnections"

  # Check we have not got an error
  hasError="$(jq 'if type=="array" then false else has("error") end' "$datadir/$keycloakLdapConnections")"
  if [ "$hasError" == "true" ]
  then
      echo ""
      echo "An error occurred checking LDAP connections in keycloak, Exiting..."
      exit 1
  fi
}

function getKeycloakIdpConnections {
  curl -ks "https://$keycloakUrl/admin/realms/$keycloakCloudPakRealm/identity-provider/instances" \
       --header "Authorization: Bearer $keycloakAccessToken" > "$datadir/$keycloakIdpConnections"

  # Check we have not got an error
  hasError="$(jq 'if type=="array" then false else has("error") end' "$datadir/$keycloakIdpConnections")"
  if [ "$hasError" == "true" ]
  then
      echo ""
      echo "An error occurred checking SAML connections in keycloak, Exiting..."
      exit 1
  fi
}

function inspectIdpConnections {
  ldapCount="$(jq -r length "$datadir/$csLdapConnections")"
  samlCount="$(jq -r '.idp | length' "$datadir/$csSamlConnections")"
  oidcCount="$(jq -r '.idp | length' "$datadir/$csOidcConnections")"

  if [[ "$ldapCount" -gt "0" ]]; 
  then
    if [[ "$checkAgainstKeycloak" == "true" ]]
    then
      getKeycloakLdapConnections
    fi
    
    echo "LDAP connections"
    echo "================"
    jq -c '.[]' "$datadir/$csLdapConnections" | while read -r i; do
      ldapConnection=$i
      ldapName="$(echo "$ldapConnection" | jq -r .LDAP_ID)"
      ldapUrl="$(echo "$ldapConnection" | jq -r .LDAP_URL)"
      migrated=" "

      if [[ "$checkAgainstKeycloak" == "true" ]]
      then
        # Check if the LDAP connection is added to keycloak
        ldapsFound="$(jq -r ". | map(select(.name == \"$ldapName\"))" "$datadir/$keycloakLdapConnections")"
        ldapCount="$(echo "$ldapsFound" | jq -r length)"
        if [[ "$ldapCount" -eq "1" ]]
        then
          migrated="x"
        fi
      fi

      echo "[$migrated] Migrate $ldapName - $ldapUrl"
    done
  fi

  if [[ "$samlCount" -gt "0" ]]; 
  then
    if [[ "$checkAgainstKeycloak" == "true" ]]
    then
      # Check if the SAML connection has been migrated
      getKeycloakIdpConnections
    fi

    echo ""
    echo "SAML connections"
    echo "================"
    jq -c '.idp[]' "$datadir/$csSamlConnections" | while read -r i; do
      samlConnection=$i
      samlName="$(echo "$samlConnection" | jq -r .name)"
      migrated=" "

      if [[ "$checkAgainstKeycloak" == "true" ]]
      then
        # Check if the SAML connection is added to keycloak
        samlsFound="$(jq -r ". | map(select(.alias == \"$samlName\"))" "$datadir/$keycloakIdpConnections")"
        samlCount="$(echo "$samlsFound" | jq -r length)"
        if [[ "$samlCount" -eq "1" ]]
        then
          migrated="x"
        fi
      fi
      echo "[$migrated] Migrate $samlName"
    done
  fi

  if [[ "$oidcCount" -gt "0" ]]; 
  then
    # TODO - Check OIDC connection in Keycloak
    echo "OIDC connections"
    echo "================"
    jq -c '.idp[]' "$datadir/$csOidcConnections" | while read -r i; do
      oidcConnection=$i
      oidcName="$(echo "$oidcConnection" | jq -r .name)"
      oidcUrl="$(echo "$oidcConnection" | jq -r .idp_config.discovery_url)"
      echo "[ ] Migrate $oidcName - $oidcUrl"
    done
  fi
}

function getKeycloakGroup() {
  keycloakGroups="$(curl -ks "https://$keycloakUrl/admin/realms/$keycloakCloudPakRealm/ui-ext/groups?search=$1&exact=true" \
  --header "Authorization: Bearer $keycloakAccessToken")"

  # Check we have not got an error
  hasError="$(echo "$keycloakGroups" | jq 'if type=="array" then false else has("error") end')"
  if [ "$hasError" == "true" ]
  then
      echo ""
      echo "An error occurred getting groups in keycloak, Exiting..."
      exit 1
  fi
}

function getMembersFromGroup() {
    keycloakGroupMembers="$(curl -ks "https://$keycloakUrl/admin/realms/$keycloakCloudPakRealm/groups/$1/members" \
  --header "Authorization: Bearer $keycloakAccessToken")"

  # Check we have not got an error
  hasError="$(echo "$keycloakGroupMembers" | jq 'if type=="array" then false else has("error") end')"
  if [ "$hasError" == "true" ]
  then
      echo ""
      echo "An error occurred getting members for group $1 in keycloak, Exiting..."
      exit 1
  else
    keycloakGroupMembers="$(echo "$keycloakGroupMembers" | jq -r "map(.username)")"
  fi
}

function checkIfGroupRoleAndUsersMigrated() {
  getMembers="$1"
  groupMembers="$2"
  # Has the group been created?
  getKeycloakGroup "$groupName"
  groupFound="$(echo "$keycloakGroups" | jq -r length)"

  # Put into a function?
  if [[ "$groupFound" -eq "1" ]]
  then
    groupCreated="x"
    # Has the role been added to the group?
    # Check if we can see our client id under clientRoles, then check if the array contains the role
    hasRolesFromClient="$(echo "$keycloakGroups" | jq -r ".[0].clientRoles | has(\"$cp4iKeycloakClientId\")")"
    if [[ "$hasRolesFromClient" == "true" ]]
    then
      roles="$(echo "$keycloakGroups" | jq -r ".[0].clientRoles[\"$cp4iKeycloakClientId\"]")"
      containsRole="$(echo "$roles" | jq -r ".[] | contains(\"$groupRole\")")"
      if [[ "$containsRole" == "true" ]]
      then
        roleAdded="x"
      fi
    fi
    if [[ "$getMembers" == "true" ]]
    then
      # Check if users have been added
      groupId="$(echo "$keycloakGroups" | jq -r ".[0].id")"
      getMembersFromGroup "$groupId"

      # Have any members been added to the team?
      memberCount=$(echo "$keycloakGroupMembers" | jq -r length)
      if [[ "$memberCount" -gt "0" ]]
      then
        # Have all users been added?
        allUsersAdded="$(jq --null-input "$groupMembers - $keycloakGroupMembers" | jq -r length)"
        if [[ "$allUsersAdded" -eq "0" ]]
        then
          usersAdded="x"
        fi
      fi
    fi
  fi
}

### End Functions

### MAIN ###

## Check parameters and environment

while getopts ":d:" o; do
    case "${o}" in
        d)
            datadir="${OPTARG%/}"
            mkdir -p "$datadir"
            ;;
        *)
            usage "$OPTARG not a recognised parameter"
            ;;
    esac
done
shift $((OPTIND-1))

if [ -z "${1-}" ]; then
    usage "ERROR: No namespace specified"
fi

namespace="${1}"

# If we don't have a data dir, make a temporary one and cleanup after the run
if [ -z "${datadir-}" ]; then
    datadir=$(mktemp -d)
    cleanup()
    {
      rm -rf "${datadir}"
    }
    trap cleanup EXIT
fi

if [ ! -x "$(command -v oc)" ]; then echo "You need the OpenShift CLI tool, oc"; exit 1; fi
if [ ! -x "$(command -v jq)" ]; then echo "You need jq: https://jqlang.github.io/jq/download"; exit 1; fi

# Make sure we are oc logged in
echo ""
echo "Checking we are logged into a cluster..."
if ! oc whoami > /dev/null
then
  echo "You must be oc logged in before continuing. Exiting..."
  exit 1
fi

# Get cp-console url and admin cred secret
echo ""
echo "Getting login information from the cluster..."

## Get a CPFS IAM token

# Work out what namespace IAM is in
iamNamespace="${IAM_NAMESPACE:-}"
if [ -z "$iamNamespace" ]; then
  # Logic for IAM namespace:
  # - If cp4i used an isolated bedrock 3, IAM is in namespace
  # - If cp4i used a cluster scoped bedrock 3, IAM is likely to be in ibm-common-services
  # Try the cp4i namespace, and if its not there, try ibm-common-services
  if oc get route cp-console -n "${namespace}" > /dev/null 2>&1; then
    iamNamespace="${namespace}"
  elif oc get route cp-console -n ibm-common-services > /dev/null 2>&1; then
    iamNamespace=ibm-common-services
  else
    fatal "Could not find cp-console route in either the ${namespace} or ibm-common-services namespace. Set the IAM_NAMESPACE environment variable to use a custom namespace."
  fi
fi

# Get login details
idpCredentialsSecretName="platform-auth-idp-credentials"
cpConsole="$(oc get route -n "${iamNamespace}" cp-console -o jsonpath="{.spec.host}")"
cpAdminUserName="$(oc get secret -n "${iamNamespace}" "$idpCredentialsSecretName" -o jsonpath="{.data.admin_username}" | base64 -d)"
cpAdminUserPass="$(oc get secret -n "${iamNamespace}" "$idpCredentialsSecretName" -o jsonpath="{.data.admin_password}" | base64 -d)"

getCsAccessToken

if [[ "$checkAgainstKeycloak" == "true" ]]
then
  servicesNamespace="${KEYCLOAK_NAMESPACE:-}"
  if [ -z "$servicesNamespace" ]; then
    # Logic for services namespace:
    # - If cp4i is cluster scoped, CommonService in openshift-operators
    # - If cp4i is namespace scoped, CommonService in namespace
    # Try the namespace, and if its not there, try openshift-operators
    if oc get commonservice.operator.ibm.com common-service -n "${namespace}" > /dev/null 2>&1; then
      csOperatorNamespace="${namespace}"
    elif oc get commonservice.operator.ibm.com common-service -n openshift-operators > /dev/null 2>&1; then
      csOperatorNamespace=openshift-operators
    else
      fatal "Could not find CommonService resource in either the ${namespace} or openshift-operators namespace. Set the KEYCLOAK_NAMESPACE environment variable to use a custom namespace."
    fi
    servicesNamespace="$(oc get commonservice.operator.ibm.com common-service -n "${csOperatorNamespace}" -o jsonpath="{.spec.servicesNamespace}")"
  fi

  # Get the keycloak url
  keycloakUrl="$(oc get route -n "$servicesNamespace" keycloak -o jsonpath="{.spec.host}")"
  # Get the name of the keycloak client
  cp4iKeycloakClientId="$(oc get integrationkeycloakclient.keycloak.integration.ibm.com -l app.kubernetes.io/name=ibm-integration-platform-navigator -n "$servicesNamespace" -o jsonpath='{.items[0].spec.client.clientId}')"

  keycloakAdminSecretName="cs-keycloak-initial-admin"
  keycloakAdminPass="$(oc get secret "$keycloakAdminSecretName" -n "$servicesNamespace" -o jsonpath="{.data.password}" | base64 -d)"

  getKeycloakcsAccessToken
fi

echo ""
echo "Starting IAM migration helper script..."
echo ""

# Check what LDAPs and IDPs we have

echo "Checking connections to Common services"
checkForLdapConnections
checkForSamlConnections
checkForOidcConnections

# Check what teams we have set up
getCsTeams

echo ""
echo "Generating checklist..."
echo ""

# First logout the connections
inspectIdpConnections

# Inspect all teams with users and groups
# explain what needs to be done in keycloak
inspectTeams

echo "Finished IAM migration helper script"
