#!/bin/bash

# Params check, what is the cp4i namespace?
cp4iNamespace="${cp4iNamespace:-integration}"
commonServicesNamespace="${commonServicesNamespace:-ibm-common-services}"
cp4iInstanceId="${cp4iInstanceId:-integration-fs34sd}"

# Keycloak info
keycloakUrl="keycloak-keycloak.apps.hawking-keycloak.cp.fyre.ibm.com"
keycloakRealm="cp4i"
keycloakClientName="cloudPakForIntegration"
keycloakClientSecret="bFIDvqn0orTthDr1jUImkTvyfpxyCIBx"
keycloakAdminPass="icp4iprivate1"
keycloakApiEndpoint="$keycloakUrl/admin/realms/$keycloakRealm"

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
    --data-urlencode "client_id=$cp4iClientId" \
    --data-urlencode "client_secret=$cp4iClientSecret" \
    --data-urlencode "grant_type=password" \
    | jq -r .access_token)"
}

function getKeycloakcsAccessToken {
   keycloakAccessToken="$(curl -ks --location "https://$keycloakUrl/realms/$keycloakRealm/protocol/openid-connect/token" \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "password=$keycloakAdminPass" \
    --data-urlencode "username=admin" \
    --data-urlencode "client_id=$keycloakClientName" \
    --data-urlencode "client_secret=$keycloakClientSecret" \
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
    teamId="$(echo "$team" | jq -r .teamId)"
    teamName="$(echo "$team" | jq -r .name)"
    teamType="$(echo "$team" | jq -r .type)"
    teamNamespaces=""
    # teamUsers=$(echo "$1" | jq -r ".users | map(.userId)")
    # teamRoles=$(echo $1 | jq -r ".users | map(.roles)| flatten | map(.id) | unique")

    if [ "$teamType" == "System" ]
    then
        echo ""
        echo "$teamName is as system team, ignoring..."
    else
        # Do some teamwork
        echo " Processing $teamName..."

        getTeamUsers "$team" # sets teamAdmins, teamEditors, teamViewers
        getTeamGroups "$team" # sets groupAdmins, groupEditors, groupViewers
        getResourcesForTeam "$teamId" # sets $teamNamespaces

        # Keycloak pre-reqs
        getKeycloakcsAccessToken
        getClientId
        getClientRoleIds
        # End Keycloak pre-reqs
        
        processAdmins
        processEditors
        processViewers
    fi
}

function getResourcesForTeam() {
    # echo ""
    # echo "Getting resources for team"
    teamId="$1"
    namespaceResources="$(curl -ks "https://$cpConsole/idmgmt/identity/api/v1/teams/$teamId/resources" \
    --header "Authorization: Bearer $csAccessToken")"

    if [[ $csTeams == Error* ]]
    then
        echo ""
        echo "An error occurred getting resources for team ($teamId)"
        teamNamespaces="[]"
    else
        teamNamespaces="$(echo "$namespaceResources" | jq -r '. | map(select(.scope == "namespace")| .namespaceId)')"
    fi
}

function getTeamUsers() {
    # echo ""
    # echo "Getting filtered lists of admin, editor and viewer users"

    teamAdmins="$(echo $1 | jq -r ".users | map(select(.roles[].id == \"crn:v1:icp:private:iam::::role:Administrator\")) | map(.userId)")" # Need to consider CloudPak admin etc
    teamEditors="$(echo $1 | jq -r ".users | map(select(.roles[].id == \"crn:v1:icp:private:iam::::role:Editor\" or .roles[].id == \"crn:v1:icp:private:iam::::role:Operator\")) | map(.userId)")"
    teamViewers="$(echo $1 | jq -r ".users | map(select(.roles[].id == \"crn:v1:icp:private:iam::::role:Viewer\")) | map(.userId)")"
}

function getTeamGroups() {
    # echo ""
    # echo "Getting filtered lists of admin, editor and viewer users"
    groupAdmins="$(echo $1 | jq -r ".usergroups | map(select(.roles[].id == \"crn:v1:icp:private:iam::::role:Administrator\")) | map(.name)")" # TODO - Need to consider CloudPak admin etc
    groupEditors="$(echo $1 | jq -r ".usergroups | map(select(.roles[].id == \"crn:v1:icp:private:iam::::role:Editor\" or .roles[].id == \"crn:v1:icp:private:iam::::role:Operator\")) | map(.name)")"
    groupViewers="$(echo $1 | jq -r ".usergroups | map(select(.roles[].id == \"crn:v1:icp:private:iam::::role:Viewer\")) | map(.name)")"
}

function processAdmins {
  # process users first
  userCount="$(echo "$teamAdmins" | jq -r length)"
  if [[ "$userCount" -eq "0" ]]; 
  then
    echo "No admins to process"
  else
    createTeam "$teamName:$cp4iInstanceId:administrators" "$cp4iAdminRoleUid" "administrator" "$teamAdmins"
  fi

  # process groups
  groupCount="$(echo "$groupAdmins" | jq -r length)"
  if [[ "$groupCount" -eq "0" ]]; 
  then
    echo "No admin groups to process"
  else
    echo "Adding administrator role to LDAP groups in $teamName"
    # Loop round each group
    processLdapGroups "$groupAdmins"
  fi
}

function processEditors {
  # process users first
  userCount="$(echo "$teamEditors" | jq -r length)"
  if [[ "$userCount" -eq "0" ]]; 
  then
    echo "No editors to process"
  else
    createTeam "$teamName:$cp4iInstanceId:editors"
  fi

  # process groups
  groupCount="$(echo "$groupEditors" | jq -r length)"
  if [[ "$groupCount" -eq "0" ]]; 
  then
    echo "No editor groups to process"
  else
    echo "Adding editor role to LDAP groups in $teamName"
  fi
}

function processViewers {
  # process users first
  userCount="$(echo "$teamViewers" | jq -r length)"
  if [[ "$userCount" -eq "0" ]]; 
  then
    echo "No viewers to process"
  else
    createTeam "$teamName:$cp4iInstanceId:viewers"
  fi

  # process groups
  groupCount="$(echo "$groupViewers" | jq -r length)"
  if [[ "$groupCount" -eq "0" ]]; 
  then
    echo "No viewer groups to process"
  else
    echo "Adding viewer role to LDAP groups in $teamName"
  fi
}

function createTeam() { # $1 = teamName $2=roleId $3=roleName $4=users
  echo "Creating $1"
  curl -ks --location "https://$keycloakApiEndpoint/groups" \
  --header "Content-Type: application/json" \
  --header "Authorization: Bearer $keycloakAccessToken" \
  --data "{
    \"name\": \"$1\",
    \"attributes\": {
        \"integration.ibm.com/migrated\": [true],
        \"integration.ibm.com/namespaces\": $teamNamespaces
    }
}"
  getGroupId "$1"
  addRoleToGroup "$2" "$3" "$groupId"
  addUsersToGroup "$groupId" "$4"
  echo ""

}

# If the client ID is the same as the name, we don't need to do this!
function getClientId {
  cp4iClientId="$(curl -ks --location "https://$keycloakApiEndpoint/clients" \
    --header "Authorization: Bearer $keycloakAccessToken" \
   | jq -r ". | map(select(.name == \"$keycloakClientName\")) | .[].id")"

  if [ -z "$cp4iClientId" ]
  then
        echo ""
        echo "Unable to find $keycloakClientName in realm $keycloakRealm, exiting..."
        exit 1
  fi
}

function getGroupId() { # $1 = group name
  clientGroups="$(curl -ks --location "https://$keycloakApiEndpoint/groups" \
    --header "Authorization: Bearer $keycloakAccessToken")"
  groupId="$(echo $clientGroups | jq -r ". | map(select(.name == \"$1\")) | .[].id")"
}

function getClientRoleIds {
  cp4iRoles="$(curl -ks --location "https://$keycloakApiEndpoint/clients/$cp4iClientId/roles" \
    --header "Authorization: Bearer $keycloakAccessToken")"

  cp4iAdminRoleUid="$(echo $cp4iRoles | jq -r ". | map(select(.name == \"administrator\")) | .[].id")"
  cp4iEditorRoleUid="$(echo $cp4iRoles | jq -r ". | map(select(.name == \"editor\")) | .[].id")"
  cp4iViewerRoleUid="$(echo $cp4iRoles | jq -r ". | map(select(.name == \"viewer\")) | .[].id")"

  if [ -z "$cp4iAdminRoleUid" ]
  then
    echo ""
    echo "Unable to find administrator role in client $keycloakClientName, exiting..."
    exit 1
  fi
  if [ -z "$cp4iEditorRoleUid" ]
  then
    echo ""
    echo "Unable to find editor role in client $keycloakClientName, exiting..."
    exit 1
  fi
  if [ -z "$cp4iViewerRoleUid" ]
  then
    echo ""
    echo "Unable to find viewer role in client $keycloakClientName, exiting..."
    exit 1
  fi
}

function addRoleToGroup() { # $1=roleId $2=roleName $3=groupId
  curl -ks --location "https://$keycloakApiEndpoint/groups/$3/role-mappings/clients/$cp4iClientId" \
  --header "Content-Type: application/json" \
  --header "Authorization: Bearer $keycloakAccessToken" \
  --data "[
      {
        \"id\": \"$1\",
        \"name\": \"$2\"
      }
  ]"
}

function processLdapGroups() { # $1 = groups $2 = roleId $3 = roleName
  echo "$1" | jq -r '.[]' | while read i; do
    getGroupId "$i"
    if [ -z "$groupId" ]
    then
      echo ""
      echo "Unable to group $i, ignoring import..."
      echo ""
    else
      addRoleToGroup "$cp4iAdminRoleUid" "administrator" "$groupId" "$cp4iClientId"
      # Add attributes to the group
      addAttributesToGroup "$groupId" "{ \"integration.ibm.com/migrated\": [true], \"integration.ibm.com/namespaces\": $teamNamespaces }"
    fi
  done
}

function addUsersToGroup() { # $1= groupId, $2= users
  echo "$2" | jq -r '.[]' | while read i; do
    searchResults="$(curl -ks --location "https://$keycloakApiEndpoint/users?search=$i" \
      --header "Authorization: Bearer $keycloakAccessToken")"
    searchCount="$(echo "$searchResults" | jq -r length)"
    if [[ "$searchCount" -eq "1" ]]; 
    then
      userId="$(echo "$searchResults" | jq -r '.[].id')"
      curl -ks --location --request PUT "https://$keycloakApiEndpoint/users/$userId/groups/$1" \
      --header "Content-Type: application/json" \
      --header "Authorization: Bearer $keycloakAccessToken"
    else
      echo "Unable to onboard user $i"
    fi
  done
}

function addAttributesToGroup() { #$1= groupId $2=attributes
  groupMetaData="$(curl -ks --location "https://$keycloakApiEndpoint/groups/$1" \
    --header "Authorization: Bearer $keycloakAccessToken")"
  groupMetaDataWithAttributes="$(echo $groupMetaData | jq -r ".attributes += $2")"

  curl -ks --location --request PUT "https://$keycloakApiEndpoint/groups/$1" \
  --header "Content-Type: application/json" \
  --header "Authorization: Bearer $keycloakAccessToken" \
  --data "$groupMetaDataWithAttributes"
}

### End Functions

### MAIN ###

echo "Starting IAM to keycloak migration..."

# Make sure we are oc logged in
echo ""
echo "Checking we are logging into a cluster..."
currentUser=$(oc whoami)
if [ $? -eq 1 ]
then
  echo "You must be oc logged in before continuing. Exiting..."
  exit 1
fi

# Check we have jq installed!!


# Get cp-console url and admin cred secret
echo ""
echo "Getting cp4i information..."

# Get name of the PN
cp4iName="$(oc get platformnavigators -n $cp4iNamespace -o jsonpath='{.items[0].metadata.name}')"

# Get CP console route
cpConsole="$(oc get route -n $commonServicesNamespace cp-console -o jsonpath="{.spec.host}")"


# Secrets Names
idpCredentialsSecretName="ibm-iam-bindinfo-platform-auth-idp-credentials"
oidcSecretName="$cp4iName-ibm-inte-3c22-oidc-client"

# Secrets data
idpCredentialsData="$(oc get secret $idpCredentialsSecretName -n $cp4iNamespace -o json | jq -r .data)"
oidcSecretData="$(oc get secret $oidcSecretName -n $cp4iNamespace -o json | jq -r .data)"

cpAdminUserName="$(echo "$idpCredentialsData" | jq -r .admin_username | base64 -D)"
cpAdminUserPass="$(echo "$idpCredentialsData" | jq -r .admin_password | base64 -D)"
cp4iClientId="$(echo "$oicsSecretData" | jq -r .CLIENT_ID | base64 -D)"
cp4iClientSecret="$(echo "$oicsSecretData" | jq -r .CLIENT_SECRET | base64 -D)"

# Check if keycloak is installed...otherwise we cannot continue

getCsAccessToken

getCsTeams

# Log out how many teams we have found?!?

echo "$csTeams" | jq -c '.[]' | while read i; do
    processTeam $i
done

echo "Finished IAM to keycloak migration"
