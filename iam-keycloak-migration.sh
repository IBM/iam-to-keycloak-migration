#!/bin/bash

# Params check, what is the cp4i namespace?
cp4iNamespace="${cp4iNamespace:-navigator-ns}"
commonServicesNamespace="${commonServicesNamespace:-ibm-common-services}"

keycloakRealm="master"
keycloakCloudPakRealm="cloudpak"
checkAgainstKeycloak="true"

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
    echo ""
    echo "Generating Keycloak access token..."
   keycloakAccessToken="$(curl -ks --location "https://$keycloakUrl/realms/master/protocol/openid-connect/token" \
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

        getTeamUsers "$team" # sets teamAdmins, teamEditors, teamViewers
        getTeamGroups "$team" # sets groupAdmins, groupEditors, groupViewers

        # Need to tell the user to add a mapper in keycloak to pick up these groups
        
        processAdmins
        processEditors
        processViewers
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
  if [[ "$userCount" -gt "0" ]]; 
  then
    users=$(echo "$teamAdmins" | jq -r '. | join(", ")')
    echo "[ ] Create a group in the $keycloakCloudPakRealm realm called '$teamName-admins'"
    echo "[ ] Add users $users to '$teamName-admins' group"
    echo "[ ] Add 'admin' role to '$teamName-admins' group"
  fi

  # process groups
  groupCount="$(echo "$groupAdmins" | jq -r length)"
  if [[ "$groupCount" -gt "0" ]]; 
  then
    # Loop through each group
    echo "$groupAdmins" | jq -c '.[]' | while read i; do
        echo "[ ] Add 'admin' role to existing LDAP group $i"
    done
  fi
  echo ""
}

function processEditors {
  # process users first
  userCount="$(echo "$teamEditors" | jq -r length)"
  if [[ "$userCount" -gt "0" ]]; 
  then
    users=$(echo "$teamEditors" | jq -r '. | join(", ")')
    echo "[ ] Create a group in the $keycloakCloudPakRealm realm called '$teamName-editors'"
    echo "[ ] Add users $users to '$teamName-editors' group"
    echo "[ ] Add 'editor' role to '$teamName-editors' group"
  fi

  # process groups
  groupCount="$(echo "$groupEditors" | jq -r length)"
  if [[ "$groupCount" -gt "0" ]]; 
  then
    # Loop through each group
    echo "$groupEditors" | jq -c '.[]' | while read i; do
        echo "[ ] Add 'editor' role to existing LDAP group $i"
    done
  fi
  echo ""
}

function processViewers {
  # process users first
  userCount="$(echo "$teamViewers" | jq -r length)"
  if [[ "$userCount" -gt "0" ]]; 
  then
    users=$(echo "$teamViewers" | jq -r '. | join(", ")')
    echo "[ ] Create a group in the $keycloakCloudPakRealm realm called '$teamName-viewers'"
    echo "[ ] Add users $users to '$teamName-viewers' group"
    echo "[ ] Add 'viewer' role to '$teamName-viewers' group"
  fi

  # process groups
  groupCount="$(echo "$groupViewers" | jq -r length)"
  if [[ "$groupCount" -gt "0" ]]; 
  then
    # Loop through each group
    echo "$groupViewers" | jq -c '.[]' | while read i; do
        echo "[ ] Add 'viewer' role to existing LDAP group $i"
    done
  fi
  echo ""
}

function inspectTeams {
  echo "$csTeams" | jq -c '.[]' | while read i; do
      processTeam "$i"
  done
}

function checkForLdapConnections {
  ldapConnections="$(curl -ks "https://$cpConsole/idmgmt/identity/api/v1/directory/ldap/list" \
  --header "Authorization: Bearer $csAccessToken")"
  # Check we have not got an error
  if [[ $ldapConnections == Error* ]]
  then
      echo ""
      echo "An error occurred checking SAML connections, Exiting..."
      exit 1
  fi
}

function checkForSamlConnections {
  # https://www.ibm.com/docs/en/cloud-paks/foundational-services/3.23?topic=apis-identity-provider#saml-uid-idpv3
  samlConnections="$(curl -ks "https://$cpConsole/idprovider/v3/auth/idsource?protocol=saml" \
  --header "Authorization: Bearer $csAccessToken")"

  # Check we have not got an error
  if [[ $samlConnections == Error* ]]
  then
      echo ""
      echo "An error occurred checking SAML connections, Exiting..."
      exit 1
  fi
}

function checkForOidcConnections {
  # https://www.ibm.com/docs/en/cloud-paks/foundational-services/3.23?topic=apis-identity-provider#saml-uid-idpv3
  oidcConnections="$(curl -ks "https://$cpConsole/idprovider/v3/auth/idsource?protocol=oidc" \
  --header "Authorization: Bearer $csAccessToken")"
  
  # Check we have not got an error
  if [[ $oidcConnections == Error* ]]
  then
      echo ""
      echo "An error occurred checking OIDC connections, Exiting..."
      exit 1
  fi
}

function getKeycloakLdapConnections {
  keycloakLdapConnections="$(curl -ks "https://$keycloakUrl/admin/realms/$keycloakCloudPakRealm/components?type=org.keycloak.storage.UserStorageProvider" \
  --header "Authorization: Bearer $keycloakAccessToken")"

  # Check we have not got an error
  hasError="$(echo $keycloakLdapConnections | jq 'has("error")')"
  if [ "$hasError" == "true" ]
  then
      echo ""
      echo "An error occurred checking LDAP connections in keycloak, Exiting..."
      exit 1
  fi
}

function inspectIdpConnections {
  ldapCount="$(echo "$ldapConnections" | jq -r length)"
  samlCount="$(echo "$samlConnections" | jq -r '.idp | length')"
  oidcCount="$(echo "$oidcConnections" | jq -r '.idp | length')"
  
  if [[ "$ldapCount" -gt "0" ]]; 
  then
    if [[ "$checkAgainstKeycloak" == "true" ]]
    then
      getKeycloakLdapConnections
    fi
    
    echo "LDAP connections"
    echo "================"
    echo "$ldapConnections" | jq -c '.[]' | while read i; do
      ldapConnection=$i
      ldapName="$(echo $ldapConnection | jq -r .LDAP_ID)"
      ldapUrl="$(echo $ldapConnection | jq -r .LDAP_URL)"
      migrated=" "

      if [[ "$checkAgainstKeycloak" == "true" ]]
      then
        # Check if we the LDAP connection is added to keycloak
        ldapsFound="$(echo $keycloakLdapConnections | jq -r ". | map(select(.name == \"$ldapName\"))")"
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
    # TODO - Check SAML connection in Keycloak
    echo "SAML connections"
    echo "================"
    echo "$samlConnections" | jq -c '.idp[]' | while read i; do
      samlConnection=$i
      samlName="$(echo $samlConnection | jq -r .name)"
      echo "[ ] Migrate $samlName"
    done
  fi

  # Maybe we don't bother with this as it's a BETA?!?
  if [[ "$oidcCount" -gt "0" ]]; 
  then
    # TODO - Check SAML connection in Keycloak
    echo "OIDC connections"
    echo "================"
    echo "$oidcConnections" | jq -c '.idp[]' | while read i; do
      oidcConnection=$i
      oidcName="$(echo $oidcConnection | jq -r .name)"
      oidcUrl="$(echo $oidcConnection | jq -r .idp_config.discovery_url)"
      echo "[ ] Migrate $oidcName - $oidcUrl"
    done
  fi
}

### End Functions

### MAIN ###

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

# Get routes
cpConsole="$(oc get route -n $commonServicesNamespace cp-console -o jsonpath="{.spec.host}")"

if [[ "$checkAgainstKeycloak" == "true" ]]
then
  keycloakUrl="$(oc get route -n $commonServicesNamespace keycloak -o jsonpath="{.spec.host}")"

  if [[ -z "$keycloakUrl" ]]
  then
    echo "Unable to find keycloak in $commonServicesNamespace namespace. Exiting..."
    exit 1
  fi
fi

# Secrets Names
idpCredentialsSecretName="ibm-iam-bindinfo-platform-auth-idp-credentials"
oidcSecretName="$cp4iName-ibm-inte-3c22-oidc-client"
keycloakAdminSecretName="cs-keycloak-initial-admin"

# Secrets data
idpCredentialsData="$(oc get secret $idpCredentialsSecretName -n $cp4iNamespace -o json | jq -r .data)"
oidcSecretData="$(oc get secret $oidcSecretName -n $cp4iNamespace -o json | jq -r .data)"

cpAdminUserName="$(echo "$idpCredentialsData" | jq -r .admin_username | base64 -d)"
cpAdminUserPass="$(echo "$idpCredentialsData" | jq -r .admin_password | base64 -d)"
cp4iClientId="$(echo "$oicsSecretData" | jq -r .CLIENT_ID | base64 -d)"
cp4iClientSecret="$(echo "$oicsSecretData" | jq -r .CLIENT_SECRET | base64 -d)"

getCsAccessToken

if [[ "$checkAgainstKeycloak" == "true" ]]
then
  keycloakSecretData="$(oc get secret $keycloakAdminSecretName -n $commonServicesNamespace -o json | jq -r .data)"
  keycloakAdminPass="$(echo "$keycloakSecretData" | jq -r .password | base64 -d)"
  getKeycloakcsAccessToken
fi

echo ""
echo "Starting IAM migration helper script..."
echo ""

# Check what LDAPs and IDPs we have, SAML too?

echo "Checking connections to Common services"
checkForLdapConnections
checkForSamlConnections
checkForOidcConnections

# Check what teams we have set up
getCsTeams

echo ""
echo "Generating helper output..."
echo ""

# First logout the connections
inspectIdpConnections

# Inspect all teams with users and groups
# explain what needs to be done in keycloak
inspectTeams
# if we find groups, we need to point out that you need to add the LDAP mapper in keycloak !!

echo "Finished IAM migration helper script"
