# iam-to-keycloak-migration

Tools to migrate from IBM Cloud Pak foundational services Identity and Access Management (IAM) to the Red Hat build of Keycloak (RHBK) provided as a service using IBM Cloud Pak foundational services.

These tools are designed for use with IBM Cloud Pak for Integration during the migration from a version using IBM Cloud Pak foundational services Identity and Access Management (IAM) to a version using Red Hat build of Keycloak (RHBK).
For more information on user management within IBM Cloud Pak for Integration, see https://www.ibm.com/docs/en/cloud-paks/cp-integration/.

## Getting started

1. Ensure the prerequisite tools are available.

   You must have the `oc` command available on the path.

   You must have the `jq` command available on the path.

1. Log into the OpenShift cluster as a user that can read secrets from the IBM Cloud Pak foundational services namespace and the IBM Cloud Pak for Integration namespace.

1. Run the migration tool. The tool will not make any changes to your system, it will only list the changes that need to be made and verify if they have been made.

   ```
   ./iam-keycloak-migration.sh <cp4i namespace>
   ```
