| :information_source: Information                                                                                                                                                                                                                                                                                                                                                       |
| :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements. |
<br />

<p align="center">
  <img src="https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-Exchange-Online-DistributionGroup-To-SelfService-Products/blob/main/Logo.png?raw=true">
</p>

<!-- TABLE OF CONTENTS -->
## Table of Contents
- [Table of Contents](#table-of-contents)
- [Introduction](#introduction)
- [Getting started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Connection settings](#connection-settings)
- [Remarks](#remarks)
- [Getting help](#getting-help)
- [HelloID Docs](#helloid-docs)

## Introduction
By using this connector, you will have the ability to create and remove HelloID SelfService Products based on groups in your Exchange Online Distribution Groups.

The products will be create for each group in scope. This way you won't have to manually create a product for each group.

And vice versa for the removing of the products. The products will be removed (or disabled, based on your preference) when a group is nog longer in scope. This way no products will remain that "should no longer exist".

## Getting started

### Prerequisites
- [ ] Installed and available [Microsoft Exchange Online PowerShell V3 module](https://www.powershellgallery.com/packages/ExchangeOnlineManagement)
- [ ] To manage users, mailboxes and groups, the service account has to have the role "**Exchange Recipient Administrator**" assigned.
- [ ] Required to run **On-Premises** since it is not allowed to import a module with the Cloud Agent.
- [ ] Define the Global variables for your Exchange Environment

### Connection settings

The connection settings are defined in the automation variables [user defined variables](https://docs.helloid.com/hc/en-us/articles/360014169933-How-to-Create-and-Manage-User-Defined-Variables). And the Product configuration can be configured in the script


| Variable name                   | Description                                                     | Notes                                                                                                                                                                                                                                                                                                      |
| ------------------------------- | --------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| $portalBaseUrl                  | HelloID Base Url                                                | (Default Global Variable)                                                                                                                                                                                                                                                                                  |
| $portalApiKey                   | HelloID Api Key                                                 | (Default Global Variable)                                                                                                                                                                                                                                                                                  |
| $portalApiSecret                | HelloID Api Secret                                              | (Default Global Variable)                                                                                                                                                                                                                                                                                  |
| $EntraOrganization              | The Entra ID Organization yourCompany.onmicrosoft.com           | Recommended to set as Global Variable                                                                                                                                                                                                                                                                      |
| $EntraTenantID                  | String value of Entra ID Tenant ID                              | Recommended to set as Global Variable                                                                                                                                                                                                                                                                      |
| $EntraAppID                     | String value of Entra ID App ID                                 | Recommended to set as Global Variable                                                                                                                                                                                                                                                                      |
| $EntraAppSecret                 | String value of Entra ID App Secret                             | Recommended to set as Global Variable                                                                                                                                                                                                                                                                      |
| $exchangeGroupsFilter           | String value of seachfilter of which Exchange Online groups to include | Optional, when no filter is provided ($exchangeGroupsFilter = $null), all groups will be queried - Only displayName and description are supported with the search filter. Reference: https://learn.microsoft.com/en-us/graph/search-query-parameter?tabs=http#using-search-on-directory-object-collections |
| $ProductAccessGroup             | HelloID Product Access Group                                    | *If not found, the product is created without an Access Group*                                                                                                                                                                                                                                             |
| $productAccessGroup  | String value of which HelloID group will have access to the products | Optional, if not found, the product is created without Access Group  |
| $calculateProductResourceOwnerPrefixSuffix  | Boolean value of whether to check for a specific "owner" group in HelloID to use as resource owner for the products | Optional, can only be used when the "owner group" exists and is available in HelloID  |
| $calculatedResourceOwnerGroupSource  | String value of source of the groups in HelloID | Optional, if left empty, this will result in creation of a new group |
| $calculatedResourceOwnerGroupPrefix  | String value of prefix to recognize the owner group | Optional, the owner group will be queried based on the group name and the specified prefix and suffix - if both left empty, this will result in creation of a new group - if group is not found, it will be created  |
| $calculatedResourceOwnerGroupSuffix  | String value of suffix to recognize the owner group | Optional, the owner group will be queried based on the group name and the specified prefix and suffix - if both left empty, this will result in creation of a new group - if group is not found, it will be created  |
| $productResourceOwner  | String value of which HelloID group to use as resource owner for the products | Optional, if empty the groupname will be: "local/[group displayname] Resource Owners"  |
| $productApprovalWorkflowId  | String value of HelloID Approval Workflow GUID to use for the products | Optional, if empty. The Default HelloID Workflow is used. If specified Workflow does not exist the task will fail  |
| $productVisibility  | String value of which Visbility to use for the products | Supported values: All, Resource Owner And Manager, Resource Owner, Disabled. For more information, see the HelloID Docs [here](https://docs.helloid.com/en/service-automation/products/product-settings-reference.html)  |
| $productRequestCommentOption  | String value of which Comment Option to use for the products | Supported values: Optional, Hidden, Required. For more information, see the HelloID Docs [here](https://docs.helloid.com/en/service-automation/products/product-settings-reference.html)  |
| $productAllowMultipleRequests  |Boolean value of whether to allow Multiple Requests for the products | If True, the product can be requested unlimited times  |
| $productFaIcon  | String value of which Font Awesome icon to use for the products | For more valid icon names, see the Font Awesome cheat sheet [here](https://fontawesome.com/v5/cheatsheet)  |
| $productCategory  | String value of which HelloID category will be used for the products | Required, must be an existing category if not found, the task will fail  |
| $productReturnOnUserDisable  | Boolean value of whether to set the option Return Product On User Disable for the products | For more information, see the HelloID Docs [here](https://docs.helloid.com/en/service-automation/products/product-settings-reference.html)  |
| $removeProduct  | Boolean value of whether to remove the products when they are no longer in scope | If set to $false, obsolete products will be disabled  |
| $overwriteExistingProduct  | Boolean value of whether to overwrite existing products in scope with the specified properties of this task | If True, existing product will be overwritten with the input from this script (e.g. the approval worklow or icon). Only use this when you actually changed the product input. **Note:** Actions are always overwritten, no compare takes place between the current actions and the actions this sync would set  |
| $overwriteAccessGroup  | Boolean value of whether to overwrite existing access groups in scope with the specified access group this task | Should be on false by default, only set this to true to overwrite product access group - Only meant for "manual" bulk update, not daily scheduled. **Note:** Access group is always overwritten, no compare takes place between the current access group and the access group this sync would set  |
| $ProductSkuPrefix | String value of prefix that will be used in the Code for the products | Optional, but recommended, when no SkuPrefix is provided the products won't be recognizable as created by this task |
| $exchangeGroupUniqueProperty   | String value of name of the property that is unique for the Exchange Online groups and will be used in the Code for the products | The default value ("GUID") is set be as unique as possible   |                                                                                               

## Remarks
- The Products are created and disable/deleted and, when configured, updated.
- When the RemoveProduct switch is adjusted to remove the products. The products will be delete from HelloID instead of Disable. This will remove also the previous disabled products (by the sync).
- When the overwriteExistingProduct switch is adjusted to overwrite the existing products, this will be performed for all products created from this sync. This will update also the previous disabled products (by the sync).
- When the overwriteExistingProductAction switch is adjusted to overwrite the existing product actions, this will be performed for all products created from this sync. This will update also the previous disabled products (by the sync).
- The managers of the Distribution Groups are not added in the "Resource Owner Group" of the products
- The Unique identifier (CombineduniqueId / SKU)   is builded as follows:
  $SKUPrefix + GUID of the Distribution Groups without dashes + Abbreviation of the permission Type

## Getting help
> _For more information on how to configure a HelloID PowerShell scheduled task, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/115003253294-Create-Custom-Scheduled-Tasks) pages_

> _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/