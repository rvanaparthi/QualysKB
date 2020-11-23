{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
      "parameters": {
          "FunctionName": {
              "defaultValue": "QualysVM",
              "type": "string"
          },  
          "WorkspaceID": {
              "type": "string",
              "defaultValue": "<workspaceID>"
          },
          "WorkspaceKey": {
              "type": "string",
              "defaultValue": "<workspaceKey>"
          },
          "APIUsername": {
              "type": "string",
              "defaultValue": "<apiUsername>"
          },
          "APIPassword": {
              "type": "string",
              "defaultValue": "<apiPassword>"
          },
          "Uri": {
              "type": "string",
              "defaultValue": "https://<API Server URL>/api/2.0/fo/asset/host/vm/detection/?action=list&vm_processed_after="
          },
          "FilterParameters": {
              "type": "string",
              "defaultValue": "&truncation_limit=1000"
          },
          "TimeInterval": {
              "type": "string",
              "defaultValue": "5"
          }
      },
      "variables": {
           "FunctionName": "[concat(toLower(parameters('FunctionName')), uniqueString(resourceGroup().id))]"
      },
      "resources": [
          {
              "type": "Microsoft.Insights/components",
              "apiVersion": "2015-05-01",
              "name": "[variables('FunctionName')]",
              "location": "[resourceGroup().location]",
              "kind": "web",
              "properties": {
                  "Application_Type": "web",
                  "ApplicationId": "[variables('FunctionName')]"
              }
          },
          
          {
              "type": "Microsoft.Storage/storageAccounts",
              "apiVersion": "2019-06-01",
              "name": "[tolower(variables('FunctionName'))]",
              "location": "[resourceGroup().location]",
              "sku": {
                  "name": "Standard_LRS",
                  "tier": "Standard"
              },
              "kind": "StorageV2",
              "properties": {
                  "networkAcls": {
                      "bypass": "AzureServices",
                      "virtualNetworkRules": [
                      ],
                      "ipRules": [
                      ],
                      "defaultAction": "Allow"
                  },
                  "supportsHttpsTrafficOnly": true,
                  "encryption": {
                      "services": {
                          "file": {
                              "keyType": "Account",
                              "enabled": true
                          },
                          "blob": {
                              "keyType": "Account",
                              "enabled": true
                          }
                      },
                      "keySource": "Microsoft.Storage"
                  }
              }
          },
          {
              "type": "Microsoft.Web/serverfarms",
              "apiVersion": "2018-02-01",
              "name": "[variables('FunctionName')]",
              "location": "[resourceGroup().location]",
              "sku": {
                  "name": "Y1",
                  "tier": "Dynamic"
              },
              "kind": "functionapp",
              "properties": {
                  "name": "[variables('FunctionName')]",
                  "workerSize": "0",
                  "workerSizeId": "0",
                  "numberOfWorkers": "1"
              }
          },
          {
              "type": "Microsoft.Storage/storageAccounts/blobServices",
              "apiVersion": "2019-06-01",
              "name": "[concat(variables('FunctionName'), '/default')]",
              "dependsOn": [
                  "[resourceId('Microsoft.Storage/storageAccounts', tolower(variables('FunctionName')))]"
              ],
              "sku": {
                  "name": "Standard_LRS",
                  "tier": "Standard"
              },
              "properties": {
                  "cors": {
                      "corsRules": [
                      ]
                  },
                  "deleteRetentionPolicy": {
                      "enabled": false
                  }
              }
          },
          {
              "type": "Microsoft.Storage/storageAccounts/fileServices",
              "apiVersion": "2019-06-01",
              "name": "[concat(variables('FunctionName'), '/default')]",
              "dependsOn": [
                  "[resourceId('Microsoft.Storage/storageAccounts', tolower(variables('FunctionName')))]"
              ],
              "sku": {
                  "name": "Standard_LRS",
                  "tier": "Standard"
              },
              "properties": {
                  "cors": {
                      "corsRules": [
                      ]
                  }
              }
          },
          {
              "type": "Microsoft.Web/sites",
              "apiVersion": "2018-11-01",
              "name": "[variables('FunctionName')]",
              "location": "[resourceGroup().location]",
              "dependsOn": [
                  "[resourceId('Microsoft.Storage/storageAccounts', tolower(variables('FunctionName')))]",
                  "[resourceId('Microsoft.Web/serverfarms', variables('FunctionName'))]",
                  "[resourceId('Microsoft.Insights/components', variables('FunctionName'))]"
              ],
              "kind": "functionapp",
              "identity": {
                  "type": "SystemAssigned"
              },
              "properties": {
                  "name": "[variables('FunctionName')]",
                  "serverFarmId": "[resourceId('Microsoft.Web/serverfarms', variables('FunctionName'))]",
                  "httpsOnly": true,
                  "clientAffinityEnabled": true,
                   "alwaysOn": true
              },
              "resources": [
                  {
                      "apiVersion": "2018-11-01",
                      "type": "config",
                      "name": "appsettings",
                      "dependsOn": [
                          "[concat('Microsoft.Web/sites/', variables('FunctionName'))]"
                      ],
                      "properties": {
                          "FUNCTIONS_EXTENSION_VERSION": "~3",
                          "FUNCTIONS_WORKER_RUNTIME": "powershell",
                          "APPINSIGHTS_INSTRUMENTATIONKEY": "[reference(resourceId('Microsoft.insights/components', variables('FunctionName')), '2015-05-01').InstrumentationKey]",
                          "APPLICATIONINSIGHTS_CONNECTION_STRING": "[reference(resourceId('microsoft.insights/components', variables('FunctionName')), '2015-05-01').ConnectionString]",
                          "AzureWebJobsStorage": "[concat('DefaultEndpointsProtocol=https;AccountName=', toLower(variables('FunctionName')),';AccountKey=',listKeys(resourceId('Microsoft.Storage/storageAccounts', toLower(variables('FunctionName'))), '2019-06-01').keys[0].value, ';EndpointSuffix=core.windows.net')]",
                          "WEBSITE_CONTENTAZUREFILECONNECTIONSTRING": "[concat('DefaultEndpointsProtocol=https;AccountName=', toLower(variables('FunctionName')),';AccountKey=', listKeys(resourceId('Microsoft.Storage/storageAccounts', toLower(variables('FunctionName'))), '2019-06-01').keys[0].value, ';EndpointSuffix=core.windows.net')]",
                          "WEBSITE_CONTENTSHARE": "[toLower(variables('FunctionName'))]",
                          "workspaceID": "[parameters('WorkspaceID')]",
                          "workspaceKey": "[parameters('WorkspaceKey')]",
                          "apiUsername": "[parameters('APIUsername')]",
                          "apiPassword": "[parameters('APIPassword')]",
                          "uri": "[parameters('Uri')]",
                          "filterParameters": "[parameters('FilterParameters')]",
                          "timeInterval": "[parameters('TimeInterval')]",
                          "WEBSITE_RUN_FROM_PACKAGE": "https://aka.ms/sentinelqualysvmazurefunctionzip"
                                   } 
                  }
              ]
          },
          {
              "type": "Microsoft.Web/sites/hostNameBindings",
              "apiVersion": "2018-11-01",
              "name": "[concat(variables('FunctionName'), '/', variables('FunctionName'), '.azurewebsites.net')]",
              "location": "[resourceGroup().location]",
              "dependsOn": [
                  "[resourceId('Microsoft.Web/sites', variables('FunctionName'))]"
              ],
              "properties": {
                  "siteName": "[variables('FunctionName')]",
                  "hostNameType": "Verified"
              }
          },
          {
              "type": "Microsoft.Storage/storageAccounts/blobServices/containers",
              "apiVersion": "2019-06-01",
              "name": "[concat(variables('FunctionName'), '/default/azure-webjobs-hosts')]",
              "dependsOn": [
                  "[resourceId('Microsoft.Storage/storageAccounts/blobServices', variables('FunctionName'), 'default')]",
                  "[resourceId('Microsoft.Storage/storageAccounts', variables('FunctionName'))]"
              ],
              "properties": {
                  "publicAccess": "None"
              }
          },
          {
              "type": "Microsoft.Storage/storageAccounts/blobServices/containers",
              "apiVersion": "2019-06-01",
              "name": "[concat(variables('FunctionName'), '/default/azure-webjobs-secrets')]",
              "dependsOn": [
                  "[resourceId('Microsoft.Storage/storageAccounts/blobServices', variables('FunctionName'), 'default')]",
                  "[resourceId('Microsoft.Storage/storageAccounts', variables('FunctionName'))]"
              ],
              "properties": {
                  "publicAccess": "None"
              }
          },
          {
              "type": "Microsoft.Storage/storageAccounts/fileServices/shares",
              "apiVersion": "2019-06-01",
              "name": "[concat(variables('FunctionName'), '/default/', tolower(variables('FunctionName')))]",
              "dependsOn": [
                  "[resourceId('Microsoft.Storage/storageAccounts/fileServices', variables('FunctionName'), 'default')]",
                  "[resourceId('Microsoft.Storage/storageAccounts', variables('FunctionName'))]"
              ],
              "properties": {
                  "shareQuota": 5120
              }
          }
      ]
  }
  