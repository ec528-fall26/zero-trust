@description('Azure region for the Trusted Launch VM.')
param location string = resourceGroup().location

@description('Name of the Keylime VM.')
param vmName string = 'ec528-keylime'

@description('Linux administrator username.')
param adminUsername string = 'ec528admin'

@secure()
@description('SSH public key contents.')
param sshPublicKey string

@description('Single trusted source CIDR allowed to reach SSH, for example 203.0.113.4/32.')
param allowedSshCidr string

@description('Trusted Launch-compatible VM size.')
param vmSize string = 'Standard_B2s'

@description('Keylime agent UUID used by the verifier and MCP wrapper.')
param agentUuid string = 'd432fbb3-d2f1-4a97-9ef7-75bd81c00000'

@description('AlmaLinux Gen2 image from the official community gallery.')
param imageId string = '/CommunityGalleries/almalinux-56b45196-f8a2-4e53-858a-bc4d0ebca440/Images/almalinux-9-gen2/Versions/latest'

var vnetName = '${vmName}-vnet'
var subnetName = 'keylime'
var nsgName = '${vmName}-nsg'
var publicIpName = '${vmName}-ip'
var nicName = '${vmName}-nic'
var cloudInit = replace(loadTextContent('cloud-init.yaml'), '__AGENT_UUID__', agentUuid)

resource nsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: nsgName
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowSshFromTrustedCidr'
        properties: {
          priority: 100
          access: 'Allow'
          direction: 'Inbound'
          protocol: 'Tcp'
          sourceAddressPrefix: allowedSshCidr
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
        }
      }
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: vnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: ['10.52.0.0/16']
    }
    subnets: [
      {
        name: subnetName
        properties: {
          addressPrefix: '10.52.1.0/24'
          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
    ]
  }
}

resource publicIp 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: publicIpName
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource nic 'Microsoft.Network/networkInterfaces@2024-05-01' = {
  name: nicName
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'primary'
        properties: {
          primary: true
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: resourceId('Microsoft.Network/virtualNetworks/subnets', vnet.name, subnetName)
          }
          publicIPAddress: {
            id: publicIp.id
          }
        }
      }
    ]
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2024-11-01' = {
  name: vmName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    securityProfile: {
      securityType: 'TrustedLaunch'
      uefiSettings: {
        secureBootEnabled: true
        vTpmEnabled: true
      }
    }
    storageProfile: {
      imageReference: {
        communityGalleryImageId: imageId
      }
      osDisk: {
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'StandardSSD_LRS'
        }
        deleteOption: 'Delete'
      }
    }
    osProfile: {
      computerName: vmName
      adminUsername: adminUsername
      customData: base64(cloudInit)
      linuxConfiguration: {
        disablePasswordAuthentication: true
        provisionVMAgent: true
        ssh: {
          publicKeys: [
            {
              keyData: sshPublicKey
              path: '/home/${adminUsername}/.ssh/authorized_keys'
            }
          ]
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
          properties: {
            deleteOption: 'Delete'
            primary: true
          }
        }
      ]
    }
  }
}

output publicIpAddress string = publicIp.properties.ipAddress
output sshCommand string = 'ssh ${adminUsername}@${publicIp.properties.ipAddress}'
output mcpTunnelCommand string = 'ssh -N -L 3000:127.0.0.1:3000 ${adminUsername}@${publicIp.properties.ipAddress}'
output trustedLaunch object = {
  secureBootEnabled: vm.properties.securityProfile.uefiSettings.secureBootEnabled
  vTpmEnabled: vm.properties.securityProfile.uefiSettings.vTpmEnabled
}
