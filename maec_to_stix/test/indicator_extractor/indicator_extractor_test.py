# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import unittest
from StringIO import StringIO
from maec.package.package import Package
from maec_to_stix.indicator_extractor import IndicatorExtractor

class IndicatorExtractorTest(unittest.TestCase):
    MAEC_PACKAGE_XML_POSITIVE = \
    """
    <maecPackage:MAEC_Package 
	    xmlns:cyboxCommon="http://cybox.mitre.org/common-2"
	    xmlns:cybox="http://cybox.mitre.org/cybox-2"
	    xmlns:cyboxVocabs="http://cybox.mitre.org/default_vocabularies-2"
	    xmlns:AccountObj="http://cybox.mitre.org/objects#AccountObject-2"
	    xmlns:AddressObj="http://cybox.mitre.org/objects#AddressObject-2"
	    xmlns:DNSQueryObj="http://cybox.mitre.org/objects#DNSQueryObject-2"
	    xmlns:DNSRecordObj="http://cybox.mitre.org/objects#DNSRecordObject-2"
	    xmlns:FileObj="http://cybox.mitre.org/objects#FileObject-2"
	    xmlns:HTTPSessionObj="http://cybox.mitre.org/objects#HTTPSessionObject-2"
	    xmlns:MemoryObj="http://cybox.mitre.org/objects#MemoryObject-2"
	    xmlns:NetworkConnectionObj="http://cybox.mitre.org/objects#NetworkConnectionObject-2"
	    xmlns:PortObj="http://cybox.mitre.org/objects#PortObject-2"
	    xmlns:ProcessObj="http://cybox.mitre.org/objects#ProcessObject-2"
	    xmlns:SocketAddressObj="http://cybox.mitre.org/objects#SocketAddressObject-1"
	    xmlns:URIObj="http://cybox.mitre.org/objects#URIObject-2"
	    xmlns:WinComputerAccountObj="http://cybox.mitre.org/objects#WinComputerAccountObject-2"
	    xmlns:WinExecutableFileObj="http://cybox.mitre.org/objects#WinExecutableFileObject-2"
	    xmlns:WinFileObj="http://cybox.mitre.org/objects#WinFileObject-2"
	    xmlns:WinHandleObj="http://cybox.mitre.org/objects#WinHandleObject-2"
	    xmlns:WinProcessObj="http://cybox.mitre.org/objects#WinProcessObject-2"
	    xmlns:WinRegistryKeyObj="http://cybox.mitre.org/objects#WinRegistryKeyObject-2"
	    xmlns:maecBundle="http://maec.mitre.org/XMLSchema/maec-bundle-4"
	    xmlns:maecPackage="http://maec.mitre.org/XMLSchema/maec-package-2"
	    xmlns:maecVocabs="http://maec.mitre.org/default_vocabularies-1"
	    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	    xmlns:mmdef="http://xml/metadataSharing.xsd"
	    xsi:schemaLocation="http://cybox.mitre.org/common-2 http://cybox.mitre.org/XMLSchema/common/2.1/cybox_common.xsd http://cybox.mitre.org/cybox-2 http://cybox.mitre.org/XMLSchema/core/2.1/cybox_core.xsd http://cybox.mitre.org/default_vocabularies-2 http://cybox.mitre.org/XMLSchema/default_vocabularies/2.1/cybox_default_vocabularies.xsd http://cybox.mitre.org/objects#FileObject-2 http://cybox.mitre.org/XMLSchema/objects/File/2.1/File_Object.xsd http://cybox.mitre.org/objects#MemoryObject-2 http://cybox.mitre.org/XMLSchema/objects/Memory/2.1/Memory_Object.xsd http://cybox.mitre.org/objects#ProcessObject-2 http://cybox.mitre.org/XMLSchema/objects/Process/2.1/Process_Object.xsd http://cybox.mitre.org/objects#URIObject-2 http://cybox.mitre.org/XMLSchema/objects/URI/2.1/URI_Object.xsd http://cybox.mitre.org/objects#WinExecutableFileObject-2 http://cybox.mitre.org/XMLSchema/objects/Win_Executable_File/2.1/Win_Executable_File_Object.xsd http://cybox.mitre.org/objects#WinFileObject-2 http://cybox.mitre.org/XMLSchema/objects/Win_File/2.1/Win_File_Object.xsd http://cybox.mitre.org/objects#WinProcessObject-2 http://cybox.mitre.org/XMLSchema/objects/Win_Process/2.1/Win_Process_Object.xsd http://cybox.mitre.org/objects#WinRegistryKeyObject-2 http://cybox.mitre.org/XMLSchema/objects/Win_Registry_Key/2.1/Win_Registry_Key_Object.xsd http://maec.mitre.org/XMLSchema/maec-bundle-4 http://maec.mitre.org/language/version4.1/maec_bundle_schema.xsd http://maec.mitre.org/XMLSchema/maec-package-2 http://maec.mitre.org/language/version4.1/maec_package_schema.xsd http://maec.mitre.org/default_vocabularies-1 http://maec.mitre.org/language/version4.1/maec_default_vocabularies.xsd" id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-pkg-1" schema_version="2.1">
        <maecPackage:Malware_Subjects>
            <maecPackage:Malware_Subject id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-sub-1">
                <maecPackage:Malware_Instance_Object_Attributes id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-obj-1">
                    <cybox:Properties xsi:type="WinExecutableFileObj:WindowsExecutableFileObjectType">
                        <FileObj:Size_In_Bytes>232163</FileObj:Size_In_Bytes>
                        <FileObj:Hashes>
                            <cyboxCommon:Hash>
                                <cyboxCommon:Type>MD5</cyboxCommon:Type>
                                <cyboxCommon:Simple_Hash_Value>2995FE11DEDB42A1ABC1A0E5EF20C7EF</cyboxCommon:Simple_Hash_Value>
                            </cyboxCommon:Hash>
                            <cyboxCommon:Hash>
                                <cyboxCommon:Type>SHA1</cyboxCommon:Type>
                                <cyboxCommon:Simple_Hash_Value>10881635FE636A11E49C7A7429A24BAB469364C5</cyboxCommon:Simple_Hash_Value>
                            </cyboxCommon:Hash>
                        </FileObj:Hashes>
                    </cybox:Properties>
                </maecPackage:Malware_Instance_Object_Attributes>
                <maecPackage:Findings_Bundles>
                    <maecPackage:Bundle defined_subject="false" id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-bnd-1" schema_version="4.1">
                        <maecBundle:Collections>
                            <maecBundle:Action_Collections>
                                <maecBundle:Action_Collection name="Registry Actions" id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-actc-2">
                                    <maecBundle:Action_List>
                                        <maecBundle:Action id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-act-22">
                                            <cybox:Name xsi:type="maecVocabs:RegistryActionNameVocab-1.0">create registry key value</cybox:Name>
                                            <cybox:Associated_Objects>
                                                <cybox:Associated_Object id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-obj-30">
                                                    <cybox:Properties xsi:type="WinRegistryKeyObj:WindowsRegistryKeyObjectType">
                                                        <WinRegistryKeyObj:Key>.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings</WinRegistryKeyObj:Key>
                                                        <WinRegistryKeyObj:Hive>HKEY_USERS</WinRegistryKeyObj:Hive>
                                                        <WinRegistryKeyObj:Values>
                                                            <WinRegistryKeyObj:Value>
                                                                <WinRegistryKeyObj:Name>ProxyEnable</WinRegistryKeyObj:Name>
                                                                <WinRegistryKeyObj:Data>0x00000000</WinRegistryKeyObj:Data>
                                                            </WinRegistryKeyObj:Value>
                                                        </WinRegistryKeyObj:Values>
                                                    </cybox:Properties>
                                                    <cybox:Association_Type xsi:type="maecVocabs:ActionObjectAssociationTypeVocab-1.0">output</cybox:Association_Type>
                                                </cybox:Associated_Object>
                                            </cybox:Associated_Objects>
                                        </maecBundle:Action>
                                        <maecBundle:Action id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-act-23">
                                            <cybox:Name xsi:type="maecVocabs:RegistryActionNameVocab-1.0">modify registry key</cybox:Name>
                                            <cybox:Associated_Objects>
                                                <cybox:Associated_Object id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-obj-31">
                                                    <cybox:Properties xsi:type="WinRegistryKeyObj:WindowsRegistryKeyObjectType">
                                                        <WinRegistryKeyObj:Key>SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon</WinRegistryKeyObj:Key>
                                                        <WinRegistryKeyObj:Hive>HKEY_LOCAL_MACHINE</WinRegistryKeyObj:Hive>
                                                    </cybox:Properties>
                                                    <cybox:Association_Type xsi:type="maecVocabs:ActionObjectAssociationTypeVocab-1.0">input</cybox:Association_Type>
                                                </cybox:Associated_Object>
                                            </cybox:Associated_Objects>
                                        </maecBundle:Action>
                                    </maecBundle:Action_List>
                                </maecBundle:Action_Collection>
                                <maecBundle:Action_Collection name="File Actions" id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-actc-3">
                                    <maecBundle:Action_List>
                                        <maecBundle:Action id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-act-2">
                                            <cybox:Name xsi:type="maecVocabs:FileActionNameVocab-1.0">create file</cybox:Name>
                                            <cybox:Associated_Objects>
                                                <cybox:Associated_Object id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-obj-2">
                                                    <cybox:Properties xsi:type="FileObj:FileObjectType">
                                                        <FileObj:File_Path fully_qualified="false">%System%\sdra64.exe</FileObj:File_Path>
                                                        <FileObj:Size_In_Bytes>729827</FileObj:Size_In_Bytes>
                                                        <FileObj:Hashes>
                                                            <cyboxCommon:Hash>
                                                                <cyboxCommon:Type>MD5</cyboxCommon:Type>
                                                                <cyboxCommon:Simple_Hash_Value>18404AD182141B00C11993255D6C5D3F</cyboxCommon:Simple_Hash_Value>
                                                            </cyboxCommon:Hash>
                                                            <cyboxCommon:Hash>
                                                                <cyboxCommon:Type>SHA1</cyboxCommon:Type>
                                                                <cyboxCommon:Simple_Hash_Value>02ED1C86F7CDF56BF0A48EEAB2EFA75424C4472F</cyboxCommon:Simple_Hash_Value>
                                                            </cyboxCommon:Hash>
                                                        </FileObj:Hashes>
                                                    </cybox:Properties>
                                                    <cybox:Association_Type xsi:type="maecVocabs:ActionObjectAssociationTypeVocab-1.0">output</cybox:Association_Type>
                                                </cybox:Associated_Object>
                                            </cybox:Associated_Objects>
                                        </maecBundle:Action>
                                    </maecBundle:Action_List>
                                </maecBundle:Action_Collection>
                                <maecBundle:Action_Collection name="Network Actions" id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-actc-4">
                                    <maecBundle:Action_List>
                                        <maecBundle:Action id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-act-26">
                                            <cybox:Name xsi:type="maecVocabs:NetworkActionNameVocab-1.0">connect to url</cybox:Name>
                                            <cybox:Associated_Objects>
                                                <cybox:Associated_Object id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-obj-34">
                                                    <cybox:Properties xsi:type="URIObj:URIObjectType">
                                                        <URIObj:Value>http://62.193.242.95/xenix/alert1of1sun.bin</URIObj:Value>
                                                    </cybox:Properties>
                                                    <cybox:Association_Type xsi:type="maecVocabs:ActionObjectAssociationTypeVocab-1.0">input</cybox:Association_Type>
                                                </cybox:Associated_Object>
                                            </cybox:Associated_Objects>
                                        </maecBundle:Action>
                                    </maecBundle:Action_List>
                                </maecBundle:Action_Collection>
                            </maecBundle:Action_Collections>
                        </maecBundle:Collections>
                    </maecPackage:Bundle>
                </maecPackage:Findings_Bundles>
            </maecPackage:Malware_Subject>
        </maecPackage:Malware_Subjects>
    </maecPackage:MAEC_Package>
    """

    MAEC_PACKAGE_XML_NEGATIVE = \
    """
    <maecPackage:MAEC_Package 
	    xmlns:cyboxCommon="http://cybox.mitre.org/common-2"
	    xmlns:cybox="http://cybox.mitre.org/cybox-2"
	    xmlns:cyboxVocabs="http://cybox.mitre.org/default_vocabularies-2"
	    xmlns:AccountObj="http://cybox.mitre.org/objects#AccountObject-2"
	    xmlns:AddressObj="http://cybox.mitre.org/objects#AddressObject-2"
	    xmlns:DNSQueryObj="http://cybox.mitre.org/objects#DNSQueryObject-2"
	    xmlns:DNSRecordObj="http://cybox.mitre.org/objects#DNSRecordObject-2"
	    xmlns:FileObj="http://cybox.mitre.org/objects#FileObject-2"
	    xmlns:HTTPSessionObj="http://cybox.mitre.org/objects#HTTPSessionObject-2"
	    xmlns:MemoryObj="http://cybox.mitre.org/objects#MemoryObject-2"
	    xmlns:NetworkConnectionObj="http://cybox.mitre.org/objects#NetworkConnectionObject-2"
	    xmlns:PortObj="http://cybox.mitre.org/objects#PortObject-2"
	    xmlns:ProcessObj="http://cybox.mitre.org/objects#ProcessObject-2"
	    xmlns:SocketAddressObj="http://cybox.mitre.org/objects#SocketAddressObject-1"
	    xmlns:URIObj="http://cybox.mitre.org/objects#URIObject-2"
	    xmlns:WinComputerAccountObj="http://cybox.mitre.org/objects#WinComputerAccountObject-2"
	    xmlns:WinExecutableFileObj="http://cybox.mitre.org/objects#WinExecutableFileObject-2"
	    xmlns:WinFileObj="http://cybox.mitre.org/objects#WinFileObject-2"
	    xmlns:WinHandleObj="http://cybox.mitre.org/objects#WinHandleObject-2"
	    xmlns:WinProcessObj="http://cybox.mitre.org/objects#WinProcessObject-2"
	    xmlns:WinRegistryKeyObj="http://cybox.mitre.org/objects#WinRegistryKeyObject-2"
	    xmlns:maecBundle="http://maec.mitre.org/XMLSchema/maec-bundle-4"
	    xmlns:maecPackage="http://maec.mitre.org/XMLSchema/maec-package-2"
	    xmlns:maecVocabs="http://maec.mitre.org/default_vocabularies-1"
	    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	    xmlns:mmdef="http://xml/metadataSharing.xsd"
	    xsi:schemaLocation="http://cybox.mitre.org/common-2 http://cybox.mitre.org/XMLSchema/common/2.1/cybox_common.xsd http://cybox.mitre.org/cybox-2 http://cybox.mitre.org/XMLSchema/core/2.1/cybox_core.xsd http://cybox.mitre.org/default_vocabularies-2 http://cybox.mitre.org/XMLSchema/default_vocabularies/2.1/cybox_default_vocabularies.xsd http://cybox.mitre.org/objects#FileObject-2 http://cybox.mitre.org/XMLSchema/objects/File/2.1/File_Object.xsd http://cybox.mitre.org/objects#MemoryObject-2 http://cybox.mitre.org/XMLSchema/objects/Memory/2.1/Memory_Object.xsd http://cybox.mitre.org/objects#ProcessObject-2 http://cybox.mitre.org/XMLSchema/objects/Process/2.1/Process_Object.xsd http://cybox.mitre.org/objects#URIObject-2 http://cybox.mitre.org/XMLSchema/objects/URI/2.1/URI_Object.xsd http://cybox.mitre.org/objects#WinExecutableFileObject-2 http://cybox.mitre.org/XMLSchema/objects/Win_Executable_File/2.1/Win_Executable_File_Object.xsd http://cybox.mitre.org/objects#WinFileObject-2 http://cybox.mitre.org/XMLSchema/objects/Win_File/2.1/Win_File_Object.xsd http://cybox.mitre.org/objects#WinProcessObject-2 http://cybox.mitre.org/XMLSchema/objects/Win_Process/2.1/Win_Process_Object.xsd http://cybox.mitre.org/objects#WinRegistryKeyObject-2 http://cybox.mitre.org/XMLSchema/objects/Win_Registry_Key/2.1/Win_Registry_Key_Object.xsd http://maec.mitre.org/XMLSchema/maec-bundle-4 http://maec.mitre.org/language/version4.1/maec_bundle_schema.xsd http://maec.mitre.org/XMLSchema/maec-package-2 http://maec.mitre.org/language/version4.1/maec_package_schema.xsd http://maec.mitre.org/default_vocabularies-1 http://maec.mitre.org/language/version4.1/maec_default_vocabularies.xsd" id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-pkg-1" schema_version="2.1">
        <maecPackage:Malware_Subjects>
            <maecPackage:Malware_Subject id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-sub-1">
                <maecPackage:Malware_Instance_Object_Attributes id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-obj-1">
                    <cybox:Properties xsi:type="WinExecutableFileObj:WindowsExecutableFileObjectType">
                        <FileObj:Size_In_Bytes>232163</FileObj:Size_In_Bytes>
                        <FileObj:Hashes>
                            <cyboxCommon:Hash>
                                <cyboxCommon:Type>MD5</cyboxCommon:Type>
                                <cyboxCommon:Simple_Hash_Value>2995FE11DEDB42A1ABC1A0E5EF20C7EF</cyboxCommon:Simple_Hash_Value>
                            </cyboxCommon:Hash>
                            <cyboxCommon:Hash>
                                <cyboxCommon:Type>SHA1</cyboxCommon:Type>
                                <cyboxCommon:Simple_Hash_Value>10881635FE636A11E49C7A7429A24BAB469364C5</cyboxCommon:Simple_Hash_Value>
                            </cyboxCommon:Hash>
                        </FileObj:Hashes>
                    </cybox:Properties>
                </maecPackage:Malware_Instance_Object_Attributes>
                <maecPackage:Findings_Bundles>
                    <maecPackage:Bundle defined_subject="false" id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-bnd-1" schema_version="4.1">
                        <maecBundle:Collections>
                            <maecBundle:Action_Collections>
                                <maecBundle:Action_Collection name="Registry Actions" id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-actc-2">
                                    <maecBundle:Action_List>
                                        <maecBundle:Action id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-act-22">
                                            <cybox:Name xsi:type="maecVocabs:RegistryActionNameVocab-1.0">delete registry key value</cybox:Name>
                                            <cybox:Associated_Objects>
                                                <cybox:Associated_Object id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-obj-30">
                                                    <cybox:Properties xsi:type="WinRegistryKeyObj:WindowsRegistryKeyObjectType">
                                                        <WinRegistryKeyObj:Key>.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings</WinRegistryKeyObj:Key>
                                                        <WinRegistryKeyObj:Hive>HKEY_USERS</WinRegistryKeyObj:Hive>
                                                        <WinRegistryKeyObj:Values>
                                                            <WinRegistryKeyObj:Value>
                                                                <WinRegistryKeyObj:Name>ProxyEnable</WinRegistryKeyObj:Name>
                                                                <WinRegistryKeyObj:Data>0x00000000</WinRegistryKeyObj:Data>
                                                            </WinRegistryKeyObj:Value>
                                                        </WinRegistryKeyObj:Values>
                                                    </cybox:Properties>
                                                    <cybox:Association_Type xsi:type="maecVocabs:ActionObjectAssociationTypeVocab-1.0">output</cybox:Association_Type>
                                                </cybox:Associated_Object>
                                            </cybox:Associated_Objects>
                                        </maecBundle:Action>
                                        <maecBundle:Action id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-act-23">
                                            <cybox:Name xsi:type="maecVocabs:RegistryActionNameVocab-1.0">delete registry key</cybox:Name>
                                            <cybox:Associated_Objects>
                                                <cybox:Associated_Object id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-obj-31">
                                                    <cybox:Properties xsi:type="WinRegistryKeyObj:WindowsRegistryKeyObjectType">
                                                        <WinRegistryKeyObj:Key>SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon</WinRegistryKeyObj:Key>
                                                        <WinRegistryKeyObj:Hive>HKEY_LOCAL_MACHINE</WinRegistryKeyObj:Hive>
                                                    </cybox:Properties>
                                                    <cybox:Association_Type xsi:type="maecVocabs:ActionObjectAssociationTypeVocab-1.0">input</cybox:Association_Type>
                                                </cybox:Associated_Object>
                                            </cybox:Associated_Objects>
                                        </maecBundle:Action>
                                    </maecBundle:Action_List>
                                </maecBundle:Action_Collection>
                                <maecBundle:Action_Collection name="File Actions" id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-actc-3">
                                    <maecBundle:Action_List>
                                        <maecBundle:Action id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-act-2">
                                            <cybox:Name xsi:type="maecVocabs:FileActionNameVocab-1.0">delete file</cybox:Name>
                                            <cybox:Associated_Objects>
                                                <cybox:Associated_Object id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-obj-2">
                                                    <cybox:Properties xsi:type="FileObj:FileObjectType">
                                                        <FileObj:File_Path fully_qualified="false">%System%\sdra64.exe</FileObj:File_Path>
                                                        <FileObj:Size_In_Bytes>729827</FileObj:Size_In_Bytes>
                                                        <FileObj:Hashes>
                                                            <cyboxCommon:Hash>
                                                                <cyboxCommon:Type>MD5</cyboxCommon:Type>
                                                                <cyboxCommon:Simple_Hash_Value>18404AD182141B00C11993255D6C5D3F</cyboxCommon:Simple_Hash_Value>
                                                            </cyboxCommon:Hash>
                                                            <cyboxCommon:Hash>
                                                                <cyboxCommon:Type>SHA1</cyboxCommon:Type>
                                                                <cyboxCommon:Simple_Hash_Value>02ED1C86F7CDF56BF0A48EEAB2EFA75424C4472F</cyboxCommon:Simple_Hash_Value>
                                                            </cyboxCommon:Hash>
                                                        </FileObj:Hashes>
                                                    </cybox:Properties>
                                                    <cybox:Association_Type xsi:type="maecVocabs:ActionObjectAssociationTypeVocab-1.0">output</cybox:Association_Type>
                                                </cybox:Associated_Object>
                                            </cybox:Associated_Objects>
                                        </maecBundle:Action>
                                    </maecBundle:Action_List>
                                </maecBundle:Action_Collection>
                                <maecBundle:Action_Collection name="Network Actions" id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-actc-4">
                                    <maecBundle:Action_List>
                                        <maecBundle:Action id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-act-26">
                                            <cybox:Name xsi:type="maecVocabs:NetworkActionNameVocab-1.0">upload file</cybox:Name>
                                            <cybox:Associated_Objects>
                                                <cybox:Associated_Object id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-obj-34">
                                                    <cybox:Properties xsi:type="URIObj:URIObjectType">
                                                        <URIObj:Value>http://62.193.242.95/xenix/alert1of1sun.bin</URIObj:Value>
                                                    </cybox:Properties>
                                                    <cybox:Association_Type xsi:type="maecVocabs:ActionObjectAssociationTypeVocab-1.0">input</cybox:Association_Type>
                                                </cybox:Associated_Object>
                                            </cybox:Associated_Objects>
                                        </maecBundle:Action>
                                    </maecBundle:Action_List>
                                </maecBundle:Action_Collection>
                            </maecBundle:Action_Collections>
                        </maecBundle:Collections>
                    </maecPackage:Bundle>
                </maecPackage:Findings_Bundles>
            </maecPackage:Malware_Subject>
        </maecPackage:Malware_Subjects>
    </maecPackage:MAEC_Package>
    """

    @classmethod
    def setUpClass(cls):
        cls._maec_package_positive = StringIO(cls.MAEC_PACKAGE_XML_POSITIVE)
        cls._maec_package_negative = StringIO(cls.MAEC_PACKAGE_XML_NEGATIVE)

    def test_positive_stix_indicators(self):
        maec_package = Package.from_xml(self._maec_package_positive)[0]
        extractor = IndicatorExtractor(maec_package)
        stix_package = extractor.extract()
        self.assertEquals(len(stix_package.indicators), 4)

    def test_negative_stix_indicators(self):
        maec_package = Package.from_xml(self._maec_package_negative)[0]
        extractor = IndicatorExtractor(maec_package)
        stix_package = extractor.extract()
        self.assertEquals(stix_package, None)

if __name__ == "__main__":
    unittest.main()