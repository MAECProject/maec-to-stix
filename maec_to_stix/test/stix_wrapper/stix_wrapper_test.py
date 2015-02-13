# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import unittest
from StringIO import StringIO
from maec.package.package import Package
from maec_to_stix.stix_wrapper import wrap_maec

class WrapTest(unittest.TestCase):
    MAEC_PACKAGE_XML = \
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
                <maecPackage:Analyses>
                    <maecPackage:Analysis method="dynamic" type="triage" id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-ana-1">
                        <maecPackage:Findings_Bundle_Reference bundle_idref="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-bnd-1"/>
                        <maecPackage:Tools>
                            <maecPackage:Tool id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-tol-1">
                                <cyboxCommon:Name>ThreatExpert</cyboxCommon:Name>
                                <cyboxCommon:Vendor>ThreatExpert</cyboxCommon:Vendor>
                            </maecPackage:Tool>
                        </maecPackage:Tools>
                    </maecPackage:Analysis>
                </maecPackage:Analyses>
            </maecPackage:Malware_Subject>
        </maecPackage:Malware_Subjects>
    </maecPackage:MAEC_Package>
    """

    MAEC_PACKAGE_WRAPPED_XML = \
    """<maecPackage:MAEC_Package id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-pkg-1" schema_version="2.1"><maecPackage:Malware_Subjects><maecPackage:Malware_Subject id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-sub-1"><maecPackage:Malware_Instance_Object_Attributes id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-obj-1"><cybox:Properties xsi:type="WinExecutableFileObj:WindowsExecutableFileObjectType"><FileObj:Size_In_Bytes>232163</FileObj:Size_In_Bytes><FileObj:Hashes><cyboxCommon:Hash><cyboxCommon:Type>MD5</cyboxCommon:Type><cyboxCommon:Simple_Hash_Value>2995FE11DEDB42A1ABC1A0E5EF20C7EF</cyboxCommon:Simple_Hash_Value></cyboxCommon:Hash><cyboxCommon:Hash><cyboxCommon:Type>SHA1</cyboxCommon:Type><cyboxCommon:Simple_Hash_Value>10881635FE636A11E49C7A7429A24BAB469364C5</cyboxCommon:Simple_Hash_Value></cyboxCommon:Hash></FileObj:Hashes></cybox:Properties></maecPackage:Malware_Instance_Object_Attributes><maecPackage:Analyses><maecPackage:Analysis method="dynamic" type="triage" id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-ana-1"><maecPackage:Findings_Bundle_Reference bundle_idref="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-bnd-1"/><maecPackage:Tools><maecPackage:Tool id="maec-threatexpert_to_maec_2995FE11DEDB42A1ABC1A0E5EF20C7EF-tol-1"><cyboxCommon:Name>ThreatExpert</cyboxCommon:Name><cyboxCommon:Vendor>ThreatExpert</cyboxCommon:Vendor></maecPackage:Tool></maecPackage:Tools></maecPackage:Analysis></maecPackage:Analyses></maecPackage:Malware_Subject></maecPackage:Malware_Subjects></maecPackage:MAEC_Package>"""

    @classmethod
    def setUpClass(cls):
        cls._maec_package = StringIO(cls.MAEC_PACKAGE_XML)
        cls._wrapped_maec_package = cls.MAEC_PACKAGE_WRAPPED_XML

    def test_stix_ttp(self):
        maec_package = Package.from_xml(self._maec_package)[0]
        stix_package = wrap_maec(maec_package)
        self.assertEquals(len(stix_package.ttps), 1)

    def test_stix_ttp_malware_instances(self):
        maec_package = Package.from_xml(self._maec_package)[0]
        stix_package = wrap_maec(maec_package)
        stix_ttp = stix_package.ttps[0]
        malware_instances = stix_ttp.behavior.malware_instances
        self.assertEquals(len(malware_instances), 1)

    def test_maec_wrapped_in_stix(self):
        maec_package = Package.from_xml(self._maec_package)[0]
        stix_package = wrap_maec(maec_package)
        stix_ttp = stix_package.ttps[0]
        malware_instances = stix_ttp.behavior.malware_instances
        wrapped_maec_package = malware_instances[0].maec
        self.assertEqual(wrapped_maec_package.to_xml(include_namespaces=False,pretty=False),
                         self._wrapped_maec_package)

if __name__ == "__main__":
    unittest.main()