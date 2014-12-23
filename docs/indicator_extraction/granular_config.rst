Granular Configuration Files
============================
This page explains the structure and properties of the granular configuration
files used in configuring the behavior of the indicator extraction feature
of **maec-to-stix**. For the default values used in each granular configuration
file, please refer to the :doc:`granular_config_defaults` page.

Structure
---------
The system activity and granular configuration files capture two distinct entities:

1. The supported types of MAEC Actions, based on the vocabulary from which they originate.
2. The supported types of CybOX Objects, along with their individual properties. 

Thus, the general structure of the system activity and granular configuration files is
as follows:

::

	{
	  "supported actions": {"<action vocabulary>":{"<vocabulary entry>":"<boolean>"}},
	  "supported objects" : {"<object type>" : {"<object property>" : {"enabled":"<boolean>",
	                                                                   "required":"<boolean>"}}}
	}

We'll discuss the parameters relevant to each type of entity in the next sections.
	
Action Configuration Parameters
-------------------------------
All entries from each respective MAEC Action vocabulary are included inside of the 
"supported actions" section of the configuration file for the sake of completeness 
and ease-of-use. As such, not all are supported by default, but can be configured
by use of a value of **true** (indicating that it is supported for use in indicator
extraction) or **false** (indicating that it is not supported for use in indicator
extraction). Thus, the syntax for Action vocabulary entry configuration entries is
simply:

::

  {"<vocabulary entry>" : true | false}


**Example**

As an example, the following Action configuration JSON blob for the *DNSActionNameEnum*
would indicate that **maec-to-stix** would attempt to extract Indicators 
resulting from *send dns query* Actions. Conversely, it would NOT attempt to extract
indicators resulting from *send reverse dns lookup* Actions.

::

	{"DNSActionNameEnum-1.0":
		{
			"send dns query":true,
			"send reverse dns lookup":false
		}
	}

.. _object_parameters:
	
Object Configuration Parameters
-------------------------------
As compared to Actions, the act of configuring CybOX Objects in the context
of indicator extraction is inherently more complex due to the fact that it's 
necessary to configure the particular properties supported on each Object. 
Otherwise, there's no guarantee that a CybOX Object that ends up in a STIX 
Indicator will contain fields that are useful in this context (especially 
with regards to detection). 

Besides this, it can be necessary to have finer-grained control over the 
properties of an Object with respect to its usage in an indicator, including 
the ability to specify whether a particular property MUST occur on an Object, 
or whether it is optional. There may also be a need to whitelist on certain 
known property values, so that they do not inadvertently get used in an 
indicator. For instance, certain file names or registry keys may correspond
to common values that would result in false positives.

The general syntax for Object property configuration settings is:

::

  {"<object type>":
       {"<object property name>" : {"enabled": true | false,
                                    "required": true | false}}
  }							   

Where *<object type>* refers to the root type of a CybOX Object (e.g.
``FileObjectType``) and "<object property name>" refers to the name of
a property (field) of the CybOX Object (e.g. ``File_Path``).
  
Listing
~~~~~~~
  
The following parameters may be specified for each Object property.

===================== ============ ============= ========================
       Name               Type        Default      Example
===================== ============ ============= ========================
enabled                 Boolean       false         n/a
required                Boolean       false         n/a
mutually_exclusive      Boolean       n/a           n/a
whitelist               List          n/a        ["^10\\.([0-9]\\.?)+$"]
===================== ============ ============= ========================

Description
~~~~~~~~~~~

- ``enabled``: whether or not the property should be extracted and used in the STIX Indicator. A value of **true** indicates that the property should be extracted, while a value of **false** indicates that it should not be. Thus, all other parameters are valid only in conjunction with this parameter being set to **true**. Note that unless a CybOX Object has *at least one* property marked as ``enabled``, it will simply be ignored and will not be used in any STIX Indicators.

- ``required``: whether the property MUST be found on the Object in order for the Object to be included in the STIX Indicator. Only valid if ``enabled`` is set to **true**. A value of **true** indicates that the property MUST be found on the Object, whereas a value of **false** indicates that the property is optional and therefore will be included if found on the Object. Note that if multiple values are marked as ``required``, ALL must be found on the Object in order for it to be used in the STIX Indicator.

- ``mutually_exclusive`` (optional): whether the property is mutually exclusive with respect to other properties marked as such. This is intended to be used in cases where certain required properties are mutually exclusive with each other on an Object; thus, declaring such properties entails that an Object will used in the STIX Indicator only if one of these properties is found. Only valid if ``enabled`` is set to **true** AND ``required`` is set to **true**. A value of **true** indicates that the property is mutually exclusive with regards to other properties marked as such, and therefore only one of these properties must be found on the Object in order for it to be used in the STIX Indicator. A value of **false** indicates that the property functions as any other non-mutually exclusive required property. 

- ``whitelist`` (optional): a list of Python-compatible regular expressions that signify patterns of values on the property that should be ignored and thus excluded from use in the STIX Indicator. Accordingly, this means that if an Object has a property marked as ``required`` and the value of this property matches against one or more of these regular expressions, the Object will be completely excluded from the STIX Indicator output.
  
Example
~~~~~~~

As an example, the following JSON blob demonstrates that either the *Hostname/Hostname_Value* property or the *IP_Address/Address_Value* property MUST be found on an instance of the Socket Address Object (``SocketAddressObjectType``), due to the fact that both of their ``required`` and ``mutually_exclusive`` parameters are set to **true**. Also, the *Port/Port_Value* property will be included if found on an instance of the Object, but it is not required, due to the fact that its ``enabled`` parameter is set to **true** but its ``required`` parameter is set to **false**.

::

	 {"SocketAddressObjectType": {"hostname": {"hostname_value":{"enabled":true,
	                                                             "required":true,
	                                                             "mutually_exclusive":true},
	                                           "naming_system":{"enabled":false,
	                                                            "required":false}},
	                              "ip_address": {"address_value":{"enabled":true,
	                                                              "required":true,
	                                                              "mutually_exclusive":true},
	                              "vlan_name":{"enabled":false,
	                                           "required":false},
	                              "vlan_num":{"enabled":false,
	                                          "required":false}},
	                              "port": {"layer4_protocol":{"enabled":false,
	                                                          "required":false},
	                                       "port_value":{"enabled":true,
	                                                     "required":false}}}}