Granular Configuration File Defaults
====================================

This page describes the default configuration settings included in each of the
granular system activity indicator extraction configuration files. For more
information on what these settings mean, please refer to the :doc:`granular_config`
documentation.

.. _driver_activity_config.json:

driver_activity_config.json
---------------------------
**Supported Actions**

- load and call driver
- load driver

**Supported Objects**

- WindowsDriverObjectType
   
  - *Required Fields*
  
    - driver_name
    - file_path
	
  - *Optional Fields*
      
    - file_name
	
.. _file_system_activity_config.json:

file_system_activity_config.json
--------------------------------
**Supported Actions**

- copy file
- create file
- modify file
- move file
- rename file
- write to file

**Supported Objects**

- ArchiveFileObjectType
   
  - *Required Fields*
  
    - file_path
	  
  - *Optional Fields*
   
    - file_name
    - hashes/hash/simple_hash_value
    - hashes/hash/type
	 
- FileObjectType
   
  - *Required Fields*
  
    - file_path
	  
  - *Optional Fields*
   
    - file_name
    - hashes/hash/simple_hash_value
    - hashes/hash/type
	 
- ImageFileObjectType
   
  - *Required Fields*
  
    - file_path
	  
  - *Optional Fields*
   
    - file_name
    - hashes/hash/simple_hash_value
    - hashes/hash/type
- PDFFileObjectType
   
  - *Required Fields*
  
    - file_path
	  
  - *Optional Fields*
   
    - file_name
    - hashes/hash/simple_hash_value
    - hashes/hash/type
	 
- UnixFileObjectType
   
  - *Required Fields*
  
    - file_path
	  
  - *Optional Fields*
   
    - file_name
    - hashes/hash/simple_hash_value
    - hashes/hash/type
	 
- WindowsExecutableFileObjectType
   
  - *Required Fields*
  
    - file_path
	  
  - *Optional Fields*
   
    - file_name
    - hashes/hash/simple_hash_value
    - hashes/hash/type
	 
- WindowsFileObjectType
   
  - *Required Fields*
  
    - file_path
	  
  - *Optional Fields*
   
    - file_name
    - hashes/hash/simple_hash_value
    - hashes/hash/type

.. _mutex_activity_config.json:
	
mutex_activity_config.json
--------------------------
**Supported Actions**

- create mutex

**Supported Objects**

- MutexObjectType

  - *Required Fields*
  
    - name
	
- WindowsMutexObjectType

  - *Required Fields*
  
    - name

.. _network_activity_config.json:
	
network_activity_config.json
----------------------------
**Supported Actions**

- connect to ip
- connect to socket address
- connect to url
- download file
- get host by address
- send dns query
- send email message
- send http get request
- send icmp request

**Supported Objects**
 
- AddressObjectType

  - *Required Fields*
  
    - address_value
	
- DNSQueryObjectType

  - *Required Fields*
  
    - question/qname/value
	
  - *Optional Fields*
  
    - answer_resource_records/resource_record/domain_name/value
    - answer_resource_records/resource_record/ip_address/address_value
	
- DomainNameObjectType
   
  - *Required Fields*
  
    - value
	
- EmailMessageObjectType
   
  - *Required Fields*
      
    - header/subject
    - header/to/recipient/address_value
	
  - *Optional Fields*
  
    - header/from/address_value
	
- HTTPSessionObjectType

  - *Required Fields*
  
    - http_request_response/http_client_request/http_request_header/parsed_header/host/domain_name/value
    - http_request_response/http_client_request/http_request_line/value
	
  - *Optional Fields*
  
    - http_request_response/http_client_request/http_request_header/parsed_header/host/port/port_value
    - http_request_response/http_client_request/http_request_header/parsed_header/user_agent
    - http_request_response/http_client_request/http_request_line/http_method
	
- NetworkConnectionObjectType

  - *Mutually Exclusive Required Fields*
  
    - destination_socket_address/hostname/hostname_value
    - destination_socket_address/ip_address/address_value
	
  - *Optional Fields*
  
    - destination_socket_address/port/port_value
    - layer7_connections/dns_query/answer_resource_records/resource_record/domain_name/value
    - layer7_connections/dns_query/answer_resource_records/resource_record/ip_address/address_value
    - layer7_connections/dns_query/question/qname/value
    - layer7_connections/http_session/http_request_response/http_client_request/http_request_header/parsed_header/host/domain_name/value
    - layer7_connections/http_session/http_request_response/http_client_request/http_request_header/parsed_header/host/port/port_value
    - layer7_connections/http_session/http_request_response/http_client_request/http_request_header/parsed_header/user_agent
    - layer7_connections/http_session/http_request_response/http_client_request/http_request_line/http_method
    - layer7_connections/http_session/http_request_response/http_client_request/http_request_line/value
    - layer7_protocol	
	
- SocketAddressObjectType

  - *Mutually Exclusive Required Fields*
  
    - hostname/hostname_value
    - ip_address/address_value
	
  - *Optional Fields*
  
    - port/port_value 	
	
- URIObjectType

  - *Required Fields*
  
    - value

.. _process_activity_config.json:
	
process_activity_config.json
----------------------------
**Supported Actions**

- create process
- create thread

**Supported Objects**

- ProcessObjectType

  - *Required Fields*
  
    - image_info/path

  - *Optional Fields*

    - image_info/file_name
    - name

- UnixProcessObjectType

  - *Required Fields*
  
    - image_info/path

  - *Optional Fields*
    
    - image_info/file_name
    - name

- WindowsProcessObjectType

  - *Required Fields*

    - image_info/path

  - *Optional Fields*

    - image_info/file_name
    - name

.. _registry_activity_config.json:
	
registry_activity_config.json
-----------------------------
**Supported Actions**

- create registry key
- create registry key value
- modify registry key
- modify registry key value

**Supported Objects**

- WindowsRegistryKeyObjectType

  - *Required Fields*
     
    - hive
    - key

  - *Optional Fields*

    - values/value/data
    - values/value/name

.. _service_activity_config.json:

service_activity_config.json
----------------------------
**Supported Actions**

- create service

**Supported Objects**

  - WindowsServiceObjectType
  
    - *Required Fields*
      
      - image_info/path
      - service_name
   
    - *Optional Fields*
     
      - display_name
      - image_info/file_name
