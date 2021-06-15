# MMS Protocol Parser for Zeek IDS
This package provides an analyzer for the IEC61850 MMS protocol used for communication by Intelligent Electronic Devices (IEDs) within electrical substations. The analyzer is provided as a dynamically loaded plugin for Zeek network traffic monitor [1].


## System Requirements
The analyzer was tested in a Virtual Machine with the following configuration:
|Component|Setting|
|------------------|-------------------|
|Operating System  | Ubuntu 18.04      |
|RAM               | 12GB              |
|Processor         | 3.5GHz, 4 cores   |
|Zeek              | version 2.6.x     |
|BTest             | version 0.57      |

The parser and sample scripts are developed and tested based on Zeek version 2.6, also known as Bro. They may not be directly compatible with Zeek version 3.0 onwards.

## Installation
### Zeek Installation
1. Install the required dependencies for Zeek listed in the official website: [https://docs.zeek.org/en/current/install/install.html#required-dependencies](https://docs.zeek.org/en/current/install/install.html#required-dependencies)

2. Archived Zeek versions can be found in this link: [https://download.zeek.org](https://download.zeek.org)

Download and install the required version of 2.6.x. Some commands may require root privileges:

    ./configure
    make
    make install
### Plugin Installation
1. git clone https://github.com/smartgridadsc/MMS-protocol-parser-for-Zeek-IDS
2. cd MMS-protocol-parser-for-Zeek-IDS/
3. ./configure --bro-dist=/path_to_zeek
4. make
5. make install

The command below can be used to check that the plugin has been installed and loaded correctly.

    <path_to_zeek>/build/src/bro –N | grep MMS
### BTest Installation
BTest [2] is a framework for system level testing in Zeek. It must be installed separately. Download the latest btest version from [https://download.zeek.org/](https://download.zeek.org/) and enter the following commands to complete the installation:

    tar xzvf btest-*.tar.gz
    cd btest-*
    python setup.py install

## Testing
BTest test cases and corresponding trace files for the supported MMS services reside in the tests/ folder. Majority of the tested pcaps were generated using libIEC61850 v1.4.0 [3]. Samples were also extracted from pcaps generated in EPIC lab [4] in Singapore University of Technology and Design (SUTD).
The tests can be executed with the following commands:

    cd tests/
    btest

## Supported Services

The table below lists the subset of MMS PDUs and services that are currently supported by the analyzer from the IEC61850 standard.
|||
|---|---|
|**Supported PDUs**|Confirmed-RequestPDU|
||Confirmed-ResponsePDU|
||Conclude-RequestPDU|
||Conclude-ResponsePDU|
||Initiate-RequestPDU|
||Initiate-ResponsePDU|
|**Supported Confirmed Services**|Status|
||Read|
||Write|
||GetNameList|
||GetVariableAccessAttributes
||GetNamedVariableListAttributes
||FileDirectory
||FileOpen
||FileRead
||FileClose
||Identify
||FileRename
||DefineNamedVariableList
||DeleteNamedVariableList
||ObtainFile

## Event Generation

Each network packet is identified by its PDU and service type. A Zeek event is then generated with the parsed information. The signature of the event will be one of the following:

    event <service_name>_request(…)
    event <service_name>_response(…)

The input parameters to each event are a combination of the following fields tailored to the specific service:
|Name|Type|Description|
|--|--|--|
|c|Connection|Zeek record containing information about the TCP connection.|
|invoke_id|Count|Each confirmed-service request and response pair are identified through an invoke id.|
|identifier|String|In some services, requests are sent to retrieve specific object information. For easier analysis at the script level, the properties of the object are tagged as an identifier e.g. domainId/itemId. This identifier is propagated to the corresponding response event.
|data|String Vector|A vector containing data extracted from a request or response packet in sequential order.|
|datatype|Count Vector|A vector to accompany the _data_ vector containing the tags of the datatype. A user may then use Zeek’s built-in conversion functions e.g. to_int() to perform computational analysis at the script level. All tags are defined in mms-tags.pac.


## Usage
A sample script, services_log.bro, has been provided for log generation. It can be invoked with the following command:

    cd <path_to_zeek>
    ./build/src/bro -r <path_to_plugin>/tests/Traces/<filename e.g. getNameList.pcap> <path_to_plugin>/scripts/ services_log.bro

This will generate a file named ‘mms.log’ in the current folder.

## Debug Mode
Debug is disabled by default. For detailed printout of the parsing, recompile the program with DEBUG symbol by specifying _#define DEBUG_ in mms-analyzer.pac.

## Prerequisites / Limitations
The prerequisites that must be met for successful parsing of a trace file are as follows:
1. Trace files must have the 3-way TCP handshake for the connection to be recognized as established and to trigger the MMS analyzer.
2. The IEC61850 standard specifies the presence of certain services and protocols in the OSI stack. These include TPKT, COTP, Session, Presentation, ACSE (for initiate service) and MMS layers which must be present. Valid trace files are provided in the tests/ folder.
3. Reassembly of only MMS layer fragmentation is supported. Reassembly of other layers such as TPKT is not supported.
4. Port based dynamic protocol detection is used. The source or destination port must be 102.

## Extracted Data
The following section lists the PDUs/services, the selected identifier and the corresponding set of fields parsed for storage in the _data_ vector.
|PDU|Identifier|Data Fields|
|--|--|--|--|
Initiate-Request|NA|localDetailCalling|
|||proposedMaxServOutstandingCalling|
|||proposedMaxServOutstandingCalled|
|||proposedDataStructureNestingLevel|
|||initRequestDetail|
|||&nbsp;&nbsp;&nbsp;&nbsp;proposedVersionNumber|
|||&nbsp;&nbsp;&nbsp;&nbsp;proposedParameterCBB|
|||&nbsp;&nbsp;&nbsp;&nbsp;servicesSupportedCalling|
Initiate-Response|NA|localDetailCalled|
|||negotiatedMaxServOutstandingCalling|
|||negotiatedMaxServOutstandingCalled|
|||negotiatedDataStructureNestingLevel|
|||initResponseDetail|
|||&nbsp;&nbsp;&nbsp;&nbsp;negotiatedVersionNumber
|||&nbsp;&nbsp;&nbsp;&nbsp;negotiatedParameterCBB
|||&nbsp;&nbsp;&nbsp;&nbsp;servicesSupportedCalled
Conclude-Request|NA|NA|
Conclude-Response|NA|NA|

<br>


|Confirmed Service|Identifier|Data Fields|
|--|--|--|
|Status-Request|NA|Boolean|
|Status-Response|NA|vmdLogicalStatus|
|||vmdPhysicalStatus
|||localDetail
|Read-Request|domainID_itemID|NA|
|Read-Response|\<Request identifier>|Boolean|
|||Bit-string
|||Integer
|||Unsigned
|||Floating-Point
|||Octet-String
|||Visible-String
|||UTC-Time
|||MMSString
|Write-Request|domainID_itemID|Boolean|
|||Bit-string
|||Integer
|||Unsigned
|||Floating-Point
|||Octet-String
|||Visible-String
|||UTC-Time
|||MMSString
|Write-Response|\<Request identifier>|NA
|GetNameList-Request|domainSpecific|NA|
|GetNameList-Response|\<Request identifier>|listOfIdentifier|
|||moreFollows (optional)
|GetVariableAccessAttributes-Request|domainID_itemID|NA|
|GetVariableAccessAttributes-Response|\<Request identifier>|mmsDeletable|
|||typeDescription
|||&nbsp;&nbsp;&nbsp;&nbsp;structure
|GetNamedVariableListAttributes-Request|domainId_itemId|NA|
|GetNamedVariableListAttributes-Response|\<Request identifier>|mmsDeletable
|||listOfVariable
|||&nbsp;&nbsp;&nbsp;&nbsp;VariableSpecification
|||&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;name
|||&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;domain-specific
|FileDirectory-Request|NA|fileSpecification [or empty string if not present]
|FileDirectory-Response|NA|listOfDirectoryEntry|
|||&nbsp;&nbsp;&nbsp;&nbsp;filename
|||&nbsp;&nbsp;&nbsp;&nbsp;fileAttributes
|||&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;sizeOfFile
|||&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;lastModified
|FileOpen-Request|NA|filename
|||initialPosition
|FileOpen-Response|NA|frsmId
|||fileAttributes
|||&nbsp;&nbsp;&nbsp;&nbsp;sizeOfFile
|||&nbsp;&nbsp;&nbsp;&nbsp;lastModified
|FileRead-Request|NA|frsmId
|FileRead-Response|NA|fileData
|||moreFollows
|FileClose-Request|NA|frsmId|
|FileClose-Response|NA|NA|
|FileRename-Request|NA|currentFileName
|||newFileName
|FileRename-Response|NA|NA
|Identify-Request|NA|NA
|Identify-Response|NA|vendorName
|||modelName
|||revision
|DefineNamedVariableList-Request|domainId_itemId|listOfVariable
|||&nbsp;&nbsp;&nbsp;&nbsp;VariableSpecification
|||&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;name
|||&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;domain-specific
|DefineNamedVariableList-Response (NULL)|NA|NA
|DeleteNamedVariableList-Request|domainId_itemId|scopeOfDelete
|DeleteNamedVariableList-Response|NA|numberMatched
|||numberDeleted
|ObtainFile-Request|NA|sourceFile
|||destinationFile
|ObtainFile-Response|NA|NA|


## References
[1] [https://zeek.org](https://zeek.org)
[2] [https://github.com/zeek/btest](https://github.com/zeek/btest)
[3] [https://libiec61850.com/libiec61850/](https://libiec61850.com/libiec61850/)
[4] [https://itrust.sutd.edu.sg/testbeds/electric-power-intelligent-control-epic/](https://itrust.sutd.edu.sg/testbeds/electric-power-intelligent-control-epic/)

## Contact Information
If you would like to get in touch regarding our project, please contact any of our contributors via email:
1. Chen Binbin
Email: [binbin.chen@adsc-create.edu.sg](mailto:binbin.chen@adsc-create.edu.sg)
2. Tan Heng Chuan
Email: [hc.tan@adsc-create.edu.sg](mailto:hc.tan@adsc-create.edu.sg)

For more information on our organization’s research activities, please refer to our main website at [https://adsc.illinois.edu](https://adsc.illinois.edu)
